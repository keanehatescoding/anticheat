// SPDX-License-Identifier: GPL-2.0
/*
 * anticheat_module.c — kernel-mode anticheat engine.
 *
 * Defensive security instrumentation only.  Provides:
 *
 *  1. Syscall-table discovery + integrity checking (detects syscall hooks
 *     pointing outside the core kernel text, i.e. classic rootkits).
 *  2. Kernel module enumeration (userspace cross-checks /proc/modules to
 *     detect modules hidden from procfs).
 *  3. Protected process registry; protection is inherited by forked children.
 *  4. ptrace interception: attach/debug requests against protected processes
 *     are neutralised (request argument rewritten to an invalid value, so
 *     the syscall fails with -EIO and has no side effects) and, per policy,
 *     the offending tracer is SIGKILLed from a workqueue.
 *  5. execve / exit monitoring of protected processes (kprobes).
 *  6. VMA-level memory scanning (RWX "code cave" detection, plus anonymous
 *     executable mappings -- catches the write-then-mprotect(R-X) injection
 *     pattern that RWX-only detection misses).
 *  7. Event ring buffer consumed by the userspace daemon via ioctls.
 *
 * All symbol resolution is done through kprobes (kallsyms_lookup_name is not
 * exported on modern kernels); nothing relies on /proc/kallsyms content.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/err.h>
#include <asm/unistd.h>

#include "anticheat.h"

#ifndef __NR_syscalls
# define __NR_syscalls 512
#endif

/* forward declarations */
static void ac_emit(unsigned int type, int pid, const char *comm,
                    const char *fmt, ...);

/* ------------------------------------------------------------------ */
/* safe kernel reads                                                   */
/* ------------------------------------------------------------------ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
# define ac_kread(dst, src, n) copy_from_kernel_nofault((dst), (src), (n))
#else
# include <asm/uaccess.h>
# define ac_kread(dst, src, n) probe_kernel_read((dst), (src), (n))
#endif

/* ------------------------------------------------------------------ */
/* policy / parameters                                                 */
/* ------------------------------------------------------------------ */
static unsigned int ac_policy = 0x1;   /* bit0: SIGKILL tracer that ptrace()s a protected proc */
module_param(ac_policy, uint, 0600);
MODULE_PARM_DESC(ac_policy, "policy bitmask: bit0 = kill ptrace offenders");

static bool ac_verbose = true;
module_param(ac_verbose, bool, 0600);
MODULE_PARM_DESC(ac_verbose, "print extra diagnostics");

/* ------------------------------------------------------------------ */
/* symbol resolution via kprobes                                       */
/* ------------------------------------------------------------------ */
static unsigned long ac_lookup(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;

    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

/* Normalize a kprobe-reported address to the start of the function.
 * On x86-64 with IBT + fentry the kprobe lands on the ftrace call site,
 * i.e. 4 bytes after the endbr64, whereas the syscall table stores the
 * symbol start (the endbr64 itself).  Detect endbr64 (0xf3 0x0f 0x1e 0xfa)
 * right before the address and step back; on kernels without that layout
 * the address is already the function start. */
static unsigned long ac_normalize_func(unsigned long addr)
{
    unsigned int insn;

    if (!addr)
        return 0;
    if (ac_kread(&insn, (void *)(addr - 4), sizeof(insn)) == 0 &&
        insn == 0xfa1e0ff3)   /* endbr64, little-endian */
        return addr - 4;
    return addr;
}

static unsigned long ac_stext;
static unsigned long ac_etext;
static unsigned long ac_text_end;   /* upper bound for "core kernel text" */

static bool ac_module_sane(const struct module *m);   /* fwd decl */

static void ac_resolve_text_bounds(void)
{
    ac_stext = ac_lookup("_stext");
    if (!ac_stext)
        ac_stext = ac_lookup("_text");
    ac_etext = ac_lookup("_etext");
    if (!ac_etext)
        ac_etext = ac_lookup("_sinittext");

    if (ac_etext)
        ac_text_end = ac_etext;
    else if (ac_stext)
        ac_text_end = ac_stext + 0x20000000UL;   /* generous image bound */
}

/* ------------------------------------------------------------------ */
/* module list walking (kernel-internal list; module_mutex is not      */
/* exported, so we walk with preemption disabled — best effort)        */
/* ------------------------------------------------------------------ */
static bool ac_addr_in_module(unsigned long addr)
{
    struct module *m;
    bool found = false;

    preempt_disable();
    list_for_each_entry(m, &THIS_MODULE->list, list) {
        if (ac_module_sane(m) && within_module_core(addr, m)) {
            found = true;
            break;
        }
    }
    preempt_enable();
    return found;
}

static bool ac_in_core_text(unsigned long addr)
{
    if (!ac_stext || !ac_text_end)
        return false;
    if (addr < ac_stext || addr >= ac_text_end)
        return false;
    if (ac_addr_in_module(addr))
        return false;
    return true;
}

static unsigned long ac_anchor;   /* known-good syscall handler (read) */

/* Bounds-free handler sanity check: the address must live outside every
 * loaded module and within a sane window around a known-good handler.
 * (Exact _stext/_etext are preferred when kprobe-able, but are section
 * labels and may not be; this window is the fallback.) */
static bool ac_plausible_handler(unsigned long e, unsigned long anchor)
{
    if (!e)
        return false;
    if (ac_addr_in_module(e))
        return false;
    return e > anchor - 0x4000000UL && e < anchor + 0x4000000UL;
}

static bool ac_entry_bad(unsigned long e)
{
    if (ac_stext && ac_text_end)
        return !ac_in_core_text(e);
    return !ac_plausible_handler(e, ac_anchor);
}

/* ------------------------------------------------------------------ */
/* syscall table discovery                                             */
/* ------------------------------------------------------------------ */
static unsigned long ac_syscall_table;

/*
 * Locate sys_call_table without kallsyms_lookup_name:
 *  - resolve __x64_sys_read/__x64_sys_write handler addresses via kprobes,
 *  - scan the kernel image for an 8-byte slot equal to the read handler,
 *  - verify the write handler sits at table[__NR_write] and that most
 *    entries are real core-text handlers (distinguishes the main table
 *    from e.g. the x32 table, which reuses the same handlers sparsely).
 */
static bool ac_table_plausible(unsigned long base, unsigned long anchor)
{
    unsigned int i, valid = 0;

    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long e = 0;

        if (ac_kread(&e, (void *)(base + i * sizeof(e)), sizeof(e)))
            continue;
        if (!e)
            continue;
        if (ac_plausible_handler(e, anchor) && ++valid >= 400)
            return true;
    }
    if (ac_verbose)
        pr_info("plausibility for base=0x%lx: valid=%u\n", base, valid);
    return valid >= 400;
}

/* Once the table is found, derive core-text bounds from its (plausible)
 * entries so the integrity check can classify entries even when the
 * _stext/_etext kprobe lookups failed. */
static void ac_derive_bounds(unsigned long base, unsigned long anchor)
{
    unsigned int i;
    unsigned long lo = 0, hi = 0;

    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long e = 0;

        if (ac_kread(&e, (void *)(base + i * sizeof(e)), sizeof(e)))
            continue;
        if (!ac_plausible_handler(e, anchor))
            continue;
        if (!lo || e < lo)
            lo = e;
        if (e > hi)
            hi = e;
    }
    if (lo && hi) {
        if (!ac_stext)
            ac_stext = lo & ~0x1FFFFFUL;                 /* 2 MB round down */
        if (!ac_text_end)
            ac_text_end = (hi + 0x1FFFFFUL) & ~0x1FFFFFUL; /* 2 MB round up */
        pr_info("derived text bounds: stext=0x%lx end=0x%lx\n",
                ac_stext, ac_text_end);
    }
}

static unsigned long ac_find_syscall_table(void)
{
    unsigned long rh, wh, lo, hi, addr, base, v1, v2;

    rh = ac_normalize_func(ac_lookup("__x64_sys_read"));
    wh = ac_normalize_func(ac_lookup("__x64_sys_write"));
    if (ac_verbose)
        pr_info("lookup __x64_sys_read=0x%lx __x64_sys_write=0x%lx\n",
                rh, wh);
    if (!rh || !wh)
        return 0;

    /* Primary window: from the end of .text forward.  On x86-64 the table
     * lives in .rodata right after .text. */
    lo = ac_etext ? ac_etext : (ac_stext ? ac_stext : rh);
    hi = lo + 0x2000000UL;      /* 32 MB window */
    if (ac_verbose)
        pr_info("table scan window [0x%lx, 0x%lx)\n", lo, hi);

    for (addr = lo; addr < hi; addr += sizeof(unsigned long)) {
        if (ac_kread(&v1, (void *)addr, sizeof(v1)))
            continue;
        if (v1 != rh)
            continue;
        base = addr - __NR_read * sizeof(unsigned long);
        if (ac_kread(&v2, (void *)(base + __NR_write * sizeof(unsigned long)),
                     sizeof(v2)))
            continue;
        if (ac_verbose)
            pr_info("candidate addr=0x%lx base=0x%lx v2=0x%lx\n",
                    addr, base, v2);
        if (v2 == wh && ac_table_plausible(base, rh)) {
            ac_anchor = rh;
            ac_derive_bounds(base, rh);
            return base;
        }
    }

    /* Fallback: backward scan from the read handler.  Rarely taken (the
     * table is normally right after .text), so mirror the forward window
     * rather than skimping on it: some layouts place the table below the
     * first handler. */
    for (addr = rh; addr > rh - 0x2000000UL; addr -= sizeof(unsigned long)) {
        if (ac_kread(&v1, (void *)addr, sizeof(v1)))
            continue;
        if (v1 != rh)
            continue;
        base = addr - __NR_read * sizeof(unsigned long);
        if (ac_kread(&v2, (void *)(base + __NR_write * sizeof(unsigned long)),
                     sizeof(v2)))
            continue;
        if (ac_verbose)
            pr_info("fallback candidate addr=0x%lx base=0x%lx v2=0x%lx\n",
                    addr, base, v2);
        if (v2 == wh && ac_table_plausible(base, rh)) {
            ac_anchor = rh;
            ac_derive_bounds(base, rh);
            return base;
        }
    }
    return 0;
}

static int ac_check_syscalls(struct ac_syscall_check *out)
{
    unsigned long base = ac_syscall_table;
    unsigned int i;

    memset(out, 0, sizeof(*out));
    out->table_addr = base;
    if (!base)
        return -ENODEV;   /* table not located at load time; not an I/O fault */

    out->nr_syscalls = __NR_syscalls;
    for (i = 0; i < __NR_syscalls; i++) {
        unsigned long e = 0;

        if (ac_kread(&e, (void *)(base + i * sizeof(e)), sizeof(e)))
            continue;
        if (!e)
            continue;
        out->total++;
        if (ac_entry_bad(e)) {
            out->non_text++;
            out->hooked++;
            ac_emit(AC_EV_SYSCALL_HOOK, 0, "?",
                    "syscall[%u] -> 0x%lx outside core kernel text", i, e);
        }
    }
    out->ok = (out->hooked == 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* event ring buffer                                                   */
/* ------------------------------------------------------------------ */
#define AC_RING_SIZE 256

static struct ac_event ac_ring[AC_RING_SIZE];
static unsigned int ac_ring_head, ac_ring_tail, ac_ring_count;
static DEFINE_SPINLOCK(ac_ring_lock);
static unsigned int ac_dropped;

static void ac_emit(unsigned int type, int pid, const char *comm,
                    const char *fmt, ...)
{
    struct ac_event *ev;
    va_list args;
    unsigned long flags;

    spin_lock_irqsave(&ac_ring_lock, flags);
    if (ac_ring_count >= AC_RING_SIZE) {
        ac_ring_tail = (ac_ring_tail + 1) % AC_RING_SIZE;
        ac_ring_count--;
        ac_dropped++;
    }
    ev = &ac_ring[ac_ring_head];
    memset(ev, 0, sizeof(*ev));
    ev->ts = ktime_get_real_fast_ns();
    ev->pid = pid;
    strscpy(ev->comm, comm ? comm : "?", sizeof(ev->comm));
    ev->type = type;
    va_start(args, fmt);
    vsnprintf(ev->data, sizeof(ev->data), fmt, args);
    va_end(args);
    ac_ring_head = (ac_ring_head + 1) % AC_RING_SIZE;
    ac_ring_count++;
    spin_unlock_irqrestore(&ac_ring_lock, flags);
}

static int ac_drain_events(struct ac_event_list *out)
{
    unsigned long flags;

    spin_lock_irqsave(&ac_ring_lock, flags);
    if (out) {
        out->dropped = ac_dropped;
        out->count = 0;
    }
    while (ac_ring_count > 0 && (!out || out->count < AC_MAX_EVENTS)) {
        if (out)
            out->events[out->count++] = ac_ring[ac_ring_tail];
        ac_ring_tail = (ac_ring_tail + 1) % AC_RING_SIZE;
        ac_ring_count--;
    }
    spin_unlock_irqrestore(&ac_ring_lock, flags);
    return 0;
}

/* ------------------------------------------------------------------ */
/* protected process registry (task-pointer based; namespace-safe)     */
/* ------------------------------------------------------------------ */
#define AC_PROT_MAX 64

struct ac_prot_entry {
    struct task_struct *task;
    pid_t pid;                  /* display only */
    bool jit_allowed;
    char comm[AC_MAX_COMM];
};

static struct ac_prot_entry ac_prots[AC_PROT_MAX];
static DEFINE_SPINLOCK(ac_prot_lock);
static unsigned int ac_prot_count;

static struct task_struct *ac_find_task(pid_t pid)
{
    struct pid *pidp = find_get_pid(pid);
    struct task_struct *task;

    if (!pidp)
        return NULL;
    task = get_pid_task(pidp, PIDTYPE_PID);
    put_pid(pidp);
    return task;
}

/* Resolve `nr` as a pid number within the pid namespace that host-pid
 * ref_pid lives in, rather than the caller's own namespace. Lets a
 * privileged caller target a process by its in-namespace pid (e.g. a
 * sandboxed/containerized game) when it can supply some other
 * host-resolvable pid known to be in that same namespace (ref_pid).
 *
 * find_pid_ns() has no internal locking (unlike find_get_pid(), which
 * wraps rcu_read_lock() itself), and task_active_pid_ns(ref_task) is
 * only safe to read while ref_task's reference is held -- ref_task could
 * otherwise exit concurrently on another CPU. So the namespace lookup and
 * find_pid_ns() call must both happen strictly before put_task_struct().
 * The resulting struct pid is pinned with get_pid() before the RCU
 * read-side critical section ends, mirroring how find_get_pid() itself
 * pins under rcu_read_lock(). */
static struct task_struct *ac_find_task_in_ns_of(pid_t nr, pid_t ref_pid)
{
    struct task_struct *ref_task, *target;
    struct pid_namespace *ns;
    struct pid *pidp;

    ref_task = ac_find_task(ref_pid);
    if (!ref_task)
        return NULL;

    rcu_read_lock();
    ns = task_active_pid_ns(ref_task);
    pidp = ns ? find_pid_ns(nr, ns) : NULL;
    if (pidp)
        get_pid(pidp);
    rcu_read_unlock();

    put_task_struct(ref_task);
    if (!pidp)
        return NULL;

    target = get_pid_task(pidp, PIDTYPE_PID);
    put_pid(pidp);
    return target;
}

static int ac_add_prot_task(struct task_struct *t, bool jit_allowed)
{
    unsigned long flags;
    int i, slot = -1;
    int ret = 0;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].task == t) {
            ac_prots[i].jit_allowed = jit_allowed;  /* updatable via re-protect */
            ret = 0;                    /* already protected */
            goto out;
        }
        if (!ac_prots[i].task && slot < 0)
            slot = i;
    }
    if (slot < 0) {
        ret = -ENOSPC;
        goto out;
    }
    get_task_struct(t);
    ac_prots[slot].task = t;
    ac_prots[slot].pid = t->pid;
    ac_prots[slot].jit_allowed = jit_allowed;
    strscpy(ac_prots[slot].comm, t->comm, sizeof(ac_prots[slot].comm));
    ac_prot_count++;
out:
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return ret;
}

static int ac_add_prot_pid(pid_t pid, pid_t ref_pid, bool jit_allowed,
                            char *comm_out)
{
    struct task_struct *t = ref_pid > 0 ? ac_find_task_in_ns_of(pid, ref_pid)
                                         : ac_find_task(pid);
    int ret;

    if (!t)
        return -ESRCH;
    if (comm_out)
        strscpy(comm_out, t->comm, AC_MAX_COMM);
    ret = ac_add_prot_task(t, jit_allowed);
    put_task_struct(t);
    return ret;
}

static void ac_del_prot_task(struct task_struct *t)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].task == t) {
            put_task_struct(t);
            ac_prots[i].task = NULL;
            ac_prot_count--;
            break;
        }
    }
    spin_unlock_irqrestore(&ac_prot_lock, flags);
}

/* Fork inheritance already extends *protection* itself to children (see
 * ac_clone_ret()); mirror that for jit_allowed too, so a legitimate
 * JIT-marked process's child processes don't generate false anon-exec
 * reports just because the flag reset to false on them. */
static bool ac_task_jit_allowed(struct task_struct *t)
{
    unsigned long flags;
    int i;
    bool jit_allowed = false;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].task == t) {
            jit_allowed = ac_prots[i].jit_allowed;
            break;
        }
    }
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return jit_allowed;
}

static bool ac_is_protected_task(struct task_struct *t)
{
    unsigned long flags;
    int i;
    bool prot = false;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].task == t) {
            prot = true;
            break;
        }
    }
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return prot;
}

static bool ac_is_protected_pid(pid_t pid, char *comm_out)
{
    struct task_struct *t = ac_find_task(pid);
    bool prot = false;

    if (!t)
        return false;
    prot = ac_is_protected_task(t);
    if (prot && comm_out)
        strscpy(comm_out, t->comm, AC_MAX_COMM);
    put_task_struct(t);
    return prot;
}

/* lock state: pinned by AC_IOCTL_LOCK (try_module_get) */
static atomic_t ac_lock_count = ATOMIC_INIT(0);

static unsigned int ac_protected_count(void)
{
    unsigned long flags;
    unsigned int n;

    spin_lock_irqsave(&ac_prot_lock, flags);
    n = ac_prot_count;
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return n;
}

static int ac_list_protected(struct ac_prot_list *out)
{
    unsigned long flags;
    unsigned int n = 0;
    int i;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX && n < AC_MAX_PROTS; i++) {
        if (!ac_prots[i].task)
            continue;
        out->items[n].pid = ac_prots[i].pid;
        out->items[n].jit_allowed = ac_prots[i].jit_allowed;
        strscpy(out->items[n].comm, ac_prots[i].comm,
                sizeof(out->items[n].comm));
        n++;
    }
    out->count = n;
    spin_unlock_irqrestore(&ac_prot_lock, flags);
    return 0;
}

/* ------------------------------------------------------------------ */
/* kill-from-workqueue (safe delivery from atomic kprobe context)      */
/* ------------------------------------------------------------------ */
static struct workqueue_struct *ac_wq;

struct ac_kill_req {
    struct work_struct work;
    struct pid *pid;
};

static void ac_kill_worker(struct work_struct *w)
{
    struct ac_kill_req *r = container_of(w, struct ac_kill_req, work);
    struct task_struct *t = get_pid_task(r->pid, PIDTYPE_PID);

    if (t) {
        pr_info("policy: SIGKILL tracer pid %d (ptrace against protected process)\n",
                t->pid);
        send_sig(SIGKILL, t, 0);
        put_task_struct(t);
    }
    put_pid(r->pid);
    kfree(r);
}

static void ac_schedule_kill(struct task_struct *victim)
{
    struct ac_kill_req *r;

    if (!victim)
        return;
    r = kmalloc(sizeof(*r), GFP_ATOMIC);
    if (!r)
        return;
    INIT_WORK(&r->work, ac_kill_worker);
    r->pid = get_task_pid(victim, PIDTYPE_PID);
    queue_work(ac_wq, &r->work);
}

/* ------------------------------------------------------------------ */
/* kprobes                                                             */
/* ------------------------------------------------------------------ */
static int ac_ptrace_pre(struct kprobe *p, struct pt_regs *regs)
{
    /*
     * Modern x86-64 syscall wrappers (__x64_sys_*, __ia32_sys_*) are
     * `long f(const struct pt_regs *regs)`: %rdi at entry points to the
     * syscall's pt_regs frame, and the wrapper unpacks the arguments
     * from it.  The prologue loads args->di (offset 0x70) as the request
     * and args->si (offset 0x68) as the pid, so regs->di is the frame
     * pointer, not the request.
     */
    struct pt_regs *args = (struct pt_regs *)regs->di;
    long request = args->di;
    long target = args->si;
    char tcomm[AC_MAX_COMM] = "?";
    bool deny = false, kill = false;

    if (request == PTRACE_TRACEME) {
        /* the protected process itself asks to be traced; PTRACE_TRACEME
         * ignores its arguments, so args->si holds whatever was in the
         * register — report current->pid, not stale garbage */
        if (ac_is_protected_task(current)) {
            strscpy(tcomm, current->comm, sizeof(tcomm));
            target = current->pid;
            deny = true;
        }
    } else if (target > 0) {
        if (ac_is_protected_pid((pid_t)target, tcomm)) {
            deny = true;
            kill = true;
        }
    }
    if (!deny)
        return 0;

    ac_emit(AC_EV_PTRACE, (int)target, tcomm,
            "ptrace req %ld by pid %d (%s) DENIED",
            request, current->pid, current->comm);

    if (kill && (ac_policy & 0x1))
        ac_schedule_kill(current);

    /* Neutralise the syscall: rewrite the request slot in the frame to an
     * invalid value.  ptrace() rejects unknown requests with -EIO and
     * performs no side effects, so the tracer sees a clean failure. */
    args->di = -1;
    return 0;
}

/* Fork tracking: kretprobe on kernel_clone().  The ret handler receives the
 * new task's pid via regs_return_value().  (A plain kprobe post_handler runs
 * after the first instruction of the function, not after it returns, so it
 * cannot see the return value.) */
static int ac_clone_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long child_pid = (long)regs_return_value(regs);
    struct task_struct *child;
    char pcomm[AC_MAX_COMM];

    if (child_pid <= 0)
        return 0;
    if (!ac_is_protected_task(current))
        return 0;

    child = ac_find_task((pid_t)child_pid);
    if (!child)
        return 0;
    strscpy(pcomm, current->comm, sizeof(pcomm));
    ac_add_prot_task(child, ac_task_jit_allowed(current));
    ac_emit(AC_EV_FORK, child->pid, child->comm,
            "child of protected pid %d (%s); protection inherited",
            current->pid, pcomm);
    put_task_struct(child);
    return 0;
}

static struct kretprobe ac_kp_clone = {
    .kp = { .symbol_name = "kernel_clone" },
    .handler = ac_clone_ret,
    .maxactive = 128,
};
static bool ac_kp_clone_ok;

static int ac_exit_pre(struct kprobe *p, struct pt_regs *regs)
{
    if (!ac_is_protected_task(current))
        return 0;
    ac_emit(AC_EV_EXIT, current->pid, current->comm,
            "protected process exited");
    ac_del_prot_task(current);
    return 0;
}

static int ac_exec_pre(struct kprobe *p, struct pt_regs *regs)
{
    if (!ac_is_protected_task(current))
        return 0;
    ac_emit(AC_EV_EXEC, current->pid, current->comm,
            "execve() invoked (path is a user pointer, not resolved)");
    return 0;
}

static struct kprobe ac_kp_ptrace = {
    .symbol_name = "__x64_sys_ptrace",
    .pre_handler = ac_ptrace_pre,
};
static struct kprobe ac_kp_ptrace32 = {
    .symbol_name = "__ia32_sys_ptrace",
    .pre_handler = ac_ptrace_pre,
};
static struct kprobe ac_kp_exit = {
    .symbol_name = "do_exit",
    .pre_handler = ac_exit_pre,
};
static struct kprobe ac_kp_execve = {
    .symbol_name = "__x64_sys_execve",
    .pre_handler = ac_exec_pre,
};
static struct kprobe ac_kp_execveat = {
    .symbol_name = "__x64_sys_execveat",
    .pre_handler = ac_exec_pre,
};

static struct kprobe *ac_kprobes[] = {
    &ac_kp_ptrace, &ac_kp_ptrace32,
    &ac_kp_exit, &ac_kp_execve, &ac_kp_execveat,
};
static bool ac_kp_ok[ARRAY_SIZE(ac_kprobes)];  /* per-slot registration state */
static unsigned int ac_kprobes_registered;     /* count, for the log line */

static void ac_register_kprobes(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(ac_kprobes); i++) {
        int ret = register_kprobe(ac_kprobes[i]);

        ac_kp_ok[i] = (ret == 0);
        if (ret == 0) {
            ac_kprobes_registered++;
        } else if (ac_verbose) {
            pr_info("kprobe %s unavailable: %d\n",
                    ac_kprobes[i]->symbol_name, ret);
        }
    }
    if (register_kretprobe(&ac_kp_clone) == 0)
        ac_kp_clone_ok = true;
    else if (ac_verbose)
        pr_info("kretprobe kernel_clone unavailable\n");
}

static void ac_unregister_kprobes(void)
{
    unsigned int i;

    /* unregister only the probes that actually registered: a failed probe
     * (e.g. no IA32 support) must not be passed to unregister_kprobe() */
    for (i = 0; i < ARRAY_SIZE(ac_kprobes); i++)
        if (ac_kp_ok[i])
            unregister_kprobe(ac_kprobes[i]);
    ac_kprobes_registered = 0;
    memset(ac_kp_ok, 0, sizeof(ac_kp_ok));
    if (ac_kp_clone_ok) {
        unregister_kretprobe(&ac_kp_clone);
        ac_kp_clone_ok = false;
    }
}

/* ------------------------------------------------------------------ */
/* VMA scan (snapshot per file-description)                            */
/* ------------------------------------------------------------------ */
struct ac_fd_state {
    struct mutex lock;          /* serializes SCAN/MODS snapshot access:
                                 * a shared/dup'd fd must not race a GET
                                 * against a concurrent BEGIN/END */
    struct ac_vma_info *vmas;   /* SCAN snapshot */
    unsigned int n_vmas;
    unsigned int rwx_count;
    unsigned int exec_count;
    unsigned int anon_exec_count;
    unsigned int truncated;
    struct ac_mod_info *mods;   /* MODS snapshot */
    unsigned int n_mods;
};

static void ac_free_fd_state(struct ac_fd_state *st)
{
    if (!st)
        return;
    kvfree(st->vmas);
    kvfree(st->mods);
    kfree(st);
}

static struct ac_fd_state *ac_get_fd_state(struct file *file)
{
    struct ac_fd_state *st = file->private_data;

    if (!st) {
        st = kzalloc(sizeof(*st), GFP_KERNEL);
        if (st) {
            mutex_init(&st->lock);
            file->private_data = st;
        }
    }
    return st;
}

static unsigned long long ac_module_size(const struct module *mod)
{
    unsigned long long size = 0;

    for_class_mod_mem_type(type, core)
        size += mod->mem[type].size;
    return size;
}

/* A plausible module entry: LIVE with a non-zero, sane text mapping.
 * Guards the mutex-less module walk against torn/freed entries
 * (module_mutex is not exported).  A garbage entry with base=0 and a huge
 * size would otherwise make within_module_core() claim every kernel
 * address, poisoning both the hidden-module check and the syscall
 * plausibility filter. */
static bool ac_module_sane(const struct module *m)
{
    if (m->state != MODULE_STATE_LIVE)
        return false;
    if (!m->mem[MOD_TEXT].base || !m->mem[MOD_TEXT].size)
        return false;
    if (m->mem[MOD_TEXT].size > 0x40000000UL)   /* > 1 GiB text: bogus */
        return false;
    return true;
}

static int ac_build_vma_snapshot(struct ac_fd_state *st, int pid,
                                 int emit_events)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned int n = 0;

    kvfree(st->vmas);
    st->vmas = NULL;
    st->n_vmas = st->rwx_count = st->exec_count = st->anon_exec_count = st->truncated = 0;

    task = ac_find_task(pid);
    if (!task)
        return -ESRCH;
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -ESRCH;

    st->vmas = kvmalloc_array(AC_MAX_VMAS, sizeof(struct ac_vma_info),
                              GFP_KERNEL);
    if (!st->vmas) {
        pr_warn("scan: kvmalloc_array(%u, %zu) failed for pid %d\n",
                AC_MAX_VMAS, sizeof(struct ac_vma_info), pid);
        mmput(mm);
        return -ENOMEM;
    }

    mmap_read_lock(mm);
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
        struct ac_vma_info *vi;
        char *buf;
        char *p;

        if (n >= AC_MAX_VMAS) {
            st->truncated = 1;
            break;
        }
        vi = &st->vmas[n];
        memset(vi, 0, sizeof(*vi));
        vi->start = vma->vm_start;
        vi->end = vma->vm_end;
        vi->offset = (unsigned long long)vma->vm_pgoff << PAGE_SHIFT;
        vi->flags = vma->vm_flags;
        if (vma->vm_file) {
            struct file *f = vma->vm_file;

            vi->is_file = 1;
            if (f->f_inode)
                vi->inode = f->f_inode->i_ino;
            buf = kmalloc(PATH_MAX, GFP_KERNEL);
            if (buf) {
                p = d_path(&f->f_path, buf, PATH_MAX);
                if (!IS_ERR(p))
                    strscpy(vi->path, p, sizeof(vi->path));
                kfree(buf);
            }
        }
        if ((vma->vm_flags & (VM_EXEC | VM_WRITE)) == (VM_EXEC | VM_WRITE)) {
            st->rwx_count++;
            if (emit_events)
                ac_emit(AC_EV_RWX, pid, "?",
                        "RWX mapping [0x%llx-0x%llx] %s",
                        vi->start, vi->end,
                        vi->path[0] ? vi->path : "(anonymous)");
        }
        if (!vi->is_file && (vma->vm_flags & VM_EXEC)) {
            /* No backing file at all -- legitimate executable code is always
             * backed by a file (the binary or a shared library) via mmap.
             * Also catches shellcode written to a RW mapping and then
             * mprotect()'d to R-X, which never trips the RWX check above
             * since W and X are never both set at the same instant.
             * vdso/vvar are expected, harmless members of this set (see the
             * AC_EV_ANON_EXEC comment in anticheat.h) -- the daemon alerts
             * on new entries appearing after a process is first observed,
             * not on the raw count. */
            st->anon_exec_count++;
            if (emit_events)
                ac_emit(AC_EV_ANON_EXEC, pid, "?",
                        "anonymous executable mapping [0x%llx-0x%llx]",
                        vi->start, vi->end);
        }
        if (vma->vm_flags & VM_EXEC)
            st->exec_count++;
        n++;
    }
    vma_iter_invalidate(&vmi);
    mmap_read_unlock(mm);
    mmput(mm);
    st->n_vmas = n;
    return 0;
}

static int ac_build_mod_snapshot(struct ac_fd_state *st)
{
    struct module *mod;
    unsigned int n = 0;

    kvfree(st->mods);
    st->mods = NULL;
    st->n_mods = 0;

    /* Single pass with a hard cap.  module_mutex is not exported, so the
     * walk can race with concurrent load/unload (a torn entry is possible
     * but bounded; the daemon tolerates it).  A single pass avoids the
     * count/fill mismatch and the heap overflow a two-pass walk could
     * cause when the list changes between passes. */
    st->mods = kvmalloc_array(AC_MAX_MODS, sizeof(struct ac_mod_info),
                              GFP_KERNEL);
    if (!st->mods)
        return -ENOMEM;

    preempt_disable();
    list_for_each_entry(mod, &THIS_MODULE->list, list) {
        struct ac_mod_info *mi;

        if (!ac_module_sane(mod))
            continue;
        if (n >= AC_MAX_MODS)
            break;
        mi = &st->mods[n];
        /* memset first: name[]+size+state leaves 4 bytes of compiler
         * padding for 8-byte struct alignment that strscpy/direct field
         * assignment never touch. MODS_GET copies this struct to
         * userspace verbatim, so unzeroed padding is a real (if small)
         * kernel info leak -- same bug class as the GET_EVENTS fix above,
         * found by the same audit. */
        memset(mi, 0, sizeof(*mi));
        strscpy(mi->name, mod->name, sizeof(mi->name));
        mi->size = ac_module_size(mod);
        mi->state = mod->state;
        n++;
    }
    preempt_enable();
    st->n_mods = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* ioctl / misc device                                                 */
/* ------------------------------------------------------------------ */
static long ac_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    void __user *uarg = (void __user *)arg;
    int ret = 0;

    /* ac_open() already gated this fd to a CAP_SYS_ADMIN caller, but that
     * check ran once, for whoever called open() -- it says nothing about
     * who's calling ioctl() now. A process can legitimately open a
     * privileged fd and then drop privileges for the rest of its life (a
     * completely normal pattern), or the fd can cross a privilege boundary
     * entirely via SCM_RIGHTS or an inherited exec(). Without rechecking
     * here, whoever ends up holding the fd keeps full access -- including
     * LOCK (pin the module permanently) and ADD_PROC/DEL_PROC (rewrite
     * protection state) -- regardless of their current privilege. */
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    switch (cmd) {
    case AC_IOCTL_STATUS: {
        struct ac_status st;

        memset(&st, 0, sizeof(st));
        st.version = AC_IOCTL_VERSION;
        st.syscall_table_addr = ac_syscall_table;
        st.active_procs = ac_protected_count();
        st.events_dropped = READ_ONCE(ac_dropped);
        st.locked = atomic_read(&ac_lock_count) > 0 ? 1 : 0;
        if (copy_to_user(uarg, &st, sizeof(st)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_ADD_PROC: {
        struct ac_proc_id a;

        if (copy_from_user(&a, uarg, sizeof(a)))
            return -EFAULT;
        ret = ac_add_prot_pid(a.pid, a.ref_pid, a.jit_allowed != 0, a.comm);
        if (ret == 0 && ac_verbose)
            pr_info("protected pid %d (%s)\n", a.pid, a.comm);
        return ret;
    }
    case AC_IOCTL_DEL_PROC: {
        struct ac_proc_id d;
        struct task_struct *t;

        if (copy_from_user(&d, uarg, sizeof(d)))
            return -EFAULT;
        t = ac_find_task(d.pid);
        if (!t)
            return -ESRCH;
        ac_del_prot_task(t);
        put_task_struct(t);
        return 0;
    }
    case AC_IOCTL_SCAN_BEGIN: {
        struct ac_scan_begin b;
        struct ac_fd_state *st;

        if (copy_from_user(&b, uarg, sizeof(b)))
            return -EFAULT;
        st = ac_get_fd_state(file);
        if (!st) {
            pr_warn("scan: fd state alloc failed\n");
            return -ENOMEM;
        }
        mutex_lock(&st->lock);
        ret = ac_build_vma_snapshot(st, b.pid, b.emit_events);
        if (!ret) {
            b.n_vmas = st->n_vmas;
            b.rwx_count = st->rwx_count;
            b.exec_count = st->exec_count;
            b.anon_exec_count = st->anon_exec_count;
            b.truncated = st->truncated;
        }
        mutex_unlock(&st->lock);
        if (ret) {
            pr_warn("scan: build_vma_snapshot(pid=%d) = %d\n", b.pid, ret);
            return ret;
        }
        if (copy_to_user(uarg, &b, sizeof(b)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_SCAN_GET: {
        struct ac_scan_get g;
        struct ac_fd_state *st = file->private_data;
        int rc = 0;

        if (copy_from_user(&g, uarg, sizeof(g)))
            return -EFAULT;
        if (!st) {
            rc = -EINVAL;
        } else {
            mutex_lock(&st->lock);
            if (g.index >= st->n_vmas)
                rc = -EINVAL;
            else
                g.vma = st->vmas[g.index];
            mutex_unlock(&st->lock);
        }
        if (rc)
            return rc;
        if (copy_to_user(uarg, &g, sizeof(g)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_SCAN_END:
        if (file->private_data) {
            struct ac_fd_state *st = file->private_data;

            mutex_lock(&st->lock);
            kvfree(st->vmas);
            st->vmas = NULL;
            st->n_vmas = 0;
            mutex_unlock(&st->lock);
        }
        return 0;
    case AC_IOCTL_CHECK_SYSCALLS: {
        struct ac_syscall_check c;

        ret = ac_check_syscalls(&c);
        if (ret)
            return ret;
        if (copy_to_user(uarg, &c, sizeof(c)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_MODS_BEGIN: {
        struct ac_fd_state *st;
        unsigned int count;

        st = ac_get_fd_state(file);
        if (!st)
            return -ENOMEM;
        mutex_lock(&st->lock);
        ret = ac_build_mod_snapshot(st);
        if (!ret)
            count = st->n_mods;
        mutex_unlock(&st->lock);
        if (ret)
            return ret;
        if (copy_to_user(uarg, &count, sizeof(count)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_MODS_GET: {
        struct ac_mod_get g;
        struct ac_fd_state *st = file->private_data;
        int rc = 0;

        if (copy_from_user(&g, uarg, sizeof(g)))
            return -EFAULT;
        if (!st) {
            rc = -EINVAL;
        } else {
            mutex_lock(&st->lock);
            if (g.index >= st->n_mods)
                rc = -EINVAL;
            else
                g.mod = st->mods[g.index];
            mutex_unlock(&st->lock);
        }
        if (rc)
            return rc;
        if (copy_to_user(uarg, &g, sizeof(g)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_MODS_END:
        if (file->private_data) {
            struct ac_fd_state *st = file->private_data;

            mutex_lock(&st->lock);
            kvfree(st->mods);
            st->mods = NULL;
            st->n_mods = 0;
            mutex_unlock(&st->lock);
        }
        return 0;
    case AC_IOCTL_GET_EVENTS: {
        /* kzalloc, not kmalloc: ac_drain_events() only fills events[0..count),
         * leaving events[count..AC_MAX_EVENTS) untouched. The ioctl below
         * copies the whole struct to userspace regardless of count, so an
         * un-zeroed allocation would leak whatever uninitialized kernel heap
         * data happened to be in that slab slot -- a real info-disclosure
         * bug (CWE-457/CWE-200), not just a style nit. Found during an
         * input-hardening audit of every ioctl handler, not by symptom. */
        struct ac_event_list *el = kzalloc(sizeof(*el), GFP_KERNEL);

        if (!el)
            return -ENOMEM;
        ret = ac_drain_events(el);
        if (!ret && copy_to_user(uarg, el, sizeof(*el)))
            ret = -EFAULT;
        kfree(el);
        return ret;
    }
    case AC_IOCTL_FLUSH_EVENTS:
        ac_drain_events(NULL);
        return 0;
    case AC_IOCTL_LIST_PROTECTED: {
        struct ac_prot_list pl;

        memset(&pl, 0, sizeof(pl));
        ret = ac_list_protected(&pl);
        if (ret)
            return ret;
        if (copy_to_user(uarg, &pl, sizeof(pl)))
            return -EFAULT;
        return 0;
    }
    case AC_IOCTL_LOCK:
        /* Pin the module until a matching UNLOCK.  The reference is taken
         * globally (not per-fd), so the pin intentionally outlives the
         * locking process (crash, kill, or a CLI that opens/closes the
         * device).  Recovery is always possible: any CAP_SYS_ADMIN caller
         * can issue UNLOCK, which balances the count and releases the
         * reference. */
        if (try_module_get(THIS_MODULE)) {
            atomic_inc(&ac_lock_count);
            return 0;
        }
        return -EBUSY;
    case AC_IOCTL_UNLOCK:
        if (atomic_read(&ac_lock_count) > 0) {
            atomic_dec(&ac_lock_count);
            module_put(THIS_MODULE);
        }
        return 0;
    default:
        return -ENOTTY;
    }
}

static int ac_open(struct inode *inode, struct file *file)
{
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    file->private_data = NULL;
    return 0;
}

static int ac_release(struct inode *inode, struct file *file)
{
    /* Deliberately no module_put() here: the lock pin taken by
     * AC_IOCTL_LOCK is global and outlives this fd.  It is released by a
     * later AC_IOCTL_UNLOCK, which any privileged caller can issue. */
    ac_free_fd_state(file->private_data);
    file->private_data = NULL;
    return 0;
}

static const struct file_operations ac_fops = {
    .owner = THIS_MODULE,
    .open = ac_open,
    .release = ac_release,
    .unlocked_ioctl = ac_ioctl,
};

static struct miscdevice ac_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = AC_DEV_NAME,
    .fops = &ac_fops,
};

/* ------------------------------------------------------------------ */
/* module lifecycle                                                    */
/* ------------------------------------------------------------------ */
static void ac_clear_protected(void)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&ac_prot_lock, flags);
    for (i = 0; i < AC_PROT_MAX; i++) {
        if (ac_prots[i].task) {
            put_task_struct(ac_prots[i].task);
            ac_prots[i].task = NULL;
        }
    }
    ac_prot_count = 0;
    spin_unlock_irqrestore(&ac_prot_lock, flags);
}

static int __init ac_init(void)
{
    int ret;

    ac_wq = create_workqueue("anticheat");
    if (!ac_wq)
        return -ENOMEM;

    ac_resolve_text_bounds();
    if (ac_verbose)
        pr_info("text bounds: stext=0x%lx etext=0x%lx\n", ac_stext, ac_etext);

    ac_syscall_table = ac_find_syscall_table();
    if (ac_syscall_table)
        pr_info("syscall table located at 0x%lx\n", ac_syscall_table);
    else
        pr_warn("syscall table not located; syscall integrity checks disabled\n");

    ac_register_kprobes();

    ret = misc_register(&ac_misc);
    if (ret) {
        pr_err("misc_register failed: %d\n", ret);
        ac_unregister_kprobes();
        destroy_workqueue(ac_wq);
        return ret;
    }

    pr_info("loaded (policy=0x%x, %u kprobes, %u protected slots)\n",
            ac_policy, ac_kprobes_registered, AC_PROT_MAX);
    return 0;
}

static void __exit ac_exit(void)
{
    misc_deregister(&ac_misc);
    ac_unregister_kprobes();
    ac_clear_protected();
    destroy_workqueue(ac_wq);
    pr_info("unloaded\n");
}

module_init(ac_init);
module_exit(ac_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-anticheat project");
MODULE_DESCRIPTION("Kernel-mode anticheat: syscall/module integrity, "
                   "process protection, ptrace denial, RWX scan");
MODULE_VERSION("1.0.0");
