/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * test/mock_anticheat.c — a userspace stand-in for the anticheat kernel
 * module.  Loaded with LD_PRELOAD it makes the daemon CLI run end-to-end
 * without root or a real kernel module:
 *
 *   make test-mock        (or: LD_PRELOAD=test/libmock_anticheat.so ./anticheat status)
 *
 * Intercepted symbols (through the PLT):
 *   open/open64/openat/openat64  — AC_DEV_PATH returns a fake fd
 *   ioctl                        — implements the AC_IOCTL_* ABI
 *   close                        — swallows the fake fd
 *   geteuid/getuid               — returns 0 while AC_MOCK_ROOT=1
 *
 * State (protected list, lock, event queue) persists across CLI
 * invocations in $AC_MOCK_STATE (default /tmp/ac_mock_state), mirroring
 * what the kernel module keeps alive between ioctls.
 *
 * Behaviour knobs (environment):
 *   AC_MOCK_ROOT=1      fake root (geteuid == 0)
 *   AC_MOCK_ATTACK=1    simulate a ptrace attack (PTRACE-DENIED events)
 *   AC_MOCK_HOOKED=1    simulate a compromised syscall table
 *   AC_MOCK_STATE=path  state file location
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "../src/anticheat.h"

#define MOCK_FD 4242

/* ------------------------------------------------------------------ */
/* persistent state (survives across CLI processes, like the module)   */
/* ------------------------------------------------------------------ */
struct mock_state {
    unsigned int locked;
    unsigned int events_dropped_total;
    struct ac_prot_item prots[AC_MAX_PROTS];
    unsigned int nprots;
    struct ac_event evq[AC_MAX_EVENTS];
    unsigned int n_evq;
};

static struct mock_state S;
static char state_path[PATH_MAX] = "/tmp/ac_mock_state";
static int drain_count;

static void load_state(void)
{
    const char *e = getenv("AC_MOCK_STATE");
    FILE *f;

    if (e && *e)
        snprintf(state_path, sizeof(state_path), "%s", e);
    memset(&S, 0, sizeof(S));
    f = fopen(state_path, "rb");
    if (f) {
        if (fread(&S, sizeof(S), 1, f) != 1)
            memset(&S, 0, sizeof(S));   /* empty/corrupt state: start fresh */
        fclose(f);
    }
}

static void save_state(void)
{
    FILE *f = fopen(state_path, "wb");

    if (f) {
        if (fwrite(&S, sizeof(S), 1, f) != 1) {
            /* short write: drop the partial state; load_state resets
             * corrupt files, so a failed unlink is harmless */
            int rc = unlink(state_path);
            (void)rc;
        }
        fclose(f);
    }
}

/* ------------------------------------------------------------------ */
/* event queue                                                         */
/* ------------------------------------------------------------------ */
static void push_event(int type, int pid, const char *comm,
                       const char *fmt, ...)
{
    struct ac_event *e;
    va_list ap;

    if (S.n_evq >= AC_MAX_EVENTS) {
        S.events_dropped_total++;
        return;
    }
    e = &S.evq[S.n_evq++];
    memset(e, 0, sizeof(*e));
    e->ts = (unsigned long long)time(NULL) * 1000000000ULL;
    e->pid = pid;
    snprintf(e->comm, sizeof(e->comm), "%s", comm ? comm : "?");
    e->type = type;
    va_start(ap, fmt);
    vsnprintf(e->data, sizeof(e->data), fmt, ap);
    va_end(ap);
    save_state();
}

static void read_comm(int pid, char *out, size_t n)
{
    char path[64], *nl;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (!f) {
        snprintf(out, n, "?");
        return;
    }
    if (!fgets(out, (int)n, f))
        snprintf(out, n, "?");
    else if ((nl = strchr(out, '\n')))
        *nl = '\0';
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* VMA scan snapshot (parses /proc/<pid>/maps like the module walks    */
/* the mmap maple tree)                                                */
/* ------------------------------------------------------------------ */
static struct ac_vma_info *snap;
static unsigned int snap_n;

static void do_scan(int pid)
{
    char path[64], line[512];
    FILE *f;

    free(snap);
    snap = NULL;
    snap_n = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f)
        return;

    while (fgets(line, sizeof(line), f)) {
        struct ac_vma_info vi;
        unsigned long long start, end, off, inode;
        char perms[8] = "", dev[16] = "", p[AC_VMA_PATH] = "";
        unsigned long flags = 0;
        int n;

        memset(&vi, 0, sizeof(vi));
        n = sscanf(line, "%llx-%llx %7s %llx %15s %llu %127s",
                   &start, &end, perms, &off, dev, &inode, p);
        if (n < 6)
            continue;
        if (strchr(perms, 'r'))
            flags |= 0x1;   /* VM_READ */
        if (strchr(perms, 'w'))
            flags |= AC_VM_WRITE;   /* VM_WRITE */
        if (strchr(perms, 'x'))
            flags |= AC_VM_EXEC;     /* VM_EXEC */
        vi.start = start;
        vi.end = end;
        vi.offset = off;
        vi.inode = inode;
        vi.flags = flags;
        vi.is_file = inode != 0;
        if (n >= 7)
            snprintf(vi.path, sizeof(vi.path), "%s", p);
        if (snap_n < AC_MAX_VMAS) {
            snap = realloc(snap, (snap_n + 1) * sizeof(*snap));
            if (!snap) {
                snap_n = 0;
                break;
            }
            snap[snap_n++] = vi;
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* module list (real /proc/modules + one injected hidden module)       */
/* ------------------------------------------------------------------ */
static struct ac_mod_info *mods;
static unsigned int mods_n;

static void build_mods(void)
{
    char line[512];
    FILE *f;
    unsigned int cap = 512;

    free(mods);
    mods = NULL;
    mods_n = 0;
    mods = calloc(cap, sizeof(*mods));
    if (!mods)
        return;

    f = fopen("/proc/modules", "r");
    if (f) {
        while (fgets(line, sizeof(line), f) && mods_n < cap - 1) {
            if (sscanf(line, "%63s", mods[mods_n].name) == 1) {
                mods[mods_n].state = 0;   /* MODULE_STATE_LIVE */
                mods_n++;
            }
        }
        fclose(f);
    }
    /* the mock always injects one module hidden from /proc/modules,
     * exactly what a rootkit would do */
    snprintf(mods[mods_n].name, sizeof(mods[mods_n].name), "hidden_rootkit");
    mods[mods_n].size = 0xdead;
    mods[mods_n].state = 0;
    mods_n++;
}

/* ------------------------------------------------------------------ */
/* ioctl ABI                                                           */
/* ------------------------------------------------------------------ */
static int do_ioctl(unsigned long req, void *arg)
{
    switch (req) {
    case AC_IOCTL_STATUS: {
        struct ac_status *st = arg;

        st->version = AC_IOCTL_VERSION;
        st->syscall_table_addr = 0xffffffff82d02300ULL; /* mirrors this kernel */
        st->active_procs = S.nprots;
        st->events_dropped = S.events_dropped_total;
        st->locked = S.locked;
        st->syscall_hook_count = getenv("AC_MOCK_HOOKED") ? 1 : 0;
        st->hidden_modules = 1;
        return 0;
    }
    case AC_IOCTL_ADD_PROC: {
        struct ac_proc_id *id = arg;
        unsigned int i;

        if (S.nprots >= AC_MAX_PROTS) {
            errno = ENOSPC;
            return -1;
        }
        for (i = 0; i < S.nprots; i++)
            if (S.prots[i].pid == id->pid)
                return 0;   /* already protected */
        read_comm(id->pid, id->comm, sizeof(id->comm));
        S.prots[S.nprots].pid = id->pid;
        snprintf(S.prots[S.nprots].comm, sizeof(S.prots[S.nprots].comm),
                 "%s", id->comm);
        S.nprots++;
        push_event(AC_EV_INFO, id->pid, id->comm, "mock: process protected");
        return 0;
    }
    case AC_IOCTL_DEL_PROC: {
        struct ac_proc_id *id = arg;
        unsigned int i;

        for (i = 0; i < S.nprots; i++)
            if (S.prots[i].pid == id->pid) {
                S.prots[i] = S.prots[S.nprots - 1];
                S.nprots--;
                push_event(AC_EV_INFO, id->pid, "", "mock: protection removed");
                return 0;
            }
        errno = ESRCH;
        return -1;
    }
    case AC_IOCTL_LIST_PROTECTED: {
        struct ac_prot_list *pl = arg;

        pl->count = S.nprots;
        memcpy(pl->items, S.prots, S.nprots * sizeof(*S.prots));
        return 0;
    }
    case AC_IOCTL_SCAN_BEGIN: {
        struct ac_scan_begin *b = arg;
        unsigned int i;

        do_scan(b->pid);
        b->n_vmas = snap_n;
        b->rwx_count = 0;
        b->exec_count = 0;
        for (i = 0; i < snap_n; i++) {
            if (snap[i].flags & AC_VM_EXEC)
                b->exec_count++;
            if ((snap[i].flags & (AC_VM_WRITE | AC_VM_EXEC)) == (AC_VM_WRITE | AC_VM_EXEC))
                b->rwx_count++;
        }
        b->truncated = 0;
        if (b->emit_events && b->rwx_count)
            push_event(AC_EV_RWX, b->pid, "", "mock: %u RWX mapping(s)",
                       b->rwx_count);
        return 0;
    }
    case AC_IOCTL_SCAN_GET: {
        struct ac_scan_get *g = arg;

        if (g->index >= snap_n) {
            errno = EINVAL;
            return -1;
        }
        g->vma = snap[g->index];
        return 0;
    }
    case AC_IOCTL_SCAN_END:
        free(snap);
        snap = NULL;
        snap_n = 0;
        return 0;
    case AC_IOCTL_CHECK_SYSCALLS: {
        struct ac_syscall_check *c = arg;

        c->table_addr = 0xffffffff82d02300ULL;
        c->nr_syscalls = 472;
        c->total = 472;
        if (getenv("AC_MOCK_HOOKED")) {
            c->non_text = 1;
            c->hooked = 1;
            c->ok = 0;
        } else {
            c->non_text = 0;
            c->hooked = 0;
            c->ok = 1;
        }
        return 0;
    }
    case AC_IOCTL_GET_EVENTS: {
        struct ac_event_list *el = arg;

        el->count = S.n_evq;
        el->dropped = S.events_dropped_total;
        memcpy(el->events, S.evq, S.n_evq * sizeof(*S.evq));
        S.n_evq = 0;
        save_state();
        if (getenv("AC_MOCK_ATTACK") && (drain_count++ % 3) == 0)
            push_event(AC_EV_PTRACE, getpid(), "mock",
                       "mock: simulated ptrace attach DENIED");
        return 0;
    }
    case AC_IOCTL_FLUSH_EVENTS:
        S.n_evq = 0;
        save_state();
        return 0;
    case AC_IOCTL_LOCK:
        S.locked = 1;
        save_state();
        return 0;
    case AC_IOCTL_UNLOCK:
        S.locked = 0;
        save_state();
        return 0;
    case AC_IOCTL_MODS_BEGIN:
        build_mods();
        *(unsigned int *)arg = mods_n;
        return 0;
    case AC_IOCTL_MODS_GET: {
        struct ac_mod_get *g = arg;

        if (g->index >= mods_n) {
            errno = EINVAL;
            return -1;
        }
        g->mod = mods[g->index];
        return 0;
    }
    case AC_IOCTL_MODS_END:
        free(mods);
        mods = NULL;
        mods_n = 0;
        return 0;
    default:
        errno = ENOTTY;
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/* symbol interposition                                                */
/* ------------------------------------------------------------------ */
static int is_mock_path(const char *path)
{
    return strcmp(path, AC_DEV_PATH) == 0;
}

static int mock_open_common(void)
{
    load_state();
    push_event(AC_EV_INFO, getpid(), "mock", "mock: device opened");
    if (getenv("AC_MOCK_ATTACK"))
        push_event(AC_EV_PTRACE, getpid(), "mock",
                   "mock: simulated ptrace attach DENIED");
    return MOCK_FD;
}

int open(const char *path, int flags, ...)
{
    static int (*real)(const char *, int, ...);
    mode_t mode = 0;

    if (!real)
        real = dlsym(RTLD_NEXT, "open");
    if (is_mock_path(path))
        return mock_open_common();
    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return real(path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
    static int (*real)(const char *, int, ...);
    mode_t mode = 0;

    if (!real)
        real = dlsym(RTLD_NEXT, "open64");
    if (is_mock_path(path))
        return mock_open_common();
    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return real(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    static int (*real)(int, const char *, int, ...);
    mode_t mode = 0;

    if (!real)
        real = dlsym(RTLD_NEXT, "openat");
    if (is_mock_path(path))
        return mock_open_common();
    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return real(dirfd, path, flags, mode);
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    static int (*real)(int, const char *, int, ...);
    mode_t mode = 0;

    if (!real)
        real = dlsym(RTLD_NEXT, "openat64");
    if (is_mock_path(path))
        return mock_open_common();
    if (flags & O_CREAT) {
        va_list ap;

        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return real(dirfd, path, flags, mode);
}

int ioctl(int fd, unsigned long request, ...)
{
    static int (*real)(int, unsigned long, ...);
    void *arg;
    va_list ap;

    if (!real)
        real = dlsym(RTLD_NEXT, "ioctl");
    va_start(ap, request);
    arg = va_arg(ap, void *);
    va_end(ap);
    if (fd != MOCK_FD)
        return real(fd, request, arg);
    return do_ioctl(request, arg);
}

int close(int fd)
{
    static int (*real)(int);

    if (!real)
        real = dlsym(RTLD_NEXT, "close");
    if (fd == MOCK_FD)
        return 0;
    return real(fd);
}

uid_t geteuid(void)
{
    static uid_t (*real)(void);

    if (!real)
        real = dlsym(RTLD_NEXT, "geteuid");
    return getenv("AC_MOCK_ROOT") ? 0 : real();
}

uid_t getuid(void)
{
    static uid_t (*real)(void);

    if (!real)
        real = dlsym(RTLD_NEXT, "getuid");
    return getenv("AC_MOCK_ROOT") ? 0 : real();
}
