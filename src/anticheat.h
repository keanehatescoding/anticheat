/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * anticheat.h — shared ABI between the kernel module and the userspace
 * daemon/CLI.  Plain C types only so the header can be included both by
 * kernel code (Kernel: -I$(KDIR)/include) and userspace code.
 *
 * This is a defensive security tool: it detects tampering with the running
 * kernel (syscall hooks, hidden modules) and with protected processes
 * (RWX code caves, debugger attaches).  It is NOT designed to bypass any
 * protection and must not be used for that purpose.
 */
#ifndef _AC_SHARED_H_
#define _AC_SHARED_H_

#define AC_DEV_NAME     "anticheat"
#define AC_DEV_PATH     "/dev/anticheat"
#define AC_IOCTL_MAGIC  0xAC
#define AC_IOCTL_VERSION 1

#define AC_MAX_COMM     16
#define AC_MAX_PROCS    64
#define AC_MAX_VMAS     4096     /* snapshot cap for VMA scan */
#define AC_VMA_PATH     128
#define AC_MOD_NAME_LEN 64
#define AC_MAX_EVENTS   64
#define AC_MAX_PROTS    64
#define AC_MAX_MODS     1024    /* cap for module snapshot */
#define AC_EVENT_DATA   128

/* ------------------------------------------------------------------ */
/* ioctl numbers                                                       */
/* Note: the kernel ioctl size field is 14 bits (max 16383 bytes), so  */
/* bulk data is transferred with begin/get/end pairs instead of one    */
/* giant struct.                                                       */
/* ------------------------------------------------------------------ */
#define AC_IOCTL_STATUS           _IOR(AC_IOCTL_MAGIC,  1, struct ac_status)
#define AC_IOCTL_ADD_PROC         _IOW(AC_IOCTL_MAGIC,  2, struct ac_proc_id)
#define AC_IOCTL_DEL_PROC         _IOW(AC_IOCTL_MAGIC,  3, struct ac_proc_id)
#define AC_IOCTL_SCAN_BEGIN       _IOWR(AC_IOCTL_MAGIC, 4, struct ac_scan_begin)
#define AC_IOCTL_CHECK_SYSCALLS   _IOR(AC_IOCTL_MAGIC,  5, struct ac_syscall_check)
#define AC_IOCTL_GET_EVENTS       _IOR(AC_IOCTL_MAGIC,  7, struct ac_event_list)
#define AC_IOCTL_FLUSH_EVENTS     _IO(AC_IOCTL_MAGIC,   8)
#define AC_IOCTL_LIST_PROTECTED   _IOR(AC_IOCTL_MAGIC,  9, struct ac_prot_list)
#define AC_IOCTL_LOCK             _IO(AC_IOCTL_MAGIC,  10)
#define AC_IOCTL_UNLOCK           _IO(AC_IOCTL_MAGIC,  11)
#define AC_IOCTL_SCAN_GET         _IOWR(AC_IOCTL_MAGIC, 12, struct ac_scan_get)
#define AC_IOCTL_SCAN_END         _IO(AC_IOCTL_MAGIC,  13)
#define AC_IOCTL_MODS_BEGIN       _IOR(AC_IOCTL_MAGIC, 14, unsigned int)
#define AC_IOCTL_MODS_GET         _IOWR(AC_IOCTL_MAGIC, 15, struct ac_mod_get)
#define AC_IOCTL_MODS_END         _IO(AC_IOCTL_MAGIC,  16)

/* ------------------------------------------------------------------ */
/* event types                                                         */
/* ------------------------------------------------------------------ */
enum {
    AC_EV_FORK = 1,       /* protected process forked a child (child inherits) */
    AC_EV_EXEC,           /* protected process invoked execve */
    AC_EV_EXIT,           /* protected process exited */
    AC_EV_PTRACE,         /* ptrace attempt against a protected process (denied) */
    AC_EV_SYSCALL_HOOK,   /* syscall table entry outside core kernel text */
    AC_EV_RWX,            /* executable+writable mapping detected in protected proc */
    AC_EV_ANON_EXEC,      /* executable mapping with no backing file (possible
                            * injected code -- also catches write-then-mprotect(R-X),
                            * which evades RWX-only detection since W and X are
                            * never both set at once). vdso/vvar legitimately show
                            * up here too; the daemon only alerts on an *increase*
                            * in this count after a process is first observed, not
                            * on the raw count, since vdso/vvar are present from
                            * process start and never change. */
    AC_EV_INFO,           /* informational (module load/unload, ...) */
};

/* ------------------------------------------------------------------ */
/* VM flag values as seen by the daemon.  These are the Linux ABI bit
 * numbers for VM_EXEC / VM_WRITE (stable for decades); the daemon uses
 * these constants instead of pulling in kernel headers, and the module
 * reports raw vma->vm_flags so the values must match the running kernel. */
#define AC_VM_EXEC  0x4
#define AC_VM_WRITE 0x2

/* ------------------------------------------------------------------ */
/* structs                                                             */
/* ------------------------------------------------------------------ */
struct ac_status {
    unsigned long long version;      /* AC_IOCTL_VERSION */
    unsigned long long syscall_table_addr;
    unsigned int        active_procs;     /* protected process count */
    unsigned int        events_dropped;   /* ring buffer drops since load */
    unsigned int        locked;           /* module pinned by lock ioctl */
    unsigned int        syscall_hook_count; /* from last CHECK_SYSCALLS */
    unsigned int        hidden_modules;     /* from last module check */
};

struct ac_proc_id {
    int  pid;
    char comm[AC_MAX_COMM];   /* informational, may be empty on input */
};

struct ac_vma_info {
    unsigned long long start;
    unsigned long long end;
    unsigned long long offset;
    unsigned long long inode;
    unsigned long      flags;        /* VM_* flags (kernel semantics) */
    unsigned int       is_file;      /* 1 if backed by a file */
    char               path[AC_VMA_PATH];
};

struct ac_scan_begin {
    int          pid;
    int          emit_events;   /* 1 = also push AC_EV_RWX events */
    unsigned int n_vmas;        /* out */
    unsigned int rwx_count;     /* out */
    unsigned int exec_count;    /* out */
    unsigned int anon_exec_count; /* out: executable, no backing file (see AC_EV_ANON_EXEC) */
    unsigned int truncated;     /* out: snapshot cap hit */
};

struct ac_scan_get {
    int              pid;
    unsigned int     index;
    struct ac_vma_info vma;     /* out */
};

struct ac_syscall_check {
    unsigned long long table_addr;
    unsigned int       nr_syscalls;   /* table size examined */
    unsigned int       total;         /* non-NULL entries */
    unsigned int       non_text;      /* entries outside core kernel text */
    unsigned int       hooked;        /* = non_text (kept for compat) */
    unsigned int       ok;            /* 1 if no hooks found */
};

struct ac_mod_info {
    char           name[AC_MOD_NAME_LEN];
    unsigned long long size;
    unsigned int       state;   /* MODULE_STATE_* */
};

struct ac_mod_get {
    unsigned int  index;
    struct ac_mod_info mod;     /* out */
};

struct ac_event {
    unsigned long long ts;          /* ktime_get_real_fast_ns() */
    int                pid;
    char               comm[AC_MAX_COMM];
    unsigned int       type;
    char               data[AC_EVENT_DATA];
};

struct ac_event_list {
    unsigned int  count;
    unsigned int  dropped;      /* total drops (cumulative) */
    struct ac_event events[AC_MAX_EVENTS];
};

struct ac_prot_item {
    int  pid;
    char comm[AC_MAX_COMM];
};

struct ac_prot_list {
    unsigned int count;
    struct ac_prot_item items[AC_MAX_PROTS];
};

#endif /* _AC_SHARED_H_ */
