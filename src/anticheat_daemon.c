/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * anticheat_daemon.c — userspace front-end for the kernel anticheat module.
 *
 * Commands:
 *   status                 module status
 *   protect --pid N        protect a running process
 *   protect --comm NAME    protect all processes whose comm == NAME
 *   unprotect --pid N      remove protection
 *   list                   list protected processes
 *   scan --pid N           VMA scan (RWX detection)
 *   scan --pid N --hash [--save|--check]   memory integrity baselines
 *   syscalls               verify syscall table integrity
 *   modules                list modules + detect hidden modules
 *   events [--watch]       dump pending security events (--watch: poll)
 *   lock | unlock          pin / unpin the kernel module
 *   start [--foreground]   monitoring daemon (poll events + periodic checks)
 *
 * Requires root (the kernel device only opens for CAP_SYS_ADMIN).
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/wait.h>
#include <linux/limits.h>

#include "anticheat.h"
#include "sha256.h"

#define AC_BASELINE_DIR "/var/lib/anticheat/baselines"
#define AC_HASH_CAP      (16UL * 1024 * 1024)   /* max bytes hashed per mapping */
#define AC_READ_CHUNK    (1024 * 1024)

static int dev_fd = -1;
static int g_verbose = 0;
static volatile sig_atomic_t g_stop = 0;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */
static void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void logmsg(int pri, const char *fmt, ...)
{
    va_list ap;
    char buf[512];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    syslog(pri, "%s", buf);
    if (pri <= LOG_WARNING || g_verbose)
        fprintf(stderr, "%s\n", buf);
}

static int ac_open(void)
{
    dev_fd = open(AC_DEV_PATH, O_RDWR);
    if (dev_fd < 0)
        die("cannot open %s: %s (is the module loaded? try: sudo insmod anticheat.ko)",
            AC_DEV_PATH, strerror(errno));
    return dev_fd;
}

static void ac_close(void)
{
    if (dev_fd >= 0) {
        close(dev_fd);
        dev_fd = -1;
    }
}

static int ioctl_ok(unsigned long req, void *arg)
{
    int r = ioctl(dev_fd, req, arg);

    if (r < 0)
        fprintf(stderr, "ioctl %#lx failed: %s\n", req, strerror(errno));
    return r;
}

static const char *ev_type_str(unsigned int t)
{
    switch (t) {
    case AC_EV_FORK:        return "FORK";
    case AC_EV_EXEC:        return "EXEC";
    case AC_EV_EXIT:        return "EXIT";
    case AC_EV_PTRACE:      return "PTRACE-DENIED";
    case AC_EV_SYSCALL_HOOK:return "SYSCALL-HOOK";
    case AC_EV_RWX:         return "RWX";
    case AC_EV_ANON_EXEC:   return "ANON-EXEC";
    case AC_EV_INFO:        return "INFO";
    default:                return "UNKNOWN";
    }
}

static void print_event(const struct ac_event *e)
{
    time_t t = (time_t)(e->ts / 1000000000ULL);
    char ts[32];

    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
    printf("%s [%s] pid=%d comm=%s %s\n",
           ts, ev_type_str(e->type), e->pid, e->comm, e->data);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* command: status                                                     */
/* ------------------------------------------------------------------ */
static int cmd_status(void)
{
    struct ac_status st;

    ac_open();
    if (ioctl_ok(AC_IOCTL_STATUS, &st) < 0)
        return 1;
    printf("anticheat kernel module\n");
    printf("  version           : %llu\n", st.version);
    printf("  syscall table     : %#llx\n", st.syscall_table_addr);
    printf("  protected procs   : %u\n", st.active_procs);
    printf("  events dropped    : %u\n", st.events_dropped);
    printf("  locked            : %u\n", st.locked);
    printf("  syscall hooks     : %u (last check)\n", st.syscall_hook_count);
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: protect / unprotect / list                                */
/* ------------------------------------------------------------------ */
static int pid_of_comm(const char *comm, int *pids, int max)
{
    DIR *d;
    struct dirent *de;
    int n = 0;

    d = opendir("/proc");
    if (!d)
        die("opendir /proc: %s", strerror(errno));
    while ((de = readdir(d)) != NULL) {
        char path[64], buf[AC_MAX_COMM + 1];
        int pid, fd;
        ssize_t r;

        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        pid = atoi(de->d_name);
        if (pid <= 0)
            continue;
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;
        r = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (r <= 0)
            continue;
        buf[r] = '\0';
        while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == ' '))
            buf[--r] = '\0';
        if (strcmp(buf, comm) == 0 && n < max)
            pids[n++] = pid;
    }
    closedir(d);
    return n;
}

static int cmd_protect(int argc, char **argv)
{
    struct ac_proc_id id;
    int pid = -1, i, n;
    const char *comm = NULL;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = atoi(argv[++i]);
        else if (strcmp(argv[i], "--comm") == 0 && i + 1 < argc)
            comm = argv[++i];
    }
    if (pid < 0 && !comm)
        die("usage: anticheat protect --pid N | --comm NAME");

    ac_open();
    if (comm) {
        int pids[256];
        n = pid_of_comm(comm, pids, 256);
        if (n == 0) {
            fprintf(stderr, "no process with comm '%s'\n", comm);
            return 1;
        }
        for (i = 0; i < n; i++) {
            memset(&id, 0, sizeof(id));
            id.pid = pids[i];
            if (ioctl_ok(AC_IOCTL_ADD_PROC, &id) == 0)
                printf("protected pid %d (%s)\n", pids[i], id.comm);
        }
        printf("%d process(es) protected\n", n);
    } else {
        memset(&id, 0, sizeof(id));
        id.pid = pid;
        if (ioctl_ok(AC_IOCTL_ADD_PROC, &id) < 0)
            return 1;
        printf("protected pid %d (%s)\n", pid, id.comm);
    }
    ac_close();
    return 0;
}

static int cmd_unprotect(int argc, char **argv)
{
    struct ac_proc_id id;
    int pid = -1, i;

    for (i = 0; i < argc; i++)
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = atoi(argv[++i]);
    if (pid < 0)
        die("usage: anticheat unprotect --pid N");

    ac_open();
    memset(&id, 0, sizeof(id));
    id.pid = pid;
    if (ioctl_ok(AC_IOCTL_DEL_PROC, &id) < 0)
        return 1;
    printf("protection removed from pid %d\n", pid);
    ac_close();
    return 0;
}

static int cmd_list(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    ac_open();
    memset(&pl, 0, sizeof(pl));
    if (ioctl_ok(AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return 1;
    printf("%u protected process(es):\n", pl.count);
    for (i = 0; i < pl.count; i++)
        printf("  pid %-8d %s\n", pl.items[i].pid, pl.items[i].comm);
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: scan (VMA + optional hash baseline)                        */
/* ------------------------------------------------------------------ */
static char *proc_exe_path(int pid)
{
    static char link[PATH_MAX];
    ssize_t n;
    char p[64];

    snprintf(p, sizeof(p), "/proc/%d/exe", pid);
    n = readlink(p, link, sizeof(link) - 1);
    if (n < 0)
        return NULL;
    link[n] = '\0';
    return link;
}

/* hash [start, start+size) of /proc/<pid>/mem; returns 0 on success */
static int hash_proc_mem(int pid, uint64_t start, uint64_t size,
                         char out_hex[65])
{
    char path[64];
    ac_sha256_ctx ctx;
    int fd;
    uint64_t done = 0;
    uint8_t buf[AC_READ_CHUNK];

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    ac_sha256_init(&ctx);
    while (done < size) {
        uint64_t want = size - done;
        ssize_t r;

        if (want > sizeof(buf))
            want = sizeof(buf);
        r = pread(fd, buf, want, (off_t)(start + done));
        if (r < 0) {
            /* skip unreadable page-aligned chunk */
            done += want;
            continue;
        }
        if (r == 0)
            break;
        ac_sha256_update(&ctx, buf, (size_t)r);
        done += (uint64_t)r;
    }
    close(fd);
    {
        uint8_t d[32];
        static const char hexd[] = "0123456789abcdef";
        int i;
        ac_sha256_final(&ctx, d);
        for (i = 0; i < 32; i++) {
            out_hex[i * 2] = hexd[d[i] >> 4];
            out_hex[i * 2 + 1] = hexd[d[i] & 0xf];
        }
        out_hex[64] = '\0';
    }
    return 0;
}

static const char *ac_baseline_dir(void)
{
    const char *e = getenv("AC_BASELINE_DIR");

    return (e && *e) ? e : AC_BASELINE_DIR;
}

/* How often the daemon re-hashes protected processes' executables against
 * saved baselines. Overridable via AC_BASELINE_CHECK_INTERVAL (seconds) so
 * test.sh can exercise this on a live kernel without a real 60s wait. */
static int ac_baseline_check_interval(void)
{
    const char *e = getenv("AC_BASELINE_CHECK_INTERVAL");
    int v = e ? atoi(e) : 0;

    return (v > 0) ? v : 60;
}

static void ac_mkdir_baselines(void)
{
    const char *d = ac_baseline_dir();
    const char *slash = strrchr(d, '/');
    char parent[PATH_MAX];

    if (slash && slash != d) {
        snprintf(parent, sizeof(parent), "%.*s", (int)(slash - d), d);
        mkdir(parent, 0755);
    }
    mkdir(d, 0755);
}

static void baseline_path_for(const char *path, char out[PATH_MAX])
{
    char hex[65];

    ac_sha256_hex(path, strlen(path), hex);
    snprintf(out, PATH_MAX, "%s/%s.txt", ac_baseline_dir(), hex);
}

static int cmd_scan(int argc, char **argv)
{
    struct ac_scan_begin b;
    int pid = -1, i;
    int do_hash = 0, do_save = 0, do_check = 0;
    char exe[PATH_MAX] = "";
    char *exe_link;
    unsigned int v;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = atoi(argv[++i]);
        else if (strcmp(argv[i], "--hash") == 0)
            do_hash = 1;
        else if (strcmp(argv[i], "--save") == 0)
            do_save = 1;
        else if (strcmp(argv[i], "--check") == 0)
            do_check = 1;
    }
    if (pid < 0)
        die("usage: anticheat scan --pid N [--hash [--save|--check]]");

    ac_open();
    memset(&b, 0, sizeof(b));
    b.pid = pid;
    b.emit_events = 1;
    if (ioctl_ok(AC_IOCTL_SCAN_BEGIN, &b) < 0)
        return 1;

    printf("scan of pid %d: %u VMA(s), %u executable, %u RWX, %u anon-exec\n",
           pid, b.n_vmas, b.exec_count, b.rwx_count, b.anon_exec_count);
    if (b.anon_exec_count)
        printf("  (anon-exec = executable with no backing file; vdso/vvar are\n"
               "   expected here -- treat a *growing* count across repeated\n"
               "   scans as the signal, not the raw number)\n");
    if (b.truncated)
        printf("  (VMA snapshot truncated at %u entries)\n", AC_MAX_VMAS);

    for (v = 0; v < b.n_vmas; v++) {
        struct ac_scan_get g;
        struct ac_vma_info *vi;

        memset(&g, 0, sizeof(g));
        g.pid = pid;
        g.index = v;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_GET, &g) < 0)
            break;
        vi = &g.vma;

        if ((vi->flags & AC_VM_EXEC) && (vi->flags & AC_VM_WRITE))
            printf("  [!] RWX [%#llx-%#llx] %s\n",
                   vi->start, vi->end, vi->path[0] ? vi->path : "(anonymous)");
        else if ((vi->flags & AC_VM_EXEC) && !vi->is_file)
            printf("  [?] anon-exec [%#llx-%#llx]\n", vi->start, vi->end);
        else if ((vi->flags & AC_VM_EXEC) && g_verbose)
            printf("  exec [%#llx-%#llx] %s\n",
                   vi->start, vi->end, vi->path[0] ? vi->path : "(anonymous)");
    }
    ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL);

    if (do_hash) {
        exe_link = proc_exe_path(pid);
        if (exe_link)
            snprintf(exe, sizeof(exe), "%s", exe_link);

        memset(&b, 0, sizeof(b));
        b.pid = pid;
        b.emit_events = 1;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_BEGIN, &b) == 0) {
            for (v = 0; v < b.n_vmas; v++) {
                struct ac_scan_get g;
                struct ac_vma_info *vi;
                char hex[65], blpath[PATH_MAX], line[512];
                uint64_t size;
                FILE *f;
                int changed = 0;

                memset(&g, 0, sizeof(g));
                g.pid = pid;
                g.index = v;
                if (ioctl(dev_fd, AC_IOCTL_SCAN_GET, &g) < 0)
                    break;
                vi = &g.vma;
                if (!(vi->flags & AC_VM_EXEC) || !vi->is_file)
                    continue;
                size = vi->end - vi->start;
                if (size > AC_HASH_CAP)
                    size = AC_HASH_CAP;
                if (hash_proc_mem(pid, vi->start, size, hex) < 0) {
                    printf("  hash failed for %s\n", vi->path);
                    continue;
                }
                baseline_path_for(vi->path, blpath);
                printf("  %s [%#llx..%#llx] %s\n",
                       vi->path, vi->start, vi->start + size, hex);

                if (do_save) {
                    ac_mkdir_baselines();
                    f = fopen(blpath, "w");
                    if (!f) {
                        fprintf(stderr, "cannot write baseline %s: %s\n",
                                blpath, strerror(errno));
                        continue;
                    }
                    fprintf(f, "%llx %llx %s\n",
                            (unsigned long long)vi->start,
                            (unsigned long long)size, hex);
                    fclose(f);
                    printf("    baseline saved: %s\n", blpath);
                }
                if (do_check) {
                    f = fopen(blpath, "r");
                    if (!f) {
                        printf("    no baseline for %s (run with --save first)\n",
                               vi->path);
                        continue;
                    }
                    if (fgets(line, sizeof(line), f)) {
                        unsigned long long bs, bsz;
                        char bhex[65];
                        if (sscanf(line, "%llx %llx %64s", &bs, &bsz, bhex) == 3) {
                            if (strcmp(bhex, hex) != 0)
                                changed = 1;
                        }
                    }
                    fclose(f);
                    if (changed)
                        printf("    [ALERT] memory content differs from baseline"
                               " (possible runtime patching)\n");
                    else
                        printf("    ok: matches baseline\n");
                }
            }
            ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL);
        }
    }
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: syscalls                                                   */
/* ------------------------------------------------------------------ */
static int cmd_syscalls(void)
{
    struct ac_syscall_check c;

    ac_open();
    memset(&c, 0, sizeof(c));
    if (ioctl(dev_fd, AC_IOCTL_CHECK_SYSCALLS, &c) < 0) {
        if (errno == ENODEV)
            fprintf(stderr, "syscall table was not located at module load;"
                    " integrity check unavailable\n");
        else
            fprintf(stderr, "ioctl %#lx failed: %s\n", AC_IOCTL_CHECK_SYSCALLS,
                    strerror(errno));
        return 1;
    }
    printf("syscall table @ %#llx\n", c.table_addr);
    printf("  entries examined : %u\n", c.nr_syscalls);
    printf("  non-NULL entries : %u\n", c.total);
    printf("  hooked           : %u\n", c.hooked);
    if (c.ok)
        printf("  result           : OK — no hooks detected\n");
    else {
        printf("  result           : COMPROMISED — syscall hooks present!\n");
        return 2;
    }
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: modules                                                    */
/* ------------------------------------------------------------------ */
/* Shared /proc/modules cross-check for the `modules` command and the
 * periodic monitor.  The name table is static (256 KiB): the daemon is
 * single-threaded, and a stack array that large is fragile under small
 * ulimit -s / LimitSTACK=.  Returns the hidden-module count, or -1 if the
 * kernel-side module list could not be read. */
#define AC_MAX_PROC_MODS 4096
static char proc_names[AC_MAX_PROC_MODS][AC_MOD_NAME_LEN];

static unsigned int collect_proc_modules(unsigned int cap)
{
    FILE *f = fopen("/proc/modules", "r");
    char line[256];
    unsigned int n = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f) && n < cap) {
        if (sscanf(line, "%63s", proc_names[n]) == 1)
            n++;
    }
    fclose(f);
    return n;
}

static long crosscheck_modules(int verbose)
{
    unsigned int count, i, hidden = 0, proc_count;

    if (ioctl(dev_fd, AC_IOCTL_MODS_BEGIN, &count) < 0)
        return -1;
    proc_count = collect_proc_modules(AC_MAX_PROC_MODS);
    if (verbose)
        printf("%u modules in kernel list:\n", count);
    for (i = 0; i < count; i++) {
        struct ac_mod_get g;
        unsigned int j;
        int visible = 0;

        memset(&g, 0, sizeof(g));
        g.index = i;
        if (ioctl(dev_fd, AC_IOCTL_MODS_GET, &g) < 0)
            break;
        for (j = 0; j < proc_count; j++) {
            if (strcmp(proc_names[j], g.mod.name) == 0) {
                visible = 1;
                break;
            }
        }
        if (verbose)
            printf("  %-20s size=%-10llu state=%u %s\n",
                   g.mod.name, g.mod.size, g.mod.state,
                   visible ? "" : "[HIDDEN FROM /proc/modules!]");
        if (!visible)
            hidden++;
    }
    ioctl(dev_fd, AC_IOCTL_MODS_END, NULL);
    if (verbose)
        printf("hidden modules: %u\n", hidden);
    return hidden;
}

static int cmd_modules(void)
{
    long hidden;

    ac_open();
    hidden = crosscheck_modules(1);
    ac_close();
    if (hidden < 0)
        return 1;
    return hidden ? 2 : 0;
}

/* ------------------------------------------------------------------ */
/* command: events                                                     */
/* ------------------------------------------------------------------ */
static int cmd_events(int argc, char **argv)
{
    int watch = 0, i;

    for (i = 0; i < argc; i++)
        if (strcmp(argv[i], "--watch") == 0)
            watch = 1;

    ac_open();
    for (;;) {
        struct ac_event_list el;

        memset(&el, 0, sizeof(el));
        if (ioctl_ok(AC_IOCTL_GET_EVENTS, &el) < 0)
            return 1;
        for (i = 0; i < (int)el.count; i++)
            print_event(&el.events[i]);
        if (el.dropped)
            printf("(ring dropped %u events)\n", el.dropped);
        if (!watch)
            break;
        usleep(200000);
    }
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: lock / unlock                                              */
/* ------------------------------------------------------------------ */
static int cmd_lock(int lock)
{
    ac_open();
    if (ioctl_ok(lock ? AC_IOCTL_LOCK : AC_IOCTL_UNLOCK, NULL) < 0)
        return 1;
    printf("module %s (rmmod will %s while pinned)\n",
           lock ? "pinned" : "unpinned",
           lock ? "fail" : "succeed");
    ac_close();
    return 0;
}

/* ------------------------------------------------------------------ */
/* command: start (monitoring daemon)                                  */
/* ------------------------------------------------------------------ */
static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int check_syscalls_periodic(void)
{
    struct ac_syscall_check c;

    memset(&c, 0, sizeof(c));
    if (ioctl(dev_fd, AC_IOCTL_CHECK_SYSCALLS, &c) < 0)
        return -1;
    if (c.hooked)
        logmsg(LOG_CRIT, "SYSCALL TABLE COMPROMISED: %u hooked entries "
               "(table @ %#llx)", c.hooked, c.table_addr);
    return c.hooked;
}

static int check_modules_periodic(void)
{
    long hidden = crosscheck_modules(0);

    if (hidden > 0)
        logmsg(LOG_CRIT, "%ld module(s) hidden from /proc/modules", hidden);
    return (int)hidden;
}

/* Per-pid baseline for AC_EV_ANON_EXEC-style detection: vdso/vvar are
 * anonymous+executable from process start and never change, so recording
 * whatever count we see on a pid's *first* scan as its baseline and only
 * alerting when the count later grows cleanly separates "always there"
 * kernel mappings from code that gets mapped in after we started watching
 * -- without needing to identify vdso/vvar by name in the kernel (which
 * would need arch-specific, harder-to-verify code; see the discussion in
 * anticheat.h). This does mean a pid that gets reused for an unrelated
 * process between two scans could show a spurious baseline reset; that's
 * a known, accepted limitation for this pass, not a security hole -- the
 * new process's own baseline just gets (re-)established on its first
 * scan, same as any newly-protected pid. */
struct ac_anon_baseline {
    int          pid;
    unsigned int count;
    int          in_use;
};
static struct ac_anon_baseline g_anon_baseline[AC_MAX_PROTS];

static void anon_baseline_forget_stale(const struct ac_prot_list *pl)
{
    unsigned int i, j;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (!g_anon_baseline[i].in_use)
            continue;
        for (j = 0; j < pl->count; j++)
            if (pl->items[j].pid == g_anon_baseline[i].pid)
                break;
        if (j == pl->count)
            g_anon_baseline[i].in_use = 0;   /* no longer protected */
    }
}

static void anon_baseline_check(int pid, const char *comm, unsigned int count)
{
    unsigned int i, free_slot = AC_MAX_PROTS;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (g_anon_baseline[i].in_use && g_anon_baseline[i].pid == pid) {
            if (count > g_anon_baseline[i].count)
                logmsg(LOG_CRIT, "pid %d (%s): %u new anonymous executable "
                       "mapping(s) since first observed (was %u, now %u) -- "
                       "possible code injection after process start",
                       pid, comm, count - g_anon_baseline[i].count,
                       g_anon_baseline[i].count, count);
            g_anon_baseline[i].count = count;
            return;
        }
        if (free_slot == AC_MAX_PROTS && !g_anon_baseline[i].in_use)
            free_slot = i;
    }
    if (free_slot != AC_MAX_PROTS) {
        g_anon_baseline[free_slot].pid = pid;
        g_anon_baseline[free_slot].count = count;
        g_anon_baseline[free_slot].in_use = 1;
    }
}

static int scan_protected_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return -1;
    anon_baseline_forget_stale(&pl);
    for (i = 0; i < pl.count; i++) {
        struct ac_scan_begin b;

        memset(&b, 0, sizeof(b));
        b.pid = pl.items[i].pid;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_BEGIN, &b) == 0) {
            if (b.rwx_count > 0)
                logmsg(LOG_WARNING, "pid %d (%s): %u RWX mapping(s) present",
                       pl.items[i].pid, pl.items[i].comm, b.rwx_count);
            anon_baseline_check(pl.items[i].pid, pl.items[i].comm,
                                 b.anon_exec_count);
            ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL);
        }
    }
    return 0;
}

/* Re-verify every protected process's executable, file-backed mappings
 * against whatever baseline was saved for them via `scan --hash --save`.
 * Deliberately does NOT create a baseline here if one doesn't exist yet --
 * silently adopting whatever's currently loaded as "known good" the first
 * time the daemon happens to see a process would permanently hide a
 * compromise that predates monitoring starting. Baselines only ever come
 * from an explicit, operator-run `--save` on a binary already verified
 * clean -- this only re-checks what someone already vouched for. */
static int check_baselines_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return -1;
    for (i = 0; i < pl.count; i++) {
        struct ac_scan_begin b;
        unsigned int v;

        memset(&b, 0, sizeof(b));
        b.pid = pl.items[i].pid;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_BEGIN, &b) != 0)
            continue;
        for (v = 0; v < b.n_vmas; v++) {
            struct ac_scan_get g;
            struct ac_vma_info *vi;
            char blpath[PATH_MAX], line[512], hex[65], bhex[65];
            unsigned long long bs, bsz;
            uint64_t size;
            FILE *f;

            memset(&g, 0, sizeof(g));
            g.pid = pl.items[i].pid;
            g.index = v;
            if (ioctl(dev_fd, AC_IOCTL_SCAN_GET, &g) < 0)
                break;
            vi = &g.vma;
            if (!(vi->flags & AC_VM_EXEC) || !vi->is_file)
                continue;

            baseline_path_for(vi->path, blpath);
            f = fopen(blpath, "r");
            if (!f)
                continue; /* nothing saved for this file -- nothing to check */
            if (!fgets(line, sizeof(line), f)) {
                fclose(f);
                continue;
            }
            fclose(f);
            if (sscanf(line, "%llx %llx %64s", &bs, &bsz, bhex) != 3)
                continue;

            size = vi->end - vi->start;
            if (size > AC_HASH_CAP)
                size = AC_HASH_CAP;
            if (hash_proc_mem(pl.items[i].pid, vi->start, size, hex) < 0)
                continue;
            if (strcmp(bhex, hex) != 0)
                logmsg(LOG_CRIT, "pid %d (%s): memory content of %s differs "
                       "from saved baseline (possible runtime patching)",
                       pl.items[i].pid, pl.items[i].comm, vi->path);
        }
        ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL);
    }
    return 0;
}

static int cmd_start(int argc, char **argv)
{
    int foreground = 0, i;
    pid_t pid;

    for (i = 0; i < argc; i++)
        if (strcmp(argv[i], "--foreground") == 0)
            foreground = 1;

    if (geteuid() != 0)
        die("anticheat start must run as root");

    ac_open();   /* holds /dev/anticheat open -> module pinned while we live */

    if (!foreground) {
        pid = fork();
        if (pid < 0)
            die("fork: %s", strerror(errno));
        if (pid > 0) {
            printf("anticheat daemon started (pid %d)\n", pid);
            _exit(0);
        }
        setsid();
        pid = fork();
        if (pid < 0)
            die("fork: %s", strerror(errno));
        if (pid > 0)
            _exit(0);
        /* best-effort daemonization; failures are not fatal */
        if (chdir("/") < 0)
            fprintf(stderr, "daemon: chdir failed: %s\n", strerror(errno));
        if (!freopen("/dev/null", "r", stdin))
            fprintf(stderr, "daemon: stdin redirect failed\n");
        if (!freopen("/var/log/anticheat.log", "a", stdout))
            fprintf(stderr, "daemon: stdout redirect failed\n");
        if (!freopen("/var/log/anticheat.log", "a", stderr))
            fprintf(stderr, "daemon: stderr redirect failed\n");
    }

    openlog("anticheat", LOG_PID | LOG_NDELAY, LOG_AUTH);
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGHUP, SIG_IGN);

    logmsg(LOG_INFO, "anticheat daemon started (foreground=%d)", foreground);
    {
        struct ac_proc_id self;

        /* Protect our own pid: a cheat that can ptrace-attach or debug the
         * daemon away is a cheat that can bypass everything else here too.
         * This only stops ptrace-based attacks (see the kernel module's
         * ptrace-deny hook) -- it does not stop SIGKILL from a
         * root-privileged attacker, which is outside what this module can
         * defend against by design (see README's threat-model notes). */
        memset(&self, 0, sizeof(self));
        self.pid = getpid();
        if (ioctl(dev_fd, AC_IOCTL_ADD_PROC, &self) < 0)
            logmsg(LOG_WARNING, "failed to self-protect (pid %d): %s",
                   self.pid, strerror(errno));
        else
            logmsg(LOG_INFO, "self-protected (pid %d)", self.pid);
    }
    {
        time_t next_sys = 0, next_mod = 0, next_scan = 0, next_baseline = 0;

        while (!g_stop) {
            struct ac_event_list el;
            time_t now = time(NULL);

            memset(&el, 0, sizeof(el));
            if (ioctl(dev_fd, AC_IOCTL_GET_EVENTS, &el) == 0) {
                for (i = 0; i < (int)el.count; i++) {
                    struct ac_event *e = &el.events[i];

                    if (e->type == AC_EV_PTRACE)
                        logmsg(LOG_ALERT, "%s pid=%d comm=%s %s",
                               ev_type_str(e->type), e->pid, e->comm, e->data);
                    else if (e->type == AC_EV_SYSCALL_HOOK)
                        logmsg(LOG_CRIT, "%s %s", ev_type_str(e->type), e->data);
                    else
                        logmsg(LOG_INFO, "%s pid=%d comm=%s %s",
                               ev_type_str(e->type), e->pid, e->comm, e->data);
                }
            }
            if (now >= next_sys) {
                check_syscalls_periodic();
                next_sys = now + 5;
            }
            if (now >= next_mod) {
                check_modules_periodic();
                next_mod = now + 10;
            }
            if (now >= next_scan) {
                scan_protected_periodic();
                next_scan = now + 30;
            }
            if (now >= next_baseline) {
                check_baselines_periodic();
                next_baseline = now + ac_baseline_check_interval();
            }
            sleep(1);
        }
    }
    logmsg(LOG_INFO, "anticheat daemon stopped");
    ac_close();
    closelog();
    return 0;
}

/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    printf("usage: %s <command> [options]\n"
           "\n"
           "  status                     kernel module status\n"
           "  protect --pid N | --comm NAME\n"
           "  unprotect --pid N\n"
           "  list                       list protected processes\n"
           "  scan --pid N [--hash [--save|--check]]\n"
           "  syscalls                   verify syscall table integrity\n"
           "  modules                    kernel module list + hidden module check\n"
           "  events [--watch]           dump security events\n"
           "  lock | unlock              pin / unpin the kernel module\n"
           "  start [--foreground]       run the monitoring daemon\n"
           "\n"
           "All commands except 'start' may also require root.\n",
           prog);
}

int main(int argc, char **argv)
{
    const char *cmd = argc > 1 ? argv[1] : "help";

    if (geteuid() != 0 && strcmp(cmd, "help") != 0) {
        /* the kernel device enforces CAP_SYS_ADMIN anyway; pre-check helps */
        fprintf(stderr, "warning: this tool is designed to run as root\n");
    }

    if (strcmp(cmd, "status") == 0)
        return cmd_status();
    if (strcmp(cmd, "protect") == 0)
        return cmd_protect(argc - 2, argv + 2);
    if (strcmp(cmd, "unprotect") == 0)
        return cmd_unprotect(argc - 2, argv + 2);
    if (strcmp(cmd, "list") == 0)
        return cmd_list();
    if (strcmp(cmd, "scan") == 0)
        return cmd_scan(argc - 2, argv + 2);
    if (strcmp(cmd, "syscalls") == 0)
        return cmd_syscalls();
    if (strcmp(cmd, "modules") == 0)
        return cmd_modules();
    if (strcmp(cmd, "events") == 0)
        return cmd_events(argc - 2, argv + 2);
    if (strcmp(cmd, "lock") == 0)
        return cmd_lock(1);
    if (strcmp(cmd, "unlock") == 0)
        return cmd_lock(0);
    if (strcmp(cmd, "start") == 0)
        return cmd_start(argc - 2, argv + 2);
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "-h") == 0) {
        usage(argv[0]);
        return 0;
    }
    fprintf(stderr, "unknown command '%s'\n\n", cmd);
    usage(argv[0]);
    return 1;
}
