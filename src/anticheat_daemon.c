/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * anticheat_daemon.c — userspace front-end for the kernel anticheat module.
 *
 * Commands:
 *   status                 module status
 *   protect --pid N        protect a running process
 *   protect --pid N --ns-of REFPID   protect a pid as seen inside the
 *                           pid namespace that host-pid REFPID lives in
 *                           (e.g. a sandboxed/containerized game whose
 *                           in-namespace pid is known but its host pid
 *                           isn't -- --comm below is usually simpler
 *                           when a comm name is available)
 *   protect --comm NAME    protect all processes whose comm == NAME
 *   unprotect --pid N      remove protection
 *   list                   list protected processes
 *   scan --pid N           VMA scan (RWX detection)
 *   scan --pid N --hash [--save|--check]   memory integrity baselines
 *   scan --pid N --check-hooks             Vulkan present-call hook check
 *   scan --pid N --check-preload           LD_PRELOAD check (heuristic)
 *   scan --pid N --check-vklayers          Vulkan-layer env var check (heuristic)
 *   scan --pid N --check-implicit-layers   implicit Vulkan-layer manifest check (heuristic)
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
#include <elf.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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

/* Ban-pipeline reporting (see the "server-side reporting" section below
 * for the actual implementation). Forward-declared so logmsg() -- defined
 * early, used everywhere -- can call it without moving the networking code
 * up here. */
static void ac_report(const char *event_type, const char *detail);

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
    /* LOG_ALERT/LOG_CRIT are exactly the severities this file already uses
     * for genuine detections (ptrace deny, syscall hook, hidden module,
     * baseline tamper, anon-exec growth) -- LOG_WARNING/LOG_INFO are
     * operational messages (self-protect failures, startup/shutdown), not
     * violations. Reusing that existing severity split as the report
     * trigger avoids touching every call site individually. */
    if (pri <= LOG_CRIT)
        ac_report(pri <= LOG_ALERT ? "ALERT" : "CRITICAL", buf);
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
    int pid = -1, ref_pid = -1, i, n;
    const char *comm = NULL;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = atoi(argv[++i]);
        else if (strcmp(argv[i], "--comm") == 0 && i + 1 < argc)
            comm = argv[++i];
        else if (strcmp(argv[i], "--ns-of") == 0 && i + 1 < argc)
            ref_pid = atoi(argv[++i]);
    }
    if (pid < 0 && !comm)
        die("usage: anticheat protect --pid N [--ns-of REFPID] | --comm NAME");
    if (ref_pid >= 0 && comm)
        die("usage: --ns-of cannot be combined with --comm");
    if (ref_pid >= 0 && pid < 0)
        die("usage: --ns-of requires --pid");

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
        id.ref_pid = ref_pid;
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

/* ------------------------------------------------------------------ */
/* render-hook detection (frame-present-call inline-hook check)        */
/*                                                                      */
/* ESP/wallhack/aimbot overlays typically work by hooking the graphics */
/* API's frame-present call. On Linux this check targets three:        */
/* vkQueuePresentKHR in libvulkan.so covers native Vulkan games AND    */
/* Proton D3D9/10/11/12 titles, since DXVK/VKD3D-Proton translate D3D  */
/* down to Vulkan; glXSwapBuffers in libGL.so covers native OpenGL     */
/* games and older Proton titles still on wined3d's GL backend instead */
/* of DXVK; eglSwapBuffers in libEGL.so covers anything using EGL      */
/* instead of GLX to create its GL/GLES context, increasingly common   */
/* under Wayland and for GLES-based engines. A process only using one  */
/* or two of the three cleanly reports the rest as "not loaded", not   */
/* an error -- see check_render_hooks() below.                         */
/*                                                                      */
/* Detection needs no signature database: we read the exact same       */
/* on-disk file the target has mapped, parse out the target symbol's   */
/* file-relative offset and its first bytes there, and compare against */
/* the same bytes read from the target's memory at the equivalent      */
/* runtime address. A classic inline/trampoline hook (redirecting the  */
/* function to a jmp into injected code) changes those leading bytes;  */
/* a clean process matches byte-for-byte. The "known good" copy can't  */
/* go stale across distros or loader versions since it's whatever the  */
/* target itself is using, read fresh at check time.                   */
/*                                                                      */
/* Deliberately never dlopen()s that file: it's resolved through the   */
/* *target's own* mount namespace (see compare_render_symbol() below), */
/* which is not a trusted input -- a process can be set up so an       */
/* attacker controls what's mounted at the path the kernel reports for */
/* it. dlopen()ing an attacker-chosen file means running its           */
/* constructors (DT_INIT/.init_array) as root. The ELF section headers */
/* and symbol table are parsed directly with plain pread() instead --  */
/* pure data reads, no code from that file is ever executed.           */
/*                                                                      */
/* Known blind spot, documented rather than silently missed: a cheat   */
/* that hooks via LD_PRELOAD interposition or a malicious Vulkan layer */
/* (VK_LAYER_*) rather than patching vkQueuePresentKHR's bytes in      */
/* place is not caught by this check -- see README.                    */
/* ------------------------------------------------------------------ */
/* Fallback comparison length when the ELF symbol table doesn't carry a
 * usable st_size (0, or absurdly large -- that field is read from the
 * same attacker-influenceable file as everything else here, see the
 * mount-namespace block comment above, so it's bounded, never trusted
 * outright). AC_HOOK_CHECK_MIN_BYTES/MAX_BYTES clamp whatever st_size
 * *does* say to a sane range either way. */
#define AC_HOOK_CHECK_DEFAULT_BYTES 32
#define AC_HOOK_CHECK_MIN_BYTES 8
#define AC_HOOK_CHECK_MAX_BYTES 512
#define AC_ELF_MAX_SHNUM    2048           /* generous; real .so files have <100 */
#define AC_ELF_MAX_STRTAB   (4 * 1024 * 1024)
#define AC_ELF_MAX_SYMS     500000

/* Parses fd's ELF64 section headers to find `symbol` in .dynsym, using
 * only plain pread() -- never dlopen(), see the block comment above.
 * Returns 0 on success (fills *offset_out with the symbol's
 * file-relative offset, which for the ET_DYN shared libraries this
 * checks is the same value as its runtime offset from the load base,
 * and *size_out with its declared st_size, 0 if the symbol table
 * doesn't carry one), -1 on any parse/read/bounds failure. Every
 * failure is inconclusive, never a positive detection -- a malformed or
 * unexpected-shape ELF file is a skip, same as an unreadable one.
 * x86-64 only (ELFCLASS64 / little-endian), matching the rest of this
 * project's scope. */
static int elf_find_symbol_offset(int fd, const char *symbol, uint64_t *offset_out,
                                   uint64_t *size_out)
{
    Elf64_Ehdr eh;
    Elf64_Shdr *shdrs = NULL;
    char *shstrtab = NULL;
    Elf64_Sym *syms = NULL;
    char *dynstrtab = NULL;
    Elf64_Shdr *dynsym = NULL, *dynstr = NULL;
    unsigned int i, nsyms;
    int ret = -1;

    if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh))
        return -1;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB)
        return -1;
    if (eh.e_shentsize != sizeof(Elf64_Shdr) || eh.e_shnum == 0 ||
        eh.e_shnum > AC_ELF_MAX_SHNUM || eh.e_shstrndx >= eh.e_shnum)
        return -1;

    shdrs = malloc((size_t)eh.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs)
        return -1;
    if (pread(fd, shdrs, (size_t)eh.e_shnum * sizeof(Elf64_Shdr),
              (off_t)eh.e_shoff) != (ssize_t)((size_t)eh.e_shnum * sizeof(Elf64_Shdr)))
        goto out;

    {
        Elf64_Shdr *shstr = &shdrs[eh.e_shstrndx];

        if (shstr->sh_size == 0 || shstr->sh_size > AC_ELF_MAX_STRTAB)
            goto out;
        shstrtab = malloc(shstr->sh_size);
        if (!shstrtab)
            goto out;
        if (pread(fd, shstrtab, shstr->sh_size, (off_t)shstr->sh_offset) !=
            (ssize_t)shstr->sh_size)
            goto out;

        for (i = 0; i < eh.e_shnum; i++) {
            const char *name;

            if (shdrs[i].sh_name >= shstr->sh_size)
                continue;
            name = shstrtab + shdrs[i].sh_name;
            if (shdrs[i].sh_type == SHT_DYNSYM && strcmp(name, ".dynsym") == 0)
                dynsym = &shdrs[i];
            else if (shdrs[i].sh_type == SHT_STRTAB && strcmp(name, ".dynstr") == 0)
                dynstr = &shdrs[i];
        }
    }
    if (!dynsym || !dynstr || dynsym->sh_entsize != sizeof(Elf64_Sym) ||
        dynstr->sh_size == 0 || dynstr->sh_size > AC_ELF_MAX_STRTAB)
        goto out;

    nsyms = (unsigned int)(dynsym->sh_size / sizeof(Elf64_Sym));
    if (nsyms == 0 || nsyms > AC_ELF_MAX_SYMS)
        goto out;

    syms = malloc(dynsym->sh_size);
    dynstrtab = malloc(dynstr->sh_size);
    if (!syms || !dynstrtab)
        goto out;
    if (pread(fd, syms, dynsym->sh_size, (off_t)dynsym->sh_offset) !=
        (ssize_t)dynsym->sh_size)
        goto out;
    if (pread(fd, dynstrtab, dynstr->sh_size, (off_t)dynstr->sh_offset) !=
        (ssize_t)dynstr->sh_size)
        goto out;

    for (i = 0; i < nsyms; i++) {
        if (syms[i].st_name == 0 || syms[i].st_name >= dynstr->sh_size ||
            syms[i].st_value == 0)
            continue;
        if (strcmp(dynstrtab + syms[i].st_name, symbol) == 0) {
            *offset_out = syms[i].st_value;
            *size_out = syms[i].st_size;
            ret = 0;
            break;
        }
    }

out:
    free(shdrs);
    free(shstrtab);
    free(syms);
    free(dynstrtab);
    return ret;
}

/* Reads `symbol` from libpath (resolved via the target's own
 * /proc/<pid>/root/ -- see below) and compares against the same offset
 * in the target pid's live memory (lib_base = that mapping's lowest VMA
 * start, i.e. its file-offset-0 load address). Compares the symbol's
 * *entire* declared length (its ELF st_size, clamped to
 * [AC_HOOK_CHECK_MIN_BYTES, AC_HOOK_CHECK_MAX_BYTES], or
 * AC_HOOK_CHECK_DEFAULT_BYTES if the symbol table has no usable size for
 * it) rather than a fixed guess -- a "detour"-style hook patching
 * further into the function body than a small fixed window would still
 * be inside the function's own real bytes, and would still be caught.
 * Empirically, real present-call functions are tiny (glXSwapBuffers is
 * 17 bytes on a real system, smaller than the old fixed 32-byte
 * window -- meaning that window used to read a few bytes *past* the
 * real function into whatever follows it, which this also fixes).
 * Returns 1 if hooked, 0 if clean, -1 if inconclusive (never treated as
 * a positive detection -- an unreadable/unparseable library is a skip,
 * not an alert). Silent by design -- callers decide how (or whether) to
 * surface the result, since the CLI's one-shot `scan --check-hooks` and
 * the daemon's silent-unless-hooked periodic check want very different
 * presentation of the same underlying check. */
static int compare_render_symbol(int pid, const char *libpath,
                                  unsigned long long lib_base,
                                  const char *symbol)
{
    unsigned char expected[AC_HOOK_CHECK_MAX_BYTES];
    unsigned char actual[AC_HOOK_CHECK_MAX_BYTES];
    char memp[64];
    char nspath[AC_VMA_PATH + 32];
    uint64_t offset, size;
    size_t checklen;
    int fd;
    ssize_t r;

    /* libpath came from the kernel's d_path() on the target's VMA, which
     * is just a string -- opening it directly from the daemon's own
     * mount namespace trusts that whatever exists at that path here is
     * the same file the target actually has mapped. For a process in a
     * container/sandbox with a private bind-mount at that path, it can
     * be a different file entirely (or nothing), and reading it as the
     * reference would compare against the wrong bytes. Going through
     * /proc/<pid>/root/ instead resolves the path exactly as the target
     * process itself sees it -- for the common case of a target sharing
     * the daemon's own namespace, /proc/<pid>/root is just "/", so this
     * is a strict correctness fix with no downside there. Verified
     * empirically (not assumed): a plain path collides with an unrelated
     * host-side file across a private bind mount and silently returns
     * the wrong content, while /proc/<pid>/root/<path> resolves to the
     * real target-visible file, as root, via ordinary open()+read() --
     * no setns() or any persistent namespace switch needed. */
    snprintf(nspath, sizeof(nspath), "/proc/%d/root%s", pid, libpath);

    fd = open(nspath, O_RDONLY);
    if (fd < 0)
        return -1;
    if (elf_find_symbol_offset(fd, symbol, &offset, &size) != 0) {
        close(fd);
        return -1;
    }
    if (size == 0)
        checklen = AC_HOOK_CHECK_DEFAULT_BYTES;
    else if (size < AC_HOOK_CHECK_MIN_BYTES)
        checklen = AC_HOOK_CHECK_MIN_BYTES;
    else if (size > AC_HOOK_CHECK_MAX_BYTES)
        checklen = AC_HOOK_CHECK_MAX_BYTES;
    else
        checklen = (size_t)size;

    r = pread(fd, expected, checklen, (off_t)offset);
    close(fd);
    if (r != (ssize_t)checklen)
        return -1;

    snprintf(memp, sizeof(memp), "/proc/%d/mem", pid);
    fd = open(memp, O_RDONLY);
    if (fd < 0)
        return -1;
    r = pread(fd, actual, checklen, (off_t)(lib_base + offset));
    close(fd);
    if (r != (ssize_t)checklen)
        return -1;

    return memcmp(expected, actual, checklen) != 0 ? 1 : 0;
}

/* Single streaming pass over the target's VMAs to find the load base of
 * whichever mapped library's basename starts with `prefix` (e.g.
 * "libvulkan.so", "libGL.so"), without collecting the (potentially
 * thousands-of-entries) VMA list into memory -- same "don't build a big
 * buffer you don't need" discipline as the rest of this file. Returns 1
 * if found (and fills libpath/lib_base), 0 if not loaded in this
 * process, -1 on ioctl failure. */
static int find_lib_by_basename(int pid, const char *prefix, char *libpath,
                                 size_t libpath_sz, unsigned long long *lib_base)
{
    struct ac_scan_begin b;
    unsigned int v;
    size_t prefix_len = strlen(prefix);
    int found = 0;

    libpath[0] = '\0';
    *lib_base = 0;

    memset(&b, 0, sizeof(b));
    b.pid = pid;
    b.emit_events = 0;
    if (ioctl(dev_fd, AC_IOCTL_SCAN_BEGIN, &b) < 0)
        return -1;
    for (v = 0; v < b.n_vmas; v++) {
        struct ac_scan_get g;
        struct ac_vma_info *vi;
        const char *base;

        memset(&g, 0, sizeof(g));
        g.pid = pid;
        g.index = v;
        if (ioctl(dev_fd, AC_IOCTL_SCAN_GET, &g) < 0)
            break;
        vi = &g.vma;
        if (!vi->is_file || !vi->path[0])
            continue;
        base = strrchr(vi->path, '/');
        base = base ? base + 1 : vi->path;
        if (strncmp(base, prefix, prefix_len) != 0)
            continue;
        if (!found || vi->start < *lib_base) {
            *lib_base = vi->start;
            snprintf(libpath, libpath_sz, "%s", vi->path);
            found = 1;
        }
    }
    ioctl(dev_fd, AC_IOCTL_SCAN_END, NULL);
    return found;
}

/* render_hook_status_for(): the single source of truth both the one-shot
 * CLI check and the periodic daemon check build on, for a given
 * (library basename prefix, exported symbol) pair -- e.g.
 * ("libvulkan.so", "vkQueuePresentKHR") or ("libGL.so",
 * "glXSwapBuffers"). Returns -2 (that library not loaded in this
 * process -- not an error, most processes only use one rendering API),
 * -1 (inconclusive), 0 (clean), or 1 (hooked); fills libpath on any
 * non-(-2) result. */
static int render_hook_status_for(int pid, const char *lib_prefix,
                                   const char *symbol, char *libpath,
                                   size_t libpath_sz)
{
    unsigned long long lib_base;
    int found = find_lib_by_basename(pid, lib_prefix, libpath, libpath_sz, &lib_base);

    if (found < 0)
        return -1;
    if (found == 0)
        return -2;
    return compare_render_symbol(pid, libpath, lib_base, symbol);
}

/* Shared presentation for one (api, symbol) check's result -- used by
 * both check_render_hooks() below (each call prints its own line) so
 * the Vulkan and GLX/OpenGL checks don't duplicate this switch twice.
 * Returns 1 if hooked (so the caller can track "any hook found"), 0
 * otherwise (clean, skipped, or inconclusive -- none of those are a
 * positive detection). */
static int print_render_hook_result(int pid, const char *api_label,
                                     const char *symbol, const char *libpath,
                                     int status)
{
    switch (status) {
    case -2:
        printf("  render-hook check (%s): not loaded in this process, skipping\n",
               api_label);
        return 0;
    case -1:
        printf("  render-hook check (%s): could not verify %s in %s, skipping\n",
               api_label, symbol, libpath);
        return 0;
    case 1:
        printf("  [!] render hook (%s): %s in %s (target pid %d) differs\n"
               "      from a freshly-loaded reference copy of the same file --\n"
               "      possible ESP/overlay/render hijack\n",
               api_label, symbol, libpath, pid);
        return 1;
    default:
        printf("  render-hook check (%s): %s clean (%s)\n", api_label, symbol, libpath);
        return 0;
    }
}

/* CLI-facing wrapper for `scan --check-hooks`: checks every rendering
 * API a Linux game is realistically using -- native Vulkan (and Proton
 * D3D9/10/11/12 via DXVK/VKD3D, which translate down to Vulkan too) via
 * vkQueuePresentKHR; native OpenGL or older Proton titles still on
 * wined3d's GL backend via glXSwapBuffers; and anything using EGL
 * instead of GLX to create its GL/GLES context (increasingly common
 * under Wayland, and for GLES-based engines) via eglSwapBuffers. A
 * process only using one or two of the three cleanly reports the rest
 * as "not loaded", not an error. */
static int check_render_hooks(int pid)
{
    char libpath[AC_VMA_PATH];
    int status, hooked = 0;

    status = render_hook_status_for(pid, "libvulkan.so", "vkQueuePresentKHR",
                                     libpath, sizeof(libpath));
    if (print_render_hook_result(pid, "Vulkan", "vkQueuePresentKHR", libpath, status))
        hooked = 1;

    status = render_hook_status_for(pid, "libGL.so", "glXSwapBuffers",
                                     libpath, sizeof(libpath));
    if (print_render_hook_result(pid, "GLX/OpenGL", "glXSwapBuffers", libpath, status))
        hooked = 1;

    status = render_hook_status_for(pid, "libEGL.so", "eglSwapBuffers",
                                     libpath, sizeof(libpath));
    if (print_render_hook_result(pid, "EGL", "eglSwapBuffers", libpath, status))
        hooked = 1;

    return hooked;
}

/* Periodic daemon-loop counterpart: silent unless a hook is actually
 * found (matching anon_baseline_check()/check_baselines_periodic()'s
 * style -- a clean or skipped check every cycle for every protected
 * process would be log noise, not signal). A detection here flows
 * through logmsg() at LOG_CRIT, which -- via the ban-pipeline reporting
 * hook in logmsg() -- also reports it if AC_REPORT_URL is configured,
 * with no separate wiring needed. */
static void check_render_hooks_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return;
    for (i = 0; i < pl.count; i++) {
        char libpath[AC_VMA_PATH];
        int status;

        status = render_hook_status_for(pl.items[i].pid, "libvulkan.so",
                                         "vkQueuePresentKHR", libpath, sizeof(libpath));
        if (status == 1)
            logmsg(LOG_CRIT, "pid %d (%s): render hook detected in %s "
                   "(vkQueuePresentKHR differs from a freshly-loaded reference "
                   "copy -- possible ESP/overlay/render hijack)",
                   pl.items[i].pid, pl.items[i].comm, libpath);

        status = render_hook_status_for(pl.items[i].pid, "libGL.so",
                                         "glXSwapBuffers", libpath, sizeof(libpath));
        if (status == 1)
            logmsg(LOG_CRIT, "pid %d (%s): render hook detected in %s "
                   "(glXSwapBuffers differs from a freshly-loaded reference "
                   "copy -- possible ESP/overlay/render hijack)",
                   pl.items[i].pid, pl.items[i].comm, libpath);

        status = render_hook_status_for(pl.items[i].pid, "libEGL.so",
                                         "eglSwapBuffers", libpath, sizeof(libpath));
        if (status == 1)
            logmsg(LOG_CRIT, "pid %d (%s): render hook detected in %s "
                   "(eglSwapBuffers differs from a freshly-loaded reference "
                   "copy -- possible ESP/overlay/render hijack)",
                   pl.items[i].pid, pl.items[i].comm, libpath);
    }
}

/* Overridable the same way AC_BASELINE_CHECK_INTERVAL is, so test.sh can
 * exercise this on a live kernel without a long real wait. Longer default
 * than the other periodic checks: each protected process with Vulkan
 * and/or GL loaded costs an ELF section-header/symbol-table parse of
 * each library it has, not just a cheap ioctl. */
static int ac_render_hook_check_interval(void)
{
    const char *e = getenv("AC_RENDER_HOOK_CHECK_INTERVAL");
    int v = e ? atoi(e) : 0;

    return (v > 0) ? v : 30;
}

/* Full implementations are defined later, alongside the periodic
 * environment-based checks; forward declared here (plus the struct/data
 * the CLI wrappers below need at compile time) so cmd_scan doesn't need
 * that whole section moved above this one. */
#define AC_ENVIRON_VAL_LEN 512

struct ac_environ_query {
    const char *name;                    /* variable name, no '=' */
    char value[AC_ENVIRON_VAL_LEN];       /* out */
    int found;                            /* out */
};

static int ac_read_environ_vars(int pid, struct ac_environ_query *vars,
                                 unsigned int nvars);
static int ac_read_ld_preload(int pid, char *out, size_t outsz);

static const char *const AC_VK_LAYER_ENV_VARS[] = {
    "VK_INSTANCE_LAYERS",
    "VK_LOADER_LAYERS_ENABLE",
    "VK_LAYER_PATH",
    "VK_ADD_LAYER_PATH",
};
#define AC_VK_LAYER_ENV_VARS_COUNT \
    (sizeof(AC_VK_LAYER_ENV_VARS) / sizeof(AC_VK_LAYER_ENV_VARS[0]))

/* CLI-facing wrapper for `scan --check-preload`. */
static int check_ld_preload(int pid)
{
    char val[512];
    int rc = ac_read_ld_preload(pid, val, sizeof(val));

    if (rc < 0) {
        printf("  LD_PRELOAD check: could not read /proc/%d/environ (%s)\n",
               pid, strerror(errno));
        return -1;
    }
    if (rc == 0) {
        printf("  LD_PRELOAD check: not set\n");
        return 0;
    }
    printf("  LD_PRELOAD check: %s\n"
           "    (informational only -- also used by legitimate overlay/compat\n"
           "     tools like MangoHud, gamemode, gamescope; not a verdict)\n",
           val);
    return 1;
}

/* CLI-facing wrapper for `scan --check-vklayers`. Checks every candidate
 * variable in one /proc/<pid>/environ pass (see ac_read_environ_vars()). */
static int check_vk_layer_env(int pid)
{
    struct ac_environ_query vars[AC_VK_LAYER_ENV_VARS_COUNT];
    unsigned int i;
    int rc, found_any = 0;

    for (i = 0; i < AC_VK_LAYER_ENV_VARS_COUNT; i++) {
        memset(&vars[i], 0, sizeof(vars[i]));
        vars[i].name = AC_VK_LAYER_ENV_VARS[i];
    }
    rc = ac_read_environ_vars(pid, vars, AC_VK_LAYER_ENV_VARS_COUNT);
    if (rc < 0) {
        printf("  Vulkan-layer check: could not fully read /proc/%d/environ (%s)\n",
               pid, strerror(errno));
        return -1;
    }
    for (i = 0; i < AC_VK_LAYER_ENV_VARS_COUNT; i++) {
        if (!vars[i].found)
            continue;
        printf("  Vulkan-layer check: %s=%s\n", vars[i].name, vars[i].value);
        found_any = 1;
    }
    if (!found_any) {
        printf("  Vulkan-layer check: no layer-activation environment variables set\n");
        return 0;
    }
    printf("    (informational only -- also used by legitimate overlay tools\n"
           "     like MangoHud; not a verdict. An implicit layer manifest\n"
           "     dropped into the loader's default search directories needs\n"
           "     no environment variable and is not detected by this check --\n"
           "     see --check-implicit-layers for that)\n");
    return 1;
}

/* Defined later, alongside its own data structures; forward declared so
 * cmd_scan doesn't need that whole section moved above this one. */
static int check_implicit_layers(int pid);

static int cmd_scan(int argc, char **argv)
{
    struct ac_scan_begin b;
    int pid = -1, i;
    int do_hash = 0, do_save = 0, do_check = 0, do_hooks = 0, do_preload = 0;
    int do_vklayers = 0, do_implicit = 0;
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
        else if (strcmp(argv[i], "--check-hooks") == 0)
            do_hooks = 1;
        else if (strcmp(argv[i], "--check-preload") == 0)
            do_preload = 1;
        else if (strcmp(argv[i], "--check-vklayers") == 0)
            do_vklayers = 1;
        else if (strcmp(argv[i], "--check-implicit-layers") == 0)
            do_implicit = 1;
    }
    if (pid < 0)
        die("usage: anticheat scan --pid N [--hash [--save|--check]] "
            "[--check-hooks] [--check-preload] [--check-vklayers] "
            "[--check-implicit-layers]");

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

    if (do_hooks)
        check_render_hooks(pid);

    if (do_preload)
        check_ld_preload(pid);

    if (do_vklayers)
        check_vk_layer_env(pid);

    if (do_implicit)
        check_implicit_layers(pid);

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

/* ------------------------------------------------------------------ */
/* environment-based hook-evasion detection (LD_PRELOAD, Vulkan layers)*/
/*                                                                      */
/* Both checks below share one primitive: catching hooking that never   */
/* touches vkQueuePresentKHR's actual bytes, so the render-hook check   */
/* above can't see it. Both are deliberately heuristics, not verdicts   */
/* -- MangoHud, gamemode, gamescope, and other legitimate tools         */
/* routinely use both LD_PRELOAD and Vulkan layers, this is literally   */
/* how MangoHud's overlay works. Both ship at LOG_WARNING, not          */
/* LOG_ALERT/LOG_CRIT, so neither flows through the ban-pipeline        */
/* auto-report hook in logmsg() (scoped to pri <= LOG_CRIT) -- an       */
/* operator sees them in the log, but they don't accumulate as a        */
/* report against a client_id on their own.                             */
/* ------------------------------------------------------------------ */
#define AC_ENVIRON_BUF (256 * 1024)
/* struct ac_environ_query, AC_ENVIRON_VAL_LEN, and the VK layer env var
 * list are declared earlier (forward declarations before check_ld_preload)
 * since the CLI wrappers there need them at compile time too. */

/* /proc/<pid>/environ is populated once at exec() and never updated by
 * the process's own later setenv() calls -- exactly what's wanted here:
 * this shows what the process launched with, not whatever it might
 * claim about itself at runtime. NUL-separated KEY=VALUE entries.
 *
 * Reads environ exactly once and checks every entry against all of
 * `vars` in the same pass (rather than making callers re-open/re-read
 * the file once per variable name), filling vars[i].found/value for
 * whichever are present. Returns 0 on success (some or none may be
 * found; check vars[i].found individually), -1 if environ couldn't be
 * read at all or was too large to read in full before hitting
 * AC_ENVIRON_BUF -- in the latter case vars[i].found is only reliable
 * for names that were actually matched (a variable that would have
 * appeared past the truncation point is indistinguishable from one
 * that was never set, so treat -1 as inconclusive, never a confident
 * "not set"). errno is set on failure. */
static int ac_read_environ_vars(int pid, struct ac_environ_query *vars,
                                 unsigned int nvars)
{
    char path[64];
    char *buf;
    size_t total = 0;
    ssize_t n;
    int fd;
    size_t pos;
    unsigned int i;
    int truncated;

    for (i = 0; i < nvars; i++)
        vars[i].found = 0;

    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    buf = malloc(AC_ENVIRON_BUF);
    if (!buf) {
        close(fd);
        return -1;
    }

    /* Loop to true EOF rather than trusting a single read() to capture
     * the whole file -- a real Steam/Proton/Flatpak launch environment
     * can comfortably exceed one read's worth. */
    while (total < AC_ENVIRON_BUF - 1) {
        n = read(fd, buf + total, AC_ENVIRON_BUF - 1 - total);
        if (n < 0) {
            close(fd);
            free(buf);
            return -1;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }
    close(fd);
    if (total == 0) {
        free(buf);
        return 0;
    }
    truncated = (total >= AC_ENVIRON_BUF - 1);
    buf[total] = '\0';

    for (pos = 0; pos < total; ) {
        const char *entry = buf + pos;
        size_t entry_len = strlen(entry);

        if (entry_len == 0)
            break;   /* malformed/truncated read -- stop rather than misread */
        for (i = 0; i < nvars; i++) {
            size_t nlen = strlen(vars[i].name);

            if (!vars[i].found && entry_len > nlen &&
                strncmp(entry, vars[i].name, nlen) == 0 && entry[nlen] == '=') {
                snprintf(vars[i].value, sizeof(vars[i].value), "%s", entry + nlen + 1);
                vars[i].found = 1;
            }
        }
        pos += entry_len + 1;
    }
    free(buf);
    if (truncated) {
        errno = EMSGSIZE;
        return -1;
    }
    return 0;
}

static int ac_read_ld_preload(int pid, char *out, size_t outsz)
{
    struct ac_environ_query q;
    int rc;

    memset(&q, 0, sizeof(q));
    q.name = "LD_PRELOAD";
    rc = ac_read_environ_vars(pid, &q, 1);
    if (rc < 0)
        return -1;
    if (!q.found)
        return 0;
    snprintf(out, outsz, "%s", q.value);
    return 1;
}

/* Vulkan-layer injection: the render-hook check above only catches
 * in-place byte patching of vkQueuePresentKHR; a cheat can instead
 * inject its hook via a Vulkan layer, which never touches those bytes
 * at all. This covers only the environment-variable activation path:
 * VK_INSTANCE_LAYERS (older loaders) / VK_LOADER_LAYERS_ENABLE (current
 * loaders) force-enable a layer by name; VK_LAYER_PATH / VK_ADD_LAYER_PATH
 * point the loader at additional manifest directories, which is how an
 * attacker's own layer becomes discoverable at all.
 *
 * Known, honest gap: an *implicit* layer manifest dropped directly into
 * one of the Vulkan loader's default search directories (e.g.
 * ~/.local/share/vulkan/implicit_layer.d/) is auto-enabled by the
 * loader with no environment variable involved at all, and is not
 * caught by this check -- see README. Detecting that would mean parsing
 * and cross-referencing layer manifest files against some notion of
 * "expected", a meaningfully bigger feature than an environ heuristic.
 * (AC_VK_LAYER_ENV_VARS itself is declared earlier, alongside
 * struct ac_environ_query, for the same forward-declaration reason.) */

/* Warn at most once per pid -- environ is static for the process's
 * lifetime, so re-checking every cycle would either always re-find
 * nothing or always re-find the same value; neither is worth repeating
 * in the log every cycle forever. Same in_use/pid slot-tracking pattern
 * as g_anon_baseline above. */
struct ac_preload_warned {
    int pid;
    int in_use;
};
static struct ac_preload_warned g_preload_warned[AC_MAX_PROTS];

static void preload_warned_forget_stale(const struct ac_prot_list *pl)
{
    unsigned int i, j;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (!g_preload_warned[i].in_use)
            continue;
        for (j = 0; j < pl->count; j++)
            if (pl->items[j].pid == g_preload_warned[i].pid)
                break;
        if (j == pl->count)
            g_preload_warned[i].in_use = 0;
    }
}

static int preload_already_warned(int pid)
{
    unsigned int i;

    for (i = 0; i < AC_MAX_PROTS; i++)
        if (g_preload_warned[i].in_use && g_preload_warned[i].pid == pid)
            return 1;
    return 0;
}

static void preload_mark_warned(int pid)
{
    unsigned int i, free_slot = AC_MAX_PROTS;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (g_preload_warned[i].in_use && g_preload_warned[i].pid == pid)
            return;
        if (free_slot == AC_MAX_PROTS && !g_preload_warned[i].in_use)
            free_slot = i;
    }
    if (free_slot != AC_MAX_PROTS) {
        g_preload_warned[free_slot].pid = pid;
        g_preload_warned[free_slot].in_use = 1;
    }
}

static void check_ld_preload_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return;
    preload_warned_forget_stale(&pl);
    for (i = 0; i < pl.count; i++) {
        char val[512];

        if (preload_already_warned(pl.items[i].pid))
            continue;
        if (ac_read_ld_preload(pl.items[i].pid, val, sizeof(val)) != 1)
            continue;
        logmsg(LOG_WARNING, "pid %d (%s): LD_PRELOAD=%s set at exec -- "
               "common for legitimate overlay/compat tools (MangoHud, "
               "gamemode, gamescope) as well as library-injection hooking; "
               "informational only, not a verdict on its own",
               pl.items[i].pid, pl.items[i].comm, val);
        preload_mark_warned(pl.items[i].pid);
    }
}

static int ac_ld_preload_check_interval(void)
{
    const char *e = getenv("AC_LD_PRELOAD_CHECK_INTERVAL");
    int v = e ? atoi(e) : 0;

    return (v > 0) ? v : 10;
}

/* Same warn-at-most-once-per-pid reasoning and slot-tracking pattern as
 * g_preload_warned above, kept as a separate array since a pid warned
 * for one doesn't imply anything about the other. */
struct ac_vklayer_warned {
    int pid;
    int in_use;
};
static struct ac_vklayer_warned g_vklayer_warned[AC_MAX_PROTS];

static void vklayer_warned_forget_stale(const struct ac_prot_list *pl)
{
    unsigned int i, j;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (!g_vklayer_warned[i].in_use)
            continue;
        for (j = 0; j < pl->count; j++)
            if (pl->items[j].pid == g_vklayer_warned[i].pid)
                break;
        if (j == pl->count)
            g_vklayer_warned[i].in_use = 0;
    }
}

static int vklayer_already_warned(int pid)
{
    unsigned int i;

    for (i = 0; i < AC_MAX_PROTS; i++)
        if (g_vklayer_warned[i].in_use && g_vklayer_warned[i].pid == pid)
            return 1;
    return 0;
}

static void vklayer_mark_warned(int pid)
{
    unsigned int i, free_slot = AC_MAX_PROTS;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (g_vklayer_warned[i].in_use && g_vklayer_warned[i].pid == pid)
            return;
        if (free_slot == AC_MAX_PROTS && !g_vklayer_warned[i].in_use)
            free_slot = i;
    }
    if (free_slot != AC_MAX_PROTS) {
        g_vklayer_warned[free_slot].pid = pid;
        g_vklayer_warned[free_slot].in_use = 1;
    }
}

static void check_vk_layers_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i, j;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return;
    vklayer_warned_forget_stale(&pl);
    for (i = 0; i < pl.count; i++) {
        struct ac_environ_query vars[AC_VK_LAYER_ENV_VARS_COUNT];

        if (vklayer_already_warned(pl.items[i].pid))
            continue;
        for (j = 0; j < AC_VK_LAYER_ENV_VARS_COUNT; j++) {
            memset(&vars[j], 0, sizeof(vars[j]));
            vars[j].name = AC_VK_LAYER_ENV_VARS[j];
        }
        if (ac_read_environ_vars(pl.items[i].pid, vars,
                                  AC_VK_LAYER_ENV_VARS_COUNT) < 0)
            continue;
        for (j = 0; j < AC_VK_LAYER_ENV_VARS_COUNT; j++) {
            if (!vars[j].found)
                continue;
            logmsg(LOG_WARNING, "pid %d (%s): %s=%s set at exec -- "
                   "common for legitimate overlay tools (MangoHud) as well "
                   "as Vulkan-layer-based hooking; informational only, not "
                   "a verdict on its own",
                   pl.items[i].pid, pl.items[i].comm,
                   vars[j].name, vars[j].value);
        }
        vklayer_mark_warned(pl.items[i].pid);
    }
}

static int ac_vk_layer_check_interval(void)
{
    const char *e = getenv("AC_VK_LAYER_CHECK_INTERVAL");
    int v = e ? atoi(e) : 0;

    return (v > 0) ? v : 10;
}

/* ------------------------------------------------------------------ */
/* implicit Vulkan-layer manifest detection                            */
/*                                                                      */
/* --check-vklayers only sees layers activated via environment          */
/* variables. An *implicit* layer manifest dropped into one of the      */
/* Vulkan loader's default search directories is auto-enabled by the    */
/* loader for every Vulkan process -- unless the manifest itself        */
/* defines a "disable_environment" variable and the target has it set   */
/* -- with no environment variable involved at all: exactly the gap     */
/* documented when --check-vklayers shipped. This closes it by directly */
/* replicating what the loader itself does: enumerate the same          */
/* directories it searches (both the target user's own per-user paths,  */
/* the more realistic vector since writing there needs no elevated      */
/* privilege at all, and the system-wide ones), parse each manifest's    */
/* "library_path"/"disable_environment", and cross-reference against    */
/* the target's own environ (reusing ac_read_environ_vars()) to         */
/* determine whether each discovered layer is actually active for that  */
/* specific process right now.                                          */
/*                                                                      */
/* Deliberately never trusts the manifest content beyond parsing it as  */
/* data -- these files can be attacker-controlled (that's the whole     */
/* point of this check), so parsing is bounded and defensive throughout, */
/* same posture as elf_find_symbol_offset() above; nothing from a       */
/* layer's library_path is ever opened or loaded, only reported.        */
/*                                                                      */
/* A small, explicitly non-exhaustive allowlist of common legitimate    */
/* overlay layer names keeps the periodic check from warning on every   */
/* machine that happens to have MangoHud installed (extremely common).  */
/* This is a name-based heuristic, not a security boundary: a cheat     */
/* could name its own layer "VK_LAYER_MANGOHUD_overlay" to blend in --  */
/* the one-shot CLI check reports every active layer regardless of the  */
/* allowlist, precisely so a human reviewing it isn't relying on the    */
/* name check alone.                                                    */
/* ------------------------------------------------------------------ */
#define AC_MANIFEST_MAX_BYTES (64 * 1024)
#define AC_MANIFEST_STR_LEN 256
#define AC_MAX_IMPLICIT_LAYERS 64

struct ac_implicit_layer {
    char name[AC_MANIFEST_STR_LEN];
    char library_path[AC_MANIFEST_STR_LEN];
    char disable_env[AC_MANIFEST_STR_LEN];   /* empty if manifest has none */
};

/* Known-legitimate implicit overlay/compat/vendor layer name prefixes.
 * Not exhaustive, not a security boundary -- see block comment above. */
static const char *const AC_KNOWN_LAYER_PREFIXES[] = {
    "VK_LAYER_MANGOHUD",
    "VK_LAYER_OBS_HOOK",
    "VK_LAYER_OBS_hotkeys",
    "VK_LAYER_VKBASALT",
    "VK_LAYER_RENDERDOC",
    "VK_LAYER_LATENCYFLEX",
    "VK_LAYER_VALVE_steam_overlay",
    "VK_LAYER_VALVE_steam_fossilize",
    "VK_LAYER_GOOGLE_",
    "VK_LAYER_KHRONOS_",
    "VK_LAYER_MESA_",
    "VK_LAYER_INTEL_",
    "VK_LAYER_NV_",
    "VK_LAYER_AMD_",
};
#define AC_KNOWN_LAYER_PREFIXES_COUNT \
    (sizeof(AC_KNOWN_LAYER_PREFIXES) / sizeof(AC_KNOWN_LAYER_PREFIXES[0]))

static int ac_layer_name_known(const char *name)
{
    unsigned int i;

    for (i = 0; i < AC_KNOWN_LAYER_PREFIXES_COUNT; i++)
        if (strncmp(name, AC_KNOWN_LAYER_PREFIXES[i],
                    strlen(AC_KNOWN_LAYER_PREFIXES[i])) == 0)
            return 1;
    return 0;
}

/* Finds "key" as a JSON object key (a targeted extractor for the small,
 * well-defined Vulkan layer manifest schema, not a general JSON parser)
 * followed by ':' and a quoted string, and copies the string's content
 * into out. Returns 1 if found, 0 if not. Bounded and defensive
 * throughout: the manifest is attacker-influenceable content, never
 * trusted structure. Minimal escape handling -- a backslash-escaped
 * character is copied verbatim, which is close enough for the plain
 * ASCII paths/names these manifests contain in practice; a value using
 * more exotic JSON escapes just won't match cleanly, a safe failure
 * mode (skip, not misread). */
static int json_extract_string(const char *json, size_t json_len,
                                const char *key, char *out, size_t outsz)
{
    char needle[64];
    int needle_len;
    const char *p = json, *end = json + json_len;

    needle_len = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (needle_len <= 0 || (size_t)needle_len >= sizeof(needle))
        return 0;

    while (p < end) {
        const char *hit = memmem(p, (size_t)(end - p), needle, (size_t)needle_len);
        const char *q;
        size_t oi;

        if (!hit)
            return 0;
        q = hit + needle_len;
        while (q < end && isspace((unsigned char)*q))
            q++;
        if (q >= end || *q != ':') {
            p = hit + 1;
            continue;
        }
        q++;
        while (q < end && isspace((unsigned char)*q))
            q++;
        if (q >= end || *q != '"') {
            p = hit + 1;
            continue;
        }
        q++;
        oi = 0;
        while (q < end && *q != '"') {
            if (*q == '\\' && q + 1 < end)
                q++;
            if (oi + 1 < outsz)
                out[oi++] = *q;
            q++;
        }
        out[oi < outsz ? oi : outsz - 1] = '\0';
        return 1;
    }
    return 0;
}

/* Same idea as json_extract_string(), but "disable_environment"'s JSON
 * value is an object whose single key is the variable name -- e.g.
 * "disable_environment": { "DISABLE_MANGOHUD": "1" } -- so this needs
 * the first key inside that object, not a plain string value. */
static int json_extract_disable_env(const char *json, size_t json_len,
                                     char *out, size_t outsz)
{
    static const char needle[] = "\"disable_environment\"";
    const char *hit, *end = json + json_len;
    const char *q;
    size_t oi;

    hit = memmem(json, json_len, needle, sizeof(needle) - 1);
    if (!hit)
        return 0;
    q = hit + sizeof(needle) - 1;
    while (q < end && isspace((unsigned char)*q))
        q++;
    if (q >= end || *q != ':')
        return 0;
    q++;
    while (q < end && isspace((unsigned char)*q))
        q++;
    if (q >= end || *q != '{')
        return 0;
    q++;
    while (q < end && isspace((unsigned char)*q))
        q++;
    if (q >= end || *q != '"')
        return 0;
    q++;
    oi = 0;
    while (q < end && *q != '"') {
        if (*q == '\\' && q + 1 < end)
            q++;
        if (oi + 1 < outsz)
            out[oi++] = *q;
        q++;
    }
    out[oi < outsz ? oi : outsz - 1] = '\0';
    return 1;
}

/* Resolves the target process's real uid (from /proc/<pid>/status,
 * "Uid:" line, first field) and that user's home directory, so the
 * per-user implicit-layer manifest paths can be checked correctly --
 * the daemon runs as root, so its own $HOME is irrelevant to what a
 * game running as a different, unprivileged user would actually have
 * loaded. Returns 0 on success (fills home), -1 if the pid is gone or
 * the uid can't be resolved to a passwd entry (not fatal to the overall
 * check -- the system-wide directories are still checked either way). */
static int ac_resolve_pid_home(int pid, char *home, size_t homesz)
{
    char path[64];
    FILE *f;
    char line[256];
    uid_t uid = (uid_t)-1;
    struct passwd pwbuf, *pw = NULL;
    char pwdata[4096];

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    f = fopen(path, "r");
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned long v;

        if (sscanf(line, "Uid: %lu", &v) == 1) {
            uid = (uid_t)v;
            break;
        }
    }
    fclose(f);
    if (uid == (uid_t)-1)
        return -1;

    if (getpwuid_r(uid, &pwbuf, pwdata, sizeof(pwdata), &pw) != 0 ||
        !pw || !pw->pw_dir)
        return -1;
    snprintf(home, homesz, "%s", pw->pw_dir);
    return 0;
}

/* Scans one implicit_layer.d directory for *.json manifests, appending
 * successfully-parsed layers into layers[*count] (capped at
 * AC_MAX_IMPLICIT_LAYERS total across all directories -- more than that
 * many implicit layers on one machine would be extraordinary). A
 * manifest missing "name" or "library_path" is skipped, not guessed at.
 * A missing directory is the overwhelmingly common case (most machines
 * have none of these paths at all) and is silently skipped, not an
 * error. */
static void ac_scan_implicit_layer_dir(const char *dir,
                                        struct ac_implicit_layer *layers,
                                        unsigned int *count)
{
    DIR *d;
    struct dirent *de;

    d = opendir(dir);
    if (!d)
        return;
    while (*count < AC_MAX_IMPLICIT_LAYERS && (de = readdir(d)) != NULL) {
        char path[PATH_MAX];
        size_t namelen = strlen(de->d_name);
        int fd;
        char *buf;
        ssize_t n;
        struct ac_implicit_layer *layer;

        if (namelen < 5 || strcmp(de->d_name + namelen - 5, ".json") != 0)
            continue;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;
        buf = malloc(AC_MANIFEST_MAX_BYTES);
        if (!buf) {
            close(fd);
            continue;
        }
        n = read(fd, buf, AC_MANIFEST_MAX_BYTES - 1);
        close(fd);
        if (n <= 0) {
            free(buf);
            continue;
        }
        buf[n] = '\0';

        layer = &layers[*count];
        memset(layer, 0, sizeof(*layer));
        if (json_extract_string(buf, (size_t)n, "name", layer->name, sizeof(layer->name)) &&
            json_extract_string(buf, (size_t)n, "library_path", layer->library_path,
                                 sizeof(layer->library_path))) {
            json_extract_disable_env(buf, (size_t)n, layer->disable_env,
                                      sizeof(layer->disable_env));
            (*count)++;
        }
        free(buf);
    }
    closedir(d);
}

/* Enumerates every standard implicit_layer.d directory and returns the
 * layers that are actually active for this specific target: present,
 * and not disabled via its own "disable_environment" variable (if the
 * manifest defines one) in the target's own environ. Returns the count
 * found (0 is normal and common). */
static int ac_scan_active_implicit_layers(int pid,
                                           struct ac_implicit_layer *out,
                                           unsigned int outcap)
{
    struct ac_implicit_layer found[AC_MAX_IMPLICIT_LAYERS];
    unsigned int nfound = 0, nactive = 0, i;
    char home[PATH_MAX];

    if (ac_resolve_pid_home(pid, home, sizeof(home)) == 0) {
        char dir[PATH_MAX + 64];   /* home[] + the longest suffix below, with headroom */

        snprintf(dir, sizeof(dir), "%s/.config/vulkan/implicit_layer.d", home);
        ac_scan_implicit_layer_dir(dir, found, &nfound);
        snprintf(dir, sizeof(dir), "%s/.local/share/vulkan/implicit_layer.d", home);
        ac_scan_implicit_layer_dir(dir, found, &nfound);
    }
    ac_scan_implicit_layer_dir("/etc/vulkan/implicit_layer.d", found, &nfound);
    ac_scan_implicit_layer_dir("/usr/local/etc/vulkan/implicit_layer.d", found, &nfound);
    ac_scan_implicit_layer_dir("/usr/share/vulkan/implicit_layer.d", found, &nfound);
    ac_scan_implicit_layer_dir("/usr/local/share/vulkan/implicit_layer.d", found, &nfound);

    for (i = 0; i < nfound && nactive < outcap; i++) {
        if (found[i].disable_env[0]) {
            struct ac_environ_query q;

            memset(&q, 0, sizeof(q));
            q.name = found[i].disable_env;
            if (ac_read_environ_vars(pid, &q, 1) == 0 && q.found)
                continue;   /* explicitly disabled for this process */
        }
        out[nactive++] = found[i];
    }
    return (int)nactive;
}

/* CLI-facing wrapper for `scan --check-implicit-layers`. Reports every
 * active layer regardless of the allowlist -- unlike the periodic check
 * below, a human explicitly asked to see this. */
static int check_implicit_layers(int pid)
{
    struct ac_implicit_layer layers[AC_MAX_IMPLICIT_LAYERS];
    int n = ac_scan_active_implicit_layers(pid, layers, AC_MAX_IMPLICIT_LAYERS);
    int i, unknown = 0;

    if (n <= 0) {
        printf("  Implicit Vulkan-layer check: none active for this process\n");
        return 0;
    }
    for (i = 0; i < n; i++) {
        int known = ac_layer_name_known(layers[i].name);

        printf("  Implicit Vulkan-layer: %s -> %s%s\n",
               layers[i].name[0] ? layers[i].name : "(unnamed)",
               layers[i].library_path[0] ? layers[i].library_path : "(no library_path)",
               known ? "" : "  [not in the known-overlay allowlist]");
        if (!known)
            unknown++;
    }
    printf("    (informational only -- also used by legitimate overlay tools\n"
           "     like MangoHud; not a verdict. Name-based allowlist matching\n"
           "     can be spoofed by a layer that names itself similarly)\n");
    return unknown > 0 ? 1 : 0;
}

/* Periodic counterpart. Unlike the environ-based checks (LD_PRELOAD,
 * VK layer env vars), which read something fixed at exec() time,
 * manifest files live on disk and can change while a session is
 * running -- so this re-scans every cycle rather than checking once per
 * pid, but only ever warns on *growth* of the unrecognized-layer count
 * for a given pid, the same baseline-delta design as
 * anon_baseline_check(): a pid's already-active layers at first
 * observation are its baseline, not something to alert on, and only a
 * later increase (a new unrecognized layer appearing mid-session) is
 * the signal. */
struct ac_implicit_layer_baseline {
    int pid;
    unsigned int count;
    int in_use;
};
static struct ac_implicit_layer_baseline g_implicit_layer_baseline[AC_MAX_PROTS];

static void implicit_layer_baseline_forget_stale(const struct ac_prot_list *pl)
{
    unsigned int i, j;

    for (i = 0; i < AC_MAX_PROTS; i++) {
        if (!g_implicit_layer_baseline[i].in_use)
            continue;
        for (j = 0; j < pl->count; j++)
            if (pl->items[j].pid == g_implicit_layer_baseline[i].pid)
                break;
        if (j == pl->count)
            g_implicit_layer_baseline[i].in_use = 0;
    }
}

static void check_implicit_layers_periodic(void)
{
    struct ac_prot_list pl;
    unsigned int i;

    memset(&pl, 0, sizeof(pl));
    if (ioctl(dev_fd, AC_IOCTL_LIST_PROTECTED, &pl) < 0)
        return;
    implicit_layer_baseline_forget_stale(&pl);
    for (i = 0; i < pl.count; i++) {
        struct ac_implicit_layer layers[AC_MAX_IMPLICIT_LAYERS];
        int n = ac_scan_active_implicit_layers(pl.items[i].pid, layers,
                                                AC_MAX_IMPLICIT_LAYERS);
        char names[512];
        size_t noff = 0;
        unsigned int unknown = 0, j, slot = AC_MAX_PROTS, free_slot = AC_MAX_PROTS;

        if (n < 0)
            continue;
        for (j = 0; j < (unsigned int)n; j++) {
            const char *nm;

            if (ac_layer_name_known(layers[j].name))
                continue;
            nm = layers[j].name[0] ? layers[j].name : "(unnamed)";
            noff += (size_t)snprintf(names + noff,
                                      noff < sizeof(names) ? sizeof(names) - noff : 0,
                                      "%s%s", unknown ? ", " : "", nm);
            unknown++;
        }

        for (j = 0; j < AC_MAX_PROTS; j++) {
            if (g_implicit_layer_baseline[j].in_use &&
                g_implicit_layer_baseline[j].pid == pl.items[i].pid) {
                slot = j;
                break;
            }
            if (free_slot == AC_MAX_PROTS && !g_implicit_layer_baseline[j].in_use)
                free_slot = j;
        }
        if (slot == AC_MAX_PROTS) {
            if (free_slot != AC_MAX_PROTS) {
                g_implicit_layer_baseline[free_slot].pid = pl.items[i].pid;
                g_implicit_layer_baseline[free_slot].count = unknown;
                g_implicit_layer_baseline[free_slot].in_use = 1;
            }
            continue;
        }
        if (unknown > g_implicit_layer_baseline[slot].count)
            logmsg(LOG_WARNING, "pid %d (%s): %u unrecognized implicit Vulkan "
                   "layer(s) active (%s) -- not in the known-overlay "
                   "allowlist; informational only, not a verdict on its own",
                   pl.items[i].pid, pl.items[i].comm, unknown, names);
        g_implicit_layer_baseline[slot].count = unknown;
    }
}

static int ac_implicit_layer_check_interval(void)
{
    const char *e = getenv("AC_IMPLICIT_LAYER_CHECK_INTERVAL");
    int v = e ? atoi(e) : 0;

    return (v > 0) ? v : 30;
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

/* ------------------------------------------------------------------ */
/* server-side reporting (ban pipeline)                                */
/*                                                                      */
/* Opt-in only (AC_REPORT_URL + AC_REPORT_KEY unset by default -- no    */
/* network activity unless explicitly configured, same pattern as       */
/* AC_BASELINE_DIR). Every LOG_ALERT/LOG_CRIT logmsg() call -- i.e.     */
/* every genuine detection this daemon already makes, see logmsg()      */
/* above -- gets POSTed to a minimal report-ingestion server (see       */
/* server/ac_server.py) as {client_id, event_type, detail, ts}. A human */
/* reviews accumulated reports and decides whether to ban a client_id;  */
/* this deliberately does not auto-ban on an unverified client-side     */
/* report, since a false positive here bans a real player, and nothing  */
/* client-side can attest it wasn't tampered with by the very attacker  */
/* it's trying to catch. Enforcement (a game server checking            */
/* GET /banned/<id> before allowing a connection) is out of scope --    */
/* this project has no game server to integrate with, only the API a    */
/* real one would call.                                                 */
/*                                                                      */
/* No TLS: this is plain HTTP, meant for a local/LAN deployment behind  */
/* a reverse proxy that terminates TLS for anything reachable over an   */
/* untrusted network. AC_REPORT_URL is host:port, no scheme.            */
/* ------------------------------------------------------------------ */
#define AC_REPORT_TIMEOUT_SEC 3

/* connect() with an actual bound on how long it can block. On Linux,
 * SO_SNDTIMEO/SO_RCVTIMEO -- despite being set on this socket -- do NOT
 * apply to connect() itself, only to subsequent send/recv-family calls;
 * against a host that blackholes SYN packets rather than actively
 * refusing, a plain blocking connect() can hang for the kernel's TCP
 * SYN-retry timeout (~127s), not the few seconds this is supposed to be
 * bounded by. Doing the connect non-blocking and waiting on poll()
 * enforces the real bound. Returns 0 on success (fd left in its
 * original blocking mode), -1 on failure/timeout (errno set). */
static int ac_connect_timeout(int fd, const struct sockaddr *addr,
                               socklen_t addrlen, int timeout_sec)
{
    int flags, err;
    socklen_t errlen = sizeof(err);
    struct pollfd pfd;
    int rc;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    rc = connect(fd, addr, addrlen);
    if (rc == 0) {
        fcntl(fd, F_SETFL, flags);   /* restore blocking mode for send/recv */
        return 0;
    }
    if (errno != EINPROGRESS) {
        fcntl(fd, F_SETFL, flags);
        return -1;
    }

    pfd.fd = fd;
    pfd.events = POLLOUT;
    rc = poll(&pfd, 1, timeout_sec * 1000);
    if (rc <= 0) {
        fcntl(fd, F_SETFL, flags);
        errno = (rc == 0) ? ETIMEDOUT : errno;
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
        fcntl(fd, F_SETFL, flags);
        errno = (err != 0) ? err : errno;
        return -1;
    }

    fcntl(fd, F_SETFL, flags);
    return 0;
}

/* Escapes a string for embedding in a JSON string literal. event_type and
 * detail both ultimately derive from formatted log messages that can
 * contain attacker-influenced bytes (a process's comm name, a file path
 * from /proc), so this has to be correct, not just "usually fine" --
 * unescaped control characters or quotes here would let a crafted comm
 * name break the JSON body's structure. */
static void ac_json_escape(const char *in, char *out, size_t outsz)
{
    size_t o = 0;

    if (outsz == 0)
        return;
    for (; *in && o + 7 < outsz; in++) {
        unsigned char c = (unsigned char)*in;

        switch (c) {
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        default:
            if (c < 0x20)
                o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", c);
            else
                out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* /etc/machine-id is the standard systemd-provided stable-per-install
 * identifier; falling back to the hostname keeps reporting useful (if
 * less precise) on a system where it's absent rather than disabling
 * reporting outright. */
static void ac_report_client_id(char *out, size_t outsz)
{
    FILE *f = fopen("/etc/machine-id", "r");

    if (f) {
        if (fgets(out, (int)outsz, f)) {
            size_t n = strlen(out);

            while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
                out[--n] = '\0';
            if (out[0]) {
                fclose(f);
                return;
            }
        }
        fclose(f);
    }
    if (gethostname(out, outsz) == 0 && out[0])
        return;
    snprintf(out, outsz, "unknown");
}

static void ac_report(const char *event_type, const char *detail)
{
    const char *url = getenv("AC_REPORT_URL");
    const char *key = getenv("AC_REPORT_KEY");
    char host[256], client_id[128], et_esc[64], detail_esc[600];
    char body[1024], req[2048], resp[64];
    const char *port;
    char *colon;
    struct addrinfo hints, *res, *rp;
    int fd = -1, rc;
    struct timeval tv;
    ssize_t n;

    if (!url || !*url || !key || !*key)
        return;   /* not configured -- silently a no-op, by design */

    snprintf(host, sizeof(host), "%s", url);
    colon = strrchr(host, ':');
    if (!colon) {
        fprintf(stderr, "ac_report: AC_REPORT_URL must be host:port\n");
        return;
    }
    *colon = '\0';
    port = colon + 1;

    ac_report_client_id(client_id, sizeof(client_id));
    ac_json_escape(event_type, et_esc, sizeof(et_esc));
    ac_json_escape(detail, detail_esc, sizeof(detail_esc));
    snprintf(body, sizeof(body),
             "{\"client_id\":\"%s\",\"event_type\":\"%s\",\"detail\":\"%s\","
             "\"ts\":%lld}",
             client_id, et_esc, detail_esc, (long long)time(NULL));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "ac_report: getaddrinfo(%s:%s): %s\n",
                host, port, gai_strerror(rc));
        return;
    }
    /* A hung/unreachable report server must never stall the security
     * monitoring loop -- ac_connect_timeout() bounds connect() itself
     * (which SO_SNDTIMEO/SO_RCVTIMEO do not, on Linux), and those two
     * still bound the subsequent send/recv on whichever address works. */
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;
        tv.tv_sec = AC_REPORT_TIMEOUT_SEC;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (ac_connect_timeout(fd, rp->ai_addr, rp->ai_addrlen,
                                AC_REPORT_TIMEOUT_SEC) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "ac_report: could not connect to %s:%s\n", host, port);
        return;
    }

    snprintf(req, sizeof(req),
             "POST /report HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Authorization: Bearer %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             host, key, strlen(body), body);

    {
        size_t reqlen = strlen(req);
        size_t sent = 0;

        /* A short write is normal TCP socket behavior (send-buffer
         * pressure, or interrupted by the SO_SNDTIMEO deadline this
         * socket has set) -- checking only for a negative return and
         * assuming anything else means the whole request went out would
         * let a partial, malformed HTTP request reach the server
         * silently. */
        while (sent < reqlen) {
            ssize_t w = write(fd, req + sent, reqlen - sent);

            if (w < 0) {
                fprintf(stderr, "ac_report: send failed: %s\n", strerror(errno));
                close(fd);
                return;
            }
            if (w == 0)
                break;
            sent += (size_t)w;
        }
        if (sent != reqlen) {
            fprintf(stderr, "ac_report: short write (%zu of %zu bytes)\n",
                    sent, reqlen);
            close(fd);
            return;
        }
    }
    n = read(fd, resp, sizeof(resp) - 1);
    if (n > 0) {
        resp[n] = '\0';
        if (!strstr(resp, " 200") && !strstr(resp, " 201"))
            fprintf(stderr, "ac_report: server response: %.60s\n", resp);
    }
    close(fd);
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
        time_t next_render = 0, next_preload = 0, next_vklayer = 0;
        time_t next_implicit = 0;

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
            if (now >= next_render) {
                check_render_hooks_periodic();
                next_render = now + ac_render_hook_check_interval();
            }
            if (now >= next_preload) {
                check_ld_preload_periodic();
                next_preload = now + ac_ld_preload_check_interval();
            }
            if (now >= next_vklayer) {
                check_vk_layers_periodic();
                next_vklayer = now + ac_vk_layer_check_interval();
            }
            if (now >= next_implicit) {
                check_implicit_layers_periodic();
                next_implicit = now + ac_implicit_layer_check_interval();
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
           "  protect --pid N [--ns-of REFPID] | --comm NAME\n"
           "  unprotect --pid N\n"
           "  list                       list protected processes\n"
           "  scan --pid N [--hash [--save|--check]] [--check-hooks] "
           "[--check-preload]\n"
           "           [--check-vklayers] [--check-implicit-layers]\n"
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
