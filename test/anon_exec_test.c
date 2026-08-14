/*
 * anon_exec_test.c -- prints "READY pid=<pid>", then waits. On SIGUSR1,
 * maps one new anonymous, executable page in its own address space (the
 * same observable signal a JIT emitting freshly-compiled code produces,
 * and equally what injected shellcode looks like -- that ambiguity is
 * exactly what the --jit allowlist manages, not something this harness
 * needs to resolve) and goes back to waiting. Never executes the mapped
 * page, so this is safe to run; it exists purely to be scanned from
 * another process while it waits.
 *
 * Signal-triggered rather than timing-based so test.sh controls exactly
 * when the growth happens relative to the daemon's periodic baseline
 * scan (see AC_SCAN_CHECK_INTERVAL in anticheat_daemon.c).
 *
 * Usage: ./anon_exec_test &
 *   -- prints "READY pid=<pid>", then waits for SIGUSR1.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static volatile sig_atomic_t g_grow;

static void on_usr1(int sig)
{
    (void)sig;
    g_grow = 1;
}

int main(void)
{
    struct sigaction sa;
    long pagesize = sysconf(_SC_PAGESIZE);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);

    printf("READY pid=%d\n", getpid());
    fflush(stdout);

    for (;;) {
        pause();
        if (g_grow) {
            void *p = mmap(NULL, (size_t)pagesize, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            (void)p;
            g_grow = 0;
        }
    }
    return 0;
}
