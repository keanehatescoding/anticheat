/*
 * mount_ns_probe.c -- dlopen()s an explicit path and reports readiness,
 * so test.sh can run it inside a private mount namespace (a bind-mounted
 * library at a path that's a *different* file, or nothing, from outside
 * that namespace) and prove the render-hook check resolves the library
 * the way the target process actually sees it, not the way the daemon's
 * own (host) mount namespace happens to see the same path string.
 *
 * Usage: ./mount_ns_probe <path-to-dlopen>
 * Prints "READY pid=<pid>" once loaded, then sleeps forever.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    void *h;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }
    h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "mount_ns_probe: dlopen %s: %s\n", argv[1], dlerror());
        return 2;
    }
    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    for (;;)
        pause();
    return 0;
}
