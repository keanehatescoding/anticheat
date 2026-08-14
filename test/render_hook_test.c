/*
 * render_hook_test.c -- self-hooks an exported symbol (default:
 * vkQueuePresentKHR in libvulkan.so.1; pass a different library/symbol
 * pair as argv[1]/argv[2] to exercise the GLX/OpenGL or EGL path
 * instead) in its own address space, to prove `anticheat scan
 * --check-hooks` actually fires on a real tampering, not just on the
 * "library not loaded" skip path or the trivial case of matching an
 * already-clean process (test.sh separately verifies that true-negative
 * case against a real running process).
 *
 * Loads the library, makes the target symbol's page writable, and
 * overwrites 8 bytes starting at an offset within it (argv[4], default
 * 0 -- the classic inline-hook-at-entry pattern; a nonzero offset proves
 * detection isn't limited to the function's first few bytes, since the
 * check now compares the symbol's whole declared ELF size, not a fixed
 * window). The function is never actually invoked (the patched bytes
 * are inert NOPs), so this is safe to run; it exists purely to be
 * scanned from another process while it sleeps.
 *
 * Usage: ./render_hook_test [library symbol [offset]] &
 *   -- prints "READY pid=<pid>", then sleeps.
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
    void *h, *sym, *page, *target;
    long pagesize;
    unsigned char patch[8] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    const char *lib = argc > 1 ? argv[1] : "libvulkan.so.1";
    const char *symbol = argc > 2 ? argv[2] : "vkQueuePresentKHR";
    long offset = argc > 3 ? atol(argv[3]) : 0;

    h = dlopen(lib, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "render_hook_test: dlopen %s: %s\n", lib, dlerror());
        return 2;
    }
    sym = dlsym(h, symbol);
    if (!sym) {
        fprintf(stderr, "render_hook_test: dlsym %s: %s\n", symbol, dlerror());
        return 2;
    }
    target = (void *)((uintptr_t)sym + (uintptr_t)offset);

    pagesize = sysconf(_SC_PAGESIZE);
    page = (void *)((uintptr_t)target & ~(uintptr_t)(pagesize - 1));
    if (mprotect(page, (size_t)pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("render_hook_test: mprotect");
        return 2;
    }
    memcpy(target, patch, sizeof(patch));

    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    for (;;)
        pause();
    return 0;
}
