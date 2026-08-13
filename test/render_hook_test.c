/*
 * render_hook_test.c -- self-hooks vkQueuePresentKHR in its own address
 * space to prove `anticheat scan --check-hooks` actually fires on a real
 * tampering, not just on the "library not loaded" skip path or the
 * trivial case of matching an already-clean process (test.sh separately
 * verifies that true-negative case against a real running process).
 *
 * Loads libvulkan.so.1, makes vkQueuePresentKHR's page writable, and
 * overwrites its first bytes -- the same inline-hook pattern an
 * ESP/overlay cheat would install to intercept the present call. The
 * function is never actually invoked (the patched bytes are inert NOPs),
 * so this is safe to run; it exists purely to be scanned from another
 * process while it sleeps.
 *
 * Usage: ./render_hook_test &   -- prints "READY pid=<pid>", then sleeps.
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int main(void)
{
    void *h, *sym, *page;
    long pagesize;
    unsigned char patch[8] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

    h = dlopen("libvulkan.so.1", RTLD_NOW);
    if (!h) {
        fprintf(stderr, "render_hook_test: dlopen libvulkan.so.1: %s\n", dlerror());
        return 2;
    }
    sym = dlsym(h, "vkQueuePresentKHR");
    if (!sym) {
        fprintf(stderr, "render_hook_test: dlsym vkQueuePresentKHR: %s\n", dlerror());
        return 2;
    }

    pagesize = sysconf(_SC_PAGESIZE);
    page = (void *)((uintptr_t)sym & ~(uintptr_t)(pagesize - 1));
    if (mprotect(page, (size_t)pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("render_hook_test: mprotect");
        return 2;
    }
    memcpy(sym, patch, sizeof(patch));

    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    for (;;)
        pause();
    return 0;
}
