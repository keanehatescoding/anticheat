/*
 * ioctl_fuzz.c -- fuzzes every AC_IOCTL_* command with malformed sizes,
 * boundary values, and wild/null/unmapped pointers.
 *
 * This is the actual attack surface any local process holding an open fd
 * to /dev/anticheat can reach (see ac_ioctl()'s per-call CAP_SYS_ADMIN
 * recheck -- this harness assumes it already has that capability, same
 * as the real daemon; it fuzzes malformed *payloads*, not privilege
 * escalation, which priv_drop_test.c already covers separately).
 *
 * Two very different things this can be run against, and it's important
 * not to conflate what each actually proves:
 *   - The userspace mock (LD_PRELOAD=test/libmock_anticheat.so, see
 *     test/mock_test.sh) -- proves the HARNESS itself is correct
 *     (calling conventions, doesn't crash from its own bugs, exercises
 *     every ioctl end to end). Zero kernel-robustness value: the mock is
 *     plain userspace code with none of the kernel's own
 *     copy_from_user()/access_ok() machinery to stress.
 *   - A REAL loaded module, as root -- this is what actually matters.
 *     Watch `dmesg` during/after the run for any oops, WARNING, or
 *     lockdep splat; this harness's own exit code only reflects whether
 *     *userspace* survived -- a crashed kernel doesn't necessarily crash
 *     the calling process cleanly enough to be caught here at all.
 *
 * Usage: ./ioctl_fuzz [iterations-per-command] [seed]
 *   iterations-per-command defaults to 2000; seed defaults to time(NULL)
 *   and is always printed, so any run is reproducible by passing it back
 *   in explicitly.
 *
 * IOCTL_FUZZ_SAFE_POINTERS_ONLY=1 in the environment restricts every
 * call to a real, correctly-mapped payload buffer -- only the buffer's
 * *contents* (garbage values, boundary values, wrong size) are fuzzed,
 * never the pointer itself (no NULL/unmapped/wild-address variants).
 * This is what a mock dry-run should use: the mock is plain userspace
 * code with no copy_from_user()/access_ok() of its own, so handing it a
 * deliberately invalid pointer crashes the *mock*, not the module under
 * test -- a true positive for "this address is bad," just not a useful
 * one when there's no kernel on the other end to be checking it. The
 * real kernel module is expected to survive all of it; run without this
 * set for that.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "../src/anticheat.h"

/* Every ioctl this module defines, paired with the payload size the
 * kernel side actually copy_from_user()/copy_to_user()'s (see
 * anticheat.h and ac_ioctl() in anticheat_module.c). Kept as a plain
 * byte count per entry, not sizeof(struct ...) inline at each call site,
 * so malformed *sizes* (undersized buffers) can be exercised
 * independently of whichever struct a command's payload actually is. */
struct fuzz_cmd {
    const char *name;
    unsigned long request;
    size_t payload_size;
};

static const struct fuzz_cmd CMDS[] = {
    {"STATUS",         AC_IOCTL_STATUS,         sizeof(struct ac_status)},
    {"ADD_PROC",       AC_IOCTL_ADD_PROC,       sizeof(struct ac_proc_id)},
    {"DEL_PROC",       AC_IOCTL_DEL_PROC,       sizeof(struct ac_proc_id)},
    {"SCAN_BEGIN",     AC_IOCTL_SCAN_BEGIN,     sizeof(struct ac_scan_begin)},
    {"CHECK_SYSCALLS", AC_IOCTL_CHECK_SYSCALLS, sizeof(struct ac_syscall_check)},
    {"GET_EVENTS",     AC_IOCTL_GET_EVENTS,     sizeof(struct ac_event_list)},
    {"FLUSH_EVENTS",   AC_IOCTL_FLUSH_EVENTS,   0},
    {"LIST_PROTECTED", AC_IOCTL_LIST_PROTECTED, sizeof(struct ac_prot_list)},
    {"LOCK",           AC_IOCTL_LOCK,           0},
    {"UNLOCK",         AC_IOCTL_UNLOCK,         0},
    {"SCAN_GET",       AC_IOCTL_SCAN_GET,       sizeof(struct ac_scan_get)},
    {"SCAN_END",       AC_IOCTL_SCAN_END,       0},
    {"MODS_BEGIN",     AC_IOCTL_MODS_BEGIN,     sizeof(unsigned int)},
    {"MODS_GET",       AC_IOCTL_MODS_GET,       sizeof(struct ac_mod_get)},
    {"MODS_END",       AC_IOCTL_MODS_END,       0},
};
#define N_CMDS (sizeof(CMDS) / sizeof(CMDS[0]))

/* 16384 matches the actual ceiling anticheat.h documents (the kernel
 * ioctl size field is 14 bits, max 16383 bytes) -- not an arbitrary
 * guess. An earlier, unverified guess of 8192 here was itself a real
 * stack buffer overflow in this harness: sizeof(struct ac_event_list),
 * the largest real payload at 10248 bytes, silently overran it. Sized
 * against the protocol's own documented limit instead. */
#define MAX_PAYLOAD 16384

static unsigned long xorshift_state;

static unsigned long xorshift(void)
{
    unsigned long x = xorshift_state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    xorshift_state = x;
    return x;
}

static const unsigned int BOUNDARY_U32[] = {
    0, 1, 0x7fffffffu, 0x80000000u, 0xffffffffu, 4096, 65536,
};
static const int BOUNDARY_I32[] = {
    0, 1, -1, 2147483647, -2147483647 - 1, 4096, -4096,
};

/* Fills `buf` (`size` bytes) with a mix of pure-random bytes and crafted
 * boundary values planted at 4-byte-aligned offsets. Pure uniform random
 * almost never lands exactly on values like UINT_MAX, INT_MIN, or 0 by
 * chance, and those are exactly the values most likely to expose an
 * off-by-one or signedness bug in a bounds check (see ac_ioctl()'s
 * "g.index >= st->n_vmas" style checks) -- planted command-agnostically,
 * regardless of which field of which struct happens to start at that
 * offset, since that's cheap and doesn't require this harness to track
 * every struct's exact field layout. */
static void fill_payload(unsigned char *buf, size_t size)
{
    size_t i;

    for (i = 0; i < size; i++)
        buf[i] = (unsigned char)xorshift();

    for (i = 0; i + 4 <= size; i += 4) {
        if ((xorshift() & 7) != 0)
            continue;
        if (xorshift() & 1) {
            unsigned int v = BOUNDARY_U32[xorshift() %
                (sizeof(BOUNDARY_U32) / sizeof(BOUNDARY_U32[0]))];
            memcpy(buf + i, &v, 4);
        } else {
            int v = BOUNDARY_I32[xorshift() %
                (sizeof(BOUNDARY_I32) / sizeof(BOUNDARY_I32[0]))];
            memcpy(buf + i, &v, 4);
        }
    }
}

/* A page-aligned mapping that's immediately unmapped -- the address is
 * still a plausible-looking userspace pointer, but any access_ok()/
 * copy_*_user() against it must cleanly fault (-EFAULT), not touch real
 * memory. Recomputed fresh on every use since the kernel is free to hand
 * the address back out to something else once it's unmapped. */
static void *unmapped_pointer(void)
{
    void *p = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return (void *)0x1000; /* fallback: low, never mapped in a normal process */
    munmap(p, 4096);
    return p;
}

int main(int argc, char **argv)
{
    int fd;
    long iterations = 2000;
    unsigned long seed;
    size_t cmd_i, it;
    unsigned char payload[MAX_PAYLOAD];
    const char *safe_env = getenv("IOCTL_FUZZ_SAFE_POINTERS_ONLY");
    int safe_pointers_only = safe_env && *safe_env && strcmp(safe_env, "0") != 0;

    if (argc > 1)
        iterations = strtol(argv[1], NULL, 10);
    seed = (argc > 2) ? strtoul(argv[2], NULL, 10) : (unsigned long)time(NULL);
    xorshift_state = seed ? seed : 1; /* xorshift's state must never be 0 */

    printf("ioctl_fuzz: seed=%lu iterations-per-command=%ld safe_pointers_only=%d "
           "(rerun with the first two args to reproduce this exact run)\n",
           seed, iterations, safe_pointers_only);

    /* Guards exactly the bug MAX_PAYLOAD's own comment describes: catch
     * a payload that doesn't fit in this stack buffer at startup, loudly,
     * instead of silently overrunning it mid-run the way the original
     * 8192 guess did. */
    for (cmd_i = 0; cmd_i < N_CMDS; cmd_i++) {
        if (CMDS[cmd_i].payload_size > MAX_PAYLOAD) {
            fprintf(stderr, "ioctl_fuzz: BUG: %s payload_size=%zu exceeds "
                    "MAX_PAYLOAD=%d -- fix MAX_PAYLOAD in this file\n",
                    CMDS[cmd_i].name, CMDS[cmd_i].payload_size, MAX_PAYLOAD);
            return 2;
        }
    }

    fd = open(AC_DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("ioctl_fuzz: open " AC_DEV_PATH " (module loaded? running as root?)");
        return 2;
    }

    for (cmd_i = 0; cmd_i < N_CMDS; cmd_i++) {
        const struct fuzz_cmd *c = &CMDS[cmd_i];

        printf("-- %s (request=%#lx, payload=%zu bytes) --\n",
               c->name, c->request, c->payload_size);
        fflush(stdout);

        for (it = 0; it < (size_t)iterations; it++) {
            int variant = xorshift() % 6;

            /* Remap the pointer-corruption variants (1/2/4) to 0 rather
             * than skipping the iteration outright -- keeps the total
             * iteration count exactly what was asked for, still fuzzing
             * payload contents, just always through a real, correctly
             * mapped buffer. See the safe_pointers_only comment above
             * main() for why. */
            if (safe_pointers_only && (variant == 1 || variant == 2 || variant == 4))
                variant = 0;

            switch (variant) {
            case 0:
                /* pure/boundary-mixed random payload, correctly sized */
                fill_payload(payload, c->payload_size ? c->payload_size : 1);
                ioctl(fd, c->request, c->payload_size ? payload : NULL);
                break;
            case 1:
                /* NULL pointer, regardless of what the command expects */
                ioctl(fd, c->request, NULL);
                break;
            case 2:
                /* plausible-looking but unmapped pointer -- must -EFAULT,
                 * not fault the kernel */
                ioctl(fd, c->request, unmapped_pointer());
                break;
            case 3:
                /* deliberately undersized buffer: copy_from_user(&x,
                 * uarg, sizeof(x)) in the kernel reads sizeof(x)
                 * regardless of how much the caller actually allocated */
                fill_payload(payload, 1);
                ioctl(fd, c->request, payload);
                break;
            case 4:
                /* wild, obviously-invalid, non-NULL pointer */
                ioctl(fd, c->request, (void *)(0xdead0000UL + (xorshift() & 0xffff)));
                break;
            default:
                /* all-zero, valid-shape payload -- the "minimal/
                 * degenerate values" case pure random rarely produces */
                memset(payload, 0, c->payload_size ? c->payload_size : 1);
                ioctl(fd, c->request, c->payload_size ? payload : NULL);
                break;
            }
        }
    }

    close(fd);
    printf("ioctl_fuzz: completed %zu commands x %ld iterations with no crash in "
           "this process.\n"
           "This proves userspace survived -- it does NOT by itself prove the "
           "kernel did.\n"
           "If this ran against a real loaded module, check `dmesg` now for any "
           "oops, WARNING, or lockdep splat logged during the run.\n",
           N_CMDS, iterations);
    return 0;
}
