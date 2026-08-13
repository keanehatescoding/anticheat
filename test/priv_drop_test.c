/*
 * priv_drop_test.c -- proves ac_ioctl() rechecks CAP_SYS_ADMIN, not just
 * ac_open().
 *
 * Opens /dev/anticheat as root, then drops all privileges on this same
 * process while keeping the fd open -- exactly the legitimate "open
 * privileged, then de-escalate for the rest of the process's life" pattern
 * (or, equivalently, the fd having been handed to an unprivileged process
 * via SCM_RIGHTS or an inherited exec()) that the per-ioctl capability
 * check exists to cover. If the module only checked capability at open()
 * time, this ioctl would still succeed here even though the calling
 * process is no longer privileged.
 *
 * Must be run as root (to be able to open the device and to have
 * privileges to drop in the first place). Exits 0 and prints PASS if the
 * ioctl is correctly rejected with -EPERM once unprivileged; exits 1 and
 * prints FAIL if the ioctl succeeds (or fails with some other errno),
 * meaning the per-ioctl check is missing or broken; exits 2 for any
 * environment problem unrelated to what's being tested (module not
 * loaded, privilege drop itself failed, etc).
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../src/anticheat.h"

/* uid/gid 65534 is the conventional "nobody" on Linux; using the numeric
 * value avoids depending on nsswitch/getpwnam succeeding in whatever
 * environment this runs in (containers often lack a "nobody" NSS entry). */
#define AC_TEST_UNPRIV_ID 65534

int main(void)
{
    int fd, rc;
    struct ac_proc_id id;

    if (getuid() != 0) {
        fprintf(stderr, "priv_drop_test: must run as root\n");
        return 2;
    }

    fd = open("/dev/anticheat", O_RDONLY);
    if (fd < 0) {
        perror("priv_drop_test: open /dev/anticheat "
               "(is the module loaded?)");
        return 2;
    }

    /* Drop privileges for the rest of this process's life. Order matters:
     * groups and gid before uid, while we still have CAP_SETGID/CAP_SETUID
     * to change them at all. */
    if (setgroups(0, NULL) < 0 && errno != EPERM) {
        perror("priv_drop_test: setgroups");
        close(fd);
        return 2;
    }
    if (setgid(AC_TEST_UNPRIV_ID) < 0) {
        perror("priv_drop_test: setgid");
        close(fd);
        return 2;
    }
    if (setuid(AC_TEST_UNPRIV_ID) < 0) {
        perror("priv_drop_test: setuid");
        close(fd);
        return 2;
    }
    if (getuid() == 0 || geteuid() == 0) {
        fprintf(stderr, "priv_drop_test: privilege drop did not take "
                "effect (still root)\n");
        close(fd);
        return 2;
    }

    memset(&id, 0, sizeof(id));
    id.pid = getpid();
    rc = ioctl(fd, AC_IOCTL_ADD_PROC, &id);
    if (rc == 0) {
        fprintf(stderr, "FAIL: ioctl succeeded after dropping privileges "
                "-- per-ioctl CAP_SYS_ADMIN check is missing or broken\n");
        close(fd);
        return 1;
    }
    if (errno != EPERM) {
        fprintf(stderr, "FAIL: ioctl failed but with errno=%d (%s), "
                "expected EPERM\n", errno, strerror(errno));
        close(fd);
        return 1;
    }
    printf("PASS: ioctl correctly rejected with -EPERM after privilege "
           "drop (fd opened as root, then de-escalated)\n");
    close(fd);
    return 0;
}
