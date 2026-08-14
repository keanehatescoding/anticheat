#!/bin/bash
# test.sh — end-to-end live test for the kernel anticheat.
# Requires root (loads a kernel module). Run:  sudo ./test.sh
set -u

cd "$(dirname "$0")" || exit 1
VICTIM_PID=""
DAEMON_PID=""
REPORT_SERVER_PID=""
FAILED=0

say()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  PASS\033[0m  %s\n' "$*"; }
bad()  { printf '\033[1;31m  FAIL\033[0m  %s\n' "$*"; FAILED=1; }

# cleanup is invoked via trap below; shellcheck cannot always see that
# shellcheck disable=SC2317,SC2329
cleanup() {
    [ -n "$VICTIM_PID" ] && kill "$VICTIM_PID" 2>/dev/null
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    [ -n "$REPORT_SERVER_PID" ] && kill "$REPORT_SERVER_PID" 2>/dev/null
    sleep 0.2
    rmmod anticheat 2>/dev/null
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

say "building"
make >/dev/null 2>&1 || { echo "build failed"; exit 1; }
make priv-drop-test >/dev/null 2>&1 || { echo "priv-drop-test build failed"; exit 1; }

say "loading anticheat.ko"
rmmod anticheat 2>/dev/null
insmod ./anticheat.ko || { echo "insmod failed — check dmesg"; exit 1; }
sleep 0.3

say "status"
./anticheat status || bad "status"

say "syscall table integrity"
if ./anticheat syscalls; then ok "syscall table clean"; else bad "syscall check"; fi

say "module enumeration"
if ./anticheat modules >/dev/null; then ok "modules listed"; else bad "modules"; fi

say "ioctl hardening: fd opened as root, then privileges dropped"
if ./test/priv_drop_test; then
    ok "ioctl correctly rejected after privilege drop"
else
    rc=$?
    if [ "$rc" -eq 2 ]; then
        bad "priv_drop_test environment problem (see stderr above)"
    else
        bad "ioctl NOT rejected after privilege drop (see stderr above)"
    fi
fi

say "protecting a victim process (a bash that will fork a child)"
# 1800s, not 300s: this process must stay alive across the entire rest of
# the suite (its last use is the "unprotect + cleanup" section near the
# end). A fixed 300s cap already came within one added test block of
# expiring mid-run as the suite grew -- give real headroom instead of
# re-tuning this number every time a new section is added. The exit trap
# (line 19) kills it regardless of how far the script gets.
bash -c 'sleep 1800 & echo $! > /tmp/ac_child.pid; wait' &
VICTIM_PID=$!
if ./anticheat protect --pid "$VICTIM_PID" >/dev/null; then
    ok "protected pid $VICTIM_PID"
else
    bad "protect"
fi

say "fork inheritance: child of protected process should inherit"
sleep 0.5
CHILD_PID=$(cat /tmp/ac_child.pid 2>/dev/null)
rm -f /tmp/ac_child.pid
if [ -n "$CHILD_PID" ] && ./anticheat list | grep -q "$CHILD_PID"; then
    ok "child pid $CHILD_PID inherited protection"
else
    bad "fork inheritance (child pid was '$CHILD_PID')"
fi

say "ptrace denial: attempting to attach to the protected process"
# rc=124 means strace stayed attached until the timeout (denial FAILED).
# A clean denial exits immediately with a non-zero, non-124 status.
timeout 3 strace -p "$VICTIM_PID" -e trace=none >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    ok "ptrace attach to protected process failed (rc=$rc)"
else
    bad "ptrace attach not denied (rc=$rc; 124 = hung attached)"
fi

sleep 0.5
# events are drained on read, so capture once and grep for both kinds
EVENTS=$(./anticheat events)
if printf '%s' "$EVENTS" | grep -q "PTRACE-DENIED"; then ok "PTRACE-DENIED event logged"; else bad "no ptrace event"; fi
if printf '%s' "$EVENTS" | grep -q "FORK"; then ok "FORK event logged"; else bad "no fork event"; fi

say "pid-namespace resolution: protect --pid inside another namespace via --ns-of"
# --comm already works across pid namespaces for free (it walks /proc from
# the daemon's own, ancestor-namespace view, which already shows
# host-visible pids for descendant-namespace tasks). --ns-of is for the
# narrower case where a caller only has a raw in-namespace pid number
# (e.g. 1, the new namespace's own "init") and a separate host-resolvable
# reference pid known to live in that same namespace.
if unshare --pid --mount-proc --fork -- true >/dev/null 2>&1; then
    unshare --pid --mount-proc --fork -- sleep 300 &
    NSPID_UNSHARE=$!
    sleep 0.3
    # unshare --fork's direct child becomes pid 1 *inside* the new
    # namespace while still being an ordinary host process with a normal
    # host-visible pid; $! above is the outer unshare(1) wrapper itself
    # (still in the host namespace), so pgrep -P is needed to find the
    # real namespaced victim -- same wrapper-vs-real-child problem as the
    # sudo -u case solved earlier in this file.
    NSPID_HOST=$(pgrep -P "$NSPID_UNSHARE" -f "sleep 300")
    if [ -n "$NSPID_HOST" ]; then
        if ./anticheat protect --pid 1 --ns-of "$NSPID_HOST" >/dev/null 2>&1; then
            LIST_OUT=$(./anticheat list 2>&1)
            # t->pid is always the root/init-namespace number, so a
            # correct resolution shows the HOST pid here, not the literal
            # "1" that was given on the command line -- that's the proof
            # --ns-of actually resolved relative to the sandboxed
            # namespace instead of the daemon's own.
            if printf '%s' "$LIST_OUT" | grep -q "pid $NSPID_HOST "; then
                ok "pid 1 inside the new namespace resolved to host pid $NSPID_HOST"
            else
                bad "protect --ns-of did not register the expected host pid (got: $LIST_OUT)"
            fi
            ./anticheat unprotect --pid "$NSPID_HOST" >/dev/null 2>&1
        else
            bad "protect --pid 1 --ns-of $NSPID_HOST failed"
        fi
    else
        bad "could not capture the host pid of the namespaced victim"
    fi
    kill "$NSPID_UNSHARE" "$NSPID_HOST" 2>/dev/null
    wait "$NSPID_UNSHARE" 2>/dev/null
else
    say "unshare --pid/--mount-proc not available/permitted here, skipping"
fi

say "memory scan (RWX + anon-exec detection)"
SCAN_OUT=$(./anticheat scan --pid "$VICTIM_PID")
if [ -n "$SCAN_OUT" ]; then ok "scan ok"; else bad "scan"; fi
# vdso is present in every process's address space and has no backing
# file, so a correct scan must find at least one anon-exec mapping here —
# this is what makes AC_EV_ANON_EXEC's baseline-delta design testable
# without actually injecting shellcode into the victim.
if printf '%s' "$SCAN_OUT" | grep -qE 'anon-exec'; then
    ok "anon-exec detection found at least one mapping (expect vdso)"
else
    bad "anon-exec detection found nothing (expected vdso at minimum)"
fi

say "render-hook check (Vulkan present-call) against a real, untampered process"
# Find whatever process on this machine currently has libvulkan.so loaded --
# game or not, this proves the check works against a real target rather than
# only exercising the "not loaded, skip" path. Not every machine will have
# one running; that's a skip, not a failure.
VK_PID=""
for m in /proc/[0-9]*/maps; do
    if grep -q libvulkan "$m" 2>/dev/null; then
        VK_PID=$(basename "$(dirname "$m")")
        break
    fi
done
if [ -n "$VK_PID" ]; then
    HOOK_OUT=$(./anticheat scan --pid "$VK_PID" --check-hooks 2>&1)
    if printf '%s' "$HOOK_OUT" | grep -q "vkQueuePresentKHR clean"; then
        ok "vkQueuePresentKHR matched reference copy (pid $VK_PID)"
    elif printf '%s' "$HOOK_OUT" | grep -q "render hook"; then
        bad "unexpected hook flagged on an untampered process (pid $VK_PID)"
    else
        bad "render-hook check produced neither clean nor hook result"
    fi
    say "render-hook check: does it actually catch a real hook?"
    # The check above only proves the true-negative case (an untampered
    # process reads as clean). A detector that never fires is useless, so
    # also prove the true-positive case: self-hook vkQueuePresentKHR in a
    # throwaway process and confirm the scan flags it. Gated on the same
    # $VK_PID (i.e. this machine has a working Vulkan install) so a
    # machine without libvulkan skips both checks together instead of
    # this one failing for an unrelated environment reason.
    make render-hook-test >/dev/null 2>&1
    # render_hook_test loops forever once ready, so it can't be waited on
    # normally; read its one line of startup output from a FIFO instead.
    FIFO=$(mktemp -u)
    mkfifo "$FIFO"
    setsid ./test/render_hook_test >"$FIFO" 2>&1 &
    HOOK_LINE=$(timeout 5 head -n1 "$FIFO")
    rm -f "$FIFO"
    HOOK_PID=$(printf '%s' "$HOOK_LINE" | sed -n 's/^READY pid=\([0-9]*\)$/\1/p')
    if [ -n "$HOOK_PID" ]; then
        DETECT_OUT=$(./anticheat scan --pid "$HOOK_PID" --check-hooks 2>&1)
        if printf '%s' "$DETECT_OUT" | grep -q "render hook"; then
            ok "self-hooked vkQueuePresentKHR correctly flagged (pid $HOOK_PID)"
        else
            bad "self-hooked vkQueuePresentKHR was NOT flagged (pid $HOOK_PID)"
        fi

        say "render-hook check: periodic monitoring loop, not just one-shot scan"
        # Both checks above only exercise `scan --check-hooks` on demand.
        # Prove the daemon's own monitoring loop (start) catches the same
        # hook on its own -- this is the actual deployed behavior, the
        # one-shot command is a diagnostic tool on top of it.
        if ./anticheat protect --pid "$HOOK_PID" >/dev/null 2>&1; then
            AC_RENDER_HOOK_CHECK_INTERVAL=2 ./anticheat start --foreground \
                >/tmp/ac_render_hook_test_$$.log 2>&1 &
            RENDER_DAEMON_PID=$!
            sleep 4
            if grep -q "render hook detected" /tmp/ac_render_hook_test_$$.log; then
                ok "periodic monitoring loop detected the self-hooked process"
            else
                bad "periodic monitoring loop did not detect the self-hooked process"
            fi
            kill "$RENDER_DAEMON_PID" 2>/dev/null
            wait "$RENDER_DAEMON_PID" 2>/dev/null
            rm -f /tmp/ac_render_hook_test_$$.log
        else
            bad "could not protect render_hook_test pid for the periodic check"
        fi

        kill "$HOOK_PID" 2>/dev/null
        wait "$HOOK_PID" 2>/dev/null
    else
        bad "render_hook_test did not report READY (output: $HOOK_LINE)"
        # HOOK_PID was never captured (empty/timed-out READY line), so it
        # can't be killed by pid -- if the harness is just slow rather than
        # dead, it would otherwise leak as an orphan for the rest of the run.
        pkill -f "test/render_hook_test" 2>/dev/null
    fi

    say "render-hook check: catches a hook past the old fixed 32-byte window"
    # The check used to compare a fixed first-32-bytes window; it now
    # compares the symbol's whole ELF-declared size instead (see
    # compare_render_symbol()). vkQueuePresentKHR is 81 bytes on real
    # systems -- patch offset 40 is comfortably past the old window and
    # comfortably inside the real function, so this specifically proves
    # the new capability, not just that hooks at byte 0 are still caught
    # (the test above already covers that).
    OFFFIFO=$(mktemp -u)
    mkfifo "$OFFFIFO"
    setsid ./test/render_hook_test libvulkan.so.1 vkQueuePresentKHR 40 >"$OFFFIFO" 2>&1 &
    OFFHOOK_LINE=$(timeout 5 head -n1 "$OFFFIFO")
    rm -f "$OFFFIFO"
    OFFHOOK_PID=$(printf '%s' "$OFFHOOK_LINE" | sed -n 's/^READY pid=\([0-9]*\)$/\1/p')
    if [ -n "$OFFHOOK_PID" ]; then
        OFFDETECT_OUT=$(./anticheat scan --pid "$OFFHOOK_PID" --check-hooks 2>&1)
        if printf '%s' "$OFFDETECT_OUT" | grep -q "render hook"; then
            ok "hook at offset 40 (past the old 32-byte window) correctly flagged (pid $OFFHOOK_PID)"
        else
            bad "hook at offset 40 was NOT flagged -- past-window detection regressed (pid $OFFHOOK_PID)"
        fi
        kill "$OFFHOOK_PID" 2>/dev/null
        wait "$OFFHOOK_PID" 2>/dev/null
    else
        bad "offset-40 render_hook_test did not report READY (output: $OFFHOOK_LINE)"
        pkill -f "test/render_hook_test" 2>/dev/null
    fi
else
    say "no process with libvulkan loaded found on this machine, skipping both render-hook checks"
fi

say "render-hook check (GLX/OpenGL) against a real, untampered process"
GL_PID=""
for m in /proc/[0-9]*/maps; do
    if grep -q "libGL\.so" "$m" 2>/dev/null; then
        GL_PID=$(basename "$(dirname "$m")")
        break
    fi
done
if [ -n "$GL_PID" ]; then
    GLHOOK_OUT=$(./anticheat scan --pid "$GL_PID" --check-hooks 2>&1)
    if printf '%s' "$GLHOOK_OUT" | grep -q "glXSwapBuffers clean"; then
        ok "glXSwapBuffers matched reference copy (pid $GL_PID)"
    elif printf '%s' "$GLHOOK_OUT" | grep -q "render hook"; then
        bad "unexpected hook flagged on an untampered process (pid $GL_PID)"
    else
        bad "render-hook check produced neither clean nor hook result for GLX"
    fi

    say "render-hook check (GLX/OpenGL): does it actually catch a real hook?"
    make render-hook-test >/dev/null 2>&1
    GLFIFO=$(mktemp -u)
    mkfifo "$GLFIFO"
    setsid ./test/render_hook_test libGL.so.1 glXSwapBuffers >"$GLFIFO" 2>&1 &
    GLHOOK_LINE=$(timeout 5 head -n1 "$GLFIFO")
    rm -f "$GLFIFO"
    GLHOOK_PID=$(printf '%s' "$GLHOOK_LINE" | sed -n 's/^READY pid=\([0-9]*\)$/\1/p')
    if [ -n "$GLHOOK_PID" ]; then
        GLDETECT_OUT=$(./anticheat scan --pid "$GLHOOK_PID" --check-hooks 2>&1)
        if printf '%s' "$GLDETECT_OUT" | grep -q "render hook"; then
            ok "self-hooked glXSwapBuffers correctly flagged (pid $GLHOOK_PID)"
        else
            bad "self-hooked glXSwapBuffers was NOT flagged (pid $GLHOOK_PID)"
        fi

        say "render-hook check (GLX/OpenGL): periodic monitoring loop, not just one-shot scan"
        if ./anticheat protect --pid "$GLHOOK_PID" >/dev/null 2>&1; then
            AC_RENDER_HOOK_CHECK_INTERVAL=2 ./anticheat start --foreground \
                >/tmp/ac_gl_render_hook_test_$$.log 2>&1 &
            GLRENDER_DAEMON_PID=$!
            sleep 4
            if grep -q "render hook detected" /tmp/ac_gl_render_hook_test_$$.log; then
                ok "periodic monitoring loop detected the self-hooked GLX process"
            else
                bad "periodic monitoring loop did not detect the self-hooked GLX process"
            fi
            kill "$GLRENDER_DAEMON_PID" 2>/dev/null
            wait "$GLRENDER_DAEMON_PID" 2>/dev/null
            rm -f /tmp/ac_gl_render_hook_test_$$.log
        else
            bad "could not protect GL render_hook_test pid for the periodic check"
        fi

        kill "$GLHOOK_PID" 2>/dev/null
        wait "$GLHOOK_PID" 2>/dev/null
    else
        bad "GL render_hook_test did not report READY (output: $GLHOOK_LINE)"
        pkill -f "test/render_hook_test" 2>/dev/null
    fi
else
    say "no process with libGL loaded found on this machine, skipping both GLX render-hook checks"
fi

say "render-hook check (EGL) against a real, untampered process"
EGL_PID=""
for m in /proc/[0-9]*/maps; do
    if grep -q "libEGL\.so" "$m" 2>/dev/null; then
        EGL_PID=$(basename "$(dirname "$m")")
        break
    fi
done
if [ -n "$EGL_PID" ]; then
    EGLHOOK_OUT=$(./anticheat scan --pid "$EGL_PID" --check-hooks 2>&1)
    if printf '%s' "$EGLHOOK_OUT" | grep -q "eglSwapBuffers clean"; then
        ok "eglSwapBuffers matched reference copy (pid $EGL_PID)"
    elif printf '%s' "$EGLHOOK_OUT" | grep -q "render hook"; then
        bad "unexpected hook flagged on an untampered process (pid $EGL_PID)"
    else
        bad "render-hook check produced neither clean nor hook result for EGL"
    fi

    say "render-hook check (EGL): does it actually catch a real hook?"
    make render-hook-test >/dev/null 2>&1
    EGLFIFO=$(mktemp -u)
    mkfifo "$EGLFIFO"
    setsid ./test/render_hook_test libEGL.so.1 eglSwapBuffers >"$EGLFIFO" 2>&1 &
    EGLHOOK_LINE=$(timeout 5 head -n1 "$EGLFIFO")
    rm -f "$EGLFIFO"
    EGLHOOK_PID=$(printf '%s' "$EGLHOOK_LINE" | sed -n 's/^READY pid=\([0-9]*\)$/\1/p')
    if [ -n "$EGLHOOK_PID" ]; then
        EGLDETECT_OUT=$(./anticheat scan --pid "$EGLHOOK_PID" --check-hooks 2>&1)
        if printf '%s' "$EGLDETECT_OUT" | grep -q "render hook"; then
            ok "self-hooked eglSwapBuffers correctly flagged (pid $EGLHOOK_PID)"
        else
            bad "self-hooked eglSwapBuffers was NOT flagged (pid $EGLHOOK_PID)"
        fi

        say "render-hook check (EGL): periodic monitoring loop, not just one-shot scan"
        if ./anticheat protect --pid "$EGLHOOK_PID" >/dev/null 2>&1; then
            AC_RENDER_HOOK_CHECK_INTERVAL=2 ./anticheat start --foreground \
                >/tmp/ac_egl_render_hook_test_$$.log 2>&1 &
            EGLRENDER_DAEMON_PID=$!
            sleep 4
            if grep -q "render hook detected" /tmp/ac_egl_render_hook_test_$$.log; then
                ok "periodic monitoring loop detected the self-hooked EGL process"
            else
                bad "periodic monitoring loop did not detect the self-hooked EGL process"
            fi
            kill "$EGLRENDER_DAEMON_PID" 2>/dev/null
            wait "$EGLRENDER_DAEMON_PID" 2>/dev/null
            rm -f /tmp/ac_egl_render_hook_test_$$.log
        else
            bad "could not protect EGL render_hook_test pid for the periodic check"
        fi

        kill "$EGLHOOK_PID" 2>/dev/null
        wait "$EGLHOOK_PID" 2>/dev/null
    else
        bad "EGL render_hook_test did not report READY (output: $EGLHOOK_LINE)"
        pkill -f "test/render_hook_test" 2>/dev/null
    fi
else
    say "no process with libEGL loaded found on this machine, skipping both EGL render-hook checks"
fi

say "render-hook check: resolves a target-namespaced path correctly (not the host's)"
# Proves the /proc/<pid>/root/ fix in compare_render_symbol(): create a
# private mount namespace where a *different* (empty) file sits at the
# same path the daemon would naively try to open from its own (host)
# namespace, bind-mount the real libvulkan.so.1 over that path -- but
# only inside the new namespace. A daemon that opens the raw path string
# gets the wrong (empty, unopenable) file and can only report
# "inconclusive"; one that resolves through /proc/<pid>/root/ gets the
# real library the target process actually has mapped, and reports
# clean. This needs `unshare --mount`, so skip gracefully if that fails
# rather than treating an unrelated environment gap as a real failure.
NS_DIR="/tmp/ac_mount_ns_test_$$"
make mount-ns-test >/dev/null 2>&1
if [ -x ./test/mount_ns_probe ]; then
    rm -rf "$NS_DIR"
    mkdir -p "$NS_DIR"
    touch "$NS_DIR/libvulkan.so.1"
    NS_FIFO=$(mktemp -u)
    mkfifo "$NS_FIFO"
    setsid unshare --mount -- bash -c "
        mount --make-rprivate / &&
        mount --bind /usr/lib/libvulkan.so.1 '$NS_DIR/libvulkan.so.1' &&
        exec $PWD/test/mount_ns_probe '$NS_DIR/libvulkan.so.1'
    " >"$NS_FIFO" 2>&1 &
    NS_LINE=$(timeout 5 head -n1 "$NS_FIFO")
    rm -f "$NS_FIFO"
    NS_PID=$(printf '%s' "$NS_LINE" | sed -n 's/^READY pid=\([0-9]*\)$/\1/p')
    if [ -n "$NS_PID" ]; then
        NS_OUT=$(./anticheat scan --pid "$NS_PID" --check-hooks 2>&1)
        if printf '%s' "$NS_OUT" | grep -q "vkQueuePresentKHR clean"; then
            ok "resolved the target's real library through its own mount namespace"
        elif printf '%s' "$NS_OUT" | grep -q "could not verify"; then
            bad "fell back to the host's (wrong) view of the path instead of the target's"
        else
            bad "unexpected result (output: $NS_OUT)"
        fi
        kill "$NS_PID" 2>/dev/null
        wait "$NS_PID" 2>/dev/null
    else
        say "could not set up the test mount namespace (output: $NS_LINE), skipping"
        pkill -f "test/mount_ns_probe" 2>/dev/null
    fi
    rm -rf "$NS_DIR"
else
    say "mount-ns-test helper did not build, skipping"
fi

say "LD_PRELOAD check: negative case (victim has none set)"
PRELOAD_OUT=$(./anticheat scan --pid "$VICTIM_PID" --check-preload 2>&1)
if printf '%s' "$PRELOAD_OUT" | grep -q "LD_PRELOAD check: not set"; then
    ok "victim process correctly reports no LD_PRELOAD"
else
    bad "expected 'not set' for a process with no LD_PRELOAD (got: $PRELOAD_OUT)"
fi

say "LD_PRELOAD check: positive case (one-shot and periodic)"
# Preload libc itself -- completely inert (the dynamic linker already
# loads it regardless), just makes LD_PRELOAD non-empty in the target's
# environment so there's a real, harmless positive case to detect.
LIBC_PATH=$(ldd /bin/sh 2>/dev/null | awk '/libc\.so/{print $3; exit}')
if [ -n "$LIBC_PATH" ] && [ -e "$LIBC_PATH" ]; then
    LD_PRELOAD="$LIBC_PATH" bash -c 'sleep 300' &
    PRELOAD_PID=$!
    sleep 0.3

    PRELOAD_OUT=$(./anticheat scan --pid "$PRELOAD_PID" --check-preload 2>&1)
    if printf '%s' "$PRELOAD_OUT" | grep -qF "$LIBC_PATH"; then
        ok "one-shot check reports the LD_PRELOAD value"
    else
        bad "one-shot check did not report LD_PRELOAD=$LIBC_PATH (got: $PRELOAD_OUT)"
    fi

    if ./anticheat protect --pid "$PRELOAD_PID" >/dev/null 2>&1; then
        AC_LD_PRELOAD_CHECK_INTERVAL=2 ./anticheat start --foreground \
            >/tmp/ac_preload_test_$$.log 2>&1 &
        PRELOAD_DAEMON_PID=$!
        sleep 4
        if grep -q "LD_PRELOAD=$LIBC_PATH" /tmp/ac_preload_test_$$.log; then
            ok "periodic monitoring loop detected LD_PRELOAD (LOG_WARNING, not a ban-pipeline report)"
        else
            bad "periodic monitoring loop did not detect LD_PRELOAD"
        fi
        kill "$PRELOAD_DAEMON_PID" 2>/dev/null
        wait "$PRELOAD_DAEMON_PID" 2>/dev/null
        rm -f /tmp/ac_preload_test_$$.log
    else
        bad "could not protect the LD_PRELOAD victim pid for the periodic check"
    fi

    kill "$PRELOAD_PID" 2>/dev/null
    wait "$PRELOAD_PID" 2>/dev/null
else
    say "could not resolve a real libc path, skipping LD_PRELOAD positive-case checks"
fi

say "Vulkan-layer check: negative case (victim has none set)"
VKLAYER_OUT=$(./anticheat scan --pid "$VICTIM_PID" --check-vklayers 2>&1)
if printf '%s' "$VKLAYER_OUT" | grep -q "no layer-activation environment variables set"; then
    ok "victim process correctly reports no Vulkan-layer env vars"
else
    bad "expected 'no layer-activation...' for a process with none set (got: $VKLAYER_OUT)"
fi

say "Vulkan-layer check: positive case (one-shot and periodic)"
# VK_LAYER_PATH doesn't need to point at a real layer manifest for this
# check -- it only reads the environment variable's value, it never
# invokes the Vulkan loader. /tmp always exists, so this doesn't depend
# on a Vulkan SDK being installed on the test machine.
VK_LAYER_PATH=/tmp bash -c 'sleep 300' &
VKLAYER_PID=$!
sleep 0.3

VKLAYER_OUT=$(./anticheat scan --pid "$VKLAYER_PID" --check-vklayers 2>&1)
if printf '%s' "$VKLAYER_OUT" | grep -q "VK_LAYER_PATH=/tmp"; then
    ok "one-shot check reports the VK_LAYER_PATH value"
else
    bad "one-shot check did not report VK_LAYER_PATH=/tmp (got: $VKLAYER_OUT)"
fi

if ./anticheat protect --pid "$VKLAYER_PID" >/dev/null 2>&1; then
    AC_VK_LAYER_CHECK_INTERVAL=2 ./anticheat start --foreground \
        >/tmp/ac_vklayer_test_$$.log 2>&1 &
    VKLAYER_DAEMON_PID=$!
    sleep 4
    if grep -q "VK_LAYER_PATH=/tmp" /tmp/ac_vklayer_test_$$.log; then
        ok "periodic monitoring loop detected VK_LAYER_PATH (LOG_WARNING, not a ban-pipeline report)"
    else
        bad "periodic monitoring loop did not detect VK_LAYER_PATH"
    fi
    kill "$VKLAYER_DAEMON_PID" 2>/dev/null
    wait "$VKLAYER_DAEMON_PID" 2>/dev/null
    rm -f /tmp/ac_vklayer_test_$$.log
else
    bad "could not protect the VK_LAYER_PATH victim pid for the periodic check"
fi

kill "$VKLAYER_PID" 2>/dev/null
wait "$VKLAYER_PID" 2>/dev/null

say "implicit Vulkan-layer manifest check: negative, positive, disable_environment, periodic growth"
# Needs a real non-root user to place a manifest under and run a victim
# as (getpwuid() resolution is the whole point of this check -- root's
# own $HOME wouldn't exercise it). $SUDO_USER is how test.sh, itself run
# via sudo, knows who that is without hardcoding a username.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    IMPLICIT_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    IMPLICIT_HOME=""
fi
if [ -n "$IMPLICIT_HOME" ] && [ -d "$IMPLICIT_HOME" ]; then
    IMPLICIT_DIR="$IMPLICIT_HOME/.local/share/vulkan/implicit_layer.d"
    IMPLICIT_DIR_PRE_EXISTED=0
    [ -d "$IMPLICIT_DIR" ] && IMPLICIT_DIR_PRE_EXISTED=1
    mkdir -p "$IMPLICIT_DIR"
    MANIFEST="$IMPLICIT_DIR/ac_test_layer_$$.json"

    sudo -u "$SUDO_USER" bash -c 'sleep 300' &
    IMPLICIT_SUDO_PID=$!
    sleep 0.3
    # sudo forks a monitor process and runs the command in a child with
    # the target uid; $! is the monitor (still root), not the real
    # unprivileged victim -- pgrep -P finds that actual child.
    IMPLICIT_VPID=$(pgrep -P "$IMPLICIT_SUDO_PID" -f "sleep 300")

    if [ -n "$IMPLICIT_VPID" ]; then
        NEG_OUT=$(./anticheat scan --pid "$IMPLICIT_VPID" --check-implicit-layers 2>&1)
        if printf '%s' "$NEG_OUT" | grep -q "ac_test_layer_$$\|VK_LAYER_AC_TEST_$$"; then
            bad "test layer unexpectedly reported before the manifest was written"
        else
            ok "victim process does not report the not-yet-written test layer"
        fi

        cat > "$MANIFEST" <<MANIFESTEOF
{
    "file_format_version": "1.0.0",
    "layer": {
        "name": "VK_LAYER_AC_TEST_$$",
        "type": "GLOBAL",
        "library_path": "/tmp/ac-test-does-not-exist-$$.so",
        "api_version": "1.2.135",
        "implementation_version": "1",
        "description": "hypranticheat test.sh coverage for implicit-layer detection",
        "disable_environment": {
            "AC_TEST_DISABLE_LAYER_$$": "1"
        }
    }
}
MANIFESTEOF
        POS_OUT=$(./anticheat scan --pid "$IMPLICIT_VPID" --check-implicit-layers 2>&1)
        if printf '%s' "$POS_OUT" | grep -q "VK_LAYER_AC_TEST_$$" && \
            printf '%s' "$POS_OUT" | grep -q "not in the known-overlay allowlist"; then
            ok "one-shot check detects the new manifest and flags it as unrecognized"
        else
            bad "one-shot check did not detect/flag the test manifest (got: $POS_OUT)"
        fi
        kill "$IMPLICIT_SUDO_PID" "$IMPLICIT_VPID" 2>/dev/null

        sudo -u "$SUDO_USER" env "AC_TEST_DISABLE_LAYER_$$=1" bash -c 'sleep 300' &
        IMPLICIT_SUDO_PID2=$!
        sleep 0.3
        IMPLICIT_VPID2=$(pgrep -P "$IMPLICIT_SUDO_PID2" -f "sleep 300")
        if [ -n "$IMPLICIT_VPID2" ]; then
            DIS_OUT=$(./anticheat scan --pid "$IMPLICIT_VPID2" --check-implicit-layers 2>&1)
            if printf '%s' "$DIS_OUT" | grep -q "VK_LAYER_AC_TEST_$$"; then
                bad "layer still reported active with its disable_environment var set"
            else
                ok "disable_environment correctly suppresses the layer for this process"
            fi
            kill "$IMPLICIT_SUDO_PID2" "$IMPLICIT_VPID2" 2>/dev/null
        else
            bad "could not resolve the disable_environment victim's real pid"
        fi

        rm -f "$MANIFEST"
        sudo -u "$SUDO_USER" bash -c 'sleep 300' &
        IMPLICIT_SUDO_PID3=$!
        sleep 0.3
        IMPLICIT_VPID3=$(pgrep -P "$IMPLICIT_SUDO_PID3" -f "sleep 300")
        if [ -n "$IMPLICIT_VPID3" ] && ./anticheat protect --pid "$IMPLICIT_VPID3" >/dev/null 2>&1; then
            AC_IMPLICIT_LAYER_CHECK_INTERVAL=2 ./anticheat start --foreground \
                >"/tmp/ac_implicit_test_$$.log" 2>&1 &
            IMPLICIT_DAEMON_PID=$!
            sleep 3
            if grep -q "unrecognized implicit Vulkan" "/tmp/ac_implicit_test_$$.log"; then
                bad "periodic check warned before the layer was even present (bad baseline)"
            else
                ok "periodic check established a silent baseline with no layer present"
            fi
            cat > "$MANIFEST" <<MANIFESTEOF2
{
    "file_format_version": "1.0.0",
    "layer": {
        "name": "VK_LAYER_AC_TEST_$$",
        "type": "GLOBAL",
        "library_path": "/tmp/ac-test-does-not-exist-$$.so"
    }
}
MANIFESTEOF2
            sleep 5
            if grep -q "unrecognized implicit Vulkan.*VK_LAYER_AC_TEST_$$" "/tmp/ac_implicit_test_$$.log"; then
                ok "periodic check detected the layer appearing mid-session"
            else
                bad "periodic check did not detect the layer appearing mid-session"
            fi
            kill "$IMPLICIT_DAEMON_PID" 2>/dev/null
            wait "$IMPLICIT_DAEMON_PID" 2>/dev/null
            rm -f "/tmp/ac_implicit_test_$$.log"
        else
            bad "could not protect the periodic-growth victim pid"
        fi
        kill "$IMPLICIT_SUDO_PID3" "$IMPLICIT_VPID3" 2>/dev/null
    else
        bad "could not resolve the real (non-sudo-monitor) victim pid"
        kill "$IMPLICIT_SUDO_PID" 2>/dev/null
    fi

    rm -f "$MANIFEST"
    if [ "$IMPLICIT_DIR_PRE_EXISTED" -eq 0 ]; then
        rmdir "$IMPLICIT_DIR" 2>/dev/null
    fi
else
    say "no real non-root \$SUDO_USER with a resolvable home directory, skipping implicit-layer checks"
fi

say "memory integrity baseline"
if ./anticheat scan --pid "$VICTIM_PID" --hash --save >/dev/null 2>&1; then
    ok "baseline saved"
else
    bad "baseline save"
fi
if ./anticheat scan --pid "$VICTIM_PID" --hash --check >/dev/null 2>&1; then
    ok "baseline verified"
else
    bad "baseline check"
fi

say "automatic baseline re-check (daemon should detect tampering)"
BLDIR="/var/lib/anticheat/baselines"
if [ -d "$BLDIR" ]; then
    for f in "$BLDIR"/*.txt; do
        [ -f "$f" ] || continue
        sed -i 's/[0-9a-f]\{64\}$/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/' "$f"
    done
fi

# Start the report-pipeline server so this same tampering detection also
# proves the daemon's ac_report() reaches a live server correctly -- HTTP
# request framing and JSON body can't be verified by reading the code, only
# by actually running it end to end.
REPORT_PORT=18799
REPORT_KEY="test-report-key-$$"
ADMIN_KEY="test-admin-key-$$"
REPORT_DB="/tmp/ac_report_test_$$.db"
AC_SERVER_REPORT_KEY="$REPORT_KEY" AC_SERVER_ADMIN_KEY="$ADMIN_KEY" \
    python3 server/ac_server.py --host 127.0.0.1 --port "$REPORT_PORT" --db "$REPORT_DB" \
    >/tmp/ac_report_server_$$.log 2>&1 &
REPORT_SERVER_PID=$!
REPORT_SERVER_READY=0
for _ in $(seq 1 50); do
    if curl -s "http://127.0.0.1:$REPORT_PORT/banned/x" \
        -H "Authorization: Bearer $ADMIN_KEY" 2>/dev/null | grep -q '"banned"'; then
        REPORT_SERVER_READY=1
        break
    fi
    sleep 0.1
done
[ "$REPORT_SERVER_READY" -eq 1 ] || bad "report server never became ready on port $REPORT_PORT"

AC_BASELINE_CHECK_INTERVAL=2 AC_REPORT_URL="127.0.0.1:$REPORT_PORT" AC_REPORT_KEY="$REPORT_KEY" \
    ./anticheat start --foreground >/tmp/ac_baseline_test_$$.log 2>&1 &
DAEMON_PID=$!
sleep 4
if grep -q "differs from saved baseline" /tmp/ac_baseline_test_$$.log; then
    ok "periodic baseline check detected tampering"
else
    bad "periodic baseline check did not detect tampering"
fi
kill "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null

# Mirrors ac_report_client_id()'s own fallback logic exactly: a
# present-but-empty /etc/machine-id (common on freshly-provisioned
# containers/CI images before systemd-firstboot runs) must also fall
# back to the hostname, not just a missing file -- `cat ... || hostname`
# alone doesn't trigger on empty-but-successful output.
MACHINE_ID=$(cat /etc/machine-id 2>/dev/null)
[ -n "$MACHINE_ID" ] || MACHINE_ID=$(hostname)
REPORT_OUT=$(curl -s "http://127.0.0.1:$REPORT_PORT/reports/$MACHINE_ID" \
    -H "Authorization: Bearer $ADMIN_KEY")
if printf '%s' "$REPORT_OUT" | grep -q "differs from saved baseline"; then
    ok "ban-pipeline server received the report over real HTTP"
else
    bad "ban-pipeline server did not receive the report (got: $REPORT_OUT)"
fi
kill "$REPORT_SERVER_PID" 2>/dev/null
wait "$REPORT_SERVER_PID" 2>/dev/null
rm -f "$REPORT_DB" "$REPORT_DB-wal" "$REPORT_DB-shm" "/tmp/ac_report_server_$$.log"
DAEMON_PID=""
rm -f /tmp/ac_baseline_test_$$.log
# The corruption above (sed -i ... deadbeef...) hits every saved baseline
# in $BLDIR, not just VICTIM_PID's -- and baselines are keyed by file path,
# not by pid, so a common shared library (libc.so.6, ld-linux...) stays
# corrupted for any process protected afterward that also maps it, not
# just VICTIM_PID. Nothing downstream in this suite needs these restored
# (only VICTIM_PID's own --hash --save/--check pair, already exercised
# above), so clear them rather than leave a landmine for later tests --
# check_baselines_periodic() already treats "no baseline file" as
# "nothing to check," not an error (anticheat_daemon.c: "nothing saved
# for this file -- nothing to check").
[ -d "$BLDIR" ] && rm -f "$BLDIR"/*.txt

say "JIT allowlist: --jit downgrades anon-exec growth so it's still logged but not auto-reported"
# Two throwaway processes, both grow one new anonymous-executable mapping
# on command (the same observable signal a JIT or injected shellcode
# produces -- see test/anon_exec_test.c). One is protected plainly, the
# other with --jit. Proves the actual end-to-end behavior difference:
# both log the growth, but only the non-allowlisted one reaches the
# ban-pipeline server -- not just that the code paths differ, but that a
# real report is/isn't sent over real HTTP.
make anon-exec-test >/dev/null 2>&1

FIFO1=$(mktemp -u); mkfifo "$FIFO1"
setsid ./test/anon_exec_test >"$FIFO1" 2>&1 &
AE1_LINE=$(timeout 5 head -n1 "$FIFO1"); rm -f "$FIFO1"
AE1_PID=$(printf '%s' "$AE1_LINE" | sed -n 's/^READY pid=\([0-9]*\)$/\1/p')

FIFO2=$(mktemp -u); mkfifo "$FIFO2"
setsid ./test/anon_exec_test >"$FIFO2" 2>&1 &
AE2_LINE=$(timeout 5 head -n1 "$FIFO2"); rm -f "$FIFO2"
AE2_PID=$(printf '%s' "$AE2_LINE" | sed -n 's/^READY pid=\([0-9]*\)$/\1/p')

if [ -n "$AE1_PID" ] && [ -n "$AE2_PID" ]; then
    ./anticheat protect --pid "$AE1_PID" >/dev/null
    ./anticheat protect --pid "$AE2_PID" --jit >/dev/null

    JIT_REPORT_PORT=18800
    JIT_REPORT_KEY="test-jit-report-key-$$"
    JIT_ADMIN_KEY="test-jit-admin-key-$$"
    JIT_REPORT_DB="/tmp/ac_jit_report_test_$$.db"
    AC_SERVER_REPORT_KEY="$JIT_REPORT_KEY" AC_SERVER_ADMIN_KEY="$JIT_ADMIN_KEY" \
        python3 server/ac_server.py --host 127.0.0.1 --port "$JIT_REPORT_PORT" --db "$JIT_REPORT_DB" \
        >/tmp/ac_jit_report_server_$$.log 2>&1 &
    JIT_REPORT_SERVER_PID=$!
    JIT_SERVER_READY=0
    for _ in $(seq 1 50); do
        if curl -s "http://127.0.0.1:$JIT_REPORT_PORT/banned/x" \
            -H "Authorization: Bearer $JIT_ADMIN_KEY" 2>/dev/null | grep -q '"banned"'; then
            JIT_SERVER_READY=1
            break
        fi
        sleep 0.1
    done
    [ "$JIT_SERVER_READY" -eq 1 ] || bad "JIT-test report server never became ready on port $JIT_REPORT_PORT"

    AC_SCAN_CHECK_INTERVAL=2 AC_REPORT_URL="127.0.0.1:$JIT_REPORT_PORT" AC_REPORT_KEY="$JIT_REPORT_KEY" \
        ./anticheat start --foreground >/tmp/ac_jit_test_$$.log 2>&1 &
    JIT_DAEMON_PID=$!
    sleep 3    # let the first scan cycle establish both pids' anon-exec baseline
    kill -USR1 "$AE1_PID" "$AE2_PID"
    sleep 3    # let the next scan cycle observe the growth

    if grep -q "pid $AE1_PID .*possible code injection" /tmp/ac_jit_test_$$.log; then
        ok "non-allowlisted process's growth logged at CRITICAL"
    else
        bad "non-allowlisted process's growth was not logged as expected"
    fi
    if grep -q "pid $AE2_PID .*expected for a JIT-marked process" /tmp/ac_jit_test_$$.log; then
        ok "allowlisted process's growth logged at WARNING, not CRITICAL"
    else
        bad "allowlisted process's growth was not logged as expected"
    fi

    kill "$JIT_DAEMON_PID" 2>/dev/null
    wait "$JIT_DAEMON_PID" 2>/dev/null

    JIT_MACHINE_ID=$(cat /etc/machine-id 2>/dev/null)
    [ -n "$JIT_MACHINE_ID" ] || JIT_MACHINE_ID=$(hostname)
    JIT_REPORT_OUT=$(curl -s "http://127.0.0.1:$JIT_REPORT_PORT/reports/$JIT_MACHINE_ID" \
        -H "Authorization: Bearer $JIT_ADMIN_KEY")
    # Match the anon-exec-specific phrase plus "pid N (", not just "pid N"
    # -- the JSON blob can carry other, unrelated report types (baseline
    # tamper, RWX, ...) for the same pid, and a bare pid substring can also
    # coincidentally match inside an unrelated numeric field (timestamps).
    if printf '%s' "$JIT_REPORT_OUT" | grep -q "pid $AE1_PID (.*new anonymous executable"; then
        ok "non-allowlisted process's growth reached the ban-pipeline server"
    else
        bad "non-allowlisted process's growth did NOT reach the ban-pipeline server (got: $JIT_REPORT_OUT)"
    fi
    if printf '%s' "$JIT_REPORT_OUT" | grep -q "pid $AE2_PID (.*new anonymous executable"; then
        bad "allowlisted process's growth reached the ban-pipeline server (should have been suppressed; got: $JIT_REPORT_OUT)"
    else
        ok "allowlisted process's growth correctly did NOT reach the ban-pipeline server"
    fi

    kill "$JIT_REPORT_SERVER_PID" 2>/dev/null
    wait "$JIT_REPORT_SERVER_PID" 2>/dev/null
    rm -f "$JIT_REPORT_DB" "$JIT_REPORT_DB-wal" "$JIT_REPORT_DB-shm" \
        "/tmp/ac_jit_report_server_$$.log" /tmp/ac_jit_test_$$.log
else
    bad "anon_exec_test harness(es) did not report READY (got: '$AE1_LINE' / '$AE2_LINE')"
    # A pid that never got captured (empty/timed-out READY line) can't be
    # killed by pid below -- catch it by binary path instead, or a slow
    # (not dead) harness leaks as an orphan for the rest of the run.
    pkill -f "test/anon_exec_test" 2>/dev/null
fi
kill "$AE1_PID" "$AE2_PID" 2>/dev/null
wait "$AE1_PID" "$AE2_PID" 2>/dev/null

say "unprotect + cleanup"
if ./anticheat unprotect --pid "$VICTIM_PID" >/dev/null; then ok "unprotected"; else bad "unprotect"; fi
[ -n "$CHILD_PID" ] && kill "$CHILD_PID" 2>/dev/null

say "locking the module (rmmod must fail while locked)"
if ./anticheat lock >/dev/null; then ok "locked"; else bad "lock"; fi
if rmmod anticheat 2>/dev/null; then bad "rmmod succeeded while locked"; else ok "rmmod correctly refused"; fi
if ./anticheat unlock >/dev/null; then ok "unlocked"; else bad "unlock"; fi

say "self-protection: daemon should register its own pid"
./anticheat start --foreground >/tmp/ac_daemon_$$.log 2>&1 &
DAEMON_PID=$!
sleep 1
if ./anticheat list | grep -q "$DAEMON_PID"; then
    ok "daemon self-protected (pid $DAEMON_PID)"
else
    bad "daemon did not appear in protected list"
fi
timeout 3 strace -p "$DAEMON_PID" -e trace=none >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    ok "ptrace attach to daemon itself denied (rc=$rc)"
else
    bad "ptrace attach to daemon not denied (rc=$rc; 124 = hung attached)"
fi
kill "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""

say "unloading"
if rmmod anticheat; then ok "module unloaded"; else bad "rmmod"; fi

echo
if [ "$FAILED" -eq 0 ]; then
    printf '\033[1;32mALL TESTS PASSED\033[0m\n'
else
    printf '\033[1;31mSOME TESTS FAILED\033[0m\n'
fi
exit "$FAILED"
