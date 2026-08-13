# kernel-anticheat: kernel module + userspace daemon
#
#   make            build both
#   make module     build anticheat.ko only
#   make daemon     build the userspace binary only
#   make clean
#   sudo make install         (binary -> /usr/local/sbin, module -> /lib/modules/.../extra)
#   sudo make uninstall
#   make install-deck         (SteamOS / immutable distros — see below)
#   make uninstall-deck
#
# Kernel module build requires linux headers for the running kernel:
#   /lib/modules/$(uname -r)/build
#
# For a distro with automatic kernel-update rebuilds and Secure Boot signing,
# use DKMS instead of `make install` — see scripts/dkms-install.sh.
#
# `install`/`uninstall` write to /usr/local and /lib/modules, which is fine
# on a normal distro but is read-only (or wiped on the next OTA update) on
# SteamOS and other immutable/atomic-image systems. `install-deck` instead
# stages everything under a user-writable directory and loads the module
# with plain `insmod` (which only needs a valid .ko for the running kernel,
# unlike `modprobe`, which needs /lib/modules to be writable and depmod'd).
# This does NOT survive a kernel update by itself — rebuild and reload after
# one, since DKMS's auto-rebuild-on-kernel-postinst hook assumes a distro
# where /lib/modules is writable.

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PWD  := $(shell pwd)
CC   ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
DECK_PREFIX ?= $(HOME)/.local/share/anticheat

# If the running kernel was built with clang/LLVM, build the module with
# the same toolchain (Kbuild flags are not compatible with gcc).
ifeq ($(shell grep -q '^CONFIG_CC_IS_CLANG=y' $(KDIR)/.config 2>/dev/null && echo 1 || echo 0),1)
LLVM := 1
endif

obj-m += anticheat.o
anticheat-objs := src/anticheat_module.o

all: module daemon

module:
	$(MAKE) -C $(KDIR) M=$(PWD) LLVM=$(LLVM) modules

daemon: src/anticheat_daemon.c src/sha256.c src/sha256.h src/anticheat.h
	$(CC) $(CFLAGS) -o anticheat src/anticheat_daemon.c src/sha256.c

mock: test/libmock_anticheat.so

test/libmock_anticheat.so: test/mock_anticheat.c src/anticheat.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl

# real (non-mock) live test helper: proves ac_ioctl() rechecks
# CAP_SYS_ADMIN by opening /dev/anticheat as root, dropping privileges,
# and confirming the ioctl is rejected. Needs the module loaded and root
# to run -- see test.sh.
priv-drop-test: test/priv_drop_test

test/priv_drop_test: test/priv_drop_test.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $<

# render-hook live test helper: self-hooks vkQueuePresentKHR in its own
# process (harmless -- the patched bytes are never called) so `scan
# --check-hooks` has a real, known-tampered target to detect. Needs root
# to run the scan against it (uses the device) -- see test.sh.
render-hook-test: test/render_hook_test

test/render_hook_test: test/render_hook_test.c src/anticheat.h
	$(CC) $(CFLAGS) -o $@ $< -ldl

# mount-namespace live test helper: dlopen()s an explicit path inside a
# private mount namespace test.sh sets up, so the render-hook check's
# /proc/<pid>/root/ resolution can be proven against a real target whose
# view of a path differs from the host's. Needs root (mount namespaces,
# the module) -- see test.sh.
mount-ns-test: test/mount_ns_probe

test/mount_ns_probe: test/mount_ns_probe.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

# run the daemon CLI against the userspace mock (no kernel module, no root)
test-mock: mock daemon
	./test/mock_test.sh

# CI entry point: rebuild all userspace with warnings-as-errors and run the
# full no-root test suite.  (The kernel module build needs real kernel
# headers and is exercised separately in CI against a prepared kernel tree.)
ci:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O2 -Wall -Wextra -Werror" daemon mock
	./test/mock_test.sh

clean:
	@if [ -d $(KDIR) ]; then $(MAKE) -C $(KDIR) M=$(PWD) clean; fi
	rm -f anticheat test/libmock_anticheat.so test/priv_drop_test test/render_hook_test test/mount_ns_probe

install: all
	install -D -m 0755 anticheat /usr/local/sbin/anticheat
	install -D -m 0644 anticheat.ko /lib/modules/$(KVER)/extra/anticheat.ko
	install -d -m 0755 /var/lib/anticheat/baselines
	depmod -a
	@echo "installed. load with: sudo modprobe anticheat  (or insmod ./anticheat.ko)"

uninstall:
	rm -f /usr/local/sbin/anticheat
	rm -f /lib/modules/$(KVER)/extra/anticheat.ko
	depmod -a

# SteamOS / immutable-distro install: everything lives under $(DECK_PREFIX)
# (default: ~/.local/share/anticheat), which survives OTA image updates
# because it's in the user's home, not the read-only system image. No
# /lib/modules write, no depmod — the module is loaded directly by path.
install-deck: all
	install -D -m 0755 anticheat $(DECK_PREFIX)/bin/anticheat
	install -D -m 0644 anticheat.ko $(DECK_PREFIX)/anticheat.ko
	install -d -m 0755 $(DECK_PREFIX)/baselines
	@echo "installed under $(DECK_PREFIX)"
	@echo "load with: sudo insmod $(DECK_PREFIX)/anticheat.ko"
	@echo "run the daemon with: sudo AC_BASELINE_DIR=$(DECK_PREFIX)/baselines $(DECK_PREFIX)/bin/anticheat start"

uninstall-deck:
	rm -rf $(DECK_PREFIX)

.PHONY: all module daemon mock test-mock priv-drop-test render-hook-test mount-ns-test ci clean install uninstall install-deck uninstall-deck
