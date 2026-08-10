# kernel-anticheat: kernel module + userspace daemon
#
#   make            build both
#   make module     build anticheat.ko only
#   make daemon     build the userspace binary only
#   make clean
#   sudo make install    (binary -> /usr/local/sbin, module -> /lib/modules/.../extra)
#   sudo make uninstall
#
# Kernel module build requires linux headers for the running kernel:
#   /lib/modules/$(uname -r)/build

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
PWD  := $(shell pwd)
CC   ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

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
	rm -f anticheat test/libmock_anticheat.so

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

.PHONY: all module daemon mock test-mock ci clean install uninstall
