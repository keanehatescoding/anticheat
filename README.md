# kernel-anticheat

A Linux kernel-mode anticheat: a loadable kernel module (LKM) that performs
kernel-level integrity checks and enforces process protection, plus a
userspace daemon/CLI that talks to it over a small ioctl interface
(`/dev/anticheat`).

> **Purpose:** defensive security instrumentation. It detects tampering with
> the running kernel (syscall hooks, hidden modules) and with protected
> processes (RWX code caves, debugger attaches, runtime code patching).
> It is **not** designed to bypass any protection.

## Architecture

```
┌────────────────────────────┐        ┌──────────────────────────────┐
│  userspace                 │ ioctl  │  kernel                      │
│  anticheat daemon/CLI      │◄──────►│  anticheat.ko (LKM)          │
│  · status / protect / scan │        │  · syscall table discovery   │
│  · baselines (SHA-256)     │        │  · syscall integrity checks  │
│  · monitor loop (start)    │        │  · module enumeration        │
└────────────────────────────┘        │  · protected process registry│
                                      │  · ptrace denial (kprobe)    │
                                      │  · fork/exec/exit tracing    │
                                      │  · VMA scan (RWX + anon-exec)│
                                      │  · event ring buffer         │
                                      └──────────────────────────────┘
```

### Kernel module features

1. **Syscall table discovery + integrity.** The module locates
   `sys_call_table` without `kallsyms_lookup_name` (not exported since 5.7):
   it resolves the `__x64_sys_read`/`__x64_sys_write` handler addresses with
   kprobes, then scans the kernel image for the 8-byte slot equal to the read
   handler and cross-validates with the write handler. Every table entry is
   then checked to lie inside the core kernel text (`[_stext, _etext)`) and
   outside any loaded module — the classic rootkit hook (redirecting a
   syscall into module/vmalloc memory) is flagged and reported as
   `AC_EV_SYSCALL_HOOK`.

2. **Module enumeration.** The kernel-internal module list is walked
   (preemption disabled, since `module_mutex` is not exported) and compared
   by the daemon against `/proc/modules`, detecting modules hidden from
   procfs.

3. **Protected process registry.** Processes are registered by pid; the
   registry stores `task_struct` references (namespace-safe, immune to pid
   reuse). **Protection is inherited by forked children** (tracked with a
   kretprobe on `kernel_clone`).

4. **ptrace denial.** A kprobe on `__x64_sys_ptrace` (and the ia32 entry)
   intercepts attach/debug requests against protected processes. The request
   argument is rewritten to an invalid value, so the syscall fails cleanly
   with `-EIO` and has **no side effects** (the attach never happens). Per
   policy (`ac_policy` bit 0, default on) the offending tracer is also
   SIGKILLed from a private workqueue (safe from atomic kprobe context).

5. **Fork / exec / exit tracing.** kretprobe on `kernel_clone` (inheritance +
   events), kprobe pre-handlers on `do_exit` and `__x64_sys_execve[at]`.

6. **VMA memory scan.** A snapshot of the process address space is built
   under the mmap read lock (maple-tree iterator) and served to userspace
   via begin/get/end ioctls (kept under the 14-bit ioctl size limit).
   Executable+writable ("RWX code cave") mappings are flagged — the classic
   runtime code-injection signature. Executable mappings with **no backing
   file at all** are flagged too (`AC_EV_ANON_EXEC`): legitimate code is
   always backed by a file (the binary or a shared library), so this also
   catches the write-then-`mprotect(R-X)` pattern, where shellcode is
   written to a RW mapping and then made executable — W and X are never
   both set at the same instant, so it never trips the RWX check. `vdso`
   and `vvar` legitimately show up in this category too (present from
   process start, never changing); the daemon's periodic scan tracks each
   protected pid's count from when it was first observed and only alerts
   on a *later increase*, so those don't generate noise (see
   `anon_baseline_check()` in the daemon).

7. **Event ring buffer.** Fixed-size ring of security events consumed by the
   daemon (`events`, and periodically by `start`).

8. **Module pinning.** While the daemon holds `/dev/anticheat` open (or after
   `anticheat lock`), `rmmod` fails with `EBUSY`.

### Userspace

```
anticheat status                     module status
anticheat protect --pid N            protect a process (children inherit)
anticheat protect --comm NAME        protect by comm name
anticheat unprotect --pid N
anticheat list                       list protected processes
anticheat scan --pid N               VMA scan, RWX + anon-exec detection
anticheat scan --pid N --hash --save    create memory-integrity baselines
anticheat scan --pid N --hash --check   verify runtime memory vs baseline
anticheat syscalls                   verify syscall table integrity
anticheat modules                    detect modules hidden from /proc/modules
anticheat events [--watch]           dump security events
anticheat lock | unlock              pin / unpin the kernel module
anticheat start [--foreground]       monitoring daemon (events + periodic checks)
```

The daemon (`start`) protects its own pid on startup (so it can't just be
ptrace-attached or debugged away — see `AC_IOCTL_ADD_PROC` in `cmd_start`),
polls security events, re-checks syscall integrity every 5 s, module
visibility every 10 s, scans protected processes every 30 s for RWX
mappings and for anonymous-executable mappings appearing *after* a process
was first observed (each pid's baseline count is recorded on first scan;
`vdso`/`vvar` never trigger since they're present from process start and
never change — see `anon_baseline_check()`), and every 60 s re-hashes every
protected process's executable, file-backed mappings against whatever
baseline was already saved for them via `--hash --save`
(`check_baselines_periodic()`). It never creates a baseline on its own —
only an operator running `--save` on a binary they've already verified
clean does that — so a process with no saved baseline is silently skipped,
not auto-trusted. Alerts go to syslog (`LOG_AUTH`) and
`/var/log/anticheat.log`.

Baselines are stored in `/var/lib/anticheat/baselines/` (one SHA-256 per
file-backed executable mapping; override the directory with the
`AC_BASELINE_DIR` environment variable). `--check` reports mappings whose
runtime content differs from the baseline — a strong signal of runtime code
patching.

## Build

Requires a C compiler for the userspace daemon. The kernel module additionally
needs kernel headers for a kernel **>= 6.12** (it uses `sized_strscpy`, the
`_noprof` allocators, `for_class_mod_mem_type`, and maple-tree VMA iteration);
build it against the headers of the kernel you intend to load it on. The
Makefile auto-detects a clang/LLVM-built kernel (as on Arch/CachyOS) and builds
with the same toolchain.

```sh
make              # builds anticheat.ko + anticheat binary
make daemon       # userspace only
make module       # module only
make test-mock    # run the CLI against the userspace mock (no root needed)
```

### No-root testing: the userspace mock

`make test-mock` (or `./test/mock_test.sh`) runs the entire daemon CLI
against a userspace stand-in for the kernel module:

```sh
LD_PRELOAD=test/libmock_anticheat.so ./anticheat status
```

`test/mock_anticheat.c` intercepts `open`/`ioctl`/`geteuid` via
`LD_PRELOAD` and implements the same ioctl ABI, so every command — status,
protect/list/unprotect, VMA scan, SHA-256 baselines, syscall integrity
(clean **and** compromised), hidden-module detection, events, lock/unlock,
and the monitoring daemon (including graceful SIGTERM shutdown) — is
exercised end-to-end without a kernel module or root. State persists across
CLI invocations in `$AC_MOCK_STATE`; `AC_MOCK_HOOKED=1` simulates a hooked
syscall table, `AC_MOCK_ATTACK=1` simulates a ptrace attack. The mock
always injects one `hidden_rootkit` module to exercise the hidden-module
path.

The mock is a development tool only — it never loads code into the kernel.

### Load / use

```sh
sudo insmod ./anticheat.ko        # or: sudo modprobe anticheat (after install)
sudo ./anticheat status
sudo ./anticheat protect --pid $(pgrep -x mygame)
sudo ./anticheat scan --pid <pid> --hash --save
sudo ./anticheat start            # run the monitor
```

`sudo make install` installs the binary to `/usr/local/sbin` and the module
to `/lib/modules/$(uname -r)/extra/`.

### Automatic rebuild on kernel updates + Secure Boot (DKMS)

`make install` puts a static build in place; it does **not** survive the
next kernel upgrade, and it won't load at all under Secure Boot without a
signature. For a normal desktop distro, use DKMS instead:

```sh
sudo ./scripts/dkms-install.sh
```

This registers the module with DKMS, which rebuilds it automatically every
time a new kernel package is installed. It also installs a small
`/etc/dkms/framework.conf.d/anticheat.conf` fragment that points DKMS's
*built-in* Secure Boot signing at a self-generated Machine Owner Key under
`/var/lib/anticheat/mok/` (DKMS signs every build with it automatically from
then on — no custom signing script needed). The *first* build on a machine
with Secure Boot enabled will ask you to reboot once and approve the key in
the firmware's blue "MOK Management" screen — that's a UEFI requirement (no
software can auto-approve a new trusted key, by design) and only happens
once per machine, not per kernel update.

### SteamOS / Steam Deck / other immutable distros

`/lib/modules` and `/usr` are read-only on SteamOS and get replaced
wholesale on every OTA update, so neither `make install` nor DKMS's
kernel-postinst rebuild hook applies there. Use:

```sh
make install-deck        # installs under ~/.local/share/anticheat
sudo insmod ~/.local/share/anticheat/anticheat.ko
```

This has to be rebuilt and reloaded manually after a SteamOS update (there
is no on-device header package for DKMS to rebuild against); see the
project notes on CI-prebuilding a `.ko` per SteamOS kernel release if you
need this to survive updates unattended.

## Live test

```sh
sudo ./test.sh
```

This loads the module, protects a victim `sleep` process, verifies fork
inheritance, attempts a `strace -p` attach (must be denied), runs scans and
baselines, and verifies lock/unlock semantics.

## Continuous integration

`.github/workflows/ci.yml` runs two jobs on every push / PR:

1. **Userspace** (`make ci`): rebuilds the daemon and mock with
   `-Wall -Wextra -Werror` (zero warnings required) and runs the full mock
test suite — every CLI command, the compromised-syscall-table simulation, the
hidden-module simulation, and the monitoring daemon — with no kernel module
and no root. The shell scripts are also checked with `shellcheck`.
2. **Kernel module**: fetches a pinned linux-6.12 LTS source tree, prepares
   it (`defconfig` + `scripts` + `modules_prepare`), and builds `anticheat.ko`
   against it. Because a prepared tree has no `Module.symvers`, CI synthesizes
   one from the object's undefined symbols (`KBUILD_EXTRA_SYMBOLS`) so the
   final modpost link succeeds; this is a compile smoke test — real load-time
   symbol resolution is validated on a live kernel (see `diag.sh`). The
   resulting `.ko` is uploaded as a build artifact.

To run the same userspace checks locally: `make ci`.

## Design notes & limitations

- **Heuristic, not provably secure.** A determined rootkit with kernel
  privileges can defeat any in-band detector. This tool is defense-in-depth:
  it raises the cost and detects the *typical* hook points.
- The syscall-entry check treats "inside `[_stext, _etext)` and outside all
  modules" as legit. A hook that redirects within core kernel text (e.g.,
  sys_read → sys_write) is not flagged (rare; also visually detectable).
  If the `_stext`/`_etext` kprobe lookups are unavailable (they are section
  labels and not always probe-able), the module derives the text bounds
  from the syscall table entries themselves and falls back to a ±64 MB
  window around a known handler — both cover all legitimate handlers.
- Kernel addresses are KASLR-randomized at boot; kprobe lookups return
  *runtime* addresses, so the table scan uses the live image (no hardcoded
  vmlinux offsets). On x86-64 with IBT the kprobe reports the ftrace call
  site (4 bytes after the `endbr64`), while the syscall table stores the
  symbol start — the module detects `endbr64` (0xf3 0x0f 0x1e 0xfa) and
  normalizes before scanning.
- The `__x64_sys_*`/`__ia32_sys_*` wrappers receive `struct pt_regs *` in
  `%rdi` and unpack the syscall arguments from that frame, so the ptrace
  kprobe reads/rewrites the request in the frame (`args->di`), not in the
  kprobe's own `regs` (which holds the frame pointer).
- The module-list walk races with concurrent module load/unload
  (`module_mutex` is not exported). It is safe (single pass, preemption
  disabled, hard-capped at 1024 entries) but a worst-case snapshot may
  contain a torn entry or miss a module being unloaded at that instant.
- `ac_policy` is read-only at runtime (module param, mode 0600): bit 0 = kill
  ptrace offenders (default on). Use `sudo insmod anticheat.ko ac_policy=0`
  to log-and-deny only.
- `lock` pins the module globally, not per-fd: the pin intentionally survives
  the locking process exiting or crashing (that is the point of the panic
  button). If the locking daemon crashes or is killed without unlocking,
  run `sudo ./anticheat unlock` from any privileged shell — it balances the
  global count and releases the reference so `rmmod` succeeds again.
- `CAP_SYS_ADMIN` is rechecked on every ioctl, not just at `open()` — a
  process that opens the device privileged and later drops privileges (a
  normal pattern), or one that receives the fd via `SCM_RIGHTS` or an
  inherited `exec()`, does not retain access once it's no longer
  privileged. `test/priv_drop_test.c` proves this directly: it opens the
  device as root, drops all privileges on the same process while keeping
  the fd open, and confirms the next ioctl is rejected with `-EPERM`
  (`sudo ./test.sh` runs it as part of the live suite).
- ptrace denial works on the standard `__x64_sys_ptrace` / `__ia32_sys_ptrace`
  entries. A cheat that invokes the `ptrace` functionality through other
  kernel paths (e.g., `process_vm_readv` on an attached victim) is out of
  scope for v1.
- Protected pids are matched via the caller's pid namespace. Games running in
  the init namespace work as expected; containerized targets need matching
  namespace awareness (future work).
- kprobes require `CONFIG_KPROBES` / `CONFIG_KALLSYMS_ALL` (both enabled on
  this kernel). If a probe cannot be registered the module still loads and
  logs the limitation.
- Anonymous-executable detection (`AC_EV_ANON_EXEC`) flags *presence*, not
  *content* — it has no signature scanning and cannot tell injected shellcode
  from a legitimate JIT engine (V8, .NET, JVM) mapping freshly-generated
  machine code the same way. The baseline-delta design (alert only on
  growth after a pid is first observed) keeps `vdso`/`vvar` quiet, but a
  JIT-heavy protected process will still show a legitimately growing count
  over its lifetime — this is a detection *signal* to correlate with other
  evidence, not a standalone verdict. Per-pid allowlisting for known
  JIT-using binaries is future work.
- Self-protection (the daemon registers its own pid on startup) only stops
  ptrace-based attacks, via the same kprobe hook everything else uses. It
  does not stop `SIGKILL` from a root-privileged attacker — nothing in this
  design can, without a much larger effort to hide/harden the daemon process
  itself, which brings its own detection-evasion tradeoffs.

## Files

```
Makefile                 build (module + daemon + mock), install/uninstall
README.md                this file
.github/workflows/ci.yml CI: userspace build + mock suite, module smoke build
test.sh                  end-to-end live test (root)
diag.sh                  root diagnostics (dmesg, discovery, module walk)
test/mock_anticheat.c    LD_PRELOAD mock of /dev/anticheat (no-root tests)
test/mock_test.sh        mock test suite: `make test-mock`
test/priv_drop_test.c    live test: proves ac_ioctl() rechecks CAP_SYS_ADMIN
                         (root, real module -- run via test.sh)
src/anticheat.h          shared ioctl ABI
src/anticheat_module.c   the kernel module
src/anticheat_daemon.c   userspace daemon + CLI
src/sha256.{c,h}         SHA-256 for integrity baselines
```

## Security & ethics

This is defensive security software. Use it only on systems you own or are
authorised to protect. It does not contain any code to bypass, disable, or
defeat other protections.
