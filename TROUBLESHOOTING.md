# Troubleshooting: crashes, panics, and safe recovery

This covers what to do if `anticheat.ko` is suspected of causing a crash
or hang, and how to get it out of the boot path if it did. It does not
cover normal usage — see `README.md` for that.

## Recognizing anticheat as the cause

Every kernel-log line this module emits is prefixed `anticheat:`
(`pr_fmt` is set to `KBUILD_MODNAME ": "`, and the module's object name is
`anticheat.o`/`anticheat.ko`). After a crash, reboot and check:

```sh
journalctl -k -b -1 | grep -i anticheat   # previous boot's kernel log
# or, if journald isn't in use / didn't capture it:
dmesg | grep -i anticheat                 # only useful if the crash was
                                           # this boot and dmesg survived it
```

A hard panic (not just an oops) means the *current* boot's `dmesg` has
nothing from before the crash — you need either `journalctl -b -1`
(persistent journal, if `Storage=persistent` in journald's config) or a
real crash dump (see below).

These two are different claims — keep them separate:

**Module implicated** (this module is involved *somewhere*, not
necessarily its kprobes specifically): any frame in `anticheat_module.c`
at all, or `anticheat` in the "Tainted:" line's loaded-module list right
before the backtrace.

**A kprobe path specifically implicated** (all `pr_fmt`-prefixed, all in
`src/anticheat_module.c`):

- `ac_ptrace_pre` — the `__x64_sys_ptrace`/`__ia32_sys_ptrace` kprobe
- `ac_exit_pre` — the `do_exit` kprobe
- `ac_exec_pre` — the `__x64_sys_execve`/`__x64_sys_execveat` kprobes
- `ac_clone_ret` — the `kernel_clone` kretprobe (fork/exec inheritance)
- `ac_kill_worker` — the deferred `SIGKILL` of a ptrace offender, running
  in the `anticheat` workqueue rather than kprobe context (the only thing
  that workqueue is used for — everything else, including the VMA scan,
  runs synchronously in ioctl context, not deferred, so a VMA-scan crash
  would show up as "module implicated" above, not one of these names)

## Immediate steps

1. **Don't reload it yet.** If it caused a real crash, reloading the same
   binary against the same kernel will very likely reproduce it.
2. **Capture everything before touching anything else** — the full
   `journalctl -k -b -1` (or crash dump, below) output, `uname -r`,
   which install method was used (`make install`, DKMS via
   `scripts/dkms-install.sh`, or `install-deck`), and the exact command
   that was running or the exact `anticheat` CLI action in flight at the
   time (`protect`, `scan --hash --check`, `start`, etc. — check
   `/var/log/anticheat.log` for the last daemon-side line logged before
   the crash).
3. **Check `ac_policy`/`ac_verbose`.** If the module was loaded with
   non-default `module_param`s (`ac_policy`, `ac_verbose` — both
   `insmod`-time-settable, mode `0600`), note the values; they change
   which code paths actually ran.

## Keeping it from loading again

Nothing in this project auto-*loads* the module on boot, DKMS included —
worth being precise about, since it's easy to assume otherwise.
`AUTOINSTALL="yes"` in `dkms.conf` only makes DKMS automatically
*rebuild and install* `anticheat.ko` for each newly-installed kernel (via
the distro's `/etc/kernel/postinst.d/dkms` hook); it does not `modprobe`
or otherwise load the freshly-built module. `scripts/dkms-install.sh`
says so explicitly at the end of a fresh install: `load it with: sudo
modprobe anticheat` — that step is manual today, on every install and
every subsequent kernel upgrade alike.

So in the state this project ships in:

- **If you never load it again, it never runs again.** Whatever
  `insmod`/`modprobe` invocation loaded it the first time (by hand, or
  from a script/cron job you set up yourself) is the only thing that can
  load it again — check for exactly that, since this project provides no
  such mechanism on its own (no `/etc/modules-load.d/` entry, no
  `systemd` unit for the module itself, no `modprobe_on_install` in
  DKMS's `framework.conf`).
- **Blacklist it anyway, as a hard stop against forgetting:**

  ```sh
  echo "blacklist anticheat" | sudo tee /etc/modprobe.d/blacklist-anticheat.conf
  sudo depmod -a
  ```

  This makes any future `modprobe anticheat` — yours, a script's, or a
  future reintroduction of an autoload mechanism — fail loudly instead
  of silently succeeding. It has no effect on `insmod ./anticheat.ko`
  run directly, since that bypasses `modprobe`/`depmod` entirely; the
  blacklist is a safety net for the loading path this project's own
  instructions actually tell you to use, not a guarantee against every
  possible way to load a `.ko`.
- **To remove the DKMS registration entirely** (if installed via
  `scripts/dkms-install.sh`): `sudo dkms remove -m anticheat -v 1.0.0
  --all` (see `dkms.conf`'s `PACKAGE_VERSION`). This stops future
  rebuild-on-kernel-upgrade too, not just loading.

## Getting a real crash dump

`dmesg`/`journalctl` only help if the machine survived long enough to
flush logs — a hard panic often doesn't. If this is reproducible enough
to be worth debugging properly, set up `kdump` (Debian/Ubuntu:
`kdump-tools`; Fedora/RHEL: `kexec-tools`; Arch: `linux-crashdump` +
`crash`) *before* reproducing it again. That captures a real `vmcore`
(loadable with `crash` against the matching `vmlinux` +
`Module.symvers`/`anticheat.ko`) instead of whatever fragment of `dmesg`
made it to disk.

If EFI pstore is available (`/sys/fs/pstore` populated after a panic on
most UEFI systems with `CONFIG_PSTORE`/`CONFIG_EFI_VARS_PSTORE` enabled) and
kdump isn't set up, check there first — it's a much lower bar than
configuring kdump and often has at least the panic backtrace:

```sh
ls /sys/fs/pstore/
cat /sys/fs/pstore/dmesg-efi-*   # or whichever backend is in use
```

## Unloading cleanly (not after a crash — routine unload)

`ac_exit()` deregisters the misc device, unregisters every kprobe, clears
the protected-process table, and destroys the `anticheat` workqueue, in
that order — this is expected to be clean and is exercised by `test.sh`.
If `rmmod anticheat` hangs or fails:

- **`EBUSY`**: the daemon is holding `/dev/anticheat` open, or the module
  is explicitly `lock`ed (`anticheat lock`). Run `sudo ./anticheat unlock`
  first — this is safe even if the locking process already crashed or
  was killed, since `unlock` balances the pin count directly rather than
  requiring the original process to release it (this is the documented
  "panic button" recovery path — see README's "Design notes &
  limitations").
- **Hangs (not `EBUSY`, just doesn't return)**: this would mean a kprobe
  unregister or the workqueue drain is stuck — not a known/expected
  failure mode, and worth capturing a stack trace of the `rmmod` process
  itself (`cat /proc/<pid>/stack`) in addition to `dmesg` before filing a
  bug report.

## kprobes and kernel live-patching

kprobe addresses are resolved once, against the *currently running*
kernel's symbols, at `insmod` time (see `ac_register_kprobes()`) — this
module has no notion of "live" re-resolution, and doesn't need one under
normal operation (a kernel update takes effect on the *next* boot, by
which point the module would be freshly reloaded against the new
kernel's symbols anyway, not patched in place).

The one combination that's genuinely untested is a kernel live-patching
mechanism (`kpatch`, `livepatch`, `ksplice`, or similar) that redirects
one of the exact functions this module already hooks (`do_exit`,
`kernel_clone`, `__x64_sys_ptrace`/`__ia32_sys_ptrace`,
`__x64_sys_execve`/`__x64_sys_execveat`) out from under an already-loaded
kprobe. Nothing in this project has been verified against that
interaction either way. If you use kernel live-patching, treat combining
it with this module as unverified: reload `anticheat.ko` after applying
a livepatch that touches any of the functions above, and if you hit a
crash specifically correlated with a livepatch load, say so explicitly
when filing a bug report — it narrows the search enormously.

## Filing a bug report

Include, at minimum:

- `uname -r` and distro
- Install method (`make install` / DKMS / `install-deck`)
- `ac_policy`/`ac_verbose` values if non-default
- The full `journalctl -k -b -1` (or crash-dump backtrace) output, not
  just the last few lines
- The last `anticheat`/daemon action in flight (from `/var/log/anticheat.log`)
- Whether any kernel live-patching mechanism is in use
