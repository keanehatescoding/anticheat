# Threat model

This is a single place stating the adversary this project defends against,
what's explicitly out of scope, and what "production ready" does and
doesn't claim today. Every individual limitation named here is already
documented inline where the relevant code lives (mostly in README's
"Design notes & limitations" and the render-hook/LD_PRELOAD sections) —
this doc compiles them into one place rather than introducing anything
new.

## Adversary

The adversary this defends against is a **cheat author with ordinary
user-level access to their own machine** — the same privilege level as
any other process the player can run, not someone who already has root or
kernel-level code execution. That's the realistic threat for a game
anticheat: cheats run as the player's own unprivileged process (or
occasionally as a userspace process the player elevated themselves, e.g.
via `sudo`), not as a kernel module the player installed to attack their
own game.

Everything this project detects follows from that framing: syscall-table
hooks, hidden kernel modules, ptrace attaches, RWX/anon-exec memory
regions, runtime code patching, and render-API inline hooks are all things
an unprivileged-to-moderately-privileged userspace (or a cheat that
itself loads a *less* trusted kernel module) attacker can attempt against
a protected process.

## Trust boundaries

- **`anticheat.ko`** — ring 0, trusted, the actual root of trust. If this
  is compromised or was never loaded, nothing else in the system holds.
- **The daemon (`anticheat`/`start`)** — userspace, runs as root,
  self-protects on startup (registers its own pid so it can't be
  ptrace-attached the same way a protected game process can't be) but is
  otherwise an ordinary process.
- **The protected process** — the thing being defended; untrusted from
  the module's point of view until proven otherwise by the checks above.
- **`server/ac_server.py`** — a *separate* trust domain on a different
  host. It receives reports from daemon instances it does not control and
  treats every report as an **unverified claim**, never as ground truth
  (see "Reports never auto-ban" in the README) — this is deliberate: the
  daemon runs on the exact machine a cheat author controls, so a report
  can be wrong, spoofed, or replayed.

## Explicitly out of scope

These are known, accepted gaps — not oversights — each already noted
where the relevant code lives:

- **A kernel-privileged attacker.** Anything that already has ring-0 code
  execution (a more-privileged rootkit, a kernel exploit unrelated to
  this project) can defeat any in-band detector, including this one. No
  purely in-kernel detection scheme can defend against an adversary with
  equal or greater kernel privilege — this is a fundamental limit, not
  something more engineering effort closes.
- **`process_vm_readv`-based ptrace bypass.** ptrace denial only covers
  the standard `__x64_sys_ptrace`/`__ia32_sys_ptrace` entry points; a
  cheat reading a protected process's memory through
  `process_vm_readv` instead of `ptrace(2)` is out of scope for v1.
- **DXVK/VKD3D-internal hooks and Vulkan loader dispatch-table hooks.**
  Render-hook detection verifies the exported symbol's own bytes in
  `libvulkan.so`/`libGL.so`/`libEGL.so`; a hook placed inside a
  translation layer's own code, or in the loader's internal dispatch
  table rather than the exported symbol, is invisible to this check.
- **LD_PRELOAD symbol interposition and malicious Vulkan layers that
  never touch target bytes.** `--check-preload`/`--check-vklayers`/
  `--check-implicit-layers` are heuristic environment/manifest signals
  for a human to correlate, not verdicts — a sufficiently disguised
  layer (named to blend into the allowlist) or a preload library that
  does nothing detectably wrong isn't flagged by name alone.
- **Within-core-kernel-text redirects.** The syscall-integrity check
  flags entries pointing outside `[_stext, _etext)` or into a module;
  a hook that redirects one core-kernel syscall handler to another
  (e.g. `sys_read` → `sys_write`) stays inside kernel text and is not
  flagged — considered rare and also visually detectable by other means.
- **`SIGKILL` of the daemon by a root-privileged attacker.** Daemon
  self-protection only stops ptrace-based attacks via the same kprobe
  everything else uses; nothing here hides or hardens the daemon process
  itself against an attacker who already has root.
- **Anonymous-executable *content*.** `AC_EV_ANON_EXEC` flags presence of
  new anon-exec mappings, not their content — it can't distinguish
  injected shellcode from a legitimate JIT engine's freshly-generated
  code. The baseline-delta design and `--jit` allowlist reduce noise, not
  eliminate the ambiguity.
- **Report authenticity.** The server never auto-bans on a report alone —
  a report is one client's unverified claim about itself, reviewed by a
  human before any ban.

## Operating assumptions

- **x86-64 only.** Kprobe names (`__x64_sys_*`/`__ia32_sys_*`), the CI
  matrix, and the kernel-fetch job (`ARCH=x86_64`) all assume this.
  Porting to another architecture is unscoped work, not a bug.
- **`CONFIG_KPROBES`/`CONFIG_KALLSYMS_ALL`** must be enabled in the target
  kernel; if a probe can't register, the module still loads and logs the
  limitation rather than failing to load.
- **`kallsyms_lookup_name`/`module_mutex` are not exported** as of the
  targeted kernel floor (6.12+), so syscall-table discovery and the
  module-list walk are hand-implemented (kprobe-based address discovery;
  a preemption-disabled, 1024-entry-capped single-pass walk). Both are
  therefore racy against concurrent kernel-internal changes in a bounded,
  documented way (a worst-case snapshot may contain a torn entry or miss
  a module being unloaded at that instant) rather than wrong outright.
- **Secure Boot enrollment is a manual, one-time, interactive step** (MOK
  enrollment via the firmware's "MOK Management" screen) — nothing here
  can or should auto-approve a new trusted key.

## What "production ready" claims today

Everything above is a *design* boundary — accepted scope, not a bug to
fix. Separately, there are engineering gates not yet closed that this
doc does **not** paper over:

- The kernel module (`src/anticheat_module.c`) has had no independent
  security audit and no fuzzing of the ioctl interface — a memory-safety
  bug there is a ring-0 crash or exploit, a materially worse failure mode
  than a userspace bug anywhere else in this project.
- No KASAN/lockdep-instrumented boot testing has been done — current
  testing is functional (does the detection work), not adversarial
  (does the module survive malformed/racing input to its own interfaces).

Until those close, "production ready" means: safe to run in the
deployment this project has actually been built and tested against (a
machine you control, a server on localhost/LAN or behind the TLS reverse
proxy documented in the README) — not yet a claim that this is safe to
distribute to end users' machines you don't control, or to expose to the
open internet without the operator's own additional review.
