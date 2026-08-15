# Threat model

This is a single place stating the adversary this project defends against,
what's explicitly out of scope, and what "production-ready" does and
doesn't claim today. Every individual limitation named here is already
documented inline where the relevant code lives (mostly in README's
"Design notes & limitations" and the render-hook/LD_PRELOAD sections) —
this doc compiles them into one place rather than introducing anything
new.

## Adversary

Root shows up on both sides of this model, in two different roles that
must not be conflated:

- **Trusted root — the operator.** Loading `anticheat.ko`, running the
  daemon, and calling its ioctls (`protect`, `lock`, `scan`, ...) all
  require root/`CAP_SYS_ADMIN` themselves. That's assumed trusted
  throughout this document — it's the prerequisite for running the tool
  at all, the same way `sudo make install`/DKMS's Secure Boot signing
  already assume the person running them is legitimate. Nothing here
  defends against the machine's own administrator; if the operator is
  the adversary, no client-side or kernel-side tool can help.
- **The attacker — a cheat author with ordinary user-level access to
  their own machine.** This is the realistic adversary the project
  actually defends against: the same starting privilege as any other
  process the player can run, not someone who already has kernel-level
  code execution equal to or greater than `anticheat.ko`'s own. Most
  detections here don't check the *caller's* privilege at all — the
  ptrace kprobe, syscall-table integrity check, and memory scans all run
  in-kernel regardless of who's asking — so an attacker who escalates to
  root *userspace* privilege (e.g. via `sudo`) *after* `anticheat.ko` is
  already loaded and protecting a process does not, by itself, defeat
  those checks. Two capabilities are explicit exceptions to that,
  already called out below: `SIGKILL`-ing the daemon outright, and
  unloading the module if it isn't `lock`ed. Loading their own kernel
  module is also within this model's actual detection surface — module
  enumeration exists specifically to catch a cheat's own loaded module
  running alongside `anticheat.ko` — but a cheat module capable of
  operating at full, undetectable kernel privilege (a genuine rootkit,
  not just a hidden LKM) crosses into the next case.

**Out of scope: an attacker who already has kernel-privileged code
execution** — via a sufficiently sophisticated kernel module of their
own, an unrelated kernel exploit, or any other means. See "Explicitly
out of scope" below. This is a fundamental limit, not a gap specific to
this project: no purely in-kernel detector can defend against an
adversary operating at its own privilege level or higher.

Everything this project detects follows from the middle case above:
syscall-table hooks, hidden kernel modules, ptrace attaches, RWX/anon-exec
memory regions, runtime code patching, and render-API inline hooks are
all things a user-level-to-root-userspace attacker can attempt against a
protected process without yet having kernel-level code execution of
their own.

## Trust boundaries

- **`anticheat.ko`** — ring 0, trusted, the actual root of trust. If this
  is compromised or was never loaded, nothing else in the system holds.
- **The daemon (`anticheat`/`start`)** — userspace, runs as root,
  self-protects on startup (registers its own pid so it can't be
  ptrace-attached the same way a protected game process can't be) but is
  otherwise an ordinary process.
- **The protected process** — the thing being defended; untrusted from
  the module's point of view until proven otherwise by the checks above.
- **`server/ac_server.py`** — a separate trust domain regardless of where
  it's physically deployed. The README documents it running on localhost,
  on the LAN, or on a genuinely separate host as equally supported —
  "separate trust domain" describes the *authorization* boundary (it
  never trusts a report as ground truth, no matter who's asking), not a
  requirement to run it on different hardware. It receives reports from
  daemon instances it does not control and treats every report as an
  **unverified claim**, never as ground truth (see "Reports never
  auto-ban" in the README) — this is deliberate: the daemon runs on the
  exact machine a cheat author controls, so a report can be wrong,
  spoofed, or replayed, whether the server happens to be co-located on
  that same machine or not.

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

## What "production-ready" claims today

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

Until those close, "production-ready" means: safe to run in the
deployment this project has actually been built and tested against — a
machine you control, with the server on localhost or on a trusted,
isolated LAN, or behind the documented TLS reverse proxy for anything
else. That LAN case is narrower than it sounds: `ac_server.service` runs
`ac_server.py` with no TLS, so `Authorization: Bearer` keys go out in
plaintext — fine on a network with no untrusted parties able to observe
traffic, not fine on a LAN an attacker (or just another tenant) can
sniff or sit on-path of, where the reverse proxy is required, not
optional. None of this is yet a claim that this is safe to distribute to
end users' machines you don't control, or to expose to the open internet
without the operator's own additional review.
