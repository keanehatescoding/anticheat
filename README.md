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
└──────────────┬─────────────┘        │  · protected process registry│
               │ HTTP (opt-in,        │  · ptrace denial (kprobe)    │
               │  AC_REPORT_URL)      │  · fork/exec/exit tracing    │
               ▼                      │  · VMA scan (RWX + anon-exec)│
┌────────────────────────────┐        │  · event ring buffer         │
│  server/ac_server.py       │        └──────────────────────────────┘
│  (optional, separate host) │
│  · report ingestion        │
│  · ban list (SQLite)       │
└────────────────────────────┘
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
anticheat protect --pid N --ns-of REFPID   protect a pid namespace-relative
                                      to host-pid REFPID (see below)
anticheat protect --pid N --jit      mark as a known JIT-using binary
                                      (anon-exec growth logs, isn't auto-reported)
anticheat protect --comm NAME [--jit]   protect by comm name
anticheat unprotect --pid N
anticheat list                       list protected processes
anticheat scan --pid N               VMA scan, RWX + anon-exec detection
anticheat scan --pid N --hash --save    create memory-integrity baselines
anticheat scan --pid N --hash --check   verify runtime memory vs baseline
anticheat scan --pid N --check-hooks    Vulkan + GLX/OpenGL + EGL present-call hook check
anticheat scan --pid N --check-preload  LD_PRELOAD check (heuristic, not a verdict)
anticheat scan --pid N --check-vklayers Vulkan-layer env var check (heuristic, not a verdict)
anticheat scan --pid N --check-implicit-layers  implicit Vulkan-layer manifest check (heuristic)
anticheat syscalls                   verify syscall table integrity
anticheat modules                    detect modules hidden from /proc/modules
anticheat events [--watch]           dump security events
anticheat lock | unlock              pin / unpin the kernel module
anticheat start [--foreground]       monitoring daemon (events + periodic checks)
```

The daemon (`start`) protects its own pid on startup (so it can't just be
ptrace-attached or debugged away — see `AC_IOCTL_ADD_PROC` in `cmd_start`),
polls security events, re-checks syscall integrity every 5 s, module
visibility every 10 s, scans protected processes every 30 s (override via
`AC_SCAN_CHECK_INTERVAL`) for RWX mappings and for anonymous-executable
mappings appearing *after* a process was first observed (each pid's
baseline count is recorded on first scan;
`vdso`/`vvar` never trigger since they're present from process start and
never change — see `anon_baseline_check()`), and every 60 s re-hashes every
protected process's executable, file-backed mappings against whatever
baseline was already saved for them via `--hash --save`
(`check_baselines_periodic()`). It never creates a baseline on its own —
only an operator running `--save` on a binary they've already verified
clean does that — so a process with no saved baseline is silently skipped,
not auto-trusted. Every 30 s (override via `AC_RENDER_HOOK_CHECK_INTERVAL`)
it also re-checks every protected process for the same
`vkQueuePresentKHR` inline-hook this checks for on demand via `scan
--check-hooks` (`check_render_hooks_periodic()`) — silent unless it
actually finds a hook, same as the baseline/anon-exec checks, since a
clean result every cycle for every protected process would be log noise
rather than signal. Every 10 s (override via
`AC_LD_PRELOAD_CHECK_INTERVAL` / `AC_VK_LAYER_CHECK_INTERVAL` respectively)
it also checks each newly-protected process's `LD_PRELOAD`
(`check_ld_preload_periodic()`) and Vulkan-layer-activation environment
variables (`check_vk_layers_periodic()`) — see below; unlike the other
periodic checks these warn **at most once per pid**, since
`/proc/<pid>/environ` is fixed at `exec()` time and re-warning about the
same unchanging values every cycle forever would be pure noise. Every
30 s (override via `AC_IMPLICIT_LAYER_CHECK_INTERVAL`) it also re-scans
each protected process's *implicit* Vulkan layer manifests
(`check_implicit_layers_periodic()`) — see below; this one re-checks every
cycle rather than once per pid (manifest files can change while a session
is running, unlike environ), but only warns on a *growth* in the
unrecognized-layer count for a pid, same baseline-delta design as
anon-exec detection above. Alerts go to syslog (`LOG_AUTH`) and
`/var/log/anticheat.log`.

Baselines are stored in `/var/lib/anticheat/baselines/` (one SHA-256 per
file-backed executable mapping; override the directory with the
`AC_BASELINE_DIR` environment variable). `--check` reports mappings whose
runtime content differs from the baseline — a strong signal of runtime code
patching.

### Render-hook detection (Vulkan + GLX/OpenGL + EGL present-call)

`scan --pid N --check-hooks` checks for the classic ESP/overlay/aimbot
technique of inline-hooking the graphics API's frame-present call. It
checks **every** rendering API a Linux game is realistically using:
`vkQueuePresentKHR` in `libvulkan.so` (native Vulkan games, and Proton
D3D9/10/11/12 titles too, since DXVK/VKD3D-Proton translate D3D calls down
to Vulkan), `glXSwapBuffers` in `libGL.so` (native OpenGL games, and older
Proton titles still on wined3d's GL backend instead of DXVK), and
`eglSwapBuffers` in `libEGL.so` (anything using EGL instead of GLX to
create its GL/GLES context — increasingly common under Wayland, and for
GLES-based engines). A process only using one or two of the three cleanly
reports the rest as "not loaded", not an error — most processes only ever
have one mapped.

This needs no signature database and can't go stale across distros or
driver/loader versions: the daemon reads the *exact same on-disk file*
the target process has mapped, parses its ELF section headers directly to
find the target symbol's file-relative offset, and compares its bytes
against the same offset read from the target's memory (`/proc/<pid>/mem`,
the same mechanism `--hash` already uses — see
`compare_render_symbol()`/`elf_find_symbol_offset()` in the daemon, and
`render_hook_status_for()`/`find_lib_by_basename()` for the
library/symbol-parameterized lookup all three APIs share). A classic
inline/trampoline hook — patching the function's bytes to jump into
injected code — changes those bytes; an unmodified process matches
byte-for-byte. The reference copy is whatever the target itself is
currently using, read fresh at check time, so there's nothing to maintain
as Mesa/NVIDIA driver or Vulkan loader versions change.

**Compares the symbol's whole declared length, not a fixed guess.** The
ELF symbol table carries each function's actual size (`st_size`); the
check reads and compares exactly that many bytes (clamped to
`[AC_HOOK_CHECK_MIN_BYTES, AC_HOOK_CHECK_MAX_BYTES]` = `[8, 512]`, or a
32-byte default if a symbol's size is unavailable) instead of a fixed
window that could either miss a hook placed further into a longer
function, or — as a real earlier version of this check did — read a few
bytes *past* a short one into whatever follows it. Verified against real
data before relying on it: `glXSwapBuffers` is 17 bytes on a real system
(smaller than the old fixed 32-byte window), `vkQueuePresentKHR` is 81.
`test.sh` proves the actual capability this unlocks, not just that
byte-0 hooks still work: it self-hooks `vkQueuePresentKHR` at offset 40
— past where the old fixed window would have looked — and confirms the
scan still flags it. `st_size` comes from the same
attacker-influenceable file as everything else this check reads, so it's
bounded, never trusted as authoritative on its own.

Deliberately never `dlopen()`s that file, and this isn't a style
preference: the path is resolved through the *target's own* mount
namespace (see below), which isn't a trusted input — a process can be set
up so an attacker controls what's mounted at the path the kernel reports
for it. `dlopen()` would run that file's constructors as root. The ELF
symbol table is parsed with plain `pread()` instead, so no code from an
untrusted file is ever executed — verified directly, not just reasoned
about: a constructor planted in a file at an attacker-controlled
mount-namespace path does not run when the check reads it.

Known blind spot, not a bug: this catches in-place byte patching of the
exported function, not a cheat that intercepts the call via `LD_PRELOAD`
symbol interposition or a malicious Vulkan layer — those never touch the
target symbol's actual bytes (neither GLX nor EGL has a layer system, so
that specific gap is Vulkan-only; LD_PRELOAD interposition applies to all
three APIs equally). `--check-preload` and `--check-vklayers` below
partially cover both cases, as heuristic signals, not verdicts — see the
environment-variable-only caveat on the Vulkan-layer one specifically.
Also known and not yet covered: hooks placed inside DXVK/VKD3D's own
translation-layer code (rather than in `libvulkan.so` itself) or in the
Vulkan loader's internal dispatch table (rather than the exported symbol)
are both invisible to a check that only verifies the exported symbol's own
bytes. A symbol with no size info in the ELF symbol table (stripped or
unusual builds) falls back to the old 32-byte default window, so a
sufficiently deep detour into an unsized symbol could still be missed.

**Mount-namespace aware.** The kernel-side VMA scan reports a path
string for the target's library; opening that string directly from the
daemon's own (host) mount namespace would trust that whatever exists
there is the same file the target actually has mapped, which isn't
guaranteed for a process in a container/sandbox with a private
bind-mount at that path (Flatpak, Steam Runtime). The daemon instead
opens it through `/proc/<pid>/root/<path>`, which the kernel resolves
exactly as the target process itself sees it — for a target sharing the
daemon's own namespace (the common case), `/proc/<pid>/root` is just
`/`, so this is a strict correctness fix with no downside there. Verified
empirically, not assumed: without this, a private bind-mount shadowing
an otherwise-identical host path silently produced the wrong reference
bytes (or an unopenable file) and the check could only report
"inconclusive"; through `/proc/<pid>/root/` it correctly loads the real,
target-visible library and compares it properly. `test/mount_ns_probe.c`
+ a real `unshare --mount` namespace in `test.sh` exercise this directly
against a real loaded module, not just in theory.

`scan --check-hooks` is the on-demand, human-facing form; the same
detection also runs automatically every 30 s against every protected
process from the `start` monitoring loop (see above) — a hook installed
mid-session gets caught without anyone running a manual scan.
`test/render_hook_test.c` proves the detection itself works (self-hooks a
given library/symbol pair — `vkQueuePresentKHR`/`libvulkan.so.1` by
default, or any other pair via `argv[1]`/`argv[2]`, e.g.
`glXSwapBuffers`/`libGL.so.1` or `eglSwapBuffers`/`libEGL.so.1` — in a
throwaway process), and `test.sh` exercises all three APIs separately: the
one-shot `scan --check-hooks` path and the periodic monitoring-loop path,
against a real loaded module, for each of Vulkan, GLX/OpenGL, and EGL.

### LD_PRELOAD and Vulkan-layer detection

`scan --pid N --check-preload` and `scan --pid N --check-vklayers` both
read a process's `/proc/<pid>/environ` for specific variables and report
them if set. Together these close the two documented render-hook blind
spots above: a cheat that intercepts `vkQueuePresentKHR` via library
interposition or a Vulkan layer, rather than inline-patching bytes, never
shows up in the render-hook check, since neither ever touches the target
function's actual code — but both require setting something in the
process's environment to get loaded in the first place, with one
exception, closed separately below: an *implicit* Vulkan layer needs no
environment variable at all.

`--check-preload` looks for `LD_PRELOAD`. `--check-vklayers` looks for
`VK_INSTANCE_LAYERS`/`VK_LOADER_LAYERS_ENABLE` (force-enabling a layer by
name — the older and current Vulkan loader mechanisms respectively) and
`VK_LAYER_PATH`/`VK_ADD_LAYER_PATH` (pointing the loader at additional
manifest directories, which is how an attacker's own layer becomes
discoverable at all) — both share one internal primitive
(`ac_read_environ_vars()`) that reads `environ` once and checks every
candidate name in the same pass, rather than reopening the file per
variable.

`environ` is read directly rather than trusted from anywhere the process
itself could have relabeled at runtime: it's populated once by the kernel
at `exec()` and never updated by the process's own later `setenv()`
calls, so this reflects what the process actually launched with.

**Deliberately heuristics, not verdicts.** `MangoHud`, `gamemode`,
`gamescope`, and plenty of other completely legitimate tools use both
`LD_PRELOAD` and Vulkan layers routinely — MangoHud's overlay *is* a
Vulkan layer. A game running with an FPS overlay or a compatibility shim
is normal, not suspicious, and both checks say so explicitly in their
output rather than framing every hit as an alert. In the periodic
monitoring loop both log at `LOG_WARNING`, not `LOG_ALERT`/`LOG_CRIT` —
which matters beyond just log severity: the ban-pipeline auto-report hook
in `logmsg()` only fires at `LOG_ALERT`/`LOG_CRIT`, so a detection here is
visible to an operator in the log but does **not** by itself accumulate as
a report against a `client_id`. It's a fact for a human reviewing other
evidence to correlate against, the same design instinct as anon-exec
detection flagging presence rather than passing judgment.

`test.sh` exercises both checks the same way: a negative case (a plain
victim process reports nothing set) and a positive case (a victim
launched with the relevant variable set to something harmless — for
`LD_PRELOAD`, its own libc, inert since the dynamic linker already loads
it regardless; for `VK_LAYER_PATH`, `/tmp`, since the check only reads the
variable's value and never invokes the Vulkan loader) through both the
one-shot `scan` path and the periodic monitoring-loop path, against a real
loaded module.

### Implicit Vulkan-layer manifest detection

`--check-vklayers` only covers the environment-variable activation path.
An *implicit* Vulkan layer manifest dropped directly into one of the
loader's default search directories is auto-enabled with no environment
variable involved at all — exactly what `scan --pid N --check-implicit-layers`
closes, by directly replicating what the Vulkan loader itself does:
enumerate the same directories it searches — both the target user's own
per-user paths (`~/.config/vulkan/implicit_layer.d/`,
`~/.local/share/vulkan/implicit_layer.d/` — the more realistic injection
vector, since writing there needs no elevated privilege at all) and the
system-wide ones (`/etc/vulkan/implicit_layer.d/`,
`/usr/share/vulkan/implicit_layer.d/`, and their `/usr/local/...`
counterparts) — parse each `*.json` manifest found, and cross-reference
against the target's own `environ` (reusing `ac_read_environ_vars()`) to
determine whether each discovered layer is actually active for that
specific process right now: present, and not disabled via its own
`disable_environment` variable (if the manifest defines one).

Since the daemon runs as root but the target runs as its own user, the
per-user paths are resolved against *that user's* home directory — read
from `/proc/<pid>/status`'s `Uid:` line, then `getpwuid_r()` — not root's
own `$HOME`, which would silently miss the entire per-user vector.

**Manifests are parsed, never executed, and never trusted as well-formed.**
This is exactly the kind of file the check exists to be suspicious of, so
`json_extract_string()`/`json_extract_disable_env()` are a small, targeted
extractor for the specific fields this schema needs (`name`,
`library_path`, and the single key inside `disable_environment`'s nested
object) — not a general JSON parser, bounded and defensive throughout, the
same posture as `elf_find_symbol_offset()` in the render-hook check.
Nothing from a discovered layer's `library_path` is ever opened or loaded,
only reported. Verified directly, not just reasoned about: a truncated,
syntactically-broken manifest and 500 bytes of raw random data dropped in
the same directory don't crash or hang the check, they're just skipped.

**A small, explicitly non-exhaustive allowlist** of common legitimate
overlay/vendor layer name prefixes (MangoHud, `vkBasalt`, RenderDoc,
LatencyFleX, Steam's overlay and Fossilize layers, and the GPU-vendor/Khronos
layers Mesa/NVIDIA/AMD/Intel ship) keeps the periodic check from warning on
every machine that happens to have a normal Linux gaming setup — verified
against a real one: this machine's actual installed Steam and Mesa layer
manifests were used to catch (and fix) a case-sensitivity bug in the
allowlist before it shipped, not just a synthetic test. This is a
name-based heuristic, not a security boundary — a cheat could name its own
layer `VK_LAYER_MANGOHUD_overlay` to blend in — so the one-shot CLI check
reports every active layer regardless of the allowlist, precisely so a
human reviewing it isn't relying on the name check alone.

**Periodic check re-scans every cycle, not once per pid.** Unlike the
environ-based checks above, manifest files live on disk and can change
while a session is already running, so treating environ's "fixed at
exec()" logic as an excuse to check once wouldn't be correct here. Instead
it reuses `anon_baseline_check()`'s exact design: whatever unrecognized
layers are already active the first time a pid is observed become that
pid's baseline, silently, and only a *later increase* — a new
unrecognized layer appearing mid-session — is the signal worth a
`LOG_WARNING`. `test.sh` proves this baseline-then-growth behavior
directly: protects a victim with no manifest present yet, confirms the
periodic check logs nothing on its first pass, drops the manifest in
while the daemon is still running, and confirms the very next cycle logs
it.

`test.sh` also proves the full mechanism against a real user's real
`$HOME` (via `$SUDO_USER`, since this all needs to run as root but
resolve a *different* user's paths to mean anything): the negative case,
the positive case, `disable_environment` suppression, and the periodic
baseline/growth behavior, all against a real loaded module.

### Ban-pipeline reporting (server-side)

Everything above is client-side detection with nowhere for the result to
go. `server/ac_server.py` is a minimal report-ingestion + ban-lookup
service closing that gap — deliberately not an enforcement point, since
this project has no game or matchmaking server to enforce anything against;
it's the API a real one would call.

**Daemon side.** Opt-in via two environment variables passed to
`anticheat start`:

```
AC_REPORT_URL=host:port    # plain HTTP, no scheme -- see TLS note below
AC_REPORT_KEY=<report-key>
```

Unset (the default), reporting is a complete no-op — no network activity
at all. When set, every detection the monitoring loop already logs at
`LOG_ALERT`/`LOG_CRIT` (syscall hook, hidden module, ptrace deny, baseline
tamper, anon-exec growth, render hook — see `logmsg()`) is also POSTed to the server as
`{client_id, event_type, detail, ts}`. `client_id` is `/etc/machine-id`
(falls back to the hostname). A hung or unreachable server can't stall
detection: connect/send/receive are all bounded to 3s (`ac_connect_timeout()`
does a non-blocking connect + `poll()`, since `SO_SNDTIMEO`/`SO_RCVTIMEO`
alone don't bound `connect()` itself on Linux — a host that blackholes SYN
packets rather than refusing them would otherwise hang for the kernel's TCP
retry timeout, not 3s), and a failed or partially-sent report only logs a
local warning, never blocks or crashes the monitoring loop. DNS resolution
via `getaddrinfo()` is not itself timeout-bounded — configure
`AC_REPORT_URL` as a literal IP if that matters for your deployment.

**Server side.** Stdlib-only Python (`http.server` + `sqlite3`, zero
third-party dependencies) with two separate bearer-token tiers:

```
POST /report            report-key   -- what the daemon uses
POST /ban               admin-key    -- {client_id, reason}
POST /unban              admin-key   -- {client_id}
GET  /banned/<id>        admin-key   -- what a game server would call
GET  /reports/<id>       admin-key   -- raw reports for a human to review
```

```
AC_SERVER_REPORT_KEY=<report-key> AC_SERVER_ADMIN_KEY=<admin-key> \
    ./server/ac_server.py --host 127.0.0.1 --port 8787 --db ac_server.db
```

Both keys are required at startup — it refuses to run with no auth
configured rather than defaulting to open. Client IDs are validated
against a bounded alnum/`.`/`_`/`-` pattern before touching the database;
report bodies are capped at 4 KiB.

**Reports never auto-ban.** A report is a client-side daemon's unverified
claim about itself, running on the exact machine a cheat author controls —
it can be wrong, or spoofed, or replayed by someone probing for false
positives. Accumulated reports are for a human to review (`GET
/reports/<id>`) before deciding to `POST /ban`; auto-banning on
unverified client input would turn a bug or a spoofed report into a
banned real player, which is a worse failure mode than a slower
human-in-the-loop pipeline. This mirrors the same design instinct as
`--hash --save` never auto-creating baselines above.

**Rate limited.** Every endpoint (not just `/report`) is limited per
source IP — `--rate-limit`/`--rate-window`, default 60 requests per 60s —
so a compromised or misbehaving client can't flood the ingestion pipeline
or the SQLite DB, and an attacker can't freely hammer `/banned/<id>` to
enumerate client IDs or brute-force the admin key. It's a simple
fixed-window counter (allows a brief double-rate burst right at a window
boundary), not built for distributed scale — enough to bound abuse
against a single small process, which is the deployment this targets.

**No TLS.** This is plain HTTP, meant for localhost/LAN or behind a
reverse proxy that terminates TLS for anything reachable over an
untrusted network — not a hardened, internet-facing service as shipped.
That's a real gap for a production deployment, not an oversight papered
over: this is the minimal version of the pipeline, not the finished one.
If you do put it behind a reverse proxy, pass `--trust-proxy` so the rate
limiter and the `source_addr` recorded on every report use the real
client IP (the last, proxy-authored hop of `X-Forwarded-For`) instead of
the proxy's own address — off by default, since trusting that header
from anything other than a proxy you control would let a client spoof
both.

**Fails closed, not silently.** An uncaught exception in a request
handler (a real disk-full or locked-database error, not just a bad
request) returns a clean `500`, not a dropped connection with no
response — and a client disconnecting mid-response is handled quietly
rather than logged as if it were a bug. `SIGTERM` (what `systemd stop`
and most orchestrators send by default) triggers the same clean shutdown
as Ctrl-C already did; previously only `SIGINT` was handled; and
`SIGTERM`'s default disposition would have hard-killed the process with
no Python cleanup at all.

**Deployment (systemd).** `server/ac_server.service` is a ready-to-copy
unit — dedicated non-root user, `Restart=on-failure`, and a handful of
standard systemd sandboxing directives (`ProtectSystem=strict`,
`NoNewPrivileges=true`, etc. — the process only ever touches its own DB
file and the network). It relies on the `SIGTERM` handling above for a
clean stop/restart, so no `KillSignal=` override is needed. See the
comment block at the top of the file for the install steps.

**TLS.** There's no TLS in `ac_server.py` itself (see "No TLS" above) —
put a reverse proxy in front for anything beyond localhost/LAN and pass
`--trust-proxy` so rate limiting and each report's recorded `source_addr`
reflect the real client rather than the proxy. A minimal Caddy config
(automatic cert via Let's Encrypt):

```
ac.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

or nginx, terminating TLS and forwarding with `X-Forwarded-For` appended
(the default behavior of `proxy_add_x_forwarded_for`, which `--trust-proxy`
depends on — see `_client_ip()`'s handling of the header's *last* hop):

```
server {
    listen 443 ssl;
    server_name ac.example.com;
    ssl_certificate     /etc/letsencrypt/live/ac.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ac.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**Key rotation.** `--report-key`/`--admin-key` (and their `AC_SERVER_*`
env-var equivalents) are static for the life of the process — there's no
way to change them without a restart. For a restart with zero dropped
requests, each tier also accepts one additional "-old" key
(`--report-key-old`/`--admin-key-old`, or `AC_SERVER_REPORT_KEY_OLD`/
`AC_SERVER_ADMIN_KEY_OLD`):

1. Restart with the *new* key as `--report-key`/`--admin-key` and the
   *current* (about-to-be-retired) key as `--report-key-old`/
   `--admin-key-old`. Both are accepted during this window.
2. Roll every daemon (`AC_REPORT_KEY`) and admin client over to the new
   key.
3. Restart once more without the `-old` flags to finish the rotation.

A key can never be valid for both tiers at once, `-old` included — the
server refuses to start if e.g. `--report-key-old` collides with
`--admin-key` (see the startup check next to `report_keys & admin_keys`).

**Backups.** The `bans` table is the one piece of state that actually
matters operationally (`reports` is useful history but not
authoritative). SQLite's own online backup handles this without stopping
the server:

```sh
sqlite3 /var/lib/anticheat/ac_server.db ".backup /var/lib/anticheat/backups/ac_server-$(date +%F).db"
```

Run that from cron/a systemd timer; WAL mode (already enabled — see
`Store._connect()`) means this doesn't block concurrent reads/writes
while it runs.

`server/test_server.sh` exercises the full server (report → review → ban
→ query → unban → query) with no root and no kernel module, and CI runs
it on every push. `test.sh`'s baseline-tamper check additionally starts a
real `ac_server.py` instance and confirms the daemon's report actually
arrives over real HTTP — proof the two sides' wire format agrees, not
just that each compiles.

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

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the adversary this defends
against, what's explicitly out of scope, and what "production ready"
claims today — a single-place compilation of the per-feature limitations
below plus the ones documented earlier in this file (render-hook blind
spots, LD_PRELOAD/Vulkan-layer heuristics, the ban pipeline's no-auto-ban
design).

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
- Protected pids are matched via the caller's pid namespace by default:
  `protect --pid N` resolves `N` as seen by the daemon itself (normally the
  host/init namespace). This is already correct, with no extra flags, for
  the common case of a sandboxed/containerized game (e.g. Steam's
  pressure-vessel/bwrap) — `/proc` viewed from the daemon's ancestor
  namespace already shows host-visible pids for descendant-namespace
  tasks, and `protect --comm NAME` matches on that view directly. The
  remaining gap is narrower: when a caller only has a *raw in-namespace*
  pid number (no usable comm), `protect --pid N --ns-of REFPID` resolves
  `N` within the pid namespace that host-pid `REFPID` lives in, given any
  other host-resolvable pid known to be in that same namespace as a
  reference point. Prefer `--comm` when a comm name is available; reach
  for `--ns-of` only when it isn't.
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
  evidence, not a standalone verdict. `protect --pid N --jit` (or `--comm
  NAME --jit`) marks a specific protected pid as a known JIT-using binary
  at protect time — per-pid, not by comm name or path, since either of
  those could be spoofed by a cheat process to gain immunity, while
  `protect` itself already requires `CAP_SYS_ADMIN`. Growth on an
  allowlisted pid is still logged (at `LOG_WARNING`, mirroring how
  LD_PRELOAD/Vulkan-layer detection avoids the ban pipeline below), just
  not auto-reported — it's a signal an operator can still see, not one
  that gets silently dropped. Fork inheritance extends this the same way
  it already extends protection itself: a JIT-marked process's children
  inherit the flag too.
- Self-protection (the daemon registers its own pid on startup) only stops
  ptrace-based attacks, via the same kprobe hook everything else uses. It
  does not stop `SIGKILL` from a root-privileged attacker — nothing in this
  design can, without a much larger effort to hide/harden the daemon process
  itself, which brings its own detection-evasion tradeoffs.

## Files

```
Makefile                 build (module + daemon + mock), install/uninstall
README.md                this file
THREAT_MODEL.md          adversary, explicit non-goals, production-readiness status
.github/workflows/ci.yml CI: userspace build + mock suite, module smoke build
test.sh                  end-to-end live test (root)
diag.sh                  root diagnostics (dmesg, discovery, module walk)
test/mock_anticheat.c    LD_PRELOAD mock of /dev/anticheat (no-root tests)
test/mock_test.sh        mock test suite: `make test-mock`
test/priv_drop_test.c    live test: proves ac_ioctl() rechecks CAP_SYS_ADMIN
                         (root, real module -- run via test.sh)
test/render_hook_test.c  live test: self-hooks vkQueuePresentKHR or (given
                         args) glXSwapBuffers, proves `scan --check-hooks`
                         detects it (root, real module -- run via test.sh)
test/mount_ns_probe.c    live test: proves render-hook detection resolves a
                         target's real mount-namespace view of a path, not
                         the host's (root, real module -- run via test.sh)
src/anticheat.h          shared ioctl ABI
src/anticheat_module.c   the kernel module
src/anticheat_daemon.c   userspace daemon + CLI
src/sha256.{c,h}         SHA-256 for integrity baselines
server/ac_server.py      ban-pipeline server: report ingestion + ban lookup
server/ac_server.service systemd unit for ac_server.py (see "Deployment" above)
server/test_server.sh    server test suite (no root): `./server/test_server.sh`
```

## Security & ethics

This is defensive security software. Use it only on systems you own or are
authorised to protect. It does not contain any code to bypass, disable, or
defeat other protections.
