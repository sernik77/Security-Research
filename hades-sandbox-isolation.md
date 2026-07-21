# Hades Sandbox Isolation Assessment
### Namespace Escape, VFS Spoofing and Host IPC Exposure in a User-Facing Code Execution Environment

> *A coordinated-disclosure case study of isolation weaknesses in Grok's user-side code-execution sandbox ("Hades"). \
> Research performed February–March 2026. The report was submitted via HackerOne and ultimately closed as Informative. \
> This write-up deliberately omits a runnable end-to-end exploit. It focuses on the isolation model, the concrete failure modes that were demonstrated, the limits of external verification, and the lessons for both researchers and platform operators.*

---

## TL;DR

The Grok code-execution sandbox (the environment behind the "Run" button) is built on gVisor + KVM and is intentionally permitted to compile and execute arbitrary user code, including C. Inside that environment it was possible to:

- create a new user + mount namespace and map UID 0 (virtual root),
- mount a tmpfs over `/etc` and other sensitive paths,
- open and write to `/proc/1/fd/1` (the host-side Sentry orchestration pipe),
- perform fileless execution via `memfd_create`,
- extract hypervisor and Kubernetes service fingerprints.

These behaviours break several isolation assumptions that a sandbox of this type is expected to enforce. The write to the host IPC pipe was confirmed from the guest side (157 bytes accepted with no error); whether the host Sentry process actually parsed or acted on the injected data could not be verified externally and remains the open question that led to the Informative resolution.

---

## Background: what the sandbox is supposed to be

The environment is a short-lived, per-request container whose purpose is to evaluate user-supplied code safely. It runs under gVisor (Sentry) on KVM, with `catatonit` as PID 1. The design goals are classic:

- contain arbitrary native code,
- prevent escape into the host or into other tenants,
- limit the blast radius of a compromised session.

Because the sandbox *must* allow compilation (`gcc`) and execution, many classic mitigations (seccomp-bpf that blocks `unshare`, `mount`, `memfd_create`, etc.) are either absent or incomplete. That is the interesting surface.

---

## Demonstrated failure modes

### 1. Namespace escape → virtual root

`unshare(CLONE_NEWUSER | CLONE_NEWNS)` succeeded. Writing the classic maps:

```
/proc/self/setgroups  → deny
/proc/self/uid_map    → 0 0 1
/proc/self/gid_map    → 0 0 1
```

immediately produced UID 0 with a full capability set inside the new namespace. From the point of view of the process tree and of the VFS, the process was root.

This is the classic "user-namespace escape" pattern. In a hardened sandbox it is expected to be blocked by seccomp, by `user.max_user_namespaces = 0`, or by a policy that refuses the combination of flags.

### 2. VFS trust bypass

With virtual root and a private mount namespace, a simple

```c
mount("none", "/etc", "tmpfs", 0, "");
```

succeeded. The same technique worked against `/hades-container-tools`. Any subsequent process that trusted files under those paths (configuration, helper binaries, etc.) would now see attacker-controlled content. This is a pure isolation failure: the mount namespace was not sufficiently restricted and the host VFS view was still reachable for overlay purposes.

### 3. Host IPC write access

`/proc/1/fd/1` resolved to a writable pipe belonging to the host-side Sentry process. A crafted JSON payload of 157 bytes was written successfully; the write system call returned the full length and produced no error. From the guest it is impossible to observe what (if anything) the host did with that data. The existence of a writable channel from an untrusted guest into the orchestration layer is itself a significant design smell, regardless of whether the particular payload triggered further behaviour.

### 4. Fileless execution

`memfd_create` + `execveat` (or the older `fexecve` path) worked without restriction. Code could be loaded entirely from an anonymous memory file descriptor, leaving no disk artifact inside the container. Useful for both stealth and for bypassing any future file-system-based scanning that might be added.

### 5. Infrastructure fingerprinting

- CPUID leaf `0x40000000` returned the classic KVM signature `KVMKVMKVM`.
- `/proc/1/cmdline` and `/proc/1/environ` leaked the container init binary (`/hades-container-tools/catatonit -P`), internal Kubernetes service DNS names (`*.hades-gix.svc.cluster.local`), and a set of environment variables that included placeholder API keys.
- Process maps and status confirmed the expected gVisor/Sentry layout.

None of these are remote code execution by themselves, but they turn an opaque black-box sandbox into a mapped internal service mesh — useful reconnaissance for any later stage.

---

## What could *not* be demonstrated externally

- Actual processing of the injected IPC data by the host Sentry. The write succeeded; the effect on the orchestration layer is invisible from the guest.
- Escape into other containers or into the Kubernetes node itself. The research stayed strictly inside one sandbox instance.
- Persistence across requests or across different users. Every session is ephemeral.

These gaps are exactly why the HackerOne report was closed Informative: without a demonstrable impact *outside* the sandbox that a triager can independently verify, the finding is treated as "interesting isolation oddity" rather than a confirmed security boundary violation with platform impact.

---

## The disclosure process (and why Informative is common here)

The report included a full C PoC, stage-by-stage logs, and a short video of the interaction with the "Run" button. The triager initially could not reproduce because the code was treated as a normal chat message rather than being executed inside the sandbox. After clarification and a video, the report was still closed with the statement that the behaviour "does not really pose a concrete and exploitable risk to the platform."

This is a recurring pattern with sandbox research:

- The most interesting effects are often one-way (guest → host pipe, guest → host mount, guest → host metadata).
- External researchers cannot see host-side logs or metrics.
- Triagers correctly refuse to treat "I wrote to a pipe and the write succeeded" as proof of compromise unless they can observe a consequence.

The research therefore stopped at the point where further verification required internal access that a good-faith outsider does not have.

---

## Recommendations (for operators of similar sandboxes)

**High priority**

- Deny `CLONE_NEWUSER` and `CLONE_NEWNS` via seccomp or via `user.max_user_namespaces` / mount-namespace policy.
- Make `/proc/*/fd/*` of the host/init process inaccessible from user namespaces (or simply unreadable/unwritable).
- Prevent mounts on sensitive paths (`/etc`, tool directories, etc.) even for UID 0 inside a user namespace — either by mount flags or by a gVisor policy.

**Medium priority**

- Tighten the capability set and the seccomp filter so that `memfd_create` + `execveat` is either blocked or heavily constrained.
- Scrub or randomise environment variables and cmdline that leak internal service names and keys.
- Add explicit logging / alerting for the exact syscalls that appeared in the PoC (`unshare`, `mount`, writes to `/proc/1/fd/*`, `memfd_create`).

**Design note**

A sandbox that must allow arbitrary native code will always be a high-value target. The correct posture is not "block every dangerous syscall" (impossible) but "assume the guest will obtain root inside its namespaces and still keep the host and other tenants unreachable." The findings above show that the second half of that assumption was incomplete.

---

## Takeaways

- **Virtual root is not "just a namespace."** Once UID 0 + mount namespace is obtained, a large fraction of the classic container escape playbook becomes available.
- **Writable host pipes are a boundary violation** even when the payload is harmless. The channel itself is the vulnerability.
- **External verification has hard limits.** Sandbox research frequently ends in Informative because the most critical effects are only observable on the host. That is not a failure of the researcher; it is a property of the problem domain.
- **Fingerprint data matters.** Leaking internal DNS names and init binary paths turns a black-box into a mapped service, lowering the cost of any future research or attack.

---

## Disclosure & ethics

- Research confined to isolated, short-lived sandbox sessions.
- No attempt to access other users' data, no persistence, no disruption of service.
- Full report submitted through the official HackerOne program (report ID referenced in the original submission).
- This public write-up contains no runnable exploit and no bypasses for any subsequently deployed controls.
- The goal is educational: to document a concrete set of isolation failures, the reasoning that led to them, and the practical difficulties of proving host-side impact from the outside.

Contact for questions about the research: eval.atob@gmail.com
