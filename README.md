# Security Research

Coordinated-disclosure write-ups and root-cause analyses of security issues in web applications and sandboxed execution environments.

Targets are anonymized unless disclosure is complete and public. Write-ups focus on the underlying
weakness, the reasoning, and correct remediation — **no working exploit payloads are published.**
All research is conducted in good faith; findings are reported to the affected party before any
write-up is made public.

## Write-ups

- **[Anatomy of Security Theater](./anatomy-of-security-theater.md)** — Vue client-side template
  injection chained with missing security headers and an unvalidated `localStorage` asset, followed
  by a lifecycle of vendor "fixes" (character-stripping filters, an `eval`-override script) that
  each treated a symptom while leaving the root cause untouched.

- **[Hades Sandbox Isolation Assessment](./hades-sandbox-isolation.md)** — Namespace escape via
  `unshare` + UID mapping, VFS trust bypass through tmpfs overlays, and direct write access to the
  host Sentry IPC pipe inside Grok's user-facing code-execution sandbox. The report was closed
  Informative; the write-up examines the isolation model failures, the limits of external
  verification, and practical hardening recommendations for similar sandboxes.

*More write-ups added over time.*

## Scope & ethics

- **Good faith only.** Research is limited to what is necessary to demonstrate a weakness
  (proof-of-concept). No user data is accessed, no data is modified, and no service is disrupted.
- **Report first.** Findings are disclosed to the affected operator (or via their bug-bounty
  program) before anything is published here.
- **No weaponization.** These write-ups explain *why* something was exploitable and *how to fix it*.
  They deliberately omit runnable exploit code and bypasses for currently-live protections.

## About
Contact: eval.atob@gmail.com
