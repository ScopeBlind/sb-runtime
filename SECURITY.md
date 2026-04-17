# Security Policy

## Supported versions

Only the latest tagged release on `main` receives security fixes during the
v0.1-alpha cycle. Once v1.0 ships, we'll support the latest two minor lines.

## Reporting a vulnerability

Please report security issues privately rather than via a public GitHub issue:

- Email: **security@scopeblind.com**
- PGP (optional): fingerprint published at https://scopeblind.com/.well-known/security.txt

We aim to acknowledge within **24 hours** and ship a fix + coordinated disclosure
within **14 days** for high-severity issues, longer for issues requiring upstream
Cedar / Landlock / seccomp changes.

## Scope

In scope:

- Anything in `crates/sb-*` — the Rust code.
- Anything in `examples/` — if an example would leak a key, mis-apply a policy,
  or otherwise teach a wrong pattern.
- Any documented CLI flag behaviour.

Out of scope:

- Bugs in the Cedar policy engine itself — please report to
  https://github.com/cedar-policy/cedar.
- Bugs in Landlock or the Linux kernel — report to
  https://landlock.io or the kernel mailing list.
- Denial-of-service attacks against the hosted receipt archival service —
  report to security@scopeblind.com (separate from the open-source repo).

## Defence-in-depth assumptions we rely on

A sandbox built from Landlock + seccomp is *best-effort*, not a complete jail.
We assume:

- The kernel is patched against public CVEs.
- The binary is not setuid. Callers drop privileges before invoking `sb`.
- A determined attacker with a kernel 0-day can escape. For higher-assurance
  workloads, layer `sb` inside a VM, a container, or a hardware sandbox —
  `sb` is *complementary* to those, not a replacement.

## Credit

Researchers who privately report valid issues are credited in release notes
unless they request anonymity.
