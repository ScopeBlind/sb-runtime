# Changelog

All notable changes to `sb-runtime` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it hits v1.0.

## [Unreleased]

### Added
- Nothing yet; PRs welcome.

## [0.1.0-alpha.1] — 2026-04-17

First public preview. Design-partner release.

### Added

- **`sb-cli`** — the `sb` binary with three subcommands: `exec`, `verify`,
  `keys generate`.
- **`sb-sandbox`** crate — OS-native sandbox primitives.
  - Linux x86_64 backend: Landlock ABI V2 (filesystem read / write / exec) +
    seccomp-BPF (strict allowlist of ~70 syscalls by default; permissive
    deny-list mode also available).
  - Linux aarch64: refuses-to-run with a clear error rather than silently
    degrading. See issue #1.
  - macOS + Windows: stubs. `--allow-unsandboxed` lets the other layers
    (Cedar + receipts) fire without OS isolation on those platforms.
- **`sb-policy`** crate — Cedar-backed policy evaluator.
- **`sb-receipt`** crate — Ed25519-signed, JCS-canonical, hash-chained
  receipts. Zero-I/O, pure-crypto. Compatible with
  [`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify)
  and the
  [IETF draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).
- **`examples/basic/`** — minimal "allow-list of commands" Cedar policy with
  smoke-test instructions.
- **`examples/agt-integration/`** — Python shim (`SbRuntimeSkill`) that
  drops into Microsoft's Agent Governance Toolkit in place of
  `openshell_agentmesh.skill.GovernanceSkill`. Same public interface; swap
  via config. Addresses [AGT issue #748](https://github.com/microsoft/agent-governance-toolkit/issues/748).
- **CI** — `cargo fmt`, `cargo clippy`, `cargo test`, and an end-to-end Linux
  smoke run on push / PR. Cross-compile to x86_64-linux / x86_64-macos /
  aarch64-macos on tagged releases.
- **Community files** — `CONTRIBUTING.md`, `SECURITY.md`, `DESIGN.md` with
  roadmap + open questions.

### Known limitations

See `DESIGN.md#known-limitations-v01` for the full list. Headlines:

- Linux x86_64 only in this release.
- Syscall allowlist is hand-curated; some programs will hit missing
  syscalls (particularly `statx`, `ioctl`, newer `getrandom` variants).
- Network policy is coarse: loopback-or-nothing via seccomp. Landlock
  network rules (kernel ≥ 6.7) land in v0.2.
- Receipt chains are single-issuer. Multi-issuer chains are issue #4.
- `sb exec` runs the command it evaluates; a pure-evaluation `--dry-run`
  mode is issue #2.

### Contributors

@tomjwxf — core scaffold, Linux backend, Cedar integration, receipt format,
AGT shim.

You? We're actively looking for design partners — see CONTRIBUTING.md.

[Unreleased]: https://github.com/ScopeBlind/sb-runtime/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/ScopeBlind/sb-runtime/releases/tag/v0.1.0-alpha.1
