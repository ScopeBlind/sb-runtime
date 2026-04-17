# sb-runtime

**Lightweight agent sandbox with Cedar policy and signed receipts.** One Rust binary, no Docker, no k3s, no gateway.

```text
┌──────────────────────────────────────────────────────────────┐
│  sb exec --policy dev-safe.cedar -- /usr/bin/cat /etc/hosts  │
│                                                                │
│  1. Cedar evaluates   → allow / deny (400 µs)                  │
│  2. Ed25519 receipt   → .receipts/000001.json (tamper-evident) │
│  3. OS sandbox        → Landlock + seccomp (Linux)             │
│  4. execve            → the target command runs confined       │
└──────────────────────────────────────────────────────────────┘
```

`sb-runtime` answers a question several AGT / OpenShell users have been asking: *can we get the "walls + brain + receipts" pattern without Docker/OCI/k3s/gateway infrastructure?* This is a single 8 MB binary that runs on dev laptops, CI, and edge.

**Status: v0.1.0-alpha.1 — design-partner preview.** Honest platform matrix:

| Platform             | Sandbox                    | Cedar + receipts |
|----------------------|----------------------------|------------------|
| Linux x86_64         | Landlock + seccomp — opt-in via `--features linux-sandbox` (see [issue #1][1]) | ✓ |
| Linux aarch64        | Refuses (see [issue #1][1]) | ✓                |
| macOS                | Stub (`--allow-unsandboxed`) — [issue #3][3] | ✓ |
| Windows              | Stub (`--allow-unsandboxed`) | ✓              |

The `linux-sandbox` cargo feature is off by default in v0.1-alpha while the
Landlock/seccomp backend is stabilized. The JCS-canonical, Ed25519-signed,
hash-chained receipts (plus Cedar policy evaluation) work on every platform
today.

We're actively looking for design-partner input on the AGT provider interface,
the Cedar schema for agent actions, and the macOS/Windows backend priorities —
see `CONTRIBUTING.md` or reply to
[microsoft/agent-governance-toolkit#748](https://github.com/microsoft/agent-governance-toolkit/issues/748).

[1]: https://github.com/ScopeBlind/sb-runtime/issues/1
[3]: https://github.com/ScopeBlind/sb-runtime/issues/3

## Quick start

```bash
cargo install --path crates/sb-cli    # or: cargo run -p sb-cli --
sb exec \
  --policy examples/basic/policy.cedar \
  --receipts .receipts \
  -- /usr/bin/cat /etc/hosts

sb verify .receipts/
# ✓ 1 receipts verified (2026-04-17T...Z → 2026-04-17T...Z)
```

The signed receipt format is compatible with [`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify) — your auditor can verify a chain offline with `npx @veritasacta/verify .receipts/` without installing the `sb` binary.

## Architecture

```text
sb-cli            — the `sb` binary
├── sb-policy     — Cedar policy evaluator
├── sb-sandbox    — OS sandbox (Landlock + seccomp on Linux; macOS/Windows WIP)
└── sb-receipt    — Ed25519-signed, JCS-canonical, hash-chained receipts
```

Each sub-crate is usable independently. `sb-receipt` is deliberately minimal (zero I/O, pure crypto) so it can be dropped into other Rust agent frameworks.

## Commands

| | |
|---|---|
| `sb exec --policy P --sandbox S -- CMD ARGS…` | evaluate P, apply S, emit receipt, exec CMD |
| `sb verify DIR` | verify a chain of receipts offline |
| `sb keys generate` | mint a fresh Ed25519 keypair |

`--allow-unsandboxed` skips the sandbox step (Cedar + receipts still fire). Useful on macOS / Windows until the native backends ship; **do not use in production**.

## Why not just…

- **…use Docker?** Docker is great but heavy for CI, edge, and dev-laptop agents. `sb-runtime` is 8 MB and starts instantly.
- **…use OpenShell?** OpenShell is the right design, but it expects Docker/OCI/k3s/gateway infrastructure. `sb-runtime` is the local-first version of the same idea. AGT's `agent-os-kernel` can talk to either; swap via config.
- **…use firejail / bubblewrap?** Those are filesystem sandboxes. They don't evaluate Cedar policy before the exec, and they don't emit signed receipts. Combine them with `sb-runtime` if you want — `sb` does Cedar + receipts + Landlock+seccomp, they do extra fs isolation layers.
- **…just use Cedar?** Cedar decides. It doesn't enforce or audit. `sb-runtime` is the enforcement layer.

## Integrating with Microsoft's Agent Governance Toolkit

See [`examples/agt-integration/`](examples/agt-integration/) for a Python
drop-in shim (`SbRuntimeSkill`) that replaces
`openshell_agentmesh.skill.GovernanceSkill` field-for-field. Swap via config,
no agent code changes required.

## Licensing

Apache-2.0. No runtime dependencies on ScopeBlind services; no telemetry. The optional managed tier (hosted receipt archival, team dashboards, compliance exports) is available at [scopeblind.com/pricing](https://scopeblind.com/pricing) but the sandbox runs local-only forever with the free binary.

## Design-partner program

We're looking for 3–5 engineers to co-design the AGT provider interface, the Cedar schema for agent actions, and the macOS / Windows backend priorities. If you're building in this space (agent governance, policy-as-code, secure-element attestation, transparency-log anchoring), open an issue or reach out — early partners get direct input on API surface before v0.1 stabilises.

## Related

- [**Agent Governance Toolkit** (Microsoft)](https://github.com/microsoft/agent-governance-toolkit) — decision layer
- [**Cedar**](https://www.cedarpolicy.com/) (AWS) — policy engine
- [**Sigstore**](https://sigstore.dev/) — transparency-log anchoring for receipt chains
- [**Veritas Acta**](https://veritasacta.com) — open protocol for contestable public records
- [**IETF draft-farley-acta-signed-receipts**](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) — standardisation of the receipt format

## Contributing

Small repo, fast iteration. PRs welcome. See [DESIGN.md](DESIGN.md) for the current roadmap.
