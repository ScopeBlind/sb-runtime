# sb-runtime

> A single binary that runs your AI agent inside an OS-level sandbox and
> signs a receipt for every decision it makes.

## What it does, in plain English

You want to run an AI agent — a coding assistant, an autonomous workflow, a
scripted LLM — but you don't fully trust what it'll do. `sb-runtime` wraps
the agent and does three things:

1. **Checks a policy before the agent runs.** Is it allowed to invoke
   `python`? Can it touch `/etc`? Can it open a network socket? You write
   the rules once in [Cedar](https://www.cedarpolicy.com/) — the same
   policy language AWS uses for IAM.
2. **Confines the agent at the OS level** while it runs. On Linux the agent
   literally cannot open files outside the allowed list, cannot make most
   syscalls, cannot open network sockets — not because the agent cooperates,
   because the kernel refuses. (Backend: Landlock + seccomp. Opt-in for
   v0.1-alpha; see the platform matrix below.)
3. **Signs a receipt for every decision.** Ed25519-signed, hash-chained,
   verifiable offline by anyone with the public key. When something goes
   wrong you can *prove* — not claim — what happened.

You don't modify the agent. You wrap it:

```bash
sb exec --policy dev.cedar -- python my_agent.py
```

## Who this is for

- **Security teams** running AI coding assistants they didn't write.
- **Compliance teams** who need tamper-evident evidence of agent behaviour.
- **CI and edge deployments** where Docker / k3s / OpenShell is too heavy.
- **Anyone nervous** about letting an LLM run commands on their machine.

## How it relates to `protect-mcp`

`sb-runtime` is the **OS sandbox around** the agent. [`protect-mcp`](https://www.npmjs.com/package/protect-mcp)
is the **policy check inside** the agent — a hook that sits between the LLM
and its tool registry in Claude Code / MCP. They're complementary:

```
┌─────────────────────────────────────────────────┐
│  sb-runtime   ← OS refuses forbidden syscalls   │
│  ┌───────────────────────────────────────────┐  │
│  │  agent process (Claude Code, Python, …)   │  │
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │  protect-mcp                        │  │  │
│  │  │    ← Cedar decides per tool call,   │  │  │
│  │  │      receipts every decision        │  │  │
│  │  └─────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

Use `protect-mcp` alone if you wrote the agent and trust its framework to
honour decisions. Use `sb-runtime` alone if you didn't write the agent and
want the OS to contain it regardless. Use both for belt-and-braces.

---

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

## Verification properties

sb-runtime receipts are **offline-verifiable** and **tamper-evident**:

- **Offline:** `@veritasacta/verify` contacts no server during verification. The math runs against a public key you source externally via `--key`, `--jwks`, or `--trust-anchor`.
- **Tamper-evident:** any modification to the receipt payload, signature, or chain linkage breaks verification. Exit code 1 is proven tampering; exit 0 is proven authenticity.
- **No vendor trust:** verification depends only on Ed25519 math and JCS canonicalization (both open standards). No ScopeBlind infrastructure is in the verification path.

What this **does not** provide: **issuer-blind / unlinkable / zero-knowledge** verification in the VOPRF sense. The Ed25519 signature identifies the signer via the public key. If you need verification where the verifier cannot link multiple presentations to the same signer (privacy-preserving metered authorization, anonymous credentials, unlinkable rate limiting), that's a different primitive with its own stack:

- **Protocol and verifier**: open-source under [Veritas Acta](https://github.com/VeritasActa), Apache-2.0. Anyone can verify.
- **Production issuer**: [ScopeBlind](https://scopeblind.com) sells the managed VOPRF issuance service. You can run your own issuer in principle; in practice the cryptographic correctness, key rotation, and metering make the managed service the usual choice.

`sb-runtime` doesn't require VOPRF for decision auditability — Ed25519 receipts cover that. The VOPRF product solves a different problem (privacy) at a different layer of the stack.

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
