# sb-runtime

Ed25519-signed decision receipts for Cedar-governed agent tool calls.

> **For kernel sandboxing, use [nono](https://github.com/always-further/nono)**
> (Luke Hinds and 50+ contributors, Apache-2.0). sb-runtime is scoped to
> receipts and Cedar policy evaluation; it composes with nono as the
> recommended Linux/macOS sandbox layer. sb-runtime's own Landlock/seccomp
> backends are legacy and will be removed in a future release.

## What it does

1. Evaluates a [Cedar](https://www.cedarpolicy.com/) policy for an agent action
2. Signs the decision (Ed25519, JCS-canonical, hash-chained receipts)
3. Defers sandboxing to nono (see banner above)

Receipts verify offline with [@veritasacta/verify](https://www.npmjs.com/package/@veritasacta/verify).

## Quick start

```bash
cargo install --path crates/sb-cli

sb exec \
  --policy examples/basic/policy.cedar \
  --receipts .receipts \
  -- /usr/bin/cat /etc/hosts

sb verify .receipts/
```

## Prior art

[**nono**](https://github.com/always-further/nono) is the canonical
community project for agent sandboxing using kernel-native primitives
(Landlock + seccomp on Linux, Seatbelt / sandbox_init on macOS). Apache-2.0,
created February 2026 by Luke Hinds, maintained by 50+ contributors.

If you need a sandbox layer, use nono. sb-runtime's focus is receipts and
Cedar policy; it does not aim to replicate nono's capability model,
supervisor mode, or contributor community. Recommended composition is
**nono as the sandbox layer with sb-runtime for Cedar + receipts on top**.

The framing "Docker / k3s is too heavy for CI and edge" was reinforced by
Luke Hinds's [microsoft/agent-governance-toolkit#748](https://github.com/microsoft/agent-governance-toolkit/issues/748)
proposal for nono integration. Credit where due.

## Status

v0.1.0-alpha.1 — exploratory. The Landlock / seccomp sandbox backends in
this tree are being deprecated; for sandboxing use nono.

## Licensing

Apache-2.0. No runtime dependencies on ScopeBlind services; no telemetry.

## Related

- [**nono** (Always Further)](https://github.com/always-further/nono) — kernel-native agent sandboxing
- [**Cedar**](https://www.cedarpolicy.com/) (AWS) — policy engine
- [**@veritasacta/verify**](https://www.npmjs.com/package/@veritasacta/verify) — offline receipt verifier
- [**IETF draft-farley-acta-signed-receipts**](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) — receipt format spec
