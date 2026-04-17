# AGT integration — `SbRuntimeSkill`

Drop-in replacement for `openshell_agentmesh.skill.GovernanceSkill` that delegates policy
evaluation + enforcement + receipt emission to the `sb` binary. Same public interface; swap
via configuration. Zero agent-code changes.

## Why

[microsoft/agent-governance-toolkit#748](https://github.com/microsoft/agent-governance-toolkit/issues/748)
asks for a lightweight sandbox alternative to OpenShell — something without Docker, k3s, or
a gateway, suitable for CI, edge, and dev machines. `sb-runtime` answers that (single ~8 MB
Rust binary; Cedar policy + Ed25519 receipts + Landlock + seccomp on Linux).
`SbRuntimeSkill` is the Python shim that lets AGT consume it.

## Drop-in swap

Before (OpenShell):

```python
from openshell_agentmesh.skill import GovernanceSkill
skill = GovernanceSkill(policy_dir=Path("policies/"))
decision = skill.check_policy("shell", {"command": "rm -rf /tmp"})
```

After (`sb-runtime`):

```python
from sb_runtime_skill import SbRuntimeSkill
skill = SbRuntimeSkill(
    policy_path=Path("policies/dev-safe.cedar"),
    receipts_dir=Path(".receipts"),
)
decision = skill.check_policy(
    "exec",
    {"command": "/usr/bin/rm", "args": ["-rf", "/tmp"]},
)
```

`PolicyDecision` is field-for-field compatible (`allowed`, `action`, `reason`, `policy_name`,
`trust_score`) plus one sb-specific extension: `receipt_path` pointing at the signed receipt
the `sb` binary just wrote. Your existing trust-score loops, audit exports, and dashboards
keep working.

## What you get that OpenShell doesn't

- **Tamper-evident audit trail.** Every decision — allow *and* deny — is an Ed25519-signed
  receipt, hash-chained by `prev_hash`. A regulator can verify the chain offline with
  `npx @veritasacta/verify` or `sb verify .receipts/` and needs to trust nothing except the
  issuer public key.
- **No infrastructure.** No Docker daemon, no k3s control plane, no network proxy. Single
  binary. Fits in CI, edge, and dev-laptop workflows OpenShell finds awkward.
- **Offline verification property.** Receipts keep verifying after the `sb` binary and the
  Skill and ScopeBlind are all gone.

## What you give up vs. OpenShell

- No network proxy interception layer (LoopbackOnly seccomp rule only, for now).
- No multi-tenant k3s isolation.
- Linux sandbox backend is x86_64-only in v0.1 (aarch64 refuses-to-run rather than
  silently falling back — see [issue #1](https://github.com/ScopeBlind/sb-runtime/issues/1)).
- macOS and Windows run in `--allow-unsandboxed` mode (Cedar + receipts only) until
  v0.2 lands `sandbox_init` and AppContainer backends.

**Use OpenShell when you need full network-proxy enforcement or multi-tenant k3s.
Use `sb-runtime` when those are overkill.**

## Open design questions (v0.1.0-alpha.1)

These are what I most want to hear from AGT maintainers + @lukehinds on:

1. **Separation of check and enforce.** `check_policy` in OpenShell's `GovernanceSkill` is
   pure evaluation — it does not run the action. `sb exec` currently evaluates *and* runs.
   We're planning a `sb exec --dry-run` in v0.1.1 so the Skill can check without running;
   the current shim uses a receipts-scan workaround. Is "check then separately enforce" the
   right mental model for this interface, or should `check_policy` also enforce?
2. **Async or sync?** The current shim is sync (matching OpenShell's `check_policy`). If
   AGT is moving async in general, say the word and we'll ship async equivalents.
3. **Receipt storage.** Should `SbRuntimeSkill` expose receipts via the existing audit log
   methods, or is the `receipt_path` on `PolicyDecision` plus `verify_chain()` enough for
   downstream consumers?
4. **Trust score feedback loop.** The Skill currently reads trust score but doesn't write
   it back from receipt outcomes. Should receipt decisions auto-decay trust the way
   OpenShell's demo does?

## Run the smoke test

```bash
# Build + install the sb binary from source (one-time)
cargo install --path ../../crates/sb-cli   # from sb-runtime root

# Run the Python demo
python sb_runtime_skill.py --smoke
```

Expected output:

```
allow case: True  allowed by policy smoke
deny case:  False denied by policy smoke:  deny policies: policy0
chain ok:   True
```

## Status

Design-partner preview. Aligned to AGT `openshell-skill` interface as of 2026-04-17.
If upstream changes, this shim follows; file an issue on sb-runtime if you spot drift.

Feedback especially welcome from the AGT + Sigstore + Red Hat alumni orbit — receipt/log
design here tries to be compatible with the patterns you've already set.
