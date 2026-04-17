# sb-runtime — Design Notes

This document explains the architecture and records decisions I want contributors to push back on. The scope is deliberately narrow; everything not listed here is either out-of-scope or v0.2+.

## Goals

1. **Lightweight.** Single binary, ~8 MB, no daemon, no Docker, no k3s, no gateway. Should start in <50 ms on a dev laptop.
2. **Cross-platform.** Linux first (Landlock + seccomp), macOS and Windows in v0.2 / v0.3. The profile surface is OS-agnostic so existing users don't re-learn anything when the other backends land.
3. **Policy-native.** Cedar is the authorization language. Authors write `permit`/`forbid` rules; `sb` evaluates before every exec.
4. **Tamper-evident.** Every decision emits an Ed25519-signed, JCS-canonical, hash-chained receipt. Any third party can verify a chain offline with `@veritasacta/verify`. No trust in ScopeBlind (or any vendor) is required.
5. **Design-partner friendly.** Small public API, short iteration cycles, explicit roadmap.

## Non-goals (v0.1)

- Process-tree isolation (PID namespaces, user namespaces) — out of scope.
- Per-syscall argument filtering (e.g., "allow openat only for path starting with X") — too much complexity for v0.1; Landlock handles path scoping.
- Network policy granularity beyond loopback-only / deny / allow — we'll wire Landlock network rules in v0.2 once kernels ≥6.7 are common.
- Kernel resource limits (cgroups) — orthogonal, can be layered on via `systemd-run`.
- Multi-issuer receipt chains — v0.1 assumes one keypair per chain. Real fleets want multi-issuer; that's v0.2.

## Architecture

```text
               ┌───────────────┐
               │   sb-cli      │   clap, orchestration
               └───────┬───────┘
     ┌─────────────────┼───────────────────┐
     │                 │                   │
┌────▼─────┐    ┌──────▼──────┐    ┌──────▼──────┐
│sb-policy │    │ sb-sandbox  │    │ sb-receipt  │
│  Cedar   │    │Linux: LL+SC │    │ Ed25519+JCS │
└──────────┘    │macOS: stub  │    │+chain      │
                │Windows: stub│    └─────────────┘
                └─────────────┘
```

Each crate has a clear responsibility and no circular dependencies. `sb-receipt` is zero-I/O: the CLI crate owns file writes.

## Execution flow (`sb exec`)

```
1. Parse CLI args (--policy, --sandbox, --receipts, -- CMD)
2. Load or create Ed25519 keypair (in ${receipts}/.sb/key.seed)
3. Load last receipt; compute prev_hash + sequence
4. Evaluate Cedar policy → Decision (Allow | Deny)
5. Build + sign receipt (whether allow or deny)
6. Write receipt to ${receipts}/${seq:06}.json
7. If Deny → print reason, exit 2
8. If Allow → load sandbox profile, apply (Landlock + seccomp)
9. execve(command, args)  [replaces sb process; no parent to hijack]
```

Step 9 is critical: `sb` replaces itself with the target. No long-running supervisor. The sandbox is inherited by every child of the target command.

## Cedar schema for agent actions

```cedar
// Principal: the agent making the request.
entity Agent = { ... };

// Actions: what the agent wants to do.
action exec        appliesTo { principal: Agent, resource: Command };
action open        appliesTo { principal: Agent, resource: File    };
action connect     appliesTo { principal: Agent, resource: Host    };
action request_tool appliesTo { principal: Agent, resource: Tool    };

entity Command = { ... };  // e.g. Command::"/usr/bin/cat"
entity File    = { ... };
entity Host    = { ... };
entity Tool    = { ... };
```

v0.1 implements `exec` only. `open` / `connect` / `request_tool` are reserved for v0.2+ when the enforcement layer for those actions lands. **Feedback welcome**: are these the right abstractions?

## Receipt format

See `crates/sb-receipt/src/lib.rs` and [the IETF draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

```json
{
  "payload": {
    "type": "scopeblind.receipt.v1",
    "decision": "allow" | "deny" | "request_approval",
    "action": { "kind": "exec", "target": "/usr/bin/cat" },
    "policy_id": "dev-safe",
    "sequence": 47,
    "prev_hash": "sha256:a8f3c9d2e1b7465f…",
    "timestamp": "2026-04-17T02:14:53Z",
    "context": { "args": ["-v", "/etc/hosts"] }
  },
  "signature": "4cde814b…",  // hex
  "pubkey":    "1a2b3c4d…"   // hex
}
```

The canonical bytes are produced via a minimal JCS implementation in `sb-receipt`. A verifier takes `{payload, signature, pubkey}`, re-canonicalises the payload, and checks Ed25519. No other information is needed.

## Linux sandbox backend

- **Landlock** (kernel ≥ 5.13) for filesystem access. We use ABI V2 rules (read / write / execute) path-scoped by `Profile::read_paths`, `write_paths`, `exec_paths`.
- **Seccomp-BPF** for syscall filtering. Two modes:
  - **Strict**: curated allowlist (~70 syscalls covering typical agent-tool needs).
  - **Permissive**: deny-list of dangerous syscalls (ptrace, kexec_*, reboot, mount, keyctl, add_key, request_key, mount/pivot_root, init_module, delete_module).
- **Network**: v0.1 blocks `socket()` via seccomp when `network == Deny | LoopbackOnly`. v0.2 will use Landlock's network rules (kernel ≥ 6.7) for fine-grained port allowlists.

### Known limitations (v0.1)

- Syscall numbers are hard-coded for x86_64; aarch64 falls back to permissive mode. v0.2 will use libseccomp or a build.rs to generate the table.
- `Profile::hostname` is declared but not enforced (would require a user namespace).
- Seccomp filters are installed per-thread; `sb` is single-threaded at exec time so this is fine.

## macOS / Windows backends

Stubs today. Priorities:
- **macOS**: use `sandbox_init()` with an SBPL profile generated from `Profile`. The SBPL language is private/undocumented; we'll follow [the sandbox-exec writeups by Peter Hosey](https://boredzo.org/sandbox/sbpl.html) + test empirically.
- **Windows**: use Job Objects + AppContainer. More involved.

**Open question for design partners**: is it acceptable for v0.1 to refuse to run (with a clear error) on macOS / Windows unless `--allow-unsandboxed` is passed, or should we ship a "warn and run" default? Current default is refuse.

## AGT integration

This is the primary near-term integration target. Planned shape:

```python
# agent-os-kernel/src/sandbox/sb_runtime.py
class SbRuntimeSandbox(SandboxProvider):
    def exec(self, command, args, policy_path, sandbox_profile):
        # Subprocess to `sb exec` with the provided policy + profile.
        # Stdout/stderr pass through; receipt is emitted to a configurable
        # directory and surfaced as a string in the SandboxResult.
```

Target interface matches the existing OpenShell provider contract so swapping is configuration-only. **Design-partner call-out**: @lukehinds + AGT maintainers — what does this contract actually look like today? The one thing we don't want to do is re-implement it differently.

## Commercial / hosted tier

The binary is MIT, forever. The hosted managed tier (optional, at [scopeblind.com/pricing](https://scopeblind.com/pricing)) solves two problems `sb-runtime` doesn't:

1. **Receipt archival at scale.** Writing millions of receipts to local disk isn't ideal for production fleets. The hosted tier accepts receipts via `POST /v1/receipts`, indexes them, and surfaces them in a dashboard for audit.
2. **Team policy management.** Versioned Cedar policies with review workflows.
3. **Compliance exports.** SOC 2, EU AI Act Annex IV bundles generated from the receipt chain.

**We're deliberately not phoning home from the binary.** No telemetry, no version-check beacon (in v0.1). You can run `sb` in an air-gapped environment forever. The hosted tier is a pull, not a push.

## Roadmap

- **v0.1.x** (now): Linux backend, `exec` action, basic receipt chain, CI for x86_64.
- **v0.2**: aarch64 syscall tables, Landlock network rules, `open` + `connect` actions, AGT provider PR, multi-issuer chains.
- **v0.3**: macOS backend, Windows backend, built-in tool-use profiles (compiler, HTTP client, SQL client).
- **v1.0**: Stable API, semver guarantees, production-grade macOS/Windows, full AGT tutorial.

## Feedback we want

1. Is the Cedar schema shape right?
2. Is the `Profile` abstraction the right level (too high? too low?)?
3. Receipt format compatibility with Sigstore Rekor anchoring — enough, or does the payload need more fields?
4. AGT provider interface — we want to match it exactly.
5. What's the right default when the OS backend isn't available (refuse vs warn-and-run)?

Open an issue; PRs welcome.
