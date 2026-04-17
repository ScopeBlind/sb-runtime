# Contributing to sb-runtime

Thank you — `sb-runtime` is a small project and every review, test, and PR
genuinely moves it forward. Three things to read before you start.

## The design-partner programme

If you're building in adjacent territory (agent governance, policy-as-code,
OS sandboxing, cryptographic supply chain, transparency logs) we'd love your
input before v0.1 stabilises. Design partners get:

- Direct read on the v0.2 roadmap before it lands in `DESIGN.md`.
- Early reviewer access on API surface — the kind of feedback that's still
  cheap to act on.
- Named credit in release notes (if you want it; anonymity is fine too).

Open an issue titled "design-partner interest" and tell us a sentence about
what you're building. Or email **tommy@scopeblind.com**.

Current design partners (or conversations in flight): TBD — you could be #1.

## PRs we'd especially welcome

Ranked by leverage:

1. **[aarch64 syscall table](https://github.com/ScopeBlind/sb-runtime/issues/1)** — unblocks Linux ARM.
2. **[--dry-run flag for sb exec](https://github.com/ScopeBlind/sb-runtime/issues/2)** — simplifies the AGT shim.
3. **[macOS sandbox backend](https://github.com/ScopeBlind/sb-runtime/issues/3)** — sandbox_init + SBPL.
4. **[Multi-issuer receipt chains](https://github.com/ScopeBlind/sb-runtime/issues/4)** — v0.2 receipt model.

See `DESIGN.md` for the v0.2/v0.3 roadmap.

## Development workflow

```bash
# Build & run the full test matrix
cargo test --workspace

# Lint (matches CI)
cargo clippy --workspace --all-targets --all-features

# Format (matches CI)
cargo fmt --all --check

# End-to-end smoke test (Linux-like OS)
cargo build -p sb-cli
./target/debug/sb exec \
  --policy examples/basic/policy.cedar \
  --receipts /tmp/sb-smoke \
  --allow-unsandboxed \
  -- /bin/echo hello
./target/debug/sb verify /tmp/sb-smoke
```

## PR conventions

- **One concern per PR.** Sandbox changes, policy changes, and receipt
  changes should not share a commit.
- **New public API requires a test.** We don't expose anything we can't point at.
- **Breaking changes need a CHANGELOG entry.** Minor doc tweaks don't.
- **`cargo fmt` + `cargo clippy` clean** before pushing. CI will block otherwise.

## Code review

One maintainer approval is enough during v0.1-alpha. Once we hit v0.1.0 stable
we'll move to a stricter review model.

## Licence

By submitting a PR you agree your contribution is licensed Apache-2.0 under the
project LICENCE. If you work at an employer that claims rights to your code,
please sort that out before PRing.

## Be kind

The project is young and evolving. Good-faith questions, arch disagreements,
and "have you considered…" are all welcome. Rudeness isn't.

Thanks. Looking forward to building this with you.
