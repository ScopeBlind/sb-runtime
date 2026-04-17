# `sb-receipt`

Ed25519-signed, hash-chained, canonical-JSON receipts for sandboxed agent decisions.

Every decision emitted by `sb-runtime` (allow, deny, request_approval, exec) is a signed
receipt carrying: the decision, the action, the policy evaluated, the sequence number in
its chain, and the SHA-256 of the prior receipt's canonical bytes. Any third party can
verify a chain offline with [`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify).

- **Ed25519** (RFC 8032) signatures
- **JCS** (RFC 8785) canonicalization
- **SHA-256** chain linkage (`prev_hash`)
- No runtime dependencies on ScopeBlind services — receipts are self-verifiable forever
