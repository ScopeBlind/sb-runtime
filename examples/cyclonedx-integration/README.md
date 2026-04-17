# CycloneDX integration

Reference tool demonstrating how an `sb-runtime` (or `protect-mcp`) receipt
attaches to a CycloneDX 1.6 BOM **without extending the spec**.

## Why this example exists

When an AI agent resolves a dependency tree (`npm install`, `pip install`,
`cargo update`, via Claude Code / MCP tool calls) the resulting lockfile
and its BOM carry *what* got resolved. They don't carry *who* resolved it,
*when*, or *under what policy*. In a post-agent world that becomes the
actual provenance gap.

CycloneDX 1.6 already has two features that, taken together, largely close
this gap without any format extension:

| Existing CycloneDX 1.6 feature | What it carries |
|---|---|
| `formula.workflow`                 | How the BOM was generated (build steps, task types, timing) |
| `properties` (namespace-scoped)    | Arbitrary tool-specific metadata alongside any entity |
| `signature` (JSF)                  | Enveloped signatures over BOM contents |

The missing dimension is **agent identity + policy digest**, i.e. linking a
workflow to the specific agent + Cedar policy that produced it. Those are
regular scalar values that fit cleanly into `properties` on the workflow
entry.

This example shows that fit. It is **not** a format proposal and **does not
require anyone to adopt any non-CycloneDX spec**. A downstream parser that
doesn't recognize the properties simply ignores them, same as any other
namespaced property bag.

## What `attach_receipt.py` does

Input: a CycloneDX 1.6 JSON BOM and a signed receipt from sb-runtime or
protect-mcp (format documented at [scopeblind.com/docs/protocol](https://scopeblind.com/docs/protocol)).

Output: a BOM with the receipt attached as:

- one new entry in `formulation[].workflows[]` describing the agent-driven
  resolution event, with `properties` carrying `agent.policy_id`,
  `agent.decision`, `agent.chain.sequence`, etc.;
- six top-level `properties[]` in the `com.scopeblind` namespace carrying
  the Ed25519 signature, the signer's public key, and a pointer to the
  offline verifier CLI.

The output validates against the stock CycloneDX 1.6 JSON schema unchanged.

## Usage

```bash
python attach_receipt.py \
  --bom       sample-bom.json \
  --receipt   .receipts/000001.json \
  --out       enriched-bom.json

python attach_receipt.py --smoke   # built-in smoke test
```

## Why Ed25519 in `properties` and not JSF

CycloneDX signatures use [JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html),
which Ed25519 is supported by but requires a specific serialisation profile.
For this reference the receipt signature rides as a property rather than a
JSF envelope; a production pipeline would JSF-sign the whole enriched BOM
using the receipt as one of several signature inputs.

If CycloneDX maintainers have thoughts on whether `properties` is the right
carrier (vs. extending the `signature` definition to accept multiple signers
with role metadata), the discussion is open at:

> [CycloneDX/specification discussion #909](https://github.com/CycloneDX/specification/discussions/909)

## Relationship to the spec

Nothing in this example proposes a spec change. Everything it does is
achievable with CycloneDX 1.6 as published. It's posted so the working
group can consider whether a small vocabulary convention (e.g. a reserved
`sbom.provenance.*` property namespace) would be worth standardising across
tools, or whether the status quo of vendor-namespaced properties is fine.

## Licence

Apache-2.0, same as the rest of `sb-runtime`.
