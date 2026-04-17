#!/usr/bin/env python3
# Copyright (c) ScopeBlind Contributors
# Licensed under the Apache-2.0 License.
"""
attach_receipt.py — compose a CycloneDX BOM with an sb-runtime /
protect-mcp receipt, using existing CycloneDX 1.6 spec fields only.

No format extensions, no new envelopes. The receipt rides as:

  * a `formula.workflow.taskType` entry describing the agent-driven
    resolution event (e.g. `npm install`), with the receipt's policy
    digest and issuer id in the workflow's `properties`.
  * a top-level `properties[]` entry (namespace `com.scopeblind`)
    carrying the raw Ed25519 signature + canonical payload bytes for
    offline verification via `@veritasacta/verify` or `sb verify`.

This is a reference implementation. A future version may render the
signature in CycloneDX's JSON Signature Format (JSF) directly, but the
spec-compliant property-bag approach below works with every existing
CycloneDX parser today.

Status
------
Design preview. Filed for community input at
https://github.com/CycloneDX/specification/discussions (link updated
once the discussion is posted).

Usage
-----
    python attach_receipt.py \\
        --bom sample-bom.json \\
        --receipt sample-receipt.json \\
        --out enriched-bom.json

The output validates against the CycloneDX 1.6 JSON schema unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ─── Constants ────────────────────────────────────────────────────────────────

PROPERTY_NAMESPACE = "com.scopeblind"
RECEIPT_PROTOCOL_URL = (
    "https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/"
)


# ─── Core composition ────────────────────────────────────────────────────────


def enrich_bom(bom: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    """
    Return a copy of `bom` with the receipt attached via existing
    CycloneDX 1.6 fields. Does not mutate the input.
    """
    out = json.loads(json.dumps(bom))  # deep copy

    payload = receipt.get("payload", {})
    signature = receipt.get("signature", "")
    pubkey = receipt.get("pubkey", "")

    action = payload.get("action", {}) or {}
    decision = payload.get("decision", "unknown")
    policy_id = payload.get("policy_id") or "unspecified"
    sequence = payload.get("sequence")
    prev_hash = payload.get("prev_hash", "")
    timestamp = payload.get("timestamp") or _now_iso()

    # 1. Formula / workflow — the idiomatic place for "how this BOM came to be"
    formulation = out.setdefault("formulation", [])
    formulation.append(
        {
            "bom-ref": f"acta-receipt-{sequence}" if sequence else "acta-receipt",
            "workflows": [
                {
                    "bom-ref": f"acta-workflow-{sequence}" if sequence else "acta-workflow",
                    "uid": f"sha256:{_canonical_hash(receipt)}",
                    "name": "Agent-attested dependency resolution",
                    "description": (
                        f"Receipt-backed record of {action.get('kind', 'resolution')} "
                        f"action producing this BOM. Decision={decision}, "
                        f"policy={policy_id}, sequence={sequence}."
                    ),
                    "taskTypes": ["build"],
                    "steps": [
                        {
                            "name": action.get("kind", "resolve"),
                            "description": action.get("target", "dependency resolution"),
                            "commands": _coerce_commands(action),
                        }
                    ],
                    "timeStart": timestamp,
                    "properties": [
                        _prop("agent.policy_id", policy_id),
                        _prop("agent.decision", decision),
                        _prop("agent.chain.sequence", str(sequence) if sequence else ""),
                        _prop("agent.chain.prev_hash", prev_hash),
                        _prop("agent.receipt.protocol", RECEIPT_PROTOCOL_URL),
                    ],
                }
            ],
        }
    )

    # 2. Top-level properties — raw Ed25519 signature + pubkey for offline verify
    properties = out.setdefault("properties", [])
    properties.extend(
        [
            _prop(f"{PROPERTY_NAMESPACE}:receipt.signature.alg", "Ed25519"),
            _prop(f"{PROPERTY_NAMESPACE}:receipt.signature.value", signature),
            _prop(f"{PROPERTY_NAMESPACE}:receipt.signature.pubkey", pubkey),
            _prop(f"{PROPERTY_NAMESPACE}:receipt.payload.canonical_sha256", _canonical_hash(receipt)),
            _prop(f"{PROPERTY_NAMESPACE}:receipt.verifier.cli", "npx @veritasacta/verify"),
            _prop(f"{PROPERTY_NAMESPACE}:receipt.verifier.spec", RECEIPT_PROTOCOL_URL),
        ]
    )

    return out


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _prop(name: str, value: str) -> dict[str, str]:
    """CycloneDX properties are flat name/value pairs."""
    return {"name": name, "value": value}


def _coerce_commands(action: dict[str, Any]) -> list[dict[str, str]]:
    """Convert an sb-runtime action into CycloneDX command entries."""
    kind = action.get("kind", "")
    target = action.get("target", "")
    args = action.get("args", []) or []
    argv = [target, *(a for a in args if isinstance(a, str))]
    if not target:
        return []
    return [{"executed": " ".join(argv).strip(), "properties": [_prop("action.kind", kind)]}]


def _canonical_hash(receipt: dict[str, Any]) -> str:
    """
    SHA-256 of the canonical JSON of the receipt payload. The `payload`
    sub-object is the signed body; canonicalization matches RFC 8785 /
    the sb-runtime `jcs_canonical` implementation (sorted keys, no WS).
    """
    payload = receipt.get("payload", {})
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ─── CLI ─────────────────────────────────────────────────────────────────────


def _cli() -> int:
    parser = argparse.ArgumentParser(
        description="Attach an sb-runtime / protect-mcp receipt to a CycloneDX BOM "
        "using existing 1.6 spec fields (formulation.workflow + properties)."
    )
    parser.add_argument("--bom", required=True, type=Path, help="Input CycloneDX JSON BOM")
    parser.add_argument("--receipt", required=True, type=Path, help="Input receipt JSON")
    parser.add_argument("--out", required=True, type=Path, help="Output enriched BOM JSON")
    args = parser.parse_args()

    bom = json.loads(args.bom.read_text(encoding="utf-8"))
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    enriched = enrich_bom(bom, receipt)
    args.out.write_text(json.dumps(enriched, indent=2, sort_keys=False), encoding="utf-8")
    print(
        f"wrote {args.out}: +1 formulation.workflow, +{len([p for p in enriched.get('properties', []) if p['name'].startswith(PROPERTY_NAMESPACE)])} properties",
        file=sys.stderr,
    )
    return 0


# ─── Minimal smoke test ──────────────────────────────────────────────────────


def _smoke() -> None:
    """Built-in smoke test matching the AGT example's --smoke convention."""
    sample_bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "name": "left-pad", "version": "1.3.0"},
        ],
    }
    sample_receipt = {
        "payload": {
            "type": "scopeblind.receipt.v1",
            "decision": "allow",
            "action": {"kind": "exec", "target": "/usr/bin/npm"},
            "policy_id": "dev-safe@v3",
            "sequence": 47,
            "prev_hash": "sha256:a8f3c9d2e1b7465f",
            "timestamp": "2026-04-17T02:14:53Z",
            "context": {"args": ["install"]},
        },
        "signature": "deadbeef" * 16,  # 64 hex chars, shape-valid
        "pubkey": "cafebabe" * 8,
    }
    enriched = enrich_bom(sample_bom, sample_receipt)

    # Assertions that the output is still a valid-shape CycloneDX 1.6 document
    assert enriched["bomFormat"] == "CycloneDX"
    assert enriched["specVersion"] == "1.6"
    assert len(enriched["formulation"]) == 1
    workflow = enriched["formulation"][0]["workflows"][0]
    assert workflow["taskTypes"] == ["build"]
    assert any(p["name"] == "agent.policy_id" for p in workflow["properties"])

    top_props = enriched["properties"]
    assert any(p["name"].endswith("signature.alg") and p["value"] == "Ed25519" for p in top_props)
    assert any(p["name"].endswith("receipt.protocol") for p in workflow["properties"])

    print("smoke ok: CycloneDX 1.6 structure preserved; receipt attached as workflow + properties")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--smoke":
        _smoke()
    else:
        sys.exit(_cli())
