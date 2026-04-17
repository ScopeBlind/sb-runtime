# Copyright (c) ScopeBlind Contributors
# Licensed under the MIT License.
"""
SbRuntimeSkill — a drop-in governance skill for Microsoft's Agent Governance
Toolkit that delegates policy evaluation + enforcement + receipt emission to
the `sb` binary from https://github.com/ScopeBlind/sb-runtime.

Mirrors the public interface of
``openshell_agentmesh.skill.GovernanceSkill`` so teams can swap
providers via configuration alone — no agent code changes required.

STATUS
------
Design-partner preview. The interface here tracks the shape of
``GovernanceSkill`` as of AGT commit HEAD ~2026-04-17. If upstream changes the
``check_policy`` signature we will follow it; this file exists to propose
the integration contract and invite feedback on
https://github.com/microsoft/agent-governance-toolkit/issues/748
and https://github.com/ScopeBlind/sb-runtime/issues.

THREAT MODEL DELTA vs. OpenShell
--------------------------------
OpenShell gives you: Landlock fs + seccomp syscalls + OPA network proxy via
Docker + k3s + gateway. sb-runtime gives you: Landlock fs + seccomp syscalls +
Cedar policy + Ed25519-signed receipts, in a single ~8 MB binary with no
container runtime. Use sb-runtime where OpenShell is too heavy (CI, edge,
dev laptops). Use OpenShell where you need full network-proxy interception or
multi-tenant k3s isolation.

USAGE
-----
>>> from sb_runtime_skill import SbRuntimeSkill
>>> skill = SbRuntimeSkill(
...     policy_path=Path("policies/dev-safe.cedar"),
...     receipts_dir=Path(".receipts"),
... )
>>> decision = skill.check_policy(
...     action="exec",
...     context={"command": "/usr/bin/cat", "args": ["/etc/hosts"]},
... )
>>> decision.allowed
True
>>> decision.policy_name
'dev-safe'
>>> # Every check emits a signed receipt in receipts_dir; verify offline:
>>> # $ sb verify .receipts/
>>> # ✓ 1 receipts verified

COMPAT
------
Python >= 3.10 (matches AGT's baseline).
Requires the `sb` binary on PATH. Install:
    curl -fsSL https://get.scopeblind.com/sb | sh   # planned; v0.1: `cargo install`
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ─── AGT-compatible decision type ─────────────────────────────────────────────
#
# Field-for-field compatible with openshell_agentmesh.skill.PolicyDecision so
# downstream code that inspects decisions (trust scoring, audit exporters,
# dashboards) works unchanged.


@dataclass
class PolicyDecision:
    allowed: bool
    action: str
    reason: str
    policy_name: Optional[str] = None
    trust_score: float = 0.0
    # Extension beyond OpenShell's PolicyDecision: a pointer to the signed
    # receipt file for this decision. Receipt is present regardless of
    # allow/deny.
    receipt_path: Optional[Path] = None


# ─── Errors ───────────────────────────────────────────────────────────────────


class SbRuntimeNotInstalled(RuntimeError):
    """Raised when the `sb` binary is not on PATH."""


class SbRuntimeCallFailed(RuntimeError):
    """Raised when the `sb` subprocess exits with an unexpected code."""


# ─── Skill ────────────────────────────────────────────────────────────────────


class SbRuntimeSkill:
    """
    Drop-in governance skill backed by the `sb` binary.

    Parameters
    ----------
    policy_path:
        Path to a Cedar policy file (`*.cedar`). Required.
    receipts_dir:
        Directory where signed receipts accumulate. One JSON file per
        decision, numbered by chain sequence.
    sandbox_profile_path:
        Optional path to a JSON sandbox profile. If omitted `sb` uses its
        built-in `read_only_transform` profile (conservative default).
    sb_bin:
        Path to the `sb` binary. Defaults to `shutil.which("sb")`.
    allow_unsandboxed:
        If True, pass `--allow-unsandboxed` — only Cedar + receipts fire,
        no OS isolation. Useful on platforms where v0.1 doesn't yet have
        a native backend (macOS, Windows, Linux aarch64). **Do not use in
        production** — the sandbox is the whole point.
    trust_threshold:
        Parity with OpenShell; reserved for future trust-score integration.
    """

    def __init__(
        self,
        policy_path: Path,
        receipts_dir: Path,
        sandbox_profile_path: Optional[Path] = None,
        sb_bin: Optional[Path] = None,
        allow_unsandboxed: bool = False,
        trust_threshold: float = 0.5,
    ) -> None:
        self.policy_path = Path(policy_path)
        self.receipts_dir = Path(receipts_dir)
        self.sandbox_profile_path = Path(sandbox_profile_path) if sandbox_profile_path else None
        self.allow_unsandboxed = allow_unsandboxed
        self.trust_threshold = trust_threshold

        resolved = sb_bin or shutil.which("sb")
        if resolved is None:
            raise SbRuntimeNotInstalled(
                "Could not find `sb` on PATH. Install from "
                "https://github.com/ScopeBlind/sb-runtime or pass sb_bin=Path(...)."
            )
        self.sb_bin: Path = Path(resolved)

        self._trust_scores: dict[str, float] = {}
        self._audit_log: list[dict[str, Any]] = []

        self.receipts_dir.mkdir(parents=True, exist_ok=True)

    # ─── Core interface (matches GovernanceSkill) ────────────────────────────

    def check_policy(
        self,
        action: str,
        context: Optional[dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Evaluate a proposed action against the Cedar policy.

        For ``action == "exec"``, ``context`` must carry:
            - ``command``: str    — the target executable path
            - ``args``:    list   — argv tail (optional)
            - ``agent_did``: str  — optional, used for trust scoring

        Other action types (``"open"``, ``"connect"``) are reserved for
        sb-runtime v0.2 and currently return a Deny decision.
        """
        context = context or {}
        agent_did = context.get("agent_did", "unknown")

        if action != "exec":
            decision = PolicyDecision(
                allowed=False,
                action=action,
                reason=f"action '{action}' is v0.2+ in sb-runtime; v0.1 supports exec only",
                policy_name=None,
                trust_score=self.get_trust_score(agent_did),
            )
            self._log(decision, agent_did, context)
            return decision

        command = context.get("command")
        if not isinstance(command, str):
            raise ValueError("context['command'] is required and must be a string for action='exec'")
        args = [str(a) for a in context.get("args", [])]

        # Call `sb exec` in dry-run mode: evaluate policy, emit receipt, then
        # return without execve. (In AGT, the *enforcement* exec usually
        # happens in a separate step; check_policy is the pure-evaluation
        # call. We model that as `sb exec --dry-run` — landing in v0.1.1.
        # Until then we read the decision from the receipt the `sb` binary
        # emits regardless of the branch.)
        cmd = [
            str(self.sb_bin),
            "exec",
            "--policy",
            str(self.policy_path),
            "--receipts",
            str(self.receipts_dir),
        ]
        if self.sandbox_profile_path:
            cmd += ["--sandbox", str(self.sandbox_profile_path)]
        if self.allow_unsandboxed:
            cmd += ["--allow-unsandboxed"]
        cmd += ["--", command, *args]

        # `sb exec` exits 2 on deny, 0 (and replaces the process) on allow.
        # In this Skill we want to *check* policy without actually running
        # the command — the preferred approach once sb-runtime v0.1.1 lands
        # `--dry-run` is:
        #     cmd.insert(2, "--dry-run")
        # For v0.1.0-alpha.1 we work around by reading the receipt the `sb`
        # binary writes before it attempts execve. When `--dry-run` lands
        # this class will switch to that and this shim stays API-compatible.
        #
        # Open question for the AGT community: is "check without run" the
        # right mental model for this skill, or should `check_policy` also
        # enforce (i.e. call execve)?  See issue #748.
        before = self._latest_receipt_path()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                env={"SB_DRY_RUN": "1"},  # honored by sb v0.1.1+; noop on v0.1.0
            )
        except FileNotFoundError as e:
            raise SbRuntimeNotInstalled(f"sb binary not executable: {e}") from e

        after = self._latest_receipt_path()
        receipt = self._read_receipt(after) if after != before else None

        if receipt is None:
            raise SbRuntimeCallFailed(
                f"sb exec produced no receipt. stdout={proc.stdout!r} stderr={proc.stderr!r}"
            )

        allowed = receipt["payload"]["decision"] == "allow"
        decision = PolicyDecision(
            allowed=allowed,
            action="exec",
            reason=_short_reason(receipt, proc.stderr),
            policy_name=receipt["payload"].get("policy_id"),
            trust_score=self.get_trust_score(agent_did),
            receipt_path=after,
        )
        self._log(decision, agent_did, context)
        return decision

    # ─── Trust scoring (parity with OpenShell) ────────────────────────────────

    def get_trust_score(self, agent_did: str) -> float:
        return self._trust_scores.get(agent_did, 1.0)

    def adjust_trust(self, agent_did: str, delta: float) -> float:
        current = self.get_trust_score(agent_did)
        new_score = max(0.0, min(1.0, current + delta))
        self._trust_scores[agent_did] = new_score
        return new_score

    # ─── Audit (parity with OpenShell) ────────────────────────────────────────

    def log_action(
        self,
        action: str,
        decision: str,
        agent_did: str = "unknown",
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "decision": decision,
            "agent_did": agent_did,
            "trust_score": self.get_trust_score(agent_did),
            "context": context or {},
        }
        self._audit_log.append(entry)
        return entry

    def get_audit_log(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._audit_log[-limit:]

    # ─── sb-runtime-specific additions (beyond OpenShell) ────────────────────

    def verify_chain(self) -> bool:
        """
        Verify the entire receipt chain offline. Returns True on a clean
        chain; raises `SbRuntimeCallFailed` on any tamper or break.

        This is the property OpenShell can't give you — the chain is
        cryptographically tamper-evident, and any third party can
        re-verify without trusting the Skill or ScopeBlind at all.
        """
        proc = subprocess.run(
            [str(self.sb_bin), "verify", str(self.receipts_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise SbRuntimeCallFailed(f"sb verify failed: {proc.stderr.strip()}")
        return True

    # ─── Internal ────────────────────────────────────────────────────────────

    def _latest_receipt_path(self) -> Optional[Path]:
        if not self.receipts_dir.exists():
            return None
        jsons = sorted(self.receipts_dir.glob("*.json"))
        return jsons[-1] if jsons else None

    def _read_receipt(self, path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    def _log(
        self,
        decision: PolicyDecision,
        agent_did: str,
        context: dict[str, Any],
    ) -> None:
        self.log_action(
            action=decision.action,
            decision="allow" if decision.allowed else "deny",
            agent_did=agent_did,
            context=context,
        )


def _short_reason(receipt: dict[str, Any], stderr: str) -> str:
    """Extract a human-readable reason from the receipt + sb stderr."""
    decision = receipt["payload"]["decision"]
    if decision == "allow":
        return f"allowed by policy {receipt['payload'].get('policy_id', '?')}"
    # sb prints "sb: denied by policy: ..." on the deny path.
    for line in stderr.splitlines():
        if "denied by policy:" in line:
            return line.split("denied by policy:", 1)[1].strip()
    return f"denied by policy {receipt['payload'].get('policy_id', '?')}"


# ─── __main__: quick smoke test matching OpenShell's demo shape ──────────────

if __name__ == "__main__":
    import sys
    import tempfile

    if len(sys.argv) > 1 and sys.argv[1] == "--smoke":
        policy = Path(tempfile.mkdtemp()) / "smoke.cedar"
        policy.write_text(
            'permit (principal, action == Action::"exec", '
            'resource == Command::"/bin/echo");\n'
        )
        with tempfile.TemporaryDirectory() as r:
            skill = SbRuntimeSkill(
                policy_path=policy,
                receipts_dir=Path(r),
                allow_unsandboxed=True,
            )
            d1 = skill.check_policy("exec", {"command": "/bin/echo", "args": ["hi"]})
            d2 = skill.check_policy("exec", {"command": "/bin/rm", "args": ["-rf", "/tmp/x"]})
            print("allow case:", d1.allowed, d1.reason)
            print("deny case: ", d2.allowed, d2.reason)
            print("chain ok: ", skill.verify_chain())
