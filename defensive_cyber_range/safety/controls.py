'''Safety and Governance Controls for the Defensive Cyber Range Simulation Platform.

Implements:
- NetworkIsolationGuard
- ToolAllowlistGuard
- HumanApprovalGate
- KillSwitch
- ImmutableAuditLogger (SHA-256 hash-chained JSONL)
- PromptSanitizer
- SafetyController (unified facade)
'''

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any


class SafetyViolationError(RuntimeError):
    '''Raised when any safety policy, isolation rule, or kill switch is violated.'''


class KillSwitch:
    '''Emergency halt switch capable of stopping agent execution immediately.'''

    def __init__(self, sentinel_file: Path | None = None):
        self._tripped = False
        self._reason = ""
        self.sentinel_file = sentinel_file

    def trip(self, reason: str) -> None:
        self._tripped = True
        self._reason = reason
        if self.sentinel_file:
            self.sentinel_file.parent.mkdir(parents=True, exist_ok=True)
            self.sentinel_file.write_text(reason, encoding="utf-8")

    def reset(self) -> None:
        self._tripped = False
        self._reason = ""
        if self.sentinel_file and self.sentinel_file.exists():
            self.sentinel_file.unlink()

    def assert_active(self) -> None:
        if self._tripped:
            raise SafetyViolationError(f"KillSwitch tripped: {self._reason}")
        if self.sentinel_file and self.sentinel_file.exists():
            reason = self.sentinel_file.read_text(encoding="utf-8").strip()
            raise SafetyViolationError(f"KillSwitch sentinel file present: {reason}")


class NetworkIsolationGuard:
    '''Ensures all simulation targets remain strictly local/sandboxed with zero external egress.'''

    ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "mock-enterprise", "cyber-range-orchestrator"}

    def validate_target_host(self, host: str) -> bool:
        normalized = host.strip().lower().split(":")[0]
        if normalized not in self.ALLOWED_HOSTS:
            raise SafetyViolationError(
                f"NetworkIsolationGuard blocked non-isolated host '{host}'. Allowed: {sorted(self.ALLOWED_HOSTS)}"
            )
        return True


class ToolAllowlistGuard:
    '''Enforces per-agent operation allowlists and filesystem sandbox path confinement.'''

    ALLOWED_AGENT_OPERATIONS: dict[str, set[str]] = {
        "SurfaceMapperAgent": {"ast_surface_scan"},
        "StaticVulnerabilityAuditorAgent": {"static_code_audit"},
        "RiskPrioritizerAgent": {"prioritize_findings"},
        "ComplianceVerifierAgent": {"verify_remediations"},
        "AnalysisReporterAgent": {"build_analysis_report"},
        "DetectionAgent": {"correlate_telemetry_and_findings"},
        "TriageAgent": {"triage_alerts"},
        "RootCauseAgent": {"inspect_source_ast"},
        "PatchGenerationAgent": {"synthesize_patch"},
        "ValidationTestingAgent": {"validate_patch_in_staging"},
        "DeploymentRollbackAgent": {"deploy_patch"},
        "SimulationOrchestrator": {"initialize_sandbox", "run_round", "finalize_simulation"},
    }

    def __init__(self, sandbox_root: Path):
        self.sandbox_root = sandbox_root.resolve()

    def verify_agent_operation(self, agent_name: str, operation: str) -> None:
        allowed_ops = self.ALLOWED_AGENT_OPERATIONS.get(agent_name, set())
        if operation not in allowed_ops:
            raise SafetyViolationError(
                f"ToolAllowlistGuard blocked unauthorized operation '{operation}' by agent '{agent_name}'."
            )

    def validate_sandbox_path(self, target_path: Path) -> Path:
        resolved = target_path.resolve()
        if not resolved.is_relative_to(self.sandbox_root):
            raise SafetyViolationError(
                f"Path confinement violation: '{resolved}' is outside sandbox '{self.sandbox_root}'."
            )
        return resolved


class PromptSanitizer:
    '''Neutralizes prompt-injection patterns in untrusted code comments, logs, or inputs.'''

    INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"system\s+override", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
        re.compile(r"<\|im_start\|>|<\|endoftext\|>", re.IGNORECASE),
        re.compile(r"disregard\s+safety\s+guidelines", re.IGNORECASE),
    ]

    def sanitize(self, text: str) -> tuple[str, list[str]]:
        warnings: list[str] = []
        sanitized = text
        for pattern in self.INJECTION_PATTERNS:
            if pattern.search(sanitized):
                warnings.append(f"Matched prompt-injection pattern: {pattern.pattern}")
                sanitized = pattern.sub("[REDACTED_PROMPT_INJECTION_ATTEMPT]", sanitized)
        return sanitized, warnings


class HumanApprovalGate:
    '''Governance gate before applying candidate patches to the target workspace.'''

    def __init__(self, mode: str = "auto_low_risk"):
        self.mode = mode  # "auto_low_risk" or "deny_all"

    def evaluate(self, patch: Any, validation: Any) -> tuple[bool, str]:
        if self.mode == "deny_all":
            return False, "Policy mode set to deny_all"
        if not validation.passed:
            return False, "Staging validation failed"
        if not patch.file_path.startswith("mock_enterprise/"):
            return False, f"File '{patch.file_path}' outside approved module scope"
        return True, f"Approved under '{self.mode}' policy (100% staging tests passed)"


class ImmutableAuditLogger:
    '''Append-only SHA-256 hash-chained audit logger for tamper-evident governance.'''

    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self.GENESIS_HASH
        if self.log_path.exists():
            lines = [ln for ln in self.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                last_record = json.loads(lines[-1])
                self._last_hash = last_record["entry_hash"]

    def log(self, actor: str, action: str, details: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "details": details,
            "prev_hash": self._last_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        record = {**payload, "entry_hash": entry_hash}
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        self._last_hash = entry_hash
        return record

    def verify_chain(self) -> tuple[bool, int]:
        if not self.log_path.exists():
            return True, 0
        lines = [ln for ln in self.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        expected_prev = self.GENESIS_HASH
        for idx, line in enumerate(lines, start=1):
            record = json.loads(line)
            if record.get("prev_hash") != expected_prev:
                return False, idx
            check_payload = {
                "timestamp": record["timestamp"],
                "actor": record["actor"],
                "action": record["action"],
                "details": record["details"],
                "prev_hash": record["prev_hash"],
            }
            canonical = json.dumps(check_payload, sort_keys=True, separators=(",", ":"))
            computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if computed != record.get("entry_hash"):
                return False, idx
            expected_prev = computed
        return True, len(lines)


class SafetyController:
    '''Unified safety and governance facade injected into all agents and orchestrator steps.'''

    def __init__(
        self,
        sandbox_root: Path,
        audit_log_path: Path,
        approval_mode: str = "auto_low_risk",
        sentinel_file: Path | None = None,
    ):
        self.sandbox_root = sandbox_root.resolve()
        self.kill_switch = KillSwitch(sentinel_file=sentinel_file)
        self.network_guard = NetworkIsolationGuard()
        self.tool_guard = ToolAllowlistGuard(self.sandbox_root)
        self.sanitizer = PromptSanitizer()
        self.approval_gate = HumanApprovalGate(mode=approval_mode)
        self.audit_logger = ImmutableAuditLogger(audit_log_path)

    def check_operation(
        self,
        agent_name: str,
        operation: str,
        target_path: Path | None = None,
        target_host: str = "localhost",
    ) -> None:
        self.kill_switch.assert_active()
        self.network_guard.validate_target_host(target_host)
        self.tool_guard.verify_agent_operation(agent_name, operation)
        if target_path is not None:
            self.tool_guard.validate_sandbox_path(target_path)
        self.audit_logger.log(
            actor=agent_name,
            action=operation,
            details={
                "target_path": str(target_path.resolve()) if target_path else None,
                "target_host": target_host,
            },
        )

    def validate_path(self, target_path: Path) -> Path:
        self.kill_switch.assert_active()
        return self.tool_guard.validate_sandbox_path(target_path)

    def request_patch_approval(self, patch: Any, validation: Any) -> tuple[bool, str]:
        self.kill_switch.assert_active()
        approved, reason = self.approval_gate.evaluate(patch, validation)
        self.audit_logger.log(
            actor="HumanApprovalGate",
            action="evaluate_patch",
            details={
                "patch_id": patch.patch_id,
                "cwe_id": patch.cwe_id,
                "approved": approved,
                "reason": reason,
            },
        )
        return approved, reason
