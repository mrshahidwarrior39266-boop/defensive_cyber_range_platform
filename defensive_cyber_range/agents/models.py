'''Shared typed data models for inter-agent communication and state tracking.'''

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class EndpointSurface:
    file_path: str
    function_name: str
    endpoint: str
    parameters: list[str]
    has_auth_guard: bool
    line_number: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityFinding:
    finding_id: str
    vuln_id: str
    cwe_id: str
    title: str
    severity: str
    cvss_score: float
    file_path: str
    function_name: str
    endpoint: str
    line_number: int
    evidence_snippet: str
    description: str
    remediation_guidance: str
    detected_at_ms: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAlert:
    alert_id: str
    finding_id: str
    cwe_id: str
    severity: str
    endpoint: str
    file_path: str
    function_name: str
    line_number: int
    triggered_at_ms: float
    correlated_telemetry_events: int
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TriagedIncident:
    incident_id: str
    alert: SecurityAlert
    finding: SecurityFinding
    priority_rank: int
    sla_target_ms: float
    assigned_module: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RootCauseAnalysis:
    incident_id: str
    cwe_id: str
    file_path: str
    function_name: str
    line_number: int
    vulnerable_block: str
    ast_node_type: str
    root_cause_explanation: str
    remediation_contract: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CandidatePatch:
    patch_id: str
    incident_id: str
    cwe_id: str
    file_path: str
    original_snippet: str
    patched_snippet: str
    unified_diff: str
    rationale: str
    generated_at_ms: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationReport:
    patch_id: str
    incident_id: str
    syntax_valid: bool
    functional_tests_passed: bool
    security_checks_passed: bool
    test_count: int
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.syntax_valid and self.functional_tests_passed and self.security_checks_passed

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["passed"] = self.passed
        return data


@dataclass
class DeploymentReceipt:
    deployment_id: str
    patch_id: str
    incident_id: str
    cwe_id: str
    file_path: str
    pre_patch_sha256: str
    post_patch_sha256: str
    backup_path: str
    deployed: bool
    rolled_back: bool
    deployed_at_ms: float
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    finding_id: str
    cwe_id: str
    file_path: str
    remediated: bool
    verification_method: str
    details: str
    verified_at_ms: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
