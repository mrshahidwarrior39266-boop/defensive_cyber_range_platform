'''Judge & Scoring Engine for evaluating Analysis and Defense Swarm performance.'''

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

from agents.models import (
    CandidatePatch,
    DeploymentReceipt,
    SecurityAlert,
    SecurityFinding,
    ValidationReport,
    VerificationResult,
)


@dataclass
class RoundScorecard:
    round_num: int
    ground_truth_total: int
    findings_discovered: int
    discovery_recall_pct: float
    alerts_triggered: int
    mean_time_to_detect_ms: float
    patches_generated: int
    patches_validated: int
    patches_deployed: int
    verified_remediated: int
    patch_correctness_pct: float
    regression_pass_rate_pct: float
    mean_time_to_remediate_ms: float
    security_posture_score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScoringEngine:
    '''Computes quantitative security engineering metrics against ground truth.'''

    def __init__(self, ground_truth_path: Path):
        raw = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        self.ground_truth_vulns = raw.get("seeded_vulnerabilities", [])
        self.ground_truth_cwe_set = {v["cwe_id"] for v in self.ground_truth_vulns}

    def score_round(
        self,
        round_num: int,
        findings: list[SecurityFinding],
        alerts: list[SecurityAlert],
        patches: list[CandidatePatch],
        validations: list[ValidationReport],
        deployments: list[DeploymentReceipt],
        verifications: list[VerificationResult],
        cumulative_remediated_cwes: set[str],
    ) -> RoundScorecard:
        gt_total = len(self.ground_truth_cwe_set)
        discovered_cwes = {f.cwe_id for f in findings}

        # Discovery recall against remaining unpatched vulnerabilities
        expected_active_cwes = self.ground_truth_cwe_set - (cumulative_remediated_cwes - discovered_cwes)
        if expected_active_cwes:
            recall_pct = round(100.0 * len(discovered_cwes & expected_active_cwes) / len(expected_active_cwes), 2)
        else:
            recall_pct = 100.0

        # Mean Time-To-Detect (TTD)
        finding_by_id = {f.finding_id: f for f in findings}
        ttd_samples = [
            max(0.1, a.triggered_at_ms - finding_by_id[a.finding_id].detected_at_ms)
            for a in alerts
            if a.finding_id in finding_by_id
        ]
        mttd_ms = round(sum(ttd_samples) / len(ttd_samples), 2) if ttd_samples else 0.0

        # Mean Time-To-Remediate (TTR)
        alert_by_cwe = {a.cwe_id: a for a in alerts}
        ttr_samples = [
            max(0.5, d.deployed_at_ms - alert_by_cwe[d.cwe_id].triggered_at_ms)
            for d in deployments
            if d.deployed and d.cwe_id in alert_by_cwe
        ]
        mttr_ms = round(sum(ttr_samples) / len(ttr_samples), 2) if ttr_samples else 0.0

        validated_count = sum(1 for v in validations if v.passed)
        deployed_count = sum(1 for d in deployments if d.deployed)
        remediated_count = sum(1 for v in verifications if v.remediated)

        regression_rate = (
            round(100.0 * validated_count / len(validations), 2) if validations else 100.0
        )
        patch_correctness = (
            round(100.0 * remediated_count / len(patches), 2) if patches else 100.0
        )

        # Posture score: percentage of ground-truth vulnerabilities remediated across the environment
        posture_score = round(100.0 * len(cumulative_remediated_cwes) / gt_total, 2) if gt_total else 100.0

        return RoundScorecard(
            round_num=round_num,
            ground_truth_total=gt_total,
            findings_discovered=len(findings),
            discovery_recall_pct=recall_pct,
            alerts_triggered=len(alerts),
            mean_time_to_detect_ms=mttd_ms,
            patches_generated=len(patches),
            patches_validated=validated_count,
            patches_deployed=deployed_count,
            verified_remediated=remediated_count,
            patch_correctness_pct=patch_correctness,
            regression_pass_rate_pct=regression_rate,
            mean_time_to_remediate_ms=mttr_ms,
            security_posture_score=posture_score,
        )
