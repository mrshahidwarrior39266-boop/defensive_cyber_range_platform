'''Closed-Loop Simulation Orchestrator.

Coordinates the multi-agent workflow across rounds:
1. Sandbox Workspace Initialization
2. Security Analysis Swarm (Surface Mapping -> Static Audit -> Risk Prioritization -> Reporting)
3. Defensive Response Swarm (Detection -> Triage -> Root Cause -> Patch Generation -> Staging Validation -> Atomic Deployment)
4. Compliance Re-Verification
5. Judge Scoring, Shared Memory Persistence & Audit Trail Verification
'''

from pathlib import Path
import json
import shutil
from typing import Any

from agents.analysis_swarm import (
    AnalysisReporterAgent,
    ComplianceVerifierAgent,
    RiskPrioritizerAgent,
    StaticVulnerabilityAuditorAgent,
    SurfaceMapperAgent,
)
from agents.defense_swarm import (
    DeploymentRollbackAgent,
    DetectionAgent,
    PatchGenerationAgent,
    RootCauseAgent,
    TriageAgent,
    ValidationTestingAgent,
)
from agents.llm_adapter import ReasoningAdapter
from mock_enterprise.telemetry import TelemetryCollector
from orchestrator.memory import SharedMemoryStore
from orchestrator.scoring import RoundScorecard, ScoringEngine
from safety.controls import SafetyController


class SimulationOrchestrator:
    '''Main orchestrator managing closed-loop defensive cyber range rounds.'''

    def __init__(self, project_root: Path, output_dir: Path, approval_mode: str = "auto_low_risk"):
        self.project_root = project_root.resolve()
        self.output_dir = output_dir.resolve()
        self.workspace_dir = self.output_dir / "workspace"
        self.backup_dir = self.workspace_dir / "backups"
        self.audit_log_path = self.output_dir / "audit_trail.jsonl"
        self.memory_db_path = self.output_dir / "simulation_memory.db"

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        self.safety = SafetyController(
            sandbox_root=self.workspace_dir,
            audit_log_path=self.audit_log_path,
            approval_mode=approval_mode,
            sentinel_file=self.output_dir / "KILL_SWITCH.lock",
        )
        self.telemetry = TelemetryCollector()
        self.memory = SharedMemoryStore(self.memory_db_path)
        self.reasoning = ReasoningAdapter(self.safety.sanitizer)

        # Instantiate Analysis Swarm
        self.surface_mapper = SurfaceMapperAgent()
        self.auditor = StaticVulnerabilityAuditorAgent()
        self.prioritizer = RiskPrioritizerAgent()
        self.verifier = ComplianceVerifierAgent(self.surface_mapper, self.auditor)
        self.reporter = AnalysisReporterAgent()

        # Instantiate Defense Swarm
        self.detector = DetectionAgent()
        self.triager = TriageAgent()
        self.rca_agent = RootCauseAgent()
        self.patch_gen = PatchGenerationAgent(self.reasoning)
        self.validator = ValidationTestingAgent()
        self.deployer = DeploymentRollbackAgent()

        self.cumulative_remediated_cwes: set[str] = set()
        self._initialize_sandbox()
        self.scoring = ScoringEngine(self.workspace_dir / "mock_enterprise" / "ground_truth.json")

    def _initialize_sandbox(self) -> None:
        self.safety.check_operation("SimulationOrchestrator", "initialize_sandbox", self.workspace_dir)
        src_pkg = self.project_root / "mock_enterprise"
        dst_pkg = self.workspace_dir / "mock_enterprise"
        if dst_pkg.exists():
            shutil.rmtree(dst_pkg)
        shutil.copytree(src_pkg, dst_pkg)

    def run_round(self, round_num: int) -> dict[str, Any]:
        self.safety.check_operation("SimulationOrchestrator", "run_round", self.workspace_dir)

        # Phase 1: Analysis Swarm maps surface & audits code
        surfaces = self.surface_mapper.map_workspace(self.workspace_dir, self.safety)
        raw_findings = self.auditor.audit_workspace(self.workspace_dir, surfaces, self.safety)
        findings = self.prioritizer.prioritize(raw_findings, self.safety)
        analysis_report = self.reporter.build_report(
            round_num, surfaces, findings, self.telemetry, self.safety
        )

        # Phase 2: Defense Swarm detects & triages alerts
        alerts = self.detector.detect(findings, self.telemetry, self.safety)
        incidents = self.triager.triage(alerts, findings, self.safety)

        # Phase 3: Root-Cause Analysis, Patch Synthesis, Staging Validation, Deployment
        rcas = []
        patches = []
        validations = []
        deployments = []

        for incident in incidents:
            rca = self.rca_agent.analyze(incident, self.workspace_dir, self.safety)
            rcas.append(rca)

            patch = self.patch_gen.generate_patch(rca, self.workspace_dir, self.safety)
            patches.append(patch)

            validation = self.validator.validate(patch, self.workspace_dir, self.safety)
            validations.append(validation)

            receipt = self.deployer.deploy(
                patch=patch,
                validation=validation,
                workspace_dir=self.workspace_dir,
                backup_dir=self.backup_dir,
                telemetry=self.telemetry,
                safety=self.safety,
            )
            deployments.append(receipt)

        # Phase 4: Compliance Re-Verification
        verifications = self.verifier.verify_remediations(
            self.workspace_dir, findings, self.safety
        )
        for ver in verifications:
            if ver.remediated:
                self.cumulative_remediated_cwes.add(ver.cwe_id)

        # Phase 5: Scoring & Shared Memory Persistence
        scorecard: RoundScorecard = self.scoring.score_round(
            round_num=round_num,
            findings=findings,
            alerts=alerts,
            patches=patches,
            validations=validations,
            deployments=deployments,
            verifications=verifications,
            cumulative_remediated_cwes=self.cumulative_remediated_cwes,
        )

        lessons = []
        ver_by_cwe = {v.cwe_id: v for v in verifications}
        for patch in patches:
            ver = ver_by_cwe.get(patch.cwe_id)
            remediated = bool(ver and ver.remediated)
            lessons.append(
                {
                    "cwe_id": patch.cwe_id,
                    "file_path": patch.file_path,
                    "patch_id": patch.patch_id,
                    "remediated": remediated,
                    "lesson_summary": patch.rationale,
                }
            )

        self.memory.record_round(
            round_num=round_num,
            findings_discovered=scorecard.findings_discovered,
            patches_deployed=scorecard.patches_deployed,
            verified_remediated=scorecard.verified_remediated,
            posture_score=scorecard.security_posture_score,
            lessons=lessons,
        )

        return {
            "round": round_num,
            "analysis_report": analysis_report,
            "alerts": [a.to_dict() for a in alerts],
            "root_causes": [r.to_dict() for r in rcas],
            "patches": [p.to_dict() for p in patches],
            "validations": [v.to_dict() for v in validations],
            "deployments": [d.to_dict() for d in deployments],
            "verifications": [v.to_dict() for v in verifications],
            "scorecard": scorecard.to_dict(),
        }

    def run_simulation(self, max_rounds: int = 2) -> dict[str, Any]:
        round_results = []
        for r in range(1, max_rounds + 1):
            round_results.append(self.run_round(r))

        self.safety.check_operation("SimulationOrchestrator", "finalize_simulation", self.workspace_dir)
        chain_valid, audit_entries = self.safety.audit_logger.verify_chain()
        memory_snapshot = self.memory.export_snapshot()
        prom_metrics = self.telemetry.export_prometheus_metrics()

        summary = {
            "platform": "Defensive Cyber Range Simulation Platform",
            "total_rounds": max_rounds,
            "final_posture_score": round_results[-1]["scorecard"]["security_posture_score"],
            "remediated_cwes": sorted(self.cumulative_remediated_cwes),
            "audit_chain_valid": chain_valid,
            "audit_entries_count": audit_entries,
            "rounds": round_results,
            "shared_memory": memory_snapshot,
        }

        # Save JSON & Markdown summary reports + Prometheus metrics
        (self.output_dir / "simulation_report.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
        (self.output_dir / "prometheus_metrics.prom").write_text(
            prom_metrics, encoding="utf-8"
        )
        (self.output_dir / "SIMULATION_SUMMARY.md").write_text(
            self._render_markdown_summary(summary), encoding="utf-8"
        )
        self.memory.close()
        return summary

    def _render_markdown_summary(self, summary: dict[str, Any]) -> str:
        lines = [
            "# Defensive Cyber Range Simulation Summary",
            "",
            f"- **Total Rounds Executed**: {summary['total_rounds']}",
            f"- **Final Security Posture Score**: {summary['final_posture_score']}%",
            f"- **Remediated CWE Classes**: {', '.join(summary['remediated_cwes'])}",
            f"- **Audit Trail Integrity**: {'VERIFIED' if summary['audit_chain_valid'] else 'FAILED'} ({summary['audit_entries_count']} hash-chained entries)",
            "",
            "## Round-by-Round Scorecard",
            "",
            "| Round | Findings | Alerts | Patches Validated | Patches Deployed | Verified Fixed | Mean TTD (ms) | Mean TTR (ms) | Posture Score |",
            "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for r in summary["rounds"]:
            sc = r["scorecard"]
            lines.append(
                f"| Round {sc['round_num']} | {sc['findings_discovered']} | {sc['alerts_triggered']} | "
                f"{sc['patches_validated']} | {sc['patches_deployed']} | {sc['verified_remediated']} | "
                f"{sc['mean_time_to_detect_ms']} | {sc['mean_time_to_remediate_ms']} | {sc['security_posture_score']}% |"
            )
        return "\n".join(lines) + "\n"
