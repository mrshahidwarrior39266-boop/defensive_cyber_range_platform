'''Defensive Response Swarm (Detection, Triage, Root-Cause, Patching, Validation & Rollback).

Implements 6 specialized Blue Team agents:
1. DetectionAgent
2. TriageAgent
3. RootCauseAgent
4. PatchGenerationAgent
5. ValidationTestingAgent
6. DeploymentRollbackAgent
'''

import ast
import difflib
import hashlib
import html
from pathlib import Path
import shutil
import tempfile
import time

from agents.llm_adapter import ReasoningAdapter
from agents.models import (
    CandidatePatch,
    DeploymentReceipt,
    RootCauseAnalysis,
    SecurityAlert,
    SecurityFinding,
    TriagedIncident,
    ValidationReport,
)
from mock_enterprise import database, service
from mock_enterprise.telemetry import TelemetryCollector
from safety.controls import SafetyController


class DetectionAgent:
    '''Agent 1: Correlates telemetry events and static audit findings into security alerts.'''

    name = "DetectionAgent"

    def detect(
        self,
        findings: list[SecurityFinding],
        telemetry: TelemetryCollector,
        safety: SafetyController,
    ) -> list[SecurityAlert]:
        safety.check_operation(self.name, "correlate_telemetry_and_findings")
        alerts: list[SecurityAlert] = []
        for idx, finding in enumerate(findings, start=1):
            now_ms = time.time() * 1000.0
            matching_events = [
                ev for ev in telemetry.events if ev.endpoint == finding.endpoint
            ]
            alert = SecurityAlert(
                alert_id=f"ALERT-{idx:03d}-{finding.cwe_id}",
                finding_id=finding.finding_id,
                cwe_id=finding.cwe_id,
                severity=finding.severity,
                endpoint=finding.endpoint,
                file_path=finding.file_path,
                function_name=finding.function_name,
                line_number=finding.line_number,
                triggered_at_ms=max(now_ms, finding.detected_at_ms + 2.5),
                correlated_telemetry_events=len(matching_events),
                summary=f"[{finding.severity}] {finding.cwe_id} detected on {finding.endpoint} ({finding.file_path}:{finding.line_number})",
            )
            telemetry.record_security_event(
                event_type="alert_triggered",
                endpoint=finding.endpoint,
                metadata={"alert_id": alert.alert_id, "cwe_id": finding.cwe_id},
            )
            alerts.append(alert)
        return alerts


class TriageAgent:
    '''Agent 2: Deduplicates alerts, assigns SLA targets, and prioritizes remediation queue.'''

    name = "TriageAgent"

    def triage(
        self,
        alerts: list[SecurityAlert],
        findings: list[SecurityFinding],
        safety: SafetyController,
    ) -> list[TriagedIncident]:
        safety.check_operation(self.name, "triage_alerts")
        finding_by_id = {f.finding_id: f for f in findings}
        sla_by_severity = {
            "CRITICAL": 1500.0,
            "HIGH": 3000.0,
            "MEDIUM": 5000.0,
            "LOW": 10000.0,
        }
        incidents: list[TriagedIncident] = []
        seen_keys: set[tuple[str, str]] = set()

        for rank, alert in enumerate(alerts, start=1):
            dedup_key = (alert.cwe_id, alert.file_path)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            finding = finding_by_id[alert.finding_id]
            incidents.append(
                TriagedIncident(
                    incident_id=f"INC-{rank:03d}-{alert.cwe_id}",
                    alert=alert,
                    finding=finding,
                    priority_rank=rank,
                    sla_target_ms=sla_by_severity.get(alert.severity, 5000.0),
                    assigned_module=alert.file_path,
                )
            )
        return incidents


class RootCauseAgent:
    '''Agent 3: Isolates the exact vulnerable AST block and source snippet in the sandbox.'''

    name = "RootCauseAgent"

    def analyze(
        self,
        incident: TriagedIncident,
        workspace_dir: Path,
        safety: SafetyController,
    ) -> RootCauseAnalysis:
        target_file = workspace_dir / incident.finding.file_path
        safety.check_operation(self.name, "inspect_source_ast", target_file)
        source = target_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(target_file))

        vulnerable_block = source
        ast_node_type = "Module"

        if incident.finding.function_name != "module_config":
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == incident.finding.function_name:
                    seg = ast.get_source_segment(source, node)
                    if seg:
                        vulnerable_block = seg
                        ast_node_type = "FunctionDef"
                    break

        return RootCauseAnalysis(
            incident_id=incident.incident_id,
            cwe_id=incident.finding.cwe_id,
            file_path=incident.finding.file_path,
            function_name=incident.finding.function_name,
            line_number=incident.finding.line_number,
            vulnerable_block=vulnerable_block,
            ast_node_type=ast_node_type,
            root_cause_explanation=incident.finding.description,
            remediation_contract=incident.finding.remediation_guidance,
        )


class PatchGenerationAgent:
    '''Agent 4: Synthesizes minimal, deterministic code patches and unified diffs.'''

    name = "PatchGenerationAgent"

    def __init__(self, reasoning_adapter: ReasoningAdapter):
        self.reasoning_adapter = reasoning_adapter

    def generate_patch(
        self,
        rca: RootCauseAnalysis,
        workspace_dir: Path,
        safety: SafetyController,
    ) -> CandidatePatch:
        target_file = workspace_dir / rca.file_path
        safety.check_operation(self.name, "synthesize_patch", target_file)
        original_file_content = target_file.read_text(encoding="utf-8")

        def _build_remediated_content() -> str:
            if rca.cwe_id == "CWE-89":
                old_block = (
                    '    query = f"SELECT id, username, email, role, department FROM users WHERE username = \'{username}\'"\n'
                    "    cursor.execute(query)"
                )
                new_block = (
                    '    query = "SELECT id, username, email, role, department FROM users WHERE username = ?"\n'
                    "    cursor.execute(query, (username,))"
                )
                return original_file_content.replace(old_block, new_block, 1)

            if rca.cwe_id == "CWE-862":
                old_block = (
                    '        self.telemetry.record_request("/api/v1/admin/export-confidential", actor=actor, status=200)\n'
                    "        cursor = self.conn.cursor()"
                )
                new_block = (
                    "        if requester_role != 'admin':\n"
                    '            self.telemetry.record_request("/api/v1/admin/export-confidential", actor=actor, status=403)\n'
                    "            raise PermissionError(\"Admin role required to export confidential documents.\")\n"
                    '        self.telemetry.record_request("/api/v1/admin/export-confidential", actor=actor, status=200)\n'
                    "        cursor = self.conn.cursor()"
                )
                return original_file_content.replace(old_block, new_block, 1)

            if rca.cwe_id == "CWE-79":
                old_block = (
                    '        self.telemetry.record_request("/ui/search-banner", actor=actor, status=200)\n'
                    "        return f\"<div class='search-banner'>Active Directory Filter: {filter_label}</div>\""
                )
                new_block = (
                    '        self.telemetry.record_request("/ui/search-banner", actor=actor, status=200)\n'
                    "        safe_label = html.escape(filter_label, quote=True)\n"
                    "        return f\"<div class='search-banner'>Active Directory Filter: {safe_label}</div>\""
                )
                return original_file_content.replace(old_block, new_block, 1)

            if rca.cwe_id == "CWE-489":
                updated = original_file_content.replace("DEBUG_MODE = True", "DEBUG_MODE = False")
                updated = updated.replace("EXPOSE_STACK_TRACES = True", "EXPOSE_STACK_TRACES = False")
                updated = updated.replace(
                    'TOKEN_SIGNING_MODE = "weak_static_secret"',
                    'TOKEN_SIGNING_MODE = "ephemeral_rotatable_key"',
                )
                return updated

            return original_file_content

        patched_content = self.reasoning_adapter.synthesize(
            system_role="Defensive Python Security Patch Synthesizer",
            untrusted_context=rca.vulnerable_block,
            fallback_fn=_build_remediated_content,
        )

        diff_lines = list(
            difflib.unified_diff(
                original_file_content.splitlines(keepends=True),
                patched_content.splitlines(keepends=True),
                fromfile=f"a/{rca.file_path}",
                tofile=f"b/{rca.file_path}",
            )
        )

        return CandidatePatch(
            patch_id=f"PATCH-{rca.incident_id}",
            incident_id=rca.incident_id,
            cwe_id=rca.cwe_id,
            file_path=rca.file_path,
            original_snippet=original_file_content,
            patched_snippet=patched_content,
            unified_diff="".join(diff_lines),
            rationale=f"Remediated {rca.cwe_id} according to contract: {rca.remediation_contract}",
            generated_at_ms=time.time() * 1000.0,
        )


class ValidationTestingAgent:
    '''Agent 5: Validates syntax, functional unit tests, and security invariants in a staging copy.'''

    name = "ValidationTestingAgent"

    def validate(
        self,
        patch: CandidatePatch,
        workspace_dir: Path,
        safety: SafetyController,
    ) -> ValidationReport:
        safety.check_operation(self.name, "validate_patch_in_staging", workspace_dir)
        details: list[str] = []

        # 1. Verify Python AST syntax validity
        try:
            ast.parse(patch.patched_snippet, filename=patch.file_path)
            syntax_valid = True
            details.append("AST syntax check passed.")
        except SyntaxError as exc:
            return ValidationReport(
                patch_id=patch.patch_id,
                incident_id=patch.incident_id,
                syntax_valid=False,
                functional_tests_passed=False,
                security_checks_passed=False,
                test_count=1,
                details=[f"SyntaxError: {exc}"],
            )

        # 2. Create isolated staging directory and execute functional + security regression checks
        with tempfile.TemporaryDirectory(prefix="cyber_range_staging_") as tmp_dir:
            staging_root = Path(tmp_dir) / "workspace"
            shutil.copytree(workspace_dir, staging_root)
            staged_target = staging_root / patch.file_path
            staged_target.write_text(patch.patched_snippet, encoding="utf-8")

            # Dynamically load the staged modules to run functional & security checks
            import importlib.util

            def _load_staged_module(mod_name: str, rel_file: str):
                spec = importlib.util.spec_from_file_location(mod_name, staging_root / rel_file)
                module = importlib.util.module_from_spec(spec)
                assert spec and spec.loader
                spec.loader.exec_module(module)
                return module

            try:
                staged_cfg = _load_staged_module("staged_config", "mock_enterprise/config.py")
                staged_db = _load_staged_module("staged_db", "mock_enterprise/database.py")
                staged_tel = _load_staged_module("staged_tel", "mock_enterprise/telemetry.py")

                conn = staged_db.create_connection(":memory:")
                staged_db.bootstrap_schema(conn)

                # Functional Test 1: Valid user lookup returns expected record
                alice_rows = staged_db.lookup_user_by_username(conn, "alice")
                assert len(alice_rows) == 1 and alice_rows[0]["department"] == "Security"
                details.append("Functional Test 1 (user directory lookup) passed.")

                # Functional Test 2: Public document query works
                pub_docs = staged_db.list_public_documents(conn)
                assert len(pub_docs) == 1 and pub_docs[0]["classification"] == "public"
                details.append("Functional Test 2 (public document listing) passed.")

                # Security Invariant Check specific to the CWE being patched
                security_passed = True
                if patch.cwe_id == "CWE-89":
                    # Special characters in username must be treated strictly as literal parameter values
                    literal_lookup = staged_db.lookup_user_by_username(conn, "alice' --")
                    security_passed = (
                        len(literal_lookup) == 0
                        and "cursor.execute(query, (username,))" in patch.patched_snippet
                    )
                    details.append(f"CWE-89 parameterized query invariant check: {security_passed}")

                elif patch.cwe_id == "CWE-862":
                    security_passed = "PermissionError" in patch.patched_snippet and "requester_role != 'admin'" in patch.patched_snippet
                    details.append(f"CWE-862 role authorization invariant check: {security_passed}")

                elif patch.cwe_id == "CWE-79":
                    security_passed = "html.escape(filter_label, quote=True)" in patch.patched_snippet
                    details.append(f"CWE-79 HTML escaping invariant check: {security_passed}")

                elif patch.cwe_id == "CWE-489":
                    security_passed = (
                        staged_cfg.DEBUG_MODE is False
                        and staged_cfg.EXPOSE_STACK_TRACES is False
                        and staged_cfg.TOKEN_SIGNING_MODE == "ephemeral_rotatable_key"
                    )
                    details.append(f"CWE-489 hardened production config check: {security_passed}")

                functional_passed = True
                _ = staged_tel
            except Exception as exc:  # pragma: no cover
                functional_passed = False
                security_passed = False
                details.append(f"Staging validation exception: {exc}")

        return ValidationReport(
            patch_id=patch.patch_id,
            incident_id=patch.incident_id,
            syntax_valid=syntax_valid,
            functional_tests_passed=functional_passed,
            security_checks_passed=security_passed,
            test_count=4,
            details=details,
        )


class DeploymentRollbackAgent:
    '''Agent 6: Atomically deploys validated patches with cryptographic backup and rollback.'''

    name = "DeploymentRollbackAgent"

    def deploy(
        self,
        patch: CandidatePatch,
        validation: ValidationReport,
        workspace_dir: Path,
        backup_dir: Path,
        telemetry: TelemetryCollector,
        safety: SafetyController,
    ) -> DeploymentReceipt:
        target_file = workspace_dir / patch.file_path
        safety.check_operation(self.name, "deploy_patch", target_file)

        backup_dir.mkdir(parents=True, exist_ok=True)
        pre_bytes = target_file.read_bytes()
        pre_sha = hashlib.sha256(pre_bytes).hexdigest()
        backup_file = backup_dir / f"{patch.patch_id}_{Path(patch.file_path).name}.bak"
        backup_file.write_bytes(pre_bytes)

        if not validation.passed:
            telemetry.record_security_event(
                event_type="patch_rollback",
                endpoint=patch.file_path,
                metadata={"patch_id": patch.patch_id, "reason": "staging_validation_failed"},
            )
            return DeploymentReceipt(
                deployment_id=f"DEP-{patch.patch_id}",
                patch_id=patch.patch_id,
                incident_id=patch.incident_id,
                cwe_id=patch.cwe_id,
                file_path=patch.file_path,
                pre_patch_sha256=pre_sha,
                post_patch_sha256=pre_sha,
                backup_path=str(backup_file),
                deployed=False,
                rolled_back=True,
                deployed_at_ms=time.time() * 1000.0,
                notes="Aborted deployment because staging validation did not pass.",
            )

        # Check human approval gate
        approved, gate_reason = safety.request_patch_approval(patch, validation)
        if not approved:
            return DeploymentReceipt(
                deployment_id=f"DEP-{patch.patch_id}",
                patch_id=patch.patch_id,
                incident_id=patch.incident_id,
                cwe_id=patch.cwe_id,
                file_path=patch.file_path,
                pre_patch_sha256=pre_sha,
                post_patch_sha256=pre_sha,
                backup_path=str(backup_file),
                deployed=False,
                rolled_back=False,
                deployed_at_ms=time.time() * 1000.0,
                notes=f"Blocked by HumanApprovalGate: {gate_reason}",
            )

        try:
            target_file.write_text(patch.patched_snippet, encoding="utf-8")
            # Verify post-write syntax integrity
            ast.parse(target_file.read_text(encoding="utf-8"), filename=str(target_file))
            post_sha = hashlib.sha256(target_file.read_bytes()).hexdigest()
            telemetry.record_security_event(
                event_type="patch_deployed",
                endpoint=patch.file_path,
                metadata={"patch_id": patch.patch_id, "cwe_id": patch.cwe_id, "post_sha256": post_sha},
            )
            return DeploymentReceipt(
                deployment_id=f"DEP-{patch.patch_id}",
                patch_id=patch.patch_id,
                incident_id=patch.incident_id,
                cwe_id=patch.cwe_id,
                file_path=patch.file_path,
                pre_patch_sha256=pre_sha,
                post_patch_sha256=post_sha,
                backup_path=str(backup_file),
                deployed=True,
                rolled_back=False,
                deployed_at_ms=time.time() * 1000.0,
                notes=f"Deployed cleanly ({gate_reason}).",
            )
        except Exception as exc:  # pragma: no cover
            # Automatic rollback from cryptographic backup
            target_file.write_bytes(backup_file.read_bytes())
            telemetry.record_security_event(
                event_type="patch_rollback",
                endpoint=patch.file_path,
                metadata={"patch_id": patch.patch_id, "reason": str(exc)},
            )
            return DeploymentReceipt(
                deployment_id=f"DEP-{patch.patch_id}",
                patch_id=patch.patch_id,
                incident_id=patch.incident_id,
                cwe_id=patch.cwe_id,
                file_path=patch.file_path,
                pre_patch_sha256=pre_sha,
                post_patch_sha256=pre_sha,
                backup_path=str(backup_file),
                deployed=False,
                rolled_back=True,
                deployed_at_ms=time.time() * 1000.0,
                notes=f"Rolled back automatically due to deployment exception: {exc}",
            )
