'''Security Analysis Swarm (Non-Destructive Static & Architectural Auditors).

Implements 5 specialized analysis agents:
1. SurfaceMapperAgent
2. StaticVulnerabilityAuditorAgent
3. RiskPrioritizerAgent
4. ComplianceVerifierAgent
5. AnalysisReporterAgent

All agents operate strictly via Python AST traversal and configuration inspection
without generating or executing live exploit payloads.
'''

import ast
from pathlib import Path
import time
from typing import Any

from agents.models import EndpointSurface, SecurityFinding, VerificationResult
from mock_enterprise.telemetry import TelemetryCollector
from safety.controls import SafetyController


class SurfaceMapperAgent:
    '''Agent 1: Maps API/UI service methods, parameters, and authorization checks via AST.'''

    name = "SurfaceMapperAgent"

    def map_workspace(self, workspace_dir: Path, safety: SafetyController) -> list[EndpointSurface]:
        safety.check_operation(self.name, "ast_surface_scan", workspace_dir)
        surfaces: list[EndpointSurface] = []

        service_file = workspace_dir / "mock_enterprise" / "service.py"
        safety.validate_path(service_file)
        source = service_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(service_file))

        endpoint_map = {
            "get_health": "/api/v1/health",
            "search_directory": "/api/v1/users/search",
            "render_search_banner": "/ui/search-banner",
            "export_confidential_documents": "/api/v1/admin/export-confidential",
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in endpoint_map:
                params = [arg.arg for arg in node.args.args if arg.arg != "self"]
                func_src = ast.get_source_segment(source, node) or ""
                has_auth = (
                    "requester_role != 'admin'" in func_src
                    or 'requester_role != "admin"' in func_src
                    or "PermissionError" in func_src
                )
                surfaces.append(
                    EndpointSurface(
                        file_path="mock_enterprise/service.py",
                        function_name=node.name,
                        endpoint=endpoint_map[node.name],
                        parameters=params,
                        has_auth_guard=has_auth,
                        line_number=node.lineno,
                    )
                )

        return surfaces


class StaticVulnerabilityAuditorAgent:
    '''Agent 2: Performs AST and pattern-based static code auditing for seeded CWE classes.'''

    name = "StaticVulnerabilityAuditorAgent"

    def audit_workspace(
        self,
        workspace_dir: Path,
        surfaces: list[EndpointSurface],
        safety: SafetyController,
    ) -> list[SecurityFinding]:
        safety.check_operation(self.name, "static_code_audit", workspace_dir)
        findings: list[SecurityFinding] = []
        now_ms = time.time() * 1000.0

        # 1. Check mock_enterprise/database.py for CWE-89 (SQL string formatting via JoinedStr / f-string)
        db_file = workspace_dir / "mock_enterprise" / "database.py"
        safety.validate_path(db_file)
        db_source = db_file.read_text(encoding="utf-8")
        db_tree = ast.parse(db_source, filename=str(db_file))

        for node in ast.walk(db_tree):
            if isinstance(node, ast.FunctionDef) and node.name == "lookup_user_by_username":
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name) and target.id == "query":
                                if isinstance(child.value, ast.JoinedStr):
                                    snippet = ast.get_source_segment(db_source, child) or ""
                                    findings.append(
                                        SecurityFinding(
                                            finding_id="FIND-CWE-89",
                                            vuln_id="VULN-001",
                                            cwe_id="CWE-89",
                                            title="Unparameterized SQL Query in User Directory Lookup",
                                            severity="CRITICAL",
                                            cvss_score=9.8,
                                            file_path="mock_enterprise/database.py",
                                            function_name="lookup_user_by_username",
                                            endpoint="/api/v1/users/search",
                                            line_number=child.lineno,
                                            evidence_snippet=snippet.strip(),
                                            description=(
                                                "SQL query string is constructed dynamically using a Python "
                                                "f-string (`ast.JoinedStr`) with user input `username` rather "
                                                "than DB-API parameterized `?` placeholders."
                                            ),
                                            remediation_guidance=(
                                                "Use parameterized SQL execution: "
                                                "cursor.execute(\"SELECT ... WHERE username = ?\", (username,))"
                                            ),
                                            detected_at_ms=now_ms,
                                        )
                                    )

        # 2. Check mock_enterprise/service.py for CWE-862 (Missing Authorization) and CWE-79 (Unescaped HTML)
        svc_file = workspace_dir / "mock_enterprise" / "service.py"
        safety.validate_path(svc_file)
        svc_source = svc_file.read_text(encoding="utf-8")
        svc_tree = ast.parse(svc_source, filename=str(svc_file))

        for node in ast.walk(svc_tree):
            if isinstance(node, ast.FunctionDef) and node.name == "export_confidential_documents":
                func_seg = ast.get_source_segment(svc_source, node) or ""
                has_role_check = (
                    "if requester_role != 'admin':" in func_seg
                    or 'if requester_role != "admin":' in func_seg
                )
                if not has_role_check:
                    findings.append(
                        SecurityFinding(
                            finding_id="FIND-CWE-862",
                            vuln_id="VULN-002",
                            cwe_id="CWE-862",
                            title="Missing Role Authorization in Confidential Document Export",
                            severity="HIGH",
                            cvss_score=8.6,
                            file_path="mock_enterprise/service.py",
                            function_name="export_confidential_documents",
                            endpoint="/api/v1/admin/export-confidential",
                            line_number=node.lineno,
                            evidence_snippet="def export_confidential_documents(self, requester_role: str, ...):",
                            description=(
                                "Administrative export method accepts `requester_role` but never validates "
                                "that the caller holds the `'admin'` role before querying confidential records."
                            ),
                            remediation_guidance=(
                                "Enforce an explicit authorization guard at the start of the method and "
                                "raise PermissionError or return HTTP 403 when `requester_role != 'admin'`."
                            ),
                            detected_at_ms=now_ms + 1.0,
                        )
                    )

            if isinstance(node, ast.FunctionDef) and node.name == "render_search_banner":
                func_seg = ast.get_source_segment(svc_source, node) or ""
                if "safe_label = html.escape(" not in func_seg:
                    findings.append(
                        SecurityFinding(
                            finding_id="FIND-CWE-79",
                            vuln_id="VULN-003",
                            cwe_id="CWE-79",
                            title="Unescaped HTML Output in Directory Search Banner",
                            severity="MEDIUM",
                            cvss_score=6.5,
                            file_path="mock_enterprise/service.py",
                            function_name="render_search_banner",
                            endpoint="/ui/search-banner",
                            line_number=node.lineno,
                            evidence_snippet='return f"<div class=\'search-banner\'>Active Directory Filter: {filter_label}</div>"',
                            description=(
                                "`render_search_banner` interpolates `filter_label` directly into an HTML "
                                "`<div>` element without calling `html.escape()`."
                            ),
                            remediation_guidance=(
                                "Escape untrusted input with `safe_label = html.escape(filter_label, quote=True)` "
                                "before rendering inside HTML markup."
                            ),
                            detected_at_ms=now_ms + 2.0,
                        )
                    )

        # 3. Check mock_enterprise/config.py for CWE-489 / CWE-209 (Debug & stack trace exposure)
        cfg_file = workspace_dir / "mock_enterprise" / "config.py"
        safety.validate_path(cfg_file)
        cfg_source = cfg_file.read_text(encoding="utf-8")
        if "DEBUG_MODE = True" in cfg_source or "EXPOSE_STACK_TRACES = True" in cfg_source or 'TOKEN_SIGNING_MODE = "weak_static_secret"' in cfg_source:
            findings.append(
                SecurityFinding(
                    finding_id="FIND-CWE-489",
                    vuln_id="VULN-004",
                    cwe_id="CWE-489",
                    title="Production Debug Mode, Verbose Stack Traces, and Static Secret Mode Enabled",
                    severity="MEDIUM",
                    cvss_score=6.1,
                    file_path="mock_enterprise/config.py",
                    function_name="module_config",
                    endpoint="/api/v1/health",
                    line_number=12,
                    evidence_snippet="DEBUG_MODE = True / EXPOSE_STACK_TRACES = True / TOKEN_SIGNING_MODE = 'weak_static_secret'",
                    description=(
                        "Production configuration enables active debug flags, stack trace exposure, "
                        "and a static token signing mode."
                    ),
                    remediation_guidance=(
                        "Set `DEBUG_MODE = False`, `EXPOSE_STACK_TRACES = False`, and "
                        "`TOKEN_SIGNING_MODE = \"ephemeral_rotatable_key\"`."
                    ),
                    detected_at_ms=now_ms + 3.0,
                )
            )

        return findings


class RiskPrioritizerAgent:
    '''Agent 3: Ranks discovered security findings by CVSS score and architectural exposure.'''

    name = "RiskPrioritizerAgent"

    def prioritize(self, findings: list[SecurityFinding], safety: SafetyController) -> list[SecurityFinding]:
        safety.check_operation(self.name, "prioritize_findings")
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 99), -f.cvss_score, f.finding_id),
        )


class ComplianceVerifierAgent:
    '''Agent 4: Re-audits patched files after Blue Team deployment to verify remediation.'''

    name = "ComplianceVerifierAgent"

    def __init__(self, surface_mapper: SurfaceMapperAgent, auditor: StaticVulnerabilityAuditorAgent):
        self.surface_mapper = surface_mapper
        self.auditor = auditor

    def verify_remediations(
        self,
        workspace_dir: Path,
        initial_findings: list[SecurityFinding],
        safety: SafetyController,
    ) -> list[VerificationResult]:
        safety.check_operation(self.name, "verify_remediations", workspace_dir)
        surfaces = self.surface_mapper.map_workspace(workspace_dir, safety)
        remaining = self.auditor.audit_workspace(workspace_dir, surfaces, safety)
        remaining_ids = {f.finding_id for f in remaining}

        results: list[VerificationResult] = []
        now_ms = time.time() * 1000.0
        for finding in initial_findings:
            is_fixed = finding.finding_id not in remaining_ids
            results.append(
                VerificationResult(
                    finding_id=finding.finding_id,
                    cwe_id=finding.cwe_id,
                    file_path=finding.file_path,
                    remediated=is_fixed,
                    verification_method="AST & Configuration Re-Audit",
                    details=(
                        f"Verified {finding.cwe_id} in {finding.file_path} is fully remediated."
                        if is_fixed
                        else f"{finding.cwe_id} remains present in {finding.file_path}."
                    ),
                    verified_at_ms=now_ms,
                )
            )
        return results


class AnalysisReporterAgent:
    '''Agent 5: Emits SARIF-aligned structured reports and updates observability telemetry.'''

    name = "AnalysisReporterAgent"

    def build_report(
        self,
        round_num: int,
        surfaces: list[EndpointSurface],
        findings: list[SecurityFinding],
        telemetry: TelemetryCollector,
        safety: SafetyController,
    ) -> dict[str, Any]:
        safety.check_operation(self.name, "build_analysis_report")
        for finding in findings:
            telemetry.record_security_event(
                event_type="finding_detected",
                endpoint=finding.endpoint,
                metadata={
                    "finding_id": finding.finding_id,
                    "cwe_id": finding.cwe_id,
                    "severity": finding.severity,
                    "file_path": finding.file_path,
                },
            )
        return {
            "round": round_num,
            "mapped_endpoints": [s.to_dict() for s in surfaces],
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
