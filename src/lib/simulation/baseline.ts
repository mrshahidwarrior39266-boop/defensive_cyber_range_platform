import reportJson from "../../data/baseline-report.json";
import auditRaw from "../../data/baseline-audit.jsonl?raw";
import type {
  AuditEntry,
  CweId,
  DeploymentReceipt,
  EndpointSurface,
  LessonLearned,
  LogEntry,
  LogTone,
  MemoryRound,
  RangeState,
  RoundResult,
  RoundScorecard,
  SecurityAlert,
  SecurityFinding,
  TelemetryEvent,
  TriagedIncident,
} from "./types";

/* --------------------------------------------------------------------------
   Raw artifact shapes (snake_case, produced by the Python platform)
   -------------------------------------------------------------------------- */

interface RawFinding {
  finding_id: string;
  vuln_id: string;
  cwe_id: string;
  title: string;
  severity: string;
  cvss_score: number;
  file_path: string;
  function_name: string;
  endpoint: string;
  line_number: number;
  evidence_snippet: string;
  description: string;
  remediation_guidance: string;
  detected_at_ms: number;
}

interface RawAlert {
  alert_id: string;
  finding_id: string;
  cwe_id: string;
  severity: string;
  endpoint: string;
  file_path: string;
  function_name: string;
  line_number: number;
  triggered_at_ms: number;
  correlated_telemetry_events: number;
  summary: string;
}

interface RawRca {
  incident_id: string;
  cwe_id: string;
  file_path: string;
  function_name: string;
  line_number: number;
  vulnerable_block: string;
  ast_node_type: string;
  root_cause_explanation: string;
  remediation_contract: string;
}

interface RawPatch {
  patch_id: string;
  incident_id: string;
  cwe_id: string;
  file_path: string;
  original_snippet: string;
  patched_snippet: string;
  unified_diff: string;
  rationale: string;
  generated_at_ms: number;
}

interface RawValidation {
  patch_id: string;
  incident_id: string;
  syntax_valid: boolean;
  functional_tests_passed: boolean;
  security_checks_passed: boolean;
  test_count: number;
  details: string[];
  passed: boolean;
}

interface RawDeployment {
  deployment_id: string;
  patch_id: string;
  incident_id: string;
  cwe_id: string;
  file_path: string;
  pre_patch_sha256: string;
  post_patch_sha256: string;
  backup_path: string;
  deployed: boolean;
  rolled_back: boolean;
  deployed_at_ms: number;
  notes: string;
}

interface RawVerification {
  finding_id: string;
  cwe_id: string;
  file_path: string;
  remediated: boolean;
  verification_method: string;
  details: string;
  verified_at_ms: number;
}

interface RawScorecard {
  round_num: number;
  ground_truth_total: number;
  findings_discovered: number;
  discovery_recall_pct: number;
  alerts_triggered: number;
  mean_time_to_detect_ms: number;
  patches_generated: number;
  patches_validated: number;
  patches_deployed: number;
  verified_remediated: number;
  patch_correctness_pct: number;
  regression_pass_rate_pct: number;
  mean_time_to_remediate_ms: number;
  security_posture_score: number;
}

interface RawRound {
  round: number;
  analysis_report: {
    mapped_endpoints: Array<{
      file_path: string;
      function_name: string;
      endpoint: string;
      parameters: string[];
      has_auth_guard: boolean;
      line_number: number;
    }>;
    findings: RawFinding[];
  };
  alerts: RawAlert[];
  root_causes: RawRca[];
  patches: RawPatch[];
  validations: RawValidation[];
  deployments: RawDeployment[];
  verifications: RawVerification[];
  scorecard: RawScorecard;
}

interface RawReport {
  platform: string;
  total_rounds: number;
  final_posture_score: number;
  remediated_cwes: string[];
  audit_chain_valid: boolean;
  audit_entries_count: number;
  rounds: RawRound[];
  shared_memory: {
    rounds: Array<{
      round_num: number;
      recorded_at: string;
      findings_discovered: number;
      patches_deployed: number;
      verified_remediated: number;
      posture_score: number;
    }>;
    lessons_learned: Array<{
      id: number;
      round_num: number;
      cwe_id: string;
      file_path: string;
      patch_id: string;
      remediated: number;
      lesson_summary: string;
    }>;
  };
}

export const BASELINE_REPORT = reportJson as unknown as RawReport;

const asCwe = (value: string): CweId => value as CweId;

const SLA_BY_SEVERITY: Record<string, number> = {
  CRITICAL: 1500,
  HIGH: 3000,
  MEDIUM: 5000,
  LOW: 10000,
};

/* --------------------------------------------------------------------------
   Mappers
   -------------------------------------------------------------------------- */

function mapFinding(raw: RawFinding): SecurityFinding {
  return {
    findingId: raw.finding_id,
    vulnId: raw.vuln_id,
    cweId: asCwe(raw.cwe_id),
    title: raw.title,
    severity: raw.severity as SecurityFinding["severity"],
    cvssScore: raw.cvss_score,
    filePath: raw.file_path,
    functionName: raw.function_name,
    endpoint: raw.endpoint,
    lineNumber: raw.line_number,
    evidenceSnippet: raw.evidence_snippet,
    description: raw.description,
    remediationGuidance: raw.remediation_guidance,
    detectedAtMs: raw.detected_at_ms,
  };
}

function mapAlert(raw: RawAlert): SecurityAlert {
  return {
    alertId: raw.alert_id,
    findingId: raw.finding_id,
    cweId: asCwe(raw.cwe_id),
    severity: raw.severity as SecurityAlert["severity"],
    endpoint: raw.endpoint,
    filePath: raw.file_path,
    functionName: raw.function_name,
    lineNumber: raw.line_number,
    triggeredAtMs: raw.triggered_at_ms,
    correlatedTelemetryEvents: raw.correlated_telemetry_events,
    summary: raw.summary,
  };
}

function mapDeployment(raw: RawDeployment): DeploymentReceipt {
  return {
    deploymentId: raw.deployment_id,
    patchId: raw.patch_id,
    incidentId: raw.incident_id,
    cweId: asCwe(raw.cwe_id),
    filePath: raw.file_path,
    prePatchSha256: raw.pre_patch_sha256,
    postPatchSha256: raw.post_patch_sha256,
    backupPath: raw.backup_path.replace(/^.*\/workspace\//, "workspace/"),
    deployed: raw.deployed,
    rolledBack: raw.rolled_back,
    status: raw.deployed
      ? "deployed"
      : raw.rolled_back
        ? "rolled_back"
        : "blocked",
    deployedAtMs: raw.deployed_at_ms,
    notes: raw.notes,
  };
}

function mapScorecard(raw: RawScorecard): RoundScorecard {
  return {
    roundNum: raw.round_num,
    groundTruthTotal: raw.ground_truth_total,
    findingsDiscovered: raw.findings_discovered,
    discoveryRecallPct: raw.discovery_recall_pct,
    alertsTriggered: raw.alerts_triggered,
    meanTimeToDetectMs: raw.mean_time_to_detect_ms,
    patchesGenerated: raw.patches_generated,
    patchesValidated: raw.patches_validated,
    patchesDeployed: raw.patches_deployed,
    verifiedRemediated: raw.verified_remediated,
    patchCorrectnessPct: raw.patch_correctness_pct,
    regressionPassRatePct: raw.regression_pass_rate_pct,
    meanTimeToRemediateMs: raw.mean_time_to_remediate_ms,
    securityPostureScore: raw.security_posture_score,
  };
}

export function incidentsForRound(
  raw: RawRound,
  findings: SecurityFinding[],
  alerts: SecurityAlert[],
): TriagedIncident[] {
  return alerts.map((alert, index) => {
    const finding =
      findings.find((item) => item.findingId === alert.findingId) ??
      findings[index];
    const rca = raw.root_causes.find(
      (item) => item.cwe_id === alert.cweId && item.file_path === alert.filePath,
    );
    return {
      incidentId:
        rca?.incident_id ?? `INC-${String(index + 1).padStart(3, "0")}-${alert.cweId}`,
      alert,
      finding,
      priorityRank: index + 1,
      slaTargetMs: SLA_BY_SEVERITY[alert.severity] ?? 5000,
      assignedModule: alert.filePath,
    };
  });
}

function mapRound(raw: RawRound): RoundResult {
  const findings = raw.analysis_report.findings.map(mapFinding);
  const alerts = raw.alerts.map(mapAlert);
  const incidents = incidentsForRound(raw, findings, alerts);
  const startCandidates = [
    ...findings.map((f) => f.detectedAtMs),
    ...alerts.map((a) => a.triggeredAtMs),
  ];
  const startedAt = startCandidates.length ? Math.min(...startCandidates) : Date.now();
  const finishedAt = Math.max(
    startedAt,
    ...raw.verifications.map((v) => v.verified_at_ms),
    ...raw.deployments.map((d) => d.deployed_at_ms),
  );

  return {
    roundNum: raw.round,
    startedAt,
    finishedAt,
    surfaces: raw.analysis_report.mapped_endpoints.map(
      (surface): EndpointSurface => ({
        filePath: surface.file_path,
        functionName: surface.function_name,
        endpoint: surface.endpoint,
        parameters: surface.parameters,
        hasAuthGuard: surface.has_auth_guard,
        lineNumber: surface.line_number,
      }),
    ),
    findings,
    alerts,
    incidents,
    rootCauses: raw.root_causes.map((rca) => ({
      incidentId: rca.incident_id,
      cweId: asCwe(rca.cwe_id),
      filePath: rca.file_path,
      functionName: rca.function_name,
      lineNumber: rca.line_number,
      vulnerableBlock: rca.vulnerable_block,
      astNodeType: rca.ast_node_type,
      rootCauseExplanation: rca.root_cause_explanation,
      remediationContract: rca.remediation_contract,
    })),
    patches: raw.patches.map((patch) => ({
      patchId: patch.patch_id,
      incidentId: patch.incident_id,
      cweId: asCwe(patch.cwe_id),
      filePath: patch.file_path,
      originalContent: patch.original_snippet,
      patchedContent: patch.patched_snippet,
      unifiedDiff: patch.unified_diff,
      rationale: patch.rationale,
      generatedAtMs: patch.generated_at_ms,
    })),
    validations: raw.validations.map((validation) => ({
      patchId: validation.patch_id,
      incidentId: validation.incident_id,
      syntaxValid: validation.syntax_valid,
      functionalTestsPassed: validation.functional_tests_passed,
      securityChecksPassed: validation.security_checks_passed,
      testCount: validation.test_count,
      details: validation.details,
      passed: validation.passed,
    })),
    deployments: raw.deployments.map(mapDeployment),
    verifications: raw.verifications.map((verification) => ({
      findingId: verification.finding_id,
      cweId: asCwe(verification.cwe_id),
      filePath: verification.file_path,
      remediated: verification.remediated,
      verificationMethod: verification.verification_method,
      details: verification.details,
      verifiedAtMs: verification.verified_at_ms,
    })),
    scorecard: mapScorecard(raw.scorecard),
  };
}

function parseAudit(raw: string): AuditEntry[] {
  return raw
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line, index) => {
      const record = JSON.parse(line) as {
        timestamp: string;
        actor: string;
        action: string;
        details: Record<string, unknown>;
        prev_hash: string;
        entry_hash: string;
      };
      return {
        id: index + 1,
        timestamp: record.timestamp,
        actor: record.actor,
        action: record.action,
        details: record.details,
        prevHash: record.prev_hash,
        entryHash: record.entry_hash,
      };
    });
}

const ACTION_MESSAGES: Record<string, string> = {
  initialize_sandbox: "Cloned mock enterprise into the disposable sandbox.",
  run_round: "Round dispatched to the analysis and defense swarms.",
  ast_surface_scan: "Mapped API and UI surface with AST traversal.",
  static_code_audit: "Completed non-destructive static code audit.",
  prioritize_findings: "Ranked findings by CVSS and architectural exposure.",
  correlate_telemetry_and_findings: "Correlated telemetry into security alerts.",
  triage_alerts: "Deduplicated alerts and assigned SLA targets.",
  inspect_source_ast: "Isolated the vulnerable AST block.",
  synthesize_patch: "Synthesized a minimal remediation patch.",
  validate_patch_in_staging: "Ran functional and security tests in staging.",
  deploy_patch: "Applied the validated patch atomically.",
  evaluate_patch: "Human approval gate evaluated the candidate patch.",
  verify_remediations: "Re-audited patched sources for compliance.",
  finalize_simulation: "Sealed the campaign and verified the audit chain.",
};

function toneFor(action: string, details: Record<string, unknown>): LogTone {
  if (action === "deploy_patch") return details.reason ? "danger" : "success";
  if (action === "evaluate_patch") return details.approved === false ? "warn" : "success";
  if (action === "verify_remediations") return "success";
  if (action === "finalize_simulation") return "success";
  if (action.includes("validate")) return "info";
  return "muted";
}

function messageFor(entry: AuditEntry): string {
  const base = ACTION_MESSAGES[entry.action] ?? entry.action;
  const cwe = entry.details.cwe_id;
  if (typeof cwe === "string") return `${base} · ${cwe}`;
  return base;
}

function logFromAudit(audit: AuditEntry[]): LogEntry[] {
  return audit.map((entry, index) => ({
    id: index + 1,
    at: Date.parse(entry.timestamp) || Date.now(),
    actor: entry.actor,
    action: entry.action,
    message: messageFor(entry),
    tone: toneFor(entry.action, entry.details),
  }));
}

function buildTelemetry(rounds: RoundResult[]): TelemetryEvent[] {
  const events: TelemetryEvent[] = [];
  let id = 1;
  const push = (
    atMs: number,
    eventType: string,
    endpoint: string,
    actor: string,
    status: number,
    metadata: Record<string, unknown>,
  ) => {
    events.push({
      id: id++,
      timestamp: new Date(atMs).toISOString(),
      traceId: (0x100000 + id * 7919).toString(16).padStart(32, "a").slice(-32),
      spanId: (0xabc000 + id * 104729).toString(16).slice(-16),
      service: "acme-enterprise-portal",
      eventType,
      endpoint,
      actor,
      statusCode: status,
      metadata,
    });
  };

  const primary = rounds.find((round) => round.findings.length) ?? rounds[0];
  if (!primary) return events;

  primary.surfaces.forEach((surface, index) => {
    push(
      primary.startedAt - 6000 + index * 900,
      "http_request",
      surface.endpoint,
      index % 2 ? "bob" : "anonymous",
      surface.functionName === "export_confidential_documents" ? 200 : 200,
      { method: "GET", route: surface.functionName },
    );
  });

  primary.findings.forEach((finding) => {
    push(finding.detectedAtMs, "finding_detected", finding.endpoint, "cyber_range_swarm", 200, {
      finding_id: finding.findingId,
      cwe_id: finding.cweId,
      severity: finding.severity,
    });
  });
  primary.alerts.forEach((alert) => {
    push(alert.triggeredAtMs, "alert_triggered", alert.endpoint, "cyber_range_swarm", 200, {
      alert_id: alert.alertId,
      cwe_id: alert.cweId,
    });
  });
  primary.deployments.forEach((deployment) => {
    push(
      deployment.deployedAtMs,
      deployment.deployed ? "patch_deployed" : "patch_rollback",
      deployment.filePath,
      "cyber_range_swarm",
      200,
      {
        patch_id: deployment.patchId,
        cwe_id: deployment.cweId,
        post_sha256: deployment.postPatchSha256.slice(0, 12),
      },
    );
  });

  return events.sort(
    (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
  );
}

/* --------------------------------------------------------------------------
   Baseline state factory
   -------------------------------------------------------------------------- */

export function createBaselineState(): RangeState {
  const report = BASELINE_REPORT;
  const rounds = report.rounds.map(mapRound);
  const focus =
    [...rounds].reverse().find((round) => round.findings.length > 0) ??
    rounds[rounds.length - 1];

  const audit = parseAudit(auditRaw);
  const memoryRounds: MemoryRound[] = report.shared_memory.rounds.map((item) => ({
    roundNum: item.round_num,
    recordedAt: item.recorded_at,
    findingsDiscovered: item.findings_discovered,
    patchesDeployed: item.patches_deployed,
    verifiedRemediated: item.verified_remediated,
    postureScore: item.posture_score,
  }));

  const lessons: LessonLearned[] = report.shared_memory.lessons_learned.map(
    (item) => ({
      id: item.id,
      roundNum: item.round_num,
      cweId: asCwe(item.cwe_id),
      filePath: item.file_path,
      patchId: item.patch_id,
      remediated: Boolean(item.remediated),
      lessonSummary: item.lesson_summary,
    }),
  );

  return {
    status: "complete",
    approvalMode: "auto",
    phase: "complete",
    phaseLabel: "Campaign complete",
    progress: 1,
    campaignRounds: report.total_rounds,
    activeRound: report.total_rounds,
    rounds,
    surfaces: focus?.surfaces ?? [],
    findings: focus?.findings ?? [],
    alerts: focus?.alerts ?? [],
    incidents: focus?.incidents ?? [],
    rootCauses: focus?.rootCauses ?? [],
    patches: focus?.patches ?? [],
    validations: focus?.validations ?? [],
    deployments: focus?.deployments ?? [],
    verifications: focus?.verifications ?? [],
    remediatedCwes: report.remediated_cwes.map(asCwe),
    telemetry: buildTelemetry(rounds),
    audit,
    memoryRounds,
    lessons,
    killSwitch: { tripped: false, reason: "", at: null },
    log: logFromAudit(audit),
    campaignStartedAt: audit.length ? Date.parse(audit[0].timestamp) : null,
    campaignFinishedAt: audit.length
      ? Date.parse(audit[audit.length - 1].timestamp)
      : null,
  };
}
