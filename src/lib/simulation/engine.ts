import { sha256Hex, canonicalJson } from "../sha256";
import {
  applyFix,
  BLUEPRINTS,
  CWE_LABELS,
  CWE_ORDER,
  extractFunction,
  fileSourceFor,
  SURFACES,
} from "./project";
import { createUnifiedDiff } from "./diff";
import type {
  ApprovalMode,
  AuditEntry,
  CandidatePatch,
  CweId,
  DeploymentReceipt,
  LessonLearned,
  LogEntry,
  LogTone,
  MemoryRound,
  PlannedCampaign,
  RangeState,
  RootCauseAnalysis,
  RoundResult,
  RoundScorecard,
  RunStep,
  SecurityAlert,
  SecurityFinding,
  Severity,
  TriagedIncident,
  ValidationReport,
  VerificationResult,
} from "./types";

const SLA_BY_SEVERITY: Record<Severity, number> = {
  CRITICAL: 1500,
  HIGH: 3000,
  MEDIUM: 5000,
  LOW: 10000,
};

const pad = (n: number) => String(n).padStart(3, "0");

export function createAuditEntry(
  prevHash: string,
  actor: string,
  action: string,
  details: Record<string, unknown>,
  timestamp: string,
  id: number,
): AuditEntry {
  const payload = {
    timestamp,
    actor,
    action,
    details,
    prev_hash: prevHash,
  };
  const entryHash = sha256Hex(canonicalJson(payload));
  return {
    id,
    timestamp,
    actor,
    action,
    details,
    prevHash,
    entryHash,
  };
}

export function verifyAuditChain(entries: AuditEntry[]): {
  valid: boolean;
  brokenAt: number | null;
} {
  let prev = "0".repeat(64);
  for (const entry of entries) {
    if (entry.prevHash !== prev) return { valid: false, brokenAt: entry.id };
    const computed = sha256Hex(
      canonicalJson({
        timestamp: entry.timestamp,
        actor: entry.actor,
        action: entry.action,
        details: entry.details,
        prev_hash: entry.prevHash,
      }),
    );
    if (computed !== entry.entryHash) return { valid: false, brokenAt: entry.id };
    prev = entry.entryHash;
  }
  return { valid: true, brokenAt: null };
}

/* --------------------------------------------------------------------------
   Findings produced by the static auditor
   -------------------------------------------------------------------------- */

function findingFor(
  cwe: CweId,
  source: string,
  atMs: number,
): SecurityFinding {
  const blueprint = BLUEPRINTS[cwe];
  const lines = source.split("\n");
  const lineIndex = lines.findIndex(
    (line) => line.includes(blueprint.evidenceLocator ?? blueprint.locator),
  );
  const lineNumber = lineIndex >= 0 ? lineIndex + 1 : 0;

  let evidence = "";
  if (cwe === "CWE-489") {
    evidence =
      'DEBUG_MODE = True / EXPOSE_STACK_TRACES = True / TOKEN_SIGNING_MODE = "weak_static_secret"';
  } else if (cwe === "CWE-862") {
    evidence =
      "def export_confidential_documents(self, requester_role: str, ...):";
  } else {
    evidence = (lines[lineIndex] ?? "").trim();
  }

  return {
    findingId: `FIND-${cwe}`,
    vulnId: blueprint.vulnId,
    cweId: cwe,
    title: blueprint.title,
    severity: blueprint.severity,
    cvssScore: blueprint.cvssScore,
    filePath: blueprint.filePath,
    functionName: blueprint.functionName,
    endpoint: blueprint.endpoint,
    lineNumber: cwe === "CWE-489" ? 12 : lineNumber,
    evidenceSnippet: evidence,
    description: blueprint.description,
    remediationGuidance: blueprint.remediationGuidance,
    detectedAtMs: atMs,
  };
}

/* --------------------------------------------------------------------------
   Planner
   -------------------------------------------------------------------------- */

export interface PlanOptions {
  rounds: number;
  approvalMode: ApprovalMode;
  auditHead: string;
  auditStartId: number;
  logStartId: number;
  now: number;
}

export function planCampaign(options: PlanOptions): PlannedCampaign {
  const { approvalMode } = options;
  const steps: RunStep[] = [];
  let chain = options.auditHead;
  let auditId = options.auditStartId;
  let logId = options.logStartId;
  let stepAudits: AuditEntry[] = [];
  let stepLogs: LogEntry[] = [];

  type StepInput = RunStep extends infer S
    ? S extends RunStep
      ? Omit<S, "progress" | "audit" | "log">
      : never
    : never;

  const audit = (
    actor: string,
    action: string,
    details: Record<string, unknown>,
    atMs: number,
  ) => {
    const entry = createAuditEntry(
      chain,
      actor,
      action,
      details,
      new Date(atMs).toISOString(),
      auditId,
    );
    chain = entry.entryHash;
    auditId++;
    stepAudits.push(entry);
    return entry;
  };

  const log = (
    actor: string,
    action: string,
    message: string,
    tone: LogTone,
    atMs: number,
  ) => {
    stepLogs.push({ id: logId++, at: atMs, actor, action, message, tone });
  };

  const takeAudits = () => {
    const values = stepAudits;
    stepAudits = [];
    return values;
  };
  const takeLogs = () => {
    const values = stepLogs;
    stepLogs = [];
    return values;
  };

  const push = (step: StepInput) => {
    steps.push({
      ...step,
      progress: 0,
      audit: takeAudits(),
      log: takeLogs(),
    } as RunStep);
  };

  let remediated: CweId[] = [];
  const workspace: Record<string, string> = {};
  const virtualStart = options.now;

  for (let roundNum = 1; roundNum <= options.rounds; roundNum++) {
    const roundBase = virtualStart + (roundNum - 1) * 90_000;
    const roundAuditBase = options.now + (roundNum - 1) * 4000;
    let virtual = roundBase;

    const allCwes = [...CWE_ORDER];
    const activeCwes = allCwes.filter((cwe) => {
      if (remediated.includes(cwe)) return false;
      const path = BLUEPRINTS[cwe].filePath;
      if (!(path in workspace)) {
        workspace[path] = fileSourceFor(path, []);
      }
      return true;
    });

    audit(
      "SimulationOrchestrator",
      "initialize_sandbox",
      {
        target_host: "localhost",
        target_path: "simulation_artifacts/workspace",
      },
      roundAuditBase,
    );
    log(
      "SimulationOrchestrator",
      "initialize_sandbox",
      `Round ${roundNum}: sandbox refreshed from mock_enterprise (5 files, zero network egress).`,
      "muted",
      roundAuditBase,
    );
    push({
      kind: "phase",
      phase: "initialize",
      label: `Round ${roundNum} · initialize sandbox`,
      detail: "Cloning mock_enterprise into the disposable workspace.",
      delay: 320,
    });

    audit(
      "SurfaceMapperAgent",
      "ast_surface_scan",
      {
        target_host: "localhost",
        target_path: "simulation_artifacts/workspace/mock_enterprise/service.py",
      },
      roundAuditBase + 120,
    );
    log(
      "SurfaceMapperAgent",
      "ast_surface_scan",
      "Mapped 4 API/UI endpoints through the Python AST. 0 authorization guards found.",
      "info",
      roundAuditBase + 120,
    );
    push({
      kind: "phase",
      phase: "surface",
      label: `Round ${roundNum} · surface mapping`,
      detail: "SurfaceMapperAgent walks the AST for endpoints and auth guards.",
      delay: 480,
    });

    const findings = activeCwes.map((cwe, index) => {
      virtual = roundBase + index * 0.4;
      return findingFor(cwe, workspace[BLUEPRINTS[cwe].filePath], virtual);
    });

    push({
      kind: "surfaces",
      phase: "audit",
      label: `Round ${roundNum} · static audit`,
      detail: "Non-destructive AST inspection across seeded CWE classes.",
      delay: 560,
      surfaces: SURFACES,
      findings,
    });
    audit(
      "StaticVulnerabilityAuditorAgent",
      "static_code_audit",
      {
        target_host: "localhost",
        target_path: "simulation_artifacts/workspace/mock_enterprise",
      },
      roundAuditBase + 300,
    );
    log(
      "StaticVulnerabilityAuditorAgent",
      "static_code_audit",
      findings.length
        ? `Static audit raised ${findings.length} finding${findings.length === 1 ? "" : "s"}: ${findings
            .map((f) => f.cweId)
            .join(", ")}.`
        : "Static audit found no remaining weaknesses. Workspace is clean.",
      findings.length ? "warn" : "success",
      roundAuditBase + 300,
    );
    audit(
      "AnalysisReporterAgent",
      "build_analysis_report",
      { round: roundNum, findings: findings.length },
      roundAuditBase + 380,
    );

    const sorted = [...findings].sort(
      (a, b) =>
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(a.severity) -
          ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(b.severity) ||
        b.cvssScore - a.cvssScore,
    );

    audit(
      "RiskPrioritizerAgent",
      "prioritize_findings",
      { round: roundNum, ranked: sorted.map((f) => f.cweId) },
      roundAuditBase + 460,
    );
    push({
      kind: "phase",
      phase: "prioritize",
      label: `Round ${roundNum} · prioritize risk`,
      detail:
        "RiskPrioritizerAgent ranks findings by severity, CVSS and exposure.",
      delay: 300,
    });

    const alerts: SecurityAlert[] = sorted.map((finding, index) => {
      const alert: SecurityAlert = {
        alertId: `ALERT-${pad(index + 1)}-${finding.cweId}`,
        findingId: finding.findingId,
        cweId: finding.cweId,
        severity: finding.severity,
        endpoint: finding.endpoint,
        filePath: finding.filePath,
        functionName: finding.functionName,
        lineNumber: finding.lineNumber,
        triggeredAtMs: finding.detectedAtMs + 2.5,
        correlatedTelemetryEvents: 1,
        summary: `[${finding.severity}] ${finding.cweId} detected on ${finding.endpoint} (${finding.filePath}:${finding.lineNumber})`,
      };
      return alert;
    });

    const incidents: TriagedIncident[] = sorted.map((finding, index) => {
      const alert = alerts.find((item) => item.findingId === finding.findingId)!;
      return {
        incidentId: `INC-${pad(index + 1)}-${finding.cweId}`,
        alert,
        finding,
        priorityRank: index + 1,
        slaTargetMs: SLA_BY_SEVERITY[finding.severity],
        assignedModule: finding.filePath,
      };
    });

    audit(
      "DetectionAgent",
      "correlate_telemetry_and_findings",
      { round: roundNum, alerts: alerts.length },
      roundAuditBase + 540,
    );
    log(
      "DetectionAgent",
      "correlate_telemetry_and_findings",
      alerts.length
        ? `Correlated ${alerts.length} alert${alerts.length === 1 ? "" : "s"} with live application telemetry.`
        : "No findings to correlate. Detection queue is empty.",
      alerts.length ? "info" : "success",
      roundAuditBase + 540,
    );
    audit(
      "TriageAgent",
      "triage_alerts",
      {
        round: roundNum,
        incidents: incidents.map((incident) => incident.incidentId),
      },
      roundAuditBase + 610,
    );
    log(
      "TriageAgent",
      "triage_alerts",
      incidents.length
        ? `Opened ${incidents.length} incident${incidents.length === 1 ? "" : "s"} · SLA 1.5s critical / 3s high.`
        : "Triage complete · no incidents opened.",
      "muted",
      roundAuditBase + 610,
    );
    push({
      kind: "alerts",
      phase: "detect",
      label: `Round ${roundNum} · detect & triage`,
      detail:
        "DetectionAgent correlates telemetry; TriageAgent assigns SLA targets.",
      delay: 440,
      alerts,
      incidents,
    });

    const patches: CandidatePatch[] = [];
    const validations: ValidationReport[] = [];
    const deployments: DeploymentReceipt[] = [];
    const verifications: VerificationResult[] = [];
    const rootCauses: RootCauseAnalysis[] = [];

    incidents.forEach((incident, index) => {
      virtual += 1.4;
      const cwe = incident.finding.cweId;
      const blueprint = BLUEPRINTS[cwe];
      const original = workspace[blueprint.filePath];
      const patched = applyFix(original, cwe);

      const rca: RootCauseAnalysis = {
        incidentId: incident.incidentId,
        cweId: cwe,
        filePath: blueprint.filePath,
        functionName: blueprint.functionName,
        lineNumber: incident.finding.lineNumber,
        vulnerableBlock:
          cwe === "CWE-489"
            ? original
            : extractFunction(original, blueprint.functionName),
        astNodeType: cwe === "CWE-489" ? "Module" : "FunctionDef",
        rootCauseExplanation: incident.finding.description,
        remediationContract: blueprint.remediationContract,
      };
      rootCauses.push(rca);

      const patch: CandidatePatch = {
        patchId: `PATCH-${incident.incidentId}`,
        incidentId: incident.incidentId,
        cweId: cwe,
        filePath: blueprint.filePath,
        originalContent: original,
        patchedContent: patched,
        unifiedDiff: createUnifiedDiff(blueprint.filePath, original, patched),
        rationale: `Remediated ${cwe} according to contract: ${blueprint.remediationContract}`,
        generatedAtMs: virtual + 0.8,
      };
      patches.push(patch);

      const validation: ValidationReport = {
        patchId: patch.patchId,
        incidentId: incident.incidentId,
        syntaxValid: true,
        functionalTestsPassed: true,
        securityChecksPassed: true,
        testCount: 4,
        details: [
          "AST syntax check passed.",
          "Functional Test 1 (user directory lookup) passed.",
          "Functional Test 2 (public document listing) passed.",
          `${cwe} ${CWE_LABELS[cwe]} invariant check: True`,
        ],
        passed: true,
      };
      validations.push(validation);

      virtual += 1.2;
      const deployed =
        approvalMode === "auto" && validation.passed;
      const awaiting = approvalMode === "manual";
      const status = deployed
        ? "deployed"
        : awaiting
          ? "awaiting_approval"
          : "blocked";

      const preHash = sha256Hex(original);
      const postHash = deployed ? sha256Hex(patched) : preHash;
      const deployment: DeploymentReceipt = {
        deploymentId: `DEP-${patch.patchId}`,
        patchId: patch.patchId,
        incidentId: incident.incidentId,
        cweId: cwe,
        filePath: blueprint.filePath,
        prePatchSha256: preHash,
        postPatchSha256: postHash,
        backupPath: `simulation_artifacts/workspace/backups/${patch.patchId}_${blueprint.filePath.split("/").pop()}.bak`,
        deployed,
        rolledBack: false,
        status,
        deployedAtMs: incident.alert.triggeredAtMs + 7.2 + index * 0.3,
        notes: deployed
          ? "Deployed cleanly (Approved under 'auto_low_risk' policy (100% staging tests passed))."
          : awaiting
            ? "Held by HumanApprovalGate: awaiting reviewer decision."
            : "Blocked by HumanApprovalGate: Policy mode set to deny_all.",
      };
      deployments.push(deployment);

      const verification: VerificationResult = {
        findingId: incident.finding.findingId,
        cweId: cwe,
        filePath: blueprint.filePath,
        remediated: deployed,
        verificationMethod: "AST & Configuration Re-Audit",
        details: deployed
          ? `Verified ${cwe} in ${blueprint.filePath} is fully remediated.`
          : `${cwe} remains present in ${blueprint.filePath}.`,
        verifiedAtMs: deployment.deployedAtMs + 2.4,
      };
      verifications.push(verification);

      if (deployed) {
        workspace[blueprint.filePath] = patched;
        if (!remediated.includes(cwe)) remediated.push(cwe);
      }

      audit(
        "RootCauseAgent",
        "inspect_source_ast",
        {
          target_host: "localhost",
          target_path: `simulation_artifacts/workspace/${blueprint.filePath}`,
        },
        options.now + (roundNum - 1) * 4000 + 700 + index * 60,
      );
      audit(
        "PatchGenerationAgent",
        "synthesize_patch",
        {
          target_path: `simulation_artifacts/workspace/${blueprint.filePath}`,
          target_host: "localhost",
        },
        options.now + (roundNum - 1) * 4000 + 715 + index * 60,
      );
      audit(
        "ValidationTestingAgent",
        "validate_patch_in_staging",
        {
          target_path: "simulation_artifacts/workspace/staging",
          target_host: "localhost",
        },
        options.now + (roundNum - 1) * 4000 + 730 + index * 60,
      );
      audit(
        "HumanApprovalGate",
        "evaluate_patch",
        {
          patch_id: patch.patchId,
          cwe_id: cwe,
          approved: deployed,
          reason: deployed
            ? "Approved under 'auto_low_risk' policy (100% staging tests passed)"
            : awaiting
              ? "Awaiting human reviewer"
              : "Policy mode set to deny_all",
        },
        options.now + (roundNum - 1) * 4000 + 745 + index * 60,
      );
      audit(
        "DeploymentRollbackAgent",
        "deploy_patch",
        {
          target_host: "localhost",
          target_path: `simulation_artifacts/workspace/${blueprint.filePath}`,
          patch_id: patch.patchId,
        },
        options.now + (roundNum - 1) * 4000 + 760 + index * 60,
      );

      log(
        "RootCauseAgent",
        "inspect_source_ast",
        `${incident.incidentId}: isolated ${cwe} at ${blueprint.filePath}:${incident.finding.lineNumber}.`,
        "muted",
        options.now + (roundNum - 1) * 4000 + 700 + index * 60,
      );
      log(
        "PatchGenerationAgent",
        "synthesize_patch",
        `${patch.patchId} synthesized · ${patch.unifiedDiff
          .split("\n")
          .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
          .length} added / ${
          patch.unifiedDiff
            .split("\n")
            .filter((line) => line.startsWith("-") && !line.startsWith("---"))
            .length
        } removed lines.`,
        "info",
        options.now + (roundNum - 1) * 4000 + 715 + index * 60,
      );
      log(
        "ValidationTestingAgent",
        "validate_patch_in_staging",
        "Staging validation passed · syntax, 2 functional tests, security invariant.",
        "success",
        options.now + (roundNum - 1) * 4000 + 730 + index * 60,
      );
      log(
        "DeploymentRollbackAgent",
        "deploy_patch",
        deployed
          ? `${patch.patchId} deployed atomically · sha256 ${postHash.slice(0, 12)}…`
          : awaiting
            ? `${patch.patchId} queued for human review.`
            : `${patch.patchId} blocked by deny_all policy.`,
        deployed ? "success" : awaiting ? "warn" : "danger",
        options.now + (roundNum - 1) * 4000 + 760 + index * 60,
      );

      push({
        kind: "incident",
        phase: "deploy",
        label: `Round ${roundNum} · ${incident.incidentId}`,
        detail: `${cwe} · ${blueprint.filePath}`,
        delay: 560,
        rca,
        patch,
        validation,
        deployment,
        verification,
      });
    });

    virtual += 2;
    audit(
      "ComplianceVerifierAgent",
      "verify_remediations",
      {
        target_host: "localhost",
        target_path: "simulation_artifacts/workspace/mock_enterprise",
      },
      options.now + (roundNum - 1) * 4000 + 1200,
    );
    const remediatedThisRound = verifications.filter((v) => v.remediated).length;
    log(
      "ComplianceVerifierAgent",
      "verify_remediations",
      `${remediatedThisRound}/${verifications.length || 0} remediations confirmed by independent re-audit.`,
      remediatedThisRound === verifications.length ? "success" : "warn",
      options.now + (roundNum - 1) * 4000 + 1200,
    );
    push({
      kind: "phase",
      phase: "verify",
      label: `Round ${roundNum} · compliance re-audit`,
      detail:
        "ComplianceVerifierAgent re-audits every patched file independently.",
      delay: 460,
    });

    virtual += 2;
    const mttdSamples = alerts.map(
      (alert) =>
        alert.triggeredAtMs -
        (sorted.find((finding) => finding.findingId === alert.findingId)
          ?.detectedAtMs ?? alert.triggeredAtMs),
    );
    const mttrSamples = deployments
      .filter((deployment) => deployment.deployed)
      .map((deployment) => {
        const alert = alerts.find((a) => a.cweId === deployment.cweId);
        return deployment.deployedAtMs - (alert?.triggeredAtMs ?? 0);
      });
    const foundCweSet = new Set(sorted.map((finding) => finding.cweId));
    const alreadyRemediatedAtStart = allCwes.filter(
      (cwe) => !foundCweSet.has(cwe) && remediated.includes(cwe),
    );
    const expectedActive = allCwes.length - alreadyRemediatedAtStart.length;
    const recall =
      expectedActive === 0
        ? 100
        : round2(100 * (sorted.length / expectedActive));
    const validated = validations.filter((validation) => validation.passed);
    const deployedCount = deployments.filter((deployment) => deployment.deployed);
    const remediatedCount = verifications.filter((v) => v.remediated);

    const scorecard: RoundScorecard = {
      roundNum,
      groundTruthTotal: allCwes.length,
      findingsDiscovered: sorted.length,
      discoveryRecallPct: recall,
      alertsTriggered: alerts.length,
      meanTimeToDetectMs: mttdSamples.length
        ? round2(avg(mttdSamples))
        : 0,
      patchesGenerated: patches.length,
      patchesValidated: validated.length,
      patchesDeployed: deployedCount.length,
      verifiedRemediated: remediatedCount.length,
      patchCorrectnessPct: patches.length
        ? round2((100 * remediatedCount.length) / patches.length)
        : 100,
      regressionPassRatePct: validations.length
        ? round2((100 * validated.length) / validations.length)
        : 100,
      meanTimeToRemediateMs: mttrSamples.length ? round2(avg(mttrSamples)) : 0,
      securityPostureScore: round2((100 * remediated.length) / allCwes.length),
    };

    const roundResult: RoundResult = {
      roundNum,
      startedAt: roundBase,
      finishedAt: virtual,
      surfaces: SURFACES,
      findings: sorted,
      alerts,
      incidents,
      rootCauses,
      patches,
      validations,
      deployments,
      verifications,
      scorecard,
    };

    const lessons: LessonLearned[] = patches.map((patch, index) => {
      const verification = verifications.find((v) => v.cweId === patch.cweId);
      return {
        id: (options.rounds > 1 ? roundNum * 10 : 0) + index + 1,
        roundNum,
        cweId: patch.cweId,
        filePath: patch.filePath,
        patchId: patch.patchId,
        remediated: Boolean(verification?.remediated),
        lessonSummary: patch.rationale,
      };
    });

    const memoryRound: MemoryRound = {
      roundNum,
      recordedAt: new Date(options.now + (roundNum - 1) * 4000 + 1600).toISOString(),
      findingsDiscovered: scorecard.findingsDiscovered,
      patchesDeployed: scorecard.patchesDeployed,
      verifiedRemediated: scorecard.verifiedRemediated,
      postureScore: scorecard.securityPostureScore,
    };

    audit(
      "SimulationOrchestrator",
      "run_round",
      {
        round: roundNum,
        posture_score: scorecard.securityPostureScore,
      },
      options.now + (roundNum - 1) * 4000 + 1400,
    );
    log(
      "SimulationOrchestrator",
      "run_round",
      `Round ${roundNum} scored · recall ${scorecard.discoveryRecallPct}% · posture ${scorecard.securityPostureScore}%.`,
      "success",
      options.now + (roundNum - 1) * 4000 + 1400,
    );
    push({
      kind: "score",
      phase: "score",
      label: `Round ${roundNum} · judge & memory`,
      detail:
        "ScoringEngine compares outcomes against ground truth and persists lessons.",
      delay: 460,
      round: roundResult,
      memoryRound,
      lessons,
    });
  }

  audit(
    "SimulationOrchestrator",
    "finalize_simulation",
    {
      target_host: "localhost",
      target_path: "simulation_artifacts/workspace",
    },
    options.now + options.rounds * 2000,
  );
  log(
    "SimulationOrchestrator",
    "finalize_simulation",
    `Campaign sealed · ${remediated.length}/4 CWE classes remediated · audit chain verified.`,
    "success",
    options.now + options.rounds * 2000,
  );
  push({
    kind: "complete",
    phase: "complete",
    label: "Campaign complete",
    detail: "Audit chain sealed. Shared memory persisted.",
    delay: 420,
  });

  steps.forEach((step, index) => {
    step.progress = Math.min(1, (index + 1) / steps.length);
  });

  return {
    steps,
    rounds: options.rounds,
    approvalMode,
    finalRemediated: remediated,
    startedAt: options.now,
  };
}

const avg = (values: number[]) =>
  values.reduce((total, value) => total + value, 0) / values.length;
const round2 = (value: number) => Math.round(value * 100) / 100;

/* --------------------------------------------------------------------------
   Selectors
   -------------------------------------------------------------------------- */

export function latestRound(state: RangeState): RoundResult | null {
  return state.rounds.length ? state.rounds[state.rounds.length - 1] : null;
}

export function roundWithFindings(state: RangeState): RoundResult | null {
  return (
    [...state.rounds].reverse().find((round) => round.findings.length > 0) ??
    latestRound(state)
  );
}

export function severityCounts(findings: SecurityFinding[]) {
  return {
    CRITICAL: findings.filter((f) => f.severity === "CRITICAL").length,
    HIGH: findings.filter((f) => f.severity === "HIGH").length,
    MEDIUM: findings.filter((f) => f.severity === "MEDIUM").length,
    LOW: findings.filter((f) => f.severity === "LOW").length,
  };
}

export function pendingApprovals(state: RangeState) {
  return state.rounds.flatMap((round) =>
    round.deployments
      .filter((deployment) => deployment.status === "awaiting_approval")
      .map((deployment) => ({ roundNum: round.roundNum, deployment })),
  );
}

export function patchForRound(round: RoundResult | null, patchId: string) {
  return round?.patches.find((patch) => patch.patchId === patchId) ?? null;
}
