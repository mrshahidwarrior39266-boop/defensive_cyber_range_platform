/* Domain model mirroring agents/models.py, orchestrator/scoring.py and
   safety/controls.py from the Defensive Cyber Range platform. */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type CweId = "CWE-89" | "CWE-862" | "CWE-79" | "CWE-489";

export type ApprovalMode = "auto" | "manual" | "deny";

export type RunStatus = "idle" | "running" | "complete" | "halted";

export type PhaseKey =
  | "idle"
  | "initialize"
  | "surface"
  | "audit"
  | "prioritize"
  | "detect"
  | "triage"
  | "rca"
  | "patch"
  | "validate"
  | "deploy"
  | "verify"
  | "score"
  | "complete"
  | "halted";

export type LogTone = "info" | "success" | "warn" | "danger" | "muted";

export interface EndpointSurface {
  filePath: string;
  functionName: string;
  endpoint: string;
  parameters: string[];
  hasAuthGuard: boolean;
  lineNumber: number;
}

export interface SecurityFinding {
  findingId: string;
  vulnId: string;
  cweId: CweId;
  title: string;
  severity: Severity;
  cvssScore: number;
  filePath: string;
  functionName: string;
  endpoint: string;
  lineNumber: number;
  evidenceSnippet: string;
  description: string;
  remediationGuidance: string;
  detectedAtMs: number;
}

export interface SecurityAlert {
  alertId: string;
  findingId: string;
  cweId: CweId;
  severity: Severity;
  endpoint: string;
  filePath: string;
  functionName: string;
  lineNumber: number;
  triggeredAtMs: number;
  correlatedTelemetryEvents: number;
  summary: string;
}

export interface TriagedIncident {
  incidentId: string;
  alert: SecurityAlert;
  finding: SecurityFinding;
  priorityRank: number;
  slaTargetMs: number;
  assignedModule: string;
}

export interface RootCauseAnalysis {
  incidentId: string;
  cweId: CweId;
  filePath: string;
  functionName: string;
  lineNumber: number;
  vulnerableBlock: string;
  astNodeType: string;
  rootCauseExplanation: string;
  remediationContract: string;
}

export interface CandidatePatch {
  patchId: string;
  incidentId: string;
  cweId: CweId;
  filePath: string;
  originalContent: string;
  patchedContent: string;
  unifiedDiff: string;
  rationale: string;
  generatedAtMs: number;
}

export interface ValidationReport {
  patchId: string;
  incidentId: string;
  syntaxValid: boolean;
  functionalTestsPassed: boolean;
  securityChecksPassed: boolean;
  testCount: number;
  details: string[];
  passed: boolean;
}

export type DeploymentStatus =
  | "deployed"
  | "blocked"
  | "rolled_back"
  | "awaiting_approval";

export interface DeploymentReceipt {
  deploymentId: string;
  patchId: string;
  incidentId: string;
  cweId: CweId;
  filePath: string;
  prePatchSha256: string;
  postPatchSha256: string;
  backupPath: string;
  deployed: boolean;
  rolledBack: boolean;
  status: DeploymentStatus;
  deployedAtMs: number;
  notes: string;
}

export interface VerificationResult {
  findingId: string;
  cweId: CweId;
  filePath: string;
  remediated: boolean;
  verificationMethod: string;
  details: string;
  verifiedAtMs: number;
}

export interface RoundScorecard {
  roundNum: number;
  groundTruthTotal: number;
  findingsDiscovered: number;
  discoveryRecallPct: number;
  alertsTriggered: number;
  meanTimeToDetectMs: number;
  patchesGenerated: number;
  patchesValidated: number;
  patchesDeployed: number;
  verifiedRemediated: number;
  patchCorrectnessPct: number;
  regressionPassRatePct: number;
  meanTimeToRemediateMs: number;
  securityPostureScore: number;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  details: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
}

export interface TelemetryEvent {
  id: number;
  timestamp: string;
  traceId: string;
  spanId: string;
  service: string;
  eventType: string;
  endpoint: string;
  actor: string;
  statusCode: number;
  metadata: Record<string, unknown>;
}

export interface MemoryRound {
  roundNum: number;
  recordedAt: string;
  findingsDiscovered: number;
  patchesDeployed: number;
  verifiedRemediated: number;
  postureScore: number;
}

export interface LessonLearned {
  id: number;
  roundNum: number;
  cweId: CweId;
  filePath: string;
  patchId: string;
  remediated: boolean;
  lessonSummary: string;
}

export interface LogEntry {
  id: number;
  at: number;
  actor: string;
  action: string;
  message: string;
  tone: LogTone;
}

export interface RoundResult {
  roundNum: number;
  startedAt: number;
  finishedAt: number;
  surfaces: EndpointSurface[];
  findings: SecurityFinding[];
  alerts: SecurityAlert[];
  incidents: TriagedIncident[];
  rootCauses: RootCauseAnalysis[];
  patches: CandidatePatch[];
  validations: ValidationReport[];
  deployments: DeploymentReceipt[];
  verifications: VerificationResult[];
  scorecard: RoundScorecard;
}

export interface RangeState {
  status: RunStatus;
  approvalMode: ApprovalMode;
  phase: PhaseKey;
  phaseLabel: string;
  progress: number;
  campaignRounds: number;
  activeRound: number;
  rounds: RoundResult[];
  surfaces: EndpointSurface[];
  findings: SecurityFinding[];
  alerts: SecurityAlert[];
  incidents: TriagedIncident[];
  rootCauses: RootCauseAnalysis[];
  patches: CandidatePatch[];
  validations: ValidationReport[];
  deployments: DeploymentReceipt[];
  verifications: VerificationResult[];
  remediatedCwes: CweId[];
  telemetry: TelemetryEvent[];
  audit: AuditEntry[];
  memoryRounds: MemoryRound[];
  lessons: LessonLearned[];
  killSwitch: { tripped: boolean; reason: string; at: number | null };
  log: LogEntry[];
  campaignStartedAt: number | null;
  campaignFinishedAt: number | null;
}

export type RunStep =
  | {
      kind: "phase";
      phase: PhaseKey;
      label: string;
      detail: string;
      delay: number;
      progress: number;
      audit: AuditEntry[];
      log: LogEntry[];
    }
  | {
      kind: "surfaces";
      phase: PhaseKey;
      label: string;
      detail: string;
      delay: number;
      progress: number;
      surfaces: EndpointSurface[];
      findings: SecurityFinding[];
      audit: AuditEntry[];
      log: LogEntry[];
    }
  | {
      kind: "alerts";
      phase: PhaseKey;
      label: string;
      detail: string;
      delay: number;
      progress: number;
      alerts: SecurityAlert[];
      incidents: TriagedIncident[];
      audit: AuditEntry[];
      log: LogEntry[];
    }
  | {
      kind: "incident";
      phase: PhaseKey;
      label: string;
      detail: string;
      delay: number;
      progress: number;
      rca: RootCauseAnalysis;
      patch: CandidatePatch;
      validation: ValidationReport;
      deployment: DeploymentReceipt;
      verification: VerificationResult;
      audit: AuditEntry[];
      log: LogEntry[];
    }
  | {
      kind: "score";
      phase: PhaseKey;
      label: string;
      detail: string;
      delay: number;
      progress: number;
      round: RoundResult;
      memoryRound: MemoryRound;
      lessons: LessonLearned[];
      audit: AuditEntry[];
      log: LogEntry[];
    }
  | {
      kind: "complete";
      phase: PhaseKey;
      label: string;
      detail: string;
      delay: number;
      progress: number;
      audit: AuditEntry[];
      log: LogEntry[];
    };

export interface PlannedCampaign {
  steps: RunStep[];
  rounds: number;
  approvalMode: ApprovalMode;
  finalRemediated: CweId[];
  startedAt: number;
}
