import {
  createContext,
  useCallback,
  useContext,
  useReducer,
  useRef,
} from "react";
import type { ReactNode } from "react";
import { createBaselineState } from "./baseline";
import {
  createAuditEntry,
  planCampaign,
  verifyAuditChain,
} from "./engine";
import { sha256Hex } from "../sha256";
import type {
  ApprovalMode,
  AuditEntry,
  CweId,
  DeploymentReceipt,
  LogEntry,
  RangeState,
  RoundResult,
  RunStep,
  TelemetryEvent,
  VerificationResult,
} from "./types";

export const GENESIS_HASH = "0".repeat(64);

type Action =
  | {
      type: "START";
      plan: {
        startedAt: number;
        rounds: number;
        approvalMode: ApprovalMode;
      };
    }
  | { type: "STEP"; step: RunStep; at: number }
  | { type: "HALT"; audits: AuditEntry[]; log: LogEntry[]; label: string }
  | {
      type: "TRIP_KILL";
      reason: string;
      at: number;
      audits: AuditEntry[];
      log: LogEntry[];
    }
  | {
      type: "RESET_KILL";
      at: number;
      audits: AuditEntry[];
      log: LogEntry[];
    }
  | {
      type: "APPROVE";
      roundNum: number;
      deployment: DeploymentReceipt;
      verification: VerificationResult;
      audits: AuditEntry[];
      log: LogEntry[];
      at: number;
      posture: number;
    }
  | {
      type: "DENY";
      roundNum: number;
      deployment: DeploymentReceipt;
      audits: AuditEntry[];
      log: LogEntry[];
      at: number;
    };

function withAudits(state: RangeState, entries: AuditEntry[]): AuditEntry[] {
  return entries.length ? [...state.audit, ...entries] : state.audit;
}

function emptyCampaignState(state: RangeState): RangeState {
  return {
    ...state,
    status: "running",
    phase: "initialize",
    phaseLabel: "Initializing sandbox",
    progress: 0,
    rounds: [],
    activeRound: 0,
    surfaces: [],
    findings: [],
    alerts: [],
    incidents: [],
    rootCauses: [],
    patches: [],
    validations: [],
    deployments: [],
    verifications: [],
    remediatedCwes: [],
    memoryRounds: [],
    lessons: [],
    log: [],
    campaignFinishedAt: null,
  };
}

function replaceRound(
  rounds: RoundResult[],
  roundNum: number,
  updater: (round: RoundResult) => RoundResult,
) {
  return rounds.map((round) =>
    round.roundNum === roundNum ? updater(round) : round,
  );
}

function telemetryForRound(
  round: RoundResult,
  startId: number,
): TelemetryEvent[] {
  const events: TelemetryEvent[] = [];
  let id = startId;
  const base = round.startedAt;
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
      traceId: `${id.toString(16)}${"7f3a9c1e5b2d4a6f".repeat(4)}`
        .slice(0, 32)
        .padEnd(32, "0"),
      spanId: id.toString(16).padStart(16, "0").slice(-16),
      service: "acme-enterprise-portal",
      eventType,
      endpoint,
      actor,
      statusCode: status,
      metadata,
    });
  };

  round.findings.forEach((finding) => {
    push(
      finding.detectedAtMs,
      "finding_detected",
      finding.endpoint,
      "cyber_range_swarm",
      200,
      { finding_id: finding.findingId, cwe_id: finding.cweId },
    );
  });
  round.alerts.forEach((alert) => {
    push(alert.triggeredAtMs, "alert_triggered", alert.endpoint, "cyber_range_swarm", 200, {
      alert_id: alert.alertId,
      cwe_id: alert.cweId,
    });
  });
  round.deployments.forEach((deployment) => {
    push(
      deployment.deployedAtMs,
      deployment.deployed ? "patch_deployed" : "patch_rollback",
      deployment.filePath,
      "cyber_range_swarm",
      200,
      { patch_id: deployment.patchId, cwe_id: deployment.cweId },
    );
  });
  if (!events.length) {
    push(base, "http_request", "/api/v1/health", "system", 200, {
      round: round.roundNum,
      result: "no active findings",
    });
  }
  return events;
}

function rangeReducer(state: RangeState, action: Action): RangeState {
  switch (action.type) {
    case "START": {
      return {
        ...emptyCampaignState(state),
        approvalMode: action.plan.approvalMode,
        campaignRounds: action.plan.rounds,
        campaignStartedAt: action.plan.startedAt,
        telemetry: state.telemetry,
        audit: state.audit,
      };
    }

    case "STEP": {
      const { step } = action;
      const base: RangeState = {
        ...state,
        phase: step.phase,
        phaseLabel: step.label,
        progress: step.progress,
        audit: withAudits(state, step.audit),
        log: step.log.length
          ? [...state.log, ...step.log].slice(-400)
          : state.log,
      };

      switch (step.kind) {
        case "phase":
          return base;

        case "surfaces":
          return {
            ...base,
            surfaces: step.surfaces,
            findings: step.findings,
          };

        case "alerts":
          return {
            ...base,
            alerts: step.alerts,
            incidents: step.incidents,
          };

        case "incident": {
          const remediated = step.deployment.deployed
            ? Array.from(new Set([...state.remediatedCwes, step.deployment.cweId]))
            : state.remediatedCwes;
          return {
            ...base,
            rootCauses: [...state.rootCauses, step.rca],
            patches: [...state.patches, step.patch],
            validations: [...state.validations, step.validation],
            deployments: [...state.deployments, step.deployment],
            verifications: [...state.verifications, step.verification],
            remediatedCwes: remediated,
          };
        }

        case "score": {
          const round = step.round;
          const remediated = Array.from(
            new Set([
              ...state.remediatedCwes,
              ...round.verifications
                .filter((verification) => verification.remediated)
                .map((verification) => verification.cweId),
            ]),
          ) as CweId[];
          return {
            ...base,
            rounds: [...state.rounds, round],
            activeRound: round.roundNum,
            findings: round.findings,
            alerts: round.alerts,
            incidents: round.incidents,
            rootCauses: round.rootCauses,
            patches: round.patches,
            validations: round.validations,
            deployments: round.deployments,
            verifications: round.verifications,
            remediatedCwes: remediated,
            memoryRounds: [...state.memoryRounds, step.memoryRound],
            lessons: [...state.lessons, ...step.lessons],
            telemetry: [
              ...state.telemetry,
              ...telemetryForRound(round, state.telemetry.length + 1),
            ],
          };
        }

        case "complete":
          return {
            ...base,
            status: "complete",
            phase: "complete",
            phaseLabel: "Campaign complete",
            progress: 1,
            campaignFinishedAt: action.at,
          };

        default:
          return base;
      }
    }

    case "HALT":
      return {
        ...state,
        status: "halted",
        phase: "halted",
        phaseLabel: action.label,
        audit: withAudits(state, action.audits),
        log: [...state.log, ...action.log].slice(-400),
      };

    case "TRIP_KILL":
      return {
        ...state,
        killSwitch: { tripped: true, reason: action.reason, at: action.at },
        status: state.status === "running" ? "halted" : state.status,
        phase: state.status === "running" ? "halted" : state.phase,
        phaseLabel:
          state.status === "running" ? "Kill switch tripped" : state.phaseLabel,
        audit: withAudits(state, action.audits),
        log: [...state.log, ...action.log].slice(-400),
      };

    case "RESET_KILL":
      return {
        ...state,
        killSwitch: { tripped: false, reason: "", at: null },
        status: state.status === "halted" ? "idle" : state.status,
        phase: state.status === "halted" ? "idle" : state.phase,
        phaseLabel:
          state.status === "halted" ? "Range ready" : state.phaseLabel,
        audit: withAudits(state, action.audits),
        log: [...state.log, ...action.log].slice(-400),
      };

    case "APPROVE": {
      const rounds = replaceRound(state.rounds, action.roundNum, (round) => {
        const deployments = round.deployments.map((deployment) =>
          deployment.deploymentId === action.deployment.deploymentId
            ? action.deployment
            : deployment,
        );
        const verifications = round.verifications.map((verification) =>
          verification.cweId === action.verification.cweId &&
          verification.findingId === action.verification.findingId
            ? action.verification
            : verification,
        );
        return {
          ...round,
          deployments,
          verifications,
          scorecard: {
            ...round.scorecard,
            patchesDeployed: deployments.filter((item) => item.deployed).length,
            verifiedRemediated: verifications.filter(
              (item) => item.remediated,
            ).length,
            patchCorrectnessPct: round.patches.length
              ? Math.round(
                  (100 *
                    verifications.filter((item) => item.remediated).length) /
                    round.patches.length,
                )
              : 100,
            securityPostureScore: action.posture,
          },
        };
      });
      const isActive = state.activeRound === action.roundNum;
      return {
        ...state,
        rounds,
        deployments: isActive
          ? state.deployments.map((deployment) =>
              deployment.deploymentId === action.deployment.deploymentId
                ? action.deployment
                : deployment,
            )
          : state.deployments,
        verifications: isActive
          ? state.verifications.map((verification) =>
              verification.findingId === action.verification.findingId
                ? action.verification
                : verification,
            )
          : state.verifications,
        remediatedCwes: Array.from(
          new Set([...state.remediatedCwes, action.deployment.cweId]),
        ) as CweId[],
        audit: withAudits(state, action.audits),
        log: [...state.log, ...action.log].slice(-400),
        telemetry: [
          ...state.telemetry,
          ...telemetryForRound(
            {
              ...(state.rounds.find((r) => r.roundNum === action.roundNum) ??
                state.rounds[0]),
              deployments: [action.deployment],
              findings: [],
              alerts: [],
            },
            state.telemetry.length + 1,
          ),
        ],
      };
    }

    case "DENY": {
      const rounds = replaceRound(state.rounds, action.roundNum, (round) => ({
        ...round,
        deployments: round.deployments.map((deployment) =>
          deployment.deploymentId === action.deployment.deploymentId
            ? action.deployment
            : deployment,
        ),
      }));
      const isActive = state.activeRound === action.roundNum;
      return {
        ...state,
        rounds,
        deployments: isActive
          ? state.deployments.map((deployment) =>
              deployment.deploymentId === action.deployment.deploymentId
                ? action.deployment
                : deployment,
            )
          : state.deployments,
        audit: withAudits(state, action.audits),
        log: [...state.log, ...action.log].slice(-400),
      };
    }

    default:
      return state;
  }
}

interface RangeContextValue {
  state: RangeState;
  startCampaign: (options: {
    rounds: number;
    approvalMode: ApprovalMode;
  }) => Promise<void>;
  abortCampaign: () => void;
  tripKillSwitch: (reason: string) => void;
  resetKillSwitch: () => void;
  approveDeployment: (roundNum: number, deploymentId: string) => boolean;
  denyDeployment: (roundNum: number, deploymentId: string) => boolean;
  verifyChain: () => { valid: boolean; brokenAt: number | null };
}

const RangeContext = createContext<RangeContextValue | null>(null);

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function RangeProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(
    rangeReducer,
    undefined,
    createBaselineState,
  );
  const stateRef = useRef(state);
  stateRef.current = state;

  const runToken = useRef(0);
  const running = useRef(false);

  const startCampaign = useCallback(
    async (options: { rounds: number; approvalMode: ApprovalMode }) => {
      const current = stateRef.current;
      if (running.current || current.killSwitch.tripped) return;
      running.current = true;
      const token = ++runToken.current;
      const now = Date.now();
      const lastAudit = current.audit[current.audit.length - 1];
      const lastLog = current.log[current.log.length - 1];
      const plan = planCampaign({
        rounds: Math.min(4, Math.max(1, options.rounds)),
        approvalMode: options.approvalMode,
        auditHead: lastAudit?.entryHash ?? GENESIS_HASH,
        auditStartId: (lastAudit?.id ?? 0) + 1,
        logStartId: (lastLog?.id ?? 0) + 1,
        now,
      });

      dispatch({
        type: "START",
        plan: {
          startedAt: plan.startedAt,
          rounds: plan.rounds,
          approvalMode: plan.approvalMode,
        },
      });

      for (const step of plan.steps) {
        await wait(step.delay || 60);
        if (token !== runToken.current) {
          running.current = false;
          return;
        }
        if (stateRef.current.killSwitch.tripped) {
          running.current = false;
          return;
        }
        dispatch({ type: "STEP", step, at: Date.now() });
      }
      running.current = false;
    },
    [],
  );

  const appendAudit = useCallback(
    (actor: string, action: string, details: Record<string, unknown>) => {
      const current = stateRef.current;
      const previous = current.audit[current.audit.length - 1];
      return createAuditEntry(
        previous?.entryHash ?? GENESIS_HASH,
        actor,
        action,
        details,
        new Date().toISOString(),
        (previous?.id ?? 0) + 1,
      );
    },
    [],
  );

  const abortCampaign = useCallback(() => {
    if (!running.current) return;
    runToken.current += 1;
    running.current = false;
    const entry = appendAudit("Operator", "abort_campaign", {
      reason: "Operator halted the active campaign.",
    });
    dispatch({
      type: "HALT",
      label: "Campaign halted by operator",
      audits: [entry],
      log: [
        {
          id: Date.now(),
          at: Date.now(),
          actor: "Operator",
          action: "abort_campaign",
          message: "Campaign halted by operator. Sandbox preserved.",
          tone: "danger",
        },
      ],
    });
  }, [appendAudit]);

  const tripKillSwitch = useCallback(
    (reason: string) => {
      if (running.current) {
        runToken.current += 1;
        running.current = false;
      }
      const at = Date.now();
      const entry = appendAudit("Operator", "trip_kill_switch", { reason });
      dispatch({
        type: "TRIP_KILL",
        reason,
        at,
        audits: [entry],
        log: [
          {
            id: at,
            at,
            actor: "Operator",
            action: "trip_kill_switch",
            message: `Kill switch tripped · ${reason}`,
            tone: "danger",
          },
        ],
      });
    },
    [appendAudit],
  );

  const resetKillSwitch = useCallback(() => {
    const at = Date.now();
    const entry = appendAudit("Operator", "reset_kill_switch", {
      reason: "Kill switch reset after review.",
    });
    dispatch({
      type: "RESET_KILL",
      at,
      audits: [entry],
      log: [
        {
          id: at,
          at,
          actor: "Operator",
          action: "reset_kill_switch",
          message: "Kill switch reset. Range ready for a new campaign.",
          tone: "success",
        },
      ],
    });
  }, [appendAudit]);

  const approveDeployment = useCallback(
    (roundNum: number, deploymentId: string) => {
      const current = stateRef.current;
      if (running.current) return false;
      const round = current.rounds.find((item) => item.roundNum === roundNum);
      const deployment = round?.deployments.find(
        (item) => item.deploymentId === deploymentId,
      );
      if (!round || !deployment || deployment.status !== "awaiting_approval") {
        return false;
      }
      const patch = round.patches.find(
        (item) => item.patchId === deployment.patchId,
      );
      if (!patch) return false;

      const now = Date.now();
      const approved: DeploymentReceipt = {
        ...deployment,
        deployed: true,
        status: "deployed",
        postPatchSha256: sha256Hex(patch.patchedContent),
        deployedAtMs: now,
        notes:
          "Deployed cleanly (HumanApprovalGate approved after staging validation).",
      };
      const verification: VerificationResult = {
        findingId:
          round.verifications.find((v) => v.cweId === deployment.cweId)
            ?.findingId ?? `FIND-${deployment.cweId}`,
        cweId: deployment.cweId,
        filePath: deployment.filePath,
        remediated: true,
        verificationMethod: "AST & Configuration Re-Audit",
        details: `Verified ${deployment.cweId} in ${deployment.filePath} is fully remediated.`,
        verifiedAtMs: now + 2,
      };
      const gate = appendAudit("HumanApprovalGate", "evaluate_patch", {
        patch_id: patch.patchId,
        cwe_id: deployment.cweId,
        approved: true,
        reason: "Approved by human reviewer after staging validation.",
      });
      const deploy = createAuditEntry(
        gate.entryHash,
        "DeploymentRollbackAgent",
        "deploy_patch",
        {
          target_host: "localhost",
          target_path: `simulation_artifacts/workspace/${deployment.filePath}`,
          patch_id: patch.patchId,
        },
        new Date(now + 1).toISOString(),
        gate.id + 1,
      );
      const posture =
        (100 *
          Array.from(new Set([...current.remediatedCwes, deployment.cweId]))
            .length) /
        4;

      dispatch({
        type: "APPROVE",
        roundNum,
        deployment: approved,
        verification,
        audits: [gate, deploy],
        posture,
        at: now,
        log: [
          {
            id: now,
            at: now,
            actor: "HumanApprovalGate",
            action: "evaluate_patch",
            message: `Reviewer approved ${patch.patchId}.`,
            tone: "success",
          },
          {
            id: now + 1,
            at: now + 1,
            actor: "DeploymentRollbackAgent",
            action: "deploy_patch",
            message: `${patch.patchId} deployed atomically · sha256 ${approved.postPatchSha256.slice(0, 12)}…`,
            tone: "success",
          },
        ],
      });
      return true;
    },
    [appendAudit],
  );

  const denyDeployment = useCallback(
    (roundNum: number, deploymentId: string) => {
      const current = stateRef.current;
      if (running.current) return false;
      const round = current.rounds.find((item) => item.roundNum === roundNum);
      const deployment = round?.deployments.find(
        (item) => item.deploymentId === deploymentId,
      );
      if (!round || !deployment || deployment.status !== "awaiting_approval") {
        return false;
      }
      const now = Date.now();
      const blocked: DeploymentReceipt = {
        ...deployment,
        deployed: false,
        status: "blocked",
        notes: "Blocked by HumanApprovalGate: reviewer denied the patch.",
      };
      const gate = appendAudit("HumanApprovalGate", "evaluate_patch", {
        patch_id: deployment.patchId,
        cwe_id: deployment.cweId,
        approved: false,
        reason: "Denied by human reviewer.",
      });
      dispatch({
        type: "DENY",
        roundNum,
        deployment: blocked,
        audits: [gate],
        at: now,
        log: [
          {
            id: now,
            at: now,
            actor: "HumanApprovalGate",
            action: "evaluate_patch",
            message: `Reviewer denied ${deployment.patchId}. Workspace left untouched.`,
            tone: "warn",
          },
        ],
      });
      return true;
    },
    [appendAudit],
  );

  const verifyChain = useCallback(
    () => verifyAuditChain(stateRef.current.audit),
    [],
  );

  return (
    <RangeContext.Provider
      value={{
        state,
        startCampaign,
        abortCampaign,
        tripKillSwitch,
        resetKillSwitch,
        approveDeployment,
        denyDeployment,
        verifyChain,
      }}
    >
      {children}
    </RangeContext.Provider>
  );
}

export function useRange() {
  const value = useContext(RangeContext);
  if (!value) throw new Error("useRange must be used inside RangeProvider");
  return value;
}
