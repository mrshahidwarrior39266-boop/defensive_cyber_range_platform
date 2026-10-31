import { useNavigate } from "react-router-dom";
import { PageHeader } from "../../components/ui/primitives";
import {
  Button,
  EmptyState,
  Panel,
  Pill,
  SeverityPill,
  Stat,
} from "../../components/ui/primitives";
import { Gauge, LineChart, SeverityBar } from "../../components/ui/viz";
import { Icon } from "../../components/ui/Icon";
import { useToast } from "../../components/ui/overlays";
import { useDocumentTitle } from "../../lib/hooks";
import {
  latestRound,
  pendingApprovals,
  roundWithFindings,
  severityCounts,
  verifyAuditChain,
} from "../../lib/simulation/engine";
import { useRange } from "../../lib/simulation/store";
import type { PhaseKey } from "../../lib/simulation/types";
import {
  cn,
  formatDuration,
  formatMs,
  formatTime,
  relativeTime,
} from "../../lib/utils";
import "../../styles/pages.css";

const PHASES: PhaseKey[] = [
  "initialize",
  "surface",
  "audit",
  "prioritize",
  "detect",
  "triage",
  "deploy",
  "verify",
  "score",
  "complete",
];

const SWARM = [
  { name: "SurfaceMapper", group: "Analysis", phase: "surface" },
  { name: "StaticAuditor", group: "Analysis", phase: "audit" },
  { name: "RiskPrioritizer", group: "Analysis", phase: "prioritize" },
  { name: "ComplianceVerifier", group: "Analysis", phase: "verify" },
  { name: "AnalysisReporter", group: "Analysis", phase: "audit" },
  { name: "Detection", group: "Defense", phase: "detect" },
  { name: "Triage", group: "Defense", phase: "triage" },
  { name: "RootCause", group: "Defense", phase: "deploy" },
  { name: "PatchGeneration", group: "Defense", phase: "deploy" },
  { name: "ValidationTesting", group: "Defense", phase: "deploy" },
  { name: "DeploymentRollback", group: "Defense", phase: "deploy" },
] as const;

const MISSION_AGENTS = [
  { name: "SimulationOrchestrator", group: "Core", phase: "initialize" },
  { name: "ScoringEngine", group: "Core", phase: "score" },
];

function statusFor(
  phase: string,
  statePhase: PhaseKey,
  status: string,
) {
  if (status === "complete") return "sealed";
  if (status !== "running") return "standby";
  const current = PHASES.indexOf(statePhase);
  const target = PHASES.indexOf(phase as PhaseKey);
  if (target === current) return "active";
  if (target !== -1 && current !== -1 && target < current) return "done";
  return "queued";
}

export default function Dashboard() {
  useDocumentTitle("Mission control — Citadel");
  const navigate = useNavigate();
  const { state } = useRange();
  const { push } = useToast();
  const round = latestRound(state);
  const focus = roundWithFindings(state);
  const measured = focus ?? round;
  const findings = focus?.findings ?? state.findings;
  const counts = severityCounts(findings);
  const audit = verifyAuditChain(state.audit);
  const posture = round
    ? round.scorecard.securityPostureScore
    : (state.remediatedCwes.length / 4) * 100;
  const deployed = state.rounds.reduce(
    (total, item) =>
      total + item.deployments.filter((deployment) => deployment.deployed).length,
    0,
  );
  const alerts = state.rounds.reduce(
    (total, item) => total + item.alerts.length,
    0,
  );
  const findingsTotal = state.rounds.reduce(
    (total, item) => total + item.findings.length,
    0,
  );
  const pending = pendingApprovals(state);
  const trend = state.rounds.map((item) => item.scorecard.securityPostureScore);
  const verificationByCwe = new Map(
    (focus?.verifications ?? []).map((verification) => [
      verification.cweId,
      verification.remediated,
    ]),
  );

  const downloadReport = () => {
    const summary = {
      platform: "Defensive Cyber Range Simulation Platform",
      total_rounds: state.rounds.length,
      final_posture_score: posture,
      remediated_cwes: state.remediatedCwes,
      audit_chain_valid: audit.valid,
      audit_entries_count: state.audit.length,
      rounds: state.rounds.map((item) => ({
        round: item.roundNum,
        scorecard: item.scorecard,
        findings: item.findings.map((finding) => ({
          finding_id: finding.findingId,
          cwe_id: finding.cweId,
          severity: finding.severity,
          endpoint: finding.endpoint,
          file_path: finding.filePath,
        })),
      })),
      shared_memory: {
        rounds: state.memoryRounds,
        lessons_learned: state.lessons,
      },
    };
    const blob = new Blob([JSON.stringify(summary, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "simulation_report.json";
    anchor.click();
    URL.revokeObjectURL(url);
    push({
      title: "Report exported",
      message: "simulation_report.json was generated from the current range.",
      tone: "success",
    });
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Range overview"
        title="Mission control"
        description="A single view of the closed loop: what the swarms found, what they proved, and what the ledger can attest to."
        actions={
          <>
            <Button
              variant="ghost"
              size="sm"
              icon="download"
              onClick={downloadReport}
            >
              Export report
            </Button>
            <Button
              to="/console/live"
              variant="quiet"
              size="sm"
              icon="folder"
            >
              Live folder mode
            </Button>
            <Button
              to="/console/simulation"
              variant="primary"
              size="sm"
              icon="play"
            >
              Run campaign
            </Button>
          </>
        }
        meta={
          <>
            <Pill tone={audit.valid ? "live" : "critical"} icon="fingerprint">
              {audit.valid ? "Audit chain verified" : "Chain broken"}
            </Pill>
            <Pill icon="server">AcmeCorp Portal</Pill>
            <Pill icon="calendar">
              {state.rounds.length} of {state.campaignRounds || 0} rounds
            </Pill>
            {pending.length > 0 && (
              <Pill tone="medium" icon="clock">
                {pending.length} awaiting review
              </Pill>
            )}
          </>
        }
      />

      {state.killSwitch.tripped && (
        <div className="banner banner--danger">
          <span className="banner__icon">
            <Icon name="power" size={16} />
          </span>
          <div>
            <b>Kill switch is tripped</b>
            <p>
              {state.killSwitch.reason ||
                "All agent activity is halted. The sandbox and audit ledger are preserved."}
            </p>
          </div>
          <Button
            to="/console/safety"
            variant="danger"
            size="sm"
            iconRight="arrow-right"
          >
            Reset in safety
          </Button>
        </div>
      )}

      <div className="glass-banner glass-banner--info" style={{ marginBottom: 20 }}>
        <div className="glass-banner__icon">
          <Icon name="target" size={16} />
        </div>
        <div className="glass-banner__content">
          <div className="row spread align-center" style={{ flexWrap: "wrap", gap: 8 }}>
            <span className="glass-banner__title">
              Mode 1: Synthetic Simulation Active · AcmeCorp Enterprise
            </span>
            <Button to="/console/live" variant="quiet" size="sm" iconRight="arrow-right">
              Switch to Mode 2: Live Folder
            </Button>
          </div>
          <p className="glass-banner__desc">
            You are viewing the disposable synthetic enterprise range. To audit and auto-remediate an independent codebase or connected local project folder, switch to Mode 2.
          </p>
        </div>
      </div>

      <div className="dash__top">
        <section className="panel posture-card">
          <div className="posture-card__glow" aria-hidden="true" />
          <div className="posture-card__head">
            <div>
              <span className="eyebrow">Current posture</span>
              <h3>{posture === 100 ? "Fully remediated" : "Remediation in progress"}</h3>
            </div>
            <Pill
              tone={audit.valid ? "live" : "critical"}
              icon={audit.valid ? "shield-check" : "alert"}
            >
              {audit.valid ? "VERIFIED" : "CHECK"}
            </Pill>
          </div>

          <div className="posture-card__body">
            <Gauge value={posture} size={186} label="posture score" />
            <div className="cwe-status">
              {(
                [
                  ["CWE-89", "SQL injection", "database.py"],
                  ["CWE-862", "Missing authz", "service.py"],
                  ["CWE-79", "XSS", "service.py"],
                  ["CWE-489", "Debug mode", "config.py"],
                ] as const
              ).map(([cwe, label, file]) => {
                const fixed = state.remediatedCwes.includes(cwe);
                return (
                  <div className="cwe-status__row" key={cwe}>
                    <span
                      className={cn(
                        "cwe-status__dot",
                        fixed ? "is-fixed" : "is-open",
                      )}
                    />
                    <div>
                      <b>{cwe}</b>
                      <span>{label}</span>
                    </div>
                    <span className="cwe-status__file mono">{file}</span>
                    <span
                      className={cn(
                        "cwe-status__state",
                        fixed ? "is-fixed" : "is-open",
                      )}
                    >
                      {fixed ? "closed" : "open"}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="posture-card__foot">
            <span>
              <Icon name="shield-check" size={11} />
              {state.remediatedCwes.length} of 4 classes remediated
            </span>
            <span>{state.audit.length} sealed actions</span>
          </div>
        </section>

        <div className="dash__kpis">
          <Stat
            label="Findings discovered"
            value={findingsTotal}
            icon="scan"
            accent="amber"
            hint="Across four seeded CWE classes"
          />
          <Stat
            label="Alerts triaged"
            value={alerts}
            icon="activity"
            accent="violet"
            hint={
              measured ? (
                <>
                  Mean detection{" "}
                  <b>{formatMs(measured.scorecard.meanTimeToDetectMs)}</b>
                </>
              ) : (
                "No campaign yet"
              )
            }
          />
          <Stat
            label="Patches deployed"
            value={deployed}
            icon="git-branch"
            accent="mint"
            hint="Atomic, staging-validated, reversible"
          />
          <Stat
            label="Mean time to remediate"
            value={measured ? formatMs(measured.scorecard.meanTimeToRemediateMs) : "—"}
            icon="clock"
            accent="ice"
            hint={
              measured ? (
                <>
                  Regression pass{" "}
                  <b>{measured.scorecard.regressionPassRatePct}%</b>
                </>
              ) : (
                "—"
              )
            }
          />
        </div>
      </div>

      <div className="dash__grid">
        <Panel
          className="span-8"
          title="Campaign performance"
          subtitle="Judge scorecard against ground truth"
          actions={
            <>
              <Pill tone={state.status === "running" ? "live" : "neutral"}>
                {state.status === "running" ? "LIVE" : state.status.toUpperCase()}
              </Pill>
              <Button
                to="/console/simulation"
                variant="quiet"
                size="sm"
                iconRight="arrow-right"
              >
                Runner
              </Button>
            </>
          }
        >
          {state.rounds.length ? (
            <div className="perf">
              <LineChart
                values={trend}
                labels={state.rounds.map(
                  (item) => `R${String(item.roundNum).padStart(2, "0")}`,
                )}
                height={116}
              />
              <div className="perf__rounds">
                {state.rounds.map((item) => (
                  <div className="perf-row" key={item.roundNum}>
                    <span className="perf-row__num">
                      R{String(item.roundNum).padStart(2, "0")}
                    </span>
                    <div className="perf-row__main">
                      <div>
                        <b>{item.scorecard.findingsDiscovered} findings</b>
                        <span>
                          {item.scorecard.patchesDeployed} deployed ·{" "}
                          {item.scorecard.verifiedRemediated} verified
                        </span>
                      </div>
                      <div className="perf-row__bar">
                        <span
                          style={{
                            width: `${item.scorecard.securityPostureScore}%`,
                          }}
                        />
                      </div>
                    </div>
                    <span className="perf-row__score">
                      {item.scorecard.securityPostureScore}%
                    </span>
                    <span className="perf-row__time mono">
                      {formatDuration(item.startedAt, item.finishedAt)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState
              icon="gauge"
              title="No campaign in memory"
              description="Launch the runner to seed the sandbox and execute a closed-loop round."
              action={
                <Button
                  to="/console/simulation"
                  variant="primary"
                  size="sm"
                  icon="play"
                >
                  Open campaign runner
                </Button>
              }
            />
          )}
        </Panel>

        <Panel
          className="span-4"
          title="Swarm activity"
          subtitle={state.status === "running" ? state.phaseLabel : "Agent readiness"}
          actions={
            <span className="live-dot" data-on={state.status === "running"} />
          }
        >
          <div className="swarm-live">
            {MISSION_AGENTS.concat([...SWARM]).map((agent) => {
              const status = statusFor(agent.phase, state.phase, state.status);
              return (
                <div
                  className={cn("swarm-live__row", `is-${status}`)}
                  key={agent.name}
                >
                  <span className="swarm-live__dot" />
                  <span className="swarm-live__name">{agent.name}</span>
                  <span className="swarm-live__group">{agent.group}</span>
                  <span className="swarm-live__state">
                    {status === "active"
                      ? "active"
                      : status === "sealed"
                        ? "sealed"
                        : status === "done"
                          ? "done"
                          : status === "queued"
                            ? "queued"
                            : "standby"}
                  </span>
                </div>
              );
            })}
          </div>
          {state.status === "running" && (
            <div className="swarm-progress">
              <div className="swarm-progress__bar">
                <span style={{ width: `${state.progress * 100}%` }} />
              </div>
              <span className="mono">
                {Math.round(state.progress * 100)}%
              </span>
            </div>
          )}
        </Panel>

        <Panel
          className="span-7"
          title="Finding registry"
          subtitle={`Round ${focus?.roundNum ?? "—"} · ${findings.length} findings`}
          actions={
            <Button
              to="/console/findings"
              variant="quiet"
              size="sm"
              iconRight="arrow-right"
            >
              All findings
            </Button>
          }
          flush
        >
          {findings.length ? (
            <>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Class</th>
                      <th>Endpoint</th>
                      <th>CVSS</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.slice(0, 4).map((finding) => {
                      const fixed =
                        verificationByCwe.get(finding.cweId) ??
                        state.remediatedCwes.includes(finding.cweId);
                      return (
                        <tr
                          key={finding.findingId}
                          className="table-click"
                          onClick={() => navigate("/console/findings")}
                        >
                          <td>
                            <SeverityPill severity={finding.severity} />
                          </td>
                          <td>
                            <span className="strong">{finding.cweId}</span>
                            <div className="cell-sub">
                              {finding.title.length > 42
                                ? `${finding.title.slice(0, 42)}…`
                                : finding.title}
                            </div>
                          </td>
                          <td className="cell-mono">{finding.endpoint}</td>
                          <td className="cell-mono">{finding.cvssScore}</td>
                          <td>
                            <span
                              className={cn(
                                "state-chip",
                                fixed ? "is-fixed" : "is-open",
                              )}
                            >
                              {fixed ? "fixed" : "open"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <div className="panel__inner-foot">
                <SeverityBar
                  counts={counts}
                  total={Math.max(findings.length, 1)}
                />
              </div>
            </>
          ) : (
            <EmptyState
              icon="shield-check"
              title="Registry is clear"
              description="No findings are present in the latest round. The workspace is fully remediated."
            />
          )}
        </Panel>

        <Panel
          className="span-5"
          title="Sealed ledger"
          subtitle="Append-only SHA-256 chain"
          actions={
            <Button
              to="/console/safety"
              variant="quiet"
              size="sm"
              iconRight="arrow-right"
            >
              Audit
            </Button>
          }
          flush
        >
          <div className="ledger-preview">
            {state.audit
              .slice(-6)
              .reverse()
              .map((entry) => (
                <div className="ledger-preview__row" key={entry.id}>
                  <span className="ledger-preview__id">
                    {String(entry.id).padStart(3, "0")}
                  </span>
                  <div className="ledger-preview__body">
                    <b>{entry.actor.replace(/([a-z])([A-Z])/g, "$1 $2")}</b>
                    <span>{entry.action.replaceAll("_", " ")}</span>
                  </div>
                  <span className="ledger-preview__hash mono">
                    {entry.entryHash.slice(0, 8)}
                  </span>
                  <span className="ledger-preview__time mono">
                    {formatTime(entry.timestamp)}
                  </span>
                </div>
              ))}
            <div className="ledger-preview__foot">
              <span>
                <Icon name="fingerprint" size={11} /> last sealed{" "}
                {state.audit.length
                  ? relativeTime(state.audit[state.audit.length - 1].timestamp)
                  : "—"}
              </span>
              <span className="mono">{state.audit.length} entries</span>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
