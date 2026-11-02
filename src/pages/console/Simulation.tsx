import { useEffect, useRef, useState } from "react";
import {
  Button,
  EmptyState,
  PageHeader,
  Panel,
  Pill,
} from "../../components/ui/primitives";
import { Gauge } from "../../components/ui/viz";
import { Icon } from "../../components/ui/Icon";
import { useToast } from "../../components/ui/overlays";
import { useActionLock, useDocumentTitle } from "../../lib/hooks";
import { latestRound } from "../../lib/simulation/engine";
import { CWE_ORDER, PROJECT_FILES } from "../../lib/simulation/project";
import { useRange } from "../../lib/simulation/store";
import type { ApprovalMode, PhaseKey } from "../../lib/simulation/types";
import {
  cn,
  copyText,
  formatDuration,
  formatMs,
  formatNumber,
  formatTime,
} from "../../lib/utils";
import "../../styles/pages.css";

const PHASE_STEPS: Array<{ key: PhaseKey; label: string; hint: string }> = [
  { key: "initialize", label: "Initialize sandbox", hint: `${PROJECT_FILES.length} files cloned` },
  { key: "surface", label: "Surface mapping", hint: "AST inventory" },
  { key: "audit", label: "Static audit", hint: "CWE traversal" },
  { key: "prioritize", label: "Risk prioritization", hint: "CVSS ranking" },
  { key: "detect", label: "Detect & triage", hint: "SLA assignment" },
  { key: "deploy", label: "Remediate", hint: "patch → validate → deploy" },
  { key: "verify", label: "Re-audit", hint: "independent verification" },
  { key: "score", label: "Score & persist", hint: "judge + memory" },
  { key: "complete", label: "Campaign sealed", hint: "chain verified" },
];

const PHASE_INDEX: Record<PhaseKey, number> = {
  idle: -1,
  initialize: 0,
  surface: 1,
  audit: 2,
  prioritize: 3,
  detect: 4,
  triage: 4,
  rca: 5,
  patch: 5,
  validate: 5,
  deploy: 5,
  verify: 6,
  score: 7,
  complete: 8,
  halted: -1,
};

const MODES: Array<{
  id: ApprovalMode;
  title: string;
  copy: string;
  icon: "zap" | "users" | "lock";
}> = [
  {
    id: "auto",
    title: "Auto-approve",
    copy: "Deploy when staging validation and module scope both pass.",
    icon: "zap",
  },
  {
    id: "manual",
    title: "Hold for review",
    copy: "Pause at the human gate. Approve each patch from Incidents.",
    icon: "users",
  },
  {
    id: "deny",
    title: "Deny all",
    copy: "Block every deployment and re-audit the residual exposure.",
    icon: "lock",
  },
];

export default function Simulation() {
  useDocumentTitle("Campaign runner — Citadel");
  const {
    state,
    startCampaign,
    abortCampaign,
  } = useRange();
  const { push } = useToast();
  const launchLock = useActionLock();
  const [rounds, setRounds] = useState(() =>
    Math.min(4, Math.max(1, state.campaignRounds || 2)),
  );
  const [mode, setMode] = useState<ApprovalMode>(
    state.approvalMode ?? "auto",
  );
  const [autoScroll, setAutoScroll] = useState(true);
  const logRef = useRef<HTMLDivElement | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const running = state.status === "running";
  const complete = state.status === "complete";
  const round = latestRound(state);

  // Track whether operator modified the configuration after a completed campaign
  const configModified = complete && (rounds !== state.campaignRounds || mode !== state.approvalMode);

  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setNow(Date.now()), 100);
    return () => window.clearInterval(timer);
  }, [running]);

  useEffect(() => {
    if (!autoScroll) return;
    const node = logRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [state.log, autoScroll]);

  const elapsed =
    state.campaignStartedAt !== null
      ? (state.campaignFinishedAt ?? now) - state.campaignStartedAt
      : 0;

  const phase = configModified ? -1 : (PHASE_INDEX[state.phase] ?? -1);

  const launch = () => {
    if (running) return; // Guard against double-click
    if (state.killSwitch.tripped) {
      push({
        title: "Kill switch is active",
        message: "Reset the kill switch before launching a campaign.",
        tone: "error",
      });
      return;
    }
    void launchLock.run(async () => {
      push({
        title: "Campaign launched",
        message: `${rounds} round${rounds === 1 ? "" : "s"} · ${
          MODES.find((item) => item.id === mode)?.title
        } policy. Sandbox restored to the seeded baseline.`,
        tone: "info",
      });
      await startCampaign({ rounds, approvalMode: mode });
    });
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Campaign runner"
        title="Launch the closed loop"
        description="Every campaign restores the disposable sandbox to the seeded baseline, then runs the analysis and defense swarms through a scored, auditable loop."
        actions={
          <>
            <Pill tone={state.killSwitch.tripped ? "critical" : "live"}>
              <span className="dot" />
              {state.killSwitch.tripped
                ? "Range halted"
                : running
                  ? "Live campaign"
                  : complete
                    ? "Campaign complete"
                    : "Range ready"}
            </Pill>
            <Button
              to="/console/findings"
              variant="ghost"
              size="sm"
              icon="scan"
            >
              Findings
            </Button>
          </>
        }
        meta={
          <>
            <Pill icon="shield">Isolated workspace</Pill>
            <Pill icon="sliders">
              {state.approvalMode === "auto"
                ? "auto_low_risk"
                : state.approvalMode === "manual"
                  ? "strict_manual"
                  : "deny_all"}
            </Pill>
            <Pill icon="calendar">
              {running
                ? `${state.campaignRounds} rounds running`
                : `${rounds} round${rounds === 1 ? "" : "s"} planned`}
            </Pill>
          </>
        }
      />

      {state.killSwitch.tripped && (
        <div className="banner banner--danger">
          <span className="banner__icon">
            <Icon name="power" size={16} />
          </span>
          <div>
            <b>Kill switch tripped</b>
            <p>{state.killSwitch.reason}</p>
          </div>
          <Button to="/console/safety" variant="danger" size="sm">
            Open safety controls
          </Button>
        </div>
      )}

      <div className="runner">
        <Panel
          className="span-7"
          title="Campaign setup"
          subtitle="Sandbox is restored before every campaign"
          actions={
            <Pill tone={state.status === "running" ? "live" : "neutral"}>
              <Icon name="terminal" size={10} />
              {state.phaseLabel}
            </Pill>
          }
        >
          <div className="launcher">
            <div className="launcher__row">
              <div>
                <span className="label">Closed-loop rounds</span>
                <p className="launcher__hint">
                  Round 1 discovers and remediates. Round 2 proves the workspace
                  stays clean.
                </p>
              </div>
              <div className="stepper" aria-label="Number of rounds">
                <button
                  type="button"
                  onClick={() => setRounds((value) => Math.max(1, value - 1))}
                  disabled={running || rounds <= 1}
                  aria-label="Fewer rounds"
                >
                  <Icon name="minus" size={13} />
                </button>
                <span>{String(rounds).padStart(2, "0")}</span>
                <button
                  type="button"
                  onClick={() => setRounds((value) => Math.min(4, value + 1))}
                  disabled={running || rounds >= 4}
                  aria-label="More rounds"
                >
                  <Icon name="plus" size={13} />
                </button>
              </div>
            </div>

            <div className="launcher__modes">
              <span className="label">Deployment policy</span>
              <div className="mode-grid">
                {MODES.map((item) => (
                  <button
                    type="button"
                    key={item.id}
                    className={cn(
                      "mode-card",
                      mode === item.id && "is-active",
                    )}
                    onClick={() => setMode(item.id)}
                    disabled={running}
                    aria-pressed={mode === item.id}
                  >
                    <span className="mode-card__icon">
                      <Icon name={item.icon} size={14} />
                    </span>
                    <b>{item.title}</b>
                    <span>{item.copy}</span>
                    <i className="mode-card__check">
                      {mode === item.id && <Icon name="check" size={11} />}
                    </i>
                  </button>
                ))}
              </div>
            </div>

            <div className="launcher__foot">
              <div className="launcher__meta">
                <span>
                  <Icon name="shield-check" size={12} /> Non-destructive
                </span>
                <span>
                  <Icon name="lock" size={12} /> No external egress
                </span>
                <span>
                  <Icon name="fingerprint" size={12} /> Ledger appended
                </span>
              </div>
              {running ? (
                <Button
                  variant="danger"
                  icon="stop"
                  onClick={() => {
                    abortCampaign();
                    push({
                      title: "Campaign halted",
                      message:
                        "Remaining phases were skipped. Partial artifacts remain visible.",
                      tone: "error",
                    });
                  }}
                >
                  Halt campaign
                </Button>
              ) : (
                <Button
                  variant="primary"
                  icon="play"
                  onClick={launch}
                  disabled={state.killSwitch.tripped || launchLock.busy}
                >
                  Launch campaign
                </Button>
              )}
            </div>

            <div className="launcher__baseline">
              <div className="launcher__baseline-head">
                <span className="label">Baseline manifest</span>
                <span className="mono">reset before every run</span>
              </div>
              <div className="launcher__manifest">
                <div>
                  <span>
                    <Icon name="file-code" size={11} /> mock_enterprise/
                  </span>
                  <em>
                    {PROJECT_FILES.length} files · {CWE_ORDER.length} seeded classes
                  </em>
                </div>
                <div>
                  <span>
                    <Icon name="server" size={11} /> simulation_artifacts/workspace
                  </span>
                  <em>recreated before each campaign</em>
                </div>
                <div>
                  <span>
                    <Icon name="database" size={11} /> simulation_memory.db
                  </span>
                  <em>persists across campaigns</em>
                </div>
              </div>
            </div>
          </div>
        </Panel>

        <Panel
          className="span-5"
          title="Live phase"
          subtitle={
            running
              ? state.phaseLabel
              : configModified
                ? `Ready to launch (${rounds} rounds · ${MODES.find((m) => m.id === mode)?.title})`
                : complete
                  ? "Campaign sealed · chain verified"
                  : "Awaiting campaign"
          }
          actions={
            <span className="live-dot" data-on={running || (complete && !configModified)} />
          }
        >
          <div className="campaign-live">
            <div className="campaign-live__stats">
              <div>
                <span>Elapsed</span>
                <b>{configModified ? "0.0s" : formatDuration(0, elapsed, running)}</b>
              </div>
              <div>
                <span>Round</span>
                <b>
                  {running
                    ? `${state.activeRound || 1} / ${state.campaignRounds}`
                    : configModified
                      ? `0 / ${rounds}`
                      : `${state.activeRound || (complete ? state.campaignRounds : 0)} / ${state.campaignRounds || rounds}`}
                </b>
              </div>
              <div>
                <span>Progress</span>
                <b>{configModified ? "0%" : `${Math.round(state.progress * 100)}%`}</b>
              </div>
            </div>
            <div className="campaign-live__bar">
              <span style={{ width: configModified ? "0%" : `${state.progress * 100}%` }} />
            </div>

            <ol className="phase-list">
              {PHASE_STEPS.map((step, index) => {
                const status =
                  configModified
                    ? "queued"
                    : state.phase === "complete" || index < phase
                      ? "done"
                      : index === phase
                        ? "active"
                        : "queued";
                return (
                  <li
                    key={step.key}
                    className={cn("phase-list__item", `is-${status}`)}
                  >
                    <span className="phase-list__marker">
                      {status === "done" ? (
                        <Icon name="check" size={10} />
                      ) : (
                        <span />
                      )}
                    </span>
                    <div>
                      <b>{step.label}</b>
                      <span>{step.hint}</span>
                    </div>
                    <em>
                      {status === "active"
                        ? "running"
                        : status === "done"
                          ? "sealed"
                          : "queued"}
                    </em>
                  </li>
                );
              })}
            </ol>
          </div>
        </Panel>
      </div>

      <div className="runner">
        <Panel
          className="span-8"
          title="Campaign console"
          subtitle="Structured agent output, mirrored from the orchestrator"
          actions={
            <>
              <button
                type="button"
                className="console-toggle"
                aria-pressed={autoScroll}
                onClick={() => setAutoScroll((value) => !value)}
              >
                <span className={cn("toggle", autoScroll && "is-on")}>
                  <i />
                </span>
                Auto-scroll
              </button>
              <button
                type="button"
                className="btn btn--quiet btn--sm"
                onClick={async () => {
                  const text = state.log
                    .map(
                      (entry) =>
                        `${formatTime(entry.at)} ${entry.actor} :: ${entry.message}`,
                    )
                    .join("\n");
                  const ok = await copyText(text);
                  push({
                    title: ok ? "Console copied" : "Copy blocked",
                    message: ok
                      ? "The campaign log is on your clipboard."
                      : "Your browser blocked clipboard access.",
                    tone: ok ? "success" : "error",
                  });
                }}
              >
                <Icon name="copy" size={12} /> Copy
              </button>
            </>
          }
          flush
        >
          <div className="terminal" ref={logRef}>
            <div className="terminal__bar">
              <span className="terminal__dots">
                <i />
                <i />
                <i />
              </span>
              <span className="mono">citadel://campaign</span>
              <span className="terminal__status mono">
                {running ? "streaming" : "idle"}
              </span>
            </div>
            <div className="terminal__body" aria-live="polite">
              {state.log.length ? (
                state.log.slice(-140).map((entry) => (
                  <div className="log-line" key={entry.id}>
                    <span className="log-line__time">
                      {formatTime(entry.at)}
                    </span>
                    <span className="log-line__actor">{entry.actor}</span>
                    <span
                      className={cn(
                        "log-line__msg",
                        `is-${entry.tone}`,
                      )}
                    >
                      {entry.message}
                    </span>
                  </div>
                ))
              ) : (
                <div className="terminal__empty">
                  <Icon name="terminal" size={18} />
                  <p>No campaign output yet. Launch a campaign to stream agent actions.</p>
                </div>
              )}
              {running && (
                <div className="log-line log-line--caret">
                  <span className="log-line__time">{formatTime(now)}</span>
                  <span className="log-line__actor">swarm</span>
                  <span className="log-line__msg">
                    <span className="caret" /> awaiting next action
                  </span>
                </div>
              )}
            </div>
          </div>
        </Panel>

        <Panel
          className="span-4"
          title="Latest scorecard"
          subtitle={round ? `Round ${String(round.roundNum).padStart(2, "0")}` : "No round scored"}
          actions={
            round && (
              <Button to="/console/memory" variant="quiet" size="sm">
                History
              </Button>
            )
          }
        >
          {round ? (
            <div className="scorecard-mini">
              <div className="scorecard-mini__gauge">
                <Gauge
                  value={round.scorecard.securityPostureScore}
                  size={150}
                  label="posture"
                />
              </div>
              <div className="scorecard-mini__grid">
                <div>
                  <span>Findings</span>
                  <b>{round.scorecard.findingsDiscovered}</b>
                </div>
                <div>
                  <span>Patches</span>
                  <b>{round.scorecard.patchesDeployed}</b>
                </div>
                <div>
                  <span>Verified</span>
                  <b>{round.scorecard.verifiedRemediated}</b>
                </div>
                <div>
                  <span>Mean TTR</span>
                  <b>{formatMs(round.scorecard.meanTimeToRemediateMs)}</b>
                </div>
              </div>
              <div className="scorecard-mini__foot">
                <span>
                  <Icon name="check-circle" size={11} />{" "}
                  {formatNumber(round.scorecard.patchesValidated)} tests passed
                </span>
                <span>
                  {round.scorecard.regressionPassRatePct}% regression
                </span>
              </div>
            </div>
          ) : (
            <EmptyState
              icon="gauge"
              title="No scorecard yet"
              description="The judge scores recall, correctness and time-to-remediate after each round."
            />
          )}
        </Panel>
      </div>

      <Panel
        className="span-12"
        title="Round history"
        subtitle="Persisted to shared memory"
        actions={
          <Button to="/console/safety" variant="quiet" size="sm" icon="fingerprint">
            Audit chain
          </Button>
        }
        flush
      >
        {state.rounds.length ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Round</th>
                  <th>Findings</th>
                  <th>Alerts</th>
                  <th>Validated</th>
                  <th>Deployed</th>
                  <th>Verified</th>
                  <th>Mean TTD</th>
                  <th>Mean TTR</th>
                  <th>Duration</th>
                  <th>Posture</th>
                </tr>
              </thead>
              <tbody>
                {[...state.rounds].reverse().map((item) => (
                  <tr key={item.roundNum}>
                    <td className="strong">
                      R{String(item.roundNum).padStart(2, "0")}
                    </td>
                    <td>{item.scorecard.findingsDiscovered}</td>
                    <td>{item.scorecard.alertsTriggered}</td>
                    <td>{item.scorecard.patchesValidated}</td>
                    <td>{item.scorecard.patchesDeployed}</td>
                    <td>{item.scorecard.verifiedRemediated}</td>
                    <td className="cell-mono">
                      {formatMs(item.scorecard.meanTimeToDetectMs)}
                    </td>
                    <td className="cell-mono">
                      {formatMs(item.scorecard.meanTimeToRemediateMs)}
                    </td>
                    <td className="cell-mono">
                      {formatDuration(item.startedAt, item.finishedAt)}
                    </td>
                    <td>
                      <span className="posture-chip">
                        {item.scorecard.securityPostureScore}%
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            icon="calendar"
            title="No rounds executed"
            description="Launch the campaign runner to populate round history and shared memory."
          />
        )}
      </Panel>
    </div>
  );
}
