import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Button,
  EmptyState,
  PageHeader,
  Panel,
  Pill,
  SeverityPill,
  Tabs,
} from "../../components/ui/primitives";
import { Drawer, useToast } from "../../components/ui/overlays";
import { CodeBlock, DiffView } from "../../components/ui/code";
import { Icon } from "../../components/ui/Icon";
import { useDocumentTitle } from "../../lib/hooks";
import {
  latestRound,
  pendingApprovals,
  roundWithFindings,
} from "../../lib/simulation/engine";
import { useRange } from "../../lib/simulation/store";
import type { DeploymentReceipt } from "../../lib/simulation/types";
import {
  cn,
  formatMs,
  formatTime,
} from "../../lib/utils";
import "../../styles/pages.css";

function deploymentLabel(deployment?: DeploymentReceipt) {
  if (!deployment) return { label: "triaged", tone: "is-open" as const };
  if (deployment.deployed)
    return { label: "deployed", tone: "is-fixed" as const };
  if (deployment.status === "awaiting_approval")
    return { label: "review", tone: "is-review" as const };
  if (deployment.status === "blocked")
    return { label: "blocked", tone: "is-blocked" as const };
  return { label: "rolled back", tone: "is-blocked" as const };
}

export default function Incidents() {
  useDocumentTitle("Incident response — Citadel");
  const {
    state,
    approveDeployment,
    denyDeployment,
  } = useRange();
  const { push } = useToast();
  const navigate = useNavigate();

  const initialRound =
    roundWithFindings(state)?.roundNum ?? latestRound(state)?.roundNum ?? 1;
  const [roundNum, setRoundNum] = useState(initialRound);
  const [tab, setTab] = useState("incidents");
  const [detail, setDetail] = useState<{
    roundNum: number;
    incidentId: string;
  } | null>(null);

  useEffect(() => {
    if (!state.rounds.length) return;
    if (!state.rounds.some((round) => round.roundNum === roundNum)) {
      setRoundNum(
        roundWithFindings(state)?.roundNum ??
          state.rounds[state.rounds.length - 1].roundNum,
      );
    }
  }, [state.rounds, state, roundNum]);

  const round =
    state.rounds.find((item) => item.roundNum === roundNum) ??
    latestRound(state);
  const pending = pendingApprovals(state);
  const busy = state.status === "running";

  const detailRound = detail
    ? state.rounds.find((item) => item.roundNum === detail.roundNum)
    : null;
  const incident = detailRound?.incidents.find(
    (item) => item.incidentId === detail?.incidentId,
  );
  const rca = detailRound?.rootCauses.find(
    (item) => item.incidentId === incident?.incidentId,
  );
  const patch = detailRound?.patches.find(
    (item) => item.incidentId === incident?.incidentId,
  );
  const validation = detailRound?.validations.find(
    (item) => item.patchId === patch?.patchId,
  );
  const deployment = detailRound?.deployments.find(
    (item) => item.patchId === patch?.patchId,
  );
  const verification = detailRound?.verifications.find(
    (item) => item.cweId === incident?.finding.cweId,
  );
  const status = deploymentLabel(deployment);

  const incidents = round?.incidents ?? [];

  const approvalSummary = useMemo(
    () =>
      pending
        .map(({ roundNum: pendingRound, deployment: item }) => {
          const sourceRound = state.rounds.find(
            (candidate) => candidate.roundNum === pendingRound,
          );
          const relatedPatch = sourceRound?.patches.find(
            (candidate) => candidate.patchId === item.patchId,
          );
          return {
            roundNum: pendingRound,
            deployment: item,
            patch: relatedPatch,
          };
        })
        .filter((item) => item.patch),
    [pending, state.rounds],
  );

  const openDetail = (incidentId: string, sourceRound: number) => {
    setDetail({ roundNum: sourceRound, incidentId });
  };

  const handleApprove = () => {
    if (!detail || !deployment) return;
    const ok = approveDeployment(detail.roundNum, deployment.deploymentId);
    if (ok) {
      push({
        title: "Patch approved",
        message: `${patch?.patchId ?? "Patch"} deployed after human review. Two ledger entries appended.`,
        tone: "success",
      });
    } else {
      push({
        title: "Approval blocked",
        message:
          "This deployment is not awaiting review, or a campaign is running.",
        tone: "error",
      });
    }
  };

  const handleDeny = () => {
    if (!detail || !deployment) return;
    const ok = denyDeployment(detail.roundNum, deployment.deploymentId);
    if (ok) {
      push({
        title: "Patch denied",
        message: "The workspace was left untouched.",
        tone: "info",
      });
    }
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Defensive response"
        title="Incident response"
        description="From alert to verified fix. Inspect root cause, patch diffs, staging evidence and deployment receipts — and clear the human gate when policy requires it."
        actions={
          <>
            {tab !== "approvals" && state.rounds.length > 0 && (
              <select
                className="select select--auto"
                value={roundNum}
                onChange={(event) => setRoundNum(Number(event.target.value))}
                aria-label="Select round"
              >
                {[...state.rounds].reverse().map((item) => (
                  <option key={item.roundNum} value={item.roundNum}>
                    Round {String(item.roundNum).padStart(2, "0")} ·{" "}
                    {item.incidents.length} incidents
                  </option>
                ))}
              </select>
            )}
            {pending.length > 0 && (
              <Button
                variant="primary"
                size="sm"
                icon="users"
                onClick={() => setTab("approvals")}
              >
                {pending.length} awaiting review
              </Button>
            )}
            {pending.length === 0 && (
              <Button
                to="/console/simulation"
                variant="primary"
                size="sm"
                icon="play"
              >
                Run campaign
              </Button>
            )}
          </>
        }
        meta={
          <>
            <Pill tone={pending.length ? "medium" : "live"} icon="users">
              {pending.length} at human gate
            </Pill>
            <Pill icon="git-branch">
              {round?.patches.length ?? 0} patches · {round?.deployments.filter((item) => item.deployed).length ?? 0} deployed
            </Pill>
            <Pill icon="sliders">
              {state.approvalMode === "manual"
                ? "strict_manual"
                : state.approvalMode === "deny"
                  ? "deny_all"
                  : "auto_low_risk"}
            </Pill>
          </>
        }
      />

      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          {
            id: "incidents",
            label: "Incidents",
            count: incidents.length,
            icon: "bug",
          },
          {
            id: "patches",
            label: "Patch ledger",
            count: round?.patches.length ?? 0,
            icon: "git-branch",
          },
          {
            id: "validations",
            label: "Validations",
            count: round?.validations.length ?? 0,
            icon: "check-circle",
          },
          {
            id: "approvals",
            label: "Approvals",
            count: pending.length,
            icon: "users",
          },
        ]}
      />

      {tab === "incidents" && (
        <Panel
          flush
          title="Triaged incidents"
          subtitle={`Round ${String(round?.roundNum ?? 0).padStart(2, "0")} · ranked by CVSS and exposure`}
          actions={
            <span className="mono registry-count">
              {incidents.filter((item) => !item.alert.correlatedTelemetryEvents).length}{" "}
              without telemetry
            </span>
          }
        >
          {incidents.length ? (
            <div className="incident-list">
              {incidents.map((item) => {
                const itemDeployment = round?.deployments.find(
                  (deploymentItem) =>
                    deploymentItem.incidentId === item.incidentId,
                );
                const itemVerification = round?.verifications.find(
                  (verificationItem) =>
                    verificationItem.cweId === item.finding.cweId,
                );
                const stateLabel = deploymentLabel(itemDeployment);
                return (
                  <button
                    type="button"
                    className="incident-row"
                    key={item.incidentId}
                    onClick={() => openDetail(item.incidentId, round!.roundNum)}
                  >
                    <span className="incident-row__rank">
                      {String(item.priorityRank).padStart(2, "0")}
                    </span>
                    <span className="incident-row__body">
                      <span className="incident-row__title">
                        <b>{item.finding.cweId}</b>
                        <span>{item.finding.title}</span>
                      </span>
                      <span className="incident-row__meta mono">
                        {item.incidentId} · {item.finding.filePath}:
                        {item.finding.lineNumber} · {item.finding.endpoint}
                      </span>
                    </span>
                    <SeverityPill severity={item.finding.severity} />
                    <span className="incident-row__sla mono">
                      SLA {formatMs(item.slaTargetMs)}
                    </span>
                    <span
                      className={cn(
                        "state-chip",
                        itemVerification?.remediated
                          ? "is-fixed"
                          : stateLabel.tone,
                      )}
                    >
                      {itemVerification?.remediated
                        ? "remediated"
                        : stateLabel.label}
                    </span>
                    <Icon name="chevron-right" size={14} />
                  </button>
                );
              })}
            </div>
          ) : (
            <EmptyState
              icon="shield-check"
              title="No incidents in this round"
              description="Either the workspace is clean or the campaign has not produced findings yet."
              action={
                <Button to="/console/simulation" variant="primary" size="sm" icon="play">
                  Launch a campaign
                </Button>
              }
            />
          )}
        </Panel>
      )}

      {tab === "patches" && (
        <Panel
          flush
          title="Patch ledger"
          subtitle="Candidate patches, staging outcomes and deployment receipts"
        >
          {round?.patches.length ? (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Patch</th>
                    <th>CWE</th>
                    <th>File</th>
                    <th>Diff</th>
                    <th>Validation</th>
                    <th>Deployment</th>
                    <th>Hash</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {round.patches.map((item) => {
                    const itemValidation = round.validations.find(
                      (validationItem) =>
                        validationItem.patchId === item.patchId,
                    );
                    const itemDeployment = round.deployments.find(
                      (deploymentItem) =>
                        deploymentItem.patchId === item.patchId,
                    );
                    const itemIncident = round.incidents.find(
                      (incidentItem) =>
                        incidentItem.incidentId === item.incidentId,
                    );
                    const additions = item.unifiedDiff
                      .split("\n")
                      .filter(
                        (line) =>
                          line.startsWith("+") && !line.startsWith("+++"),
                      ).length;
                    const deletions = item.unifiedDiff
                      .split("\n")
                      .filter(
                        (line) =>
                          line.startsWith("-") && !line.startsWith("---"),
                      ).length;
                    const label = deploymentLabel(itemDeployment);
                    return (
                      <tr
                        key={item.patchId}
                        className="table-click"
                        onClick={() =>
                          itemIncident &&
                          openDetail(itemIncident.incidentId, round.roundNum)
                        }
                      >
                        <td className="cell-mono strong">{item.patchId}</td>
                        <td>
                          <span className="tag">{item.cweId}</span>
                        </td>
                        <td className="cell-mono">
                          {item.filePath.replace("mock_enterprise/", "")}
                        </td>
                        <td>
                          <span className="diff-count">
                            <em>+{additions}</em>
                            <span>−{deletions}</span>
                          </span>
                        </td>
                        <td>
                          <span
                            className={cn(
                              "check-state",
                              itemValidation?.passed ? "is-pass" : "is-fail",
                            )}
                          >
                            <Icon
                              name={itemValidation?.passed ? "check" : "close"}
                              size={11}
                            />
                            {itemValidation?.passed ? "passed" : "failed"}
                          </span>
                        </td>
                        <td>
                          <span className={cn("state-chip", label.tone)}>
                            {label.label}
                          </span>
                        </td>
                        <td className="cell-mono">
                          {itemDeployment?.deployed
                            ? `${itemDeployment.postPatchSha256.slice(0, 8)}…`
                            : "—"}
                        </td>
                        <td className="row-action">
                          <Icon name="chevron-right" size={14} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon="git-branch"
              title="No patches generated"
              description="A patch is synthesized only when an incident reaches root-cause analysis."
            />
          )}
        </Panel>
      )}

      {tab === "validations" && (
        <div className="validation-list">
          {round?.validations.length ? (
            round.validations.map((item) => {
              const itemPatch = round.patches.find(
                (patchItem) => patchItem.patchId === item.patchId,
              );
              return (
                <div className="validation-card" key={item.patchId}>
                  <header>
                    <div>
                      <span className="mono strong">{item.patchId}</span>
                      <span className="mono muted">
                        {itemPatch?.filePath.replace("mock_enterprise/", "")}
                      </span>
                    </div>
                    <Pill tone={item.passed ? "live" : "critical"}>
                      {item.passed ? "STAGING PASSED" : "FAILED"}
                    </Pill>
                  </header>
                  <div className="validation-checks">
                    <span className={item.syntaxValid ? "is-pass" : "is-fail"}>
                      <Icon
                        name={item.syntaxValid ? "check" : "close"}
                        size={11}
                      />
                      Syntax
                    </span>
                    <span
                      className={
                        item.functionalTestsPassed ? "is-pass" : "is-fail"
                      }
                    >
                      <Icon
                        name={item.functionalTestsPassed ? "check" : "close"}
                        size={11}
                      />
                      Functional
                    </span>
                    <span
                      className={
                        item.securityChecksPassed ? "is-pass" : "is-fail"
                      }
                    >
                      <Icon
                        name={item.securityChecksPassed ? "check" : "close"}
                        size={11}
                      />
                      Security
                    </span>
                    <span className="mono">{item.testCount} tests</span>
                  </div>
                  <ul className="validation-details">
                    {item.details.map((detail) => (
                      <li key={detail}>
                        <span className="score-dot bg-mint" />
                        {detail}
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })
          ) : (
            <Panel>
              <EmptyState
                icon="check-circle"
                title="No validation reports"
                description="Staging validation runs before a patch reaches the deployment gate."
              />
            </Panel>
          )}
        </div>
      )}

      {tab === "approvals" && (
        <Panel
          flush
          title="Human approval gate"
          subtitle="Reviewer decisions append signed ledger entries"
          actions={
            <Pill tone={pending.length ? "medium" : "live"} icon="users">
              {pending.length} pending
            </Pill>
          }
        >
          {approvalSummary.length ? (
            <div className="approval-list">
              {approvalSummary.map(({ roundNum: sourceRound, deployment: item, patch: itemPatch }) => (
                <div className="approval-row" key={`${sourceRound}-${item.deploymentId}`}>
                  <span className="approval-row__icon">
                    <Icon name="git-branch" size={16} />
                  </span>
                  <div className="approval-row__body">
                    <b>
                      {item.patchId}{" "}
                      <span className="tag">{item.cweId}</span>
                    </b>
                    <span className="mono">
                      Round {String(sourceRound).padStart(2, "0")} ·{" "}
                      {item.filePath.replace("mock_enterprise/", "")} · pre{" "}
                      {item.prePatchSha256.slice(0, 8)}…
                    </span>
                    <span>{itemPatch?.rationale}</span>
                  </div>
                  <div className="approval-row__actions">
                    <Button
                      variant="quiet"
                      size="sm"
                      onClick={() =>
                        setDetail({
                          roundNum: sourceRound,
                          incidentId: item.incidentId,
                        })
                      }
                    >
                      Inspect
                    </Button>
                    <Button
                      variant="quiet"
                      size="sm"
                      icon="close"
                      disabled={busy}
                      onClick={() => {
                        const ok = denyDeployment(sourceRound, item.deploymentId);
                        if (ok)
                          push({
                            title: "Patch denied",
                            message: "The workspace was left untouched.",
                            tone: "info",
                          });
                      }}
                    >
                      Deny
                    </Button>
                    <Button
                      variant="primary"
                      size="sm"
                      icon="check"
                      disabled={busy}
                      onClick={() => {
                        const ok = approveDeployment(
                          sourceRound,
                          item.deploymentId,
                        );
                        if (ok)
                          push({
                            title: "Patch approved",
                            message: `${item.patchId} deployed and verified.`,
                            tone: "success",
                          });
                      }}
                    >
                      Approve
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon="shield-check"
              title="Human gate is clear"
              description={
                state.approvalMode === "manual"
                  ? "No patches are waiting. Launch a campaign in strict_manual policy to exercise the gate."
                  : "The current policy auto-approves validated patches. Switch to 'Hold for review' in the campaign runner to queue decisions here."
              }
              action={
                <Button
                  to="/console/simulation"
                  variant="ghost"
                  size="sm"
                  icon="play"
                >
                  Campaign runner
                </Button>
              }
            />
          )}
        </Panel>
      )}

      <Drawer
        open={Boolean(detail && incident)}
        onClose={() => setDetail(null)}
        width={720}
        eyebrow={
          incident ? `${incident.incidentId} · priority ${incident.priorityRank}` : undefined
        }
        title={incident?.finding.title ?? ""}
        subtitle={
          incident && (
            <>
              <SeverityPill severity={incident.finding.severity} />
              <span>{incident.finding.cweId}</span>
              <span>SLA {formatMs(incident.slaTargetMs)}</span>
              <span>{incident.alert.correlatedTelemetryEvents} telemetry events</span>
            </>
          )
        }
        footer={
          incident && (
            <>
              <Button
                variant="quiet"
                size="sm"
                icon="server"
                onClick={() => {
                  navigate(
                    `/console/enterprise?file=${encodeURIComponent(
                      incident.finding.filePath,
                    )}&line=${incident.finding.lineNumber}`,
                  );
                  setDetail(null);
                }}
              >
                Open source
              </Button>
              {deployment?.status === "awaiting_approval" ? (
                <>
                  <Button
                    variant="quiet"
                    size="sm"
                    icon="close"
                    onClick={handleDeny}
                    disabled={busy}
                  >
                    Deny
                  </Button>
                  <Button
                    variant="primary"
                    size="sm"
                    icon="check"
                    onClick={handleApprove}
                    disabled={busy}
                  >
                    Approve &amp; deploy
                  </Button>
                </>
              ) : (
                <Button variant="ghost" size="sm" onClick={() => setDetail(null)}>
                  Close
                </Button>
              )}
            </>
          )
        }
      >
        {incident && (
          <>
            <div className="detail-grid">
              <div>
                <span className="label">Endpoint</span>
                <b className="mono">{incident.finding.endpoint}</b>
              </div>
              <div>
                <span className="label">Module</span>
                <b className="mono">{incident.assignedModule}</b>
              </div>
              <div>
                <span className="label">Alert</span>
                <b className="mono">{incident.alert.alertId}</b>
              </div>
              <div>
                <span className="label">Gate state</span>
                <b className={cn("state-chip", status.tone)}>{status.label}</b>
              </div>
            </div>

            <section className="detail-section">
              <h4>
                <Icon name="target" size={13} /> Root cause
              </h4>
              <p>{rca?.rootCauseExplanation}</p>
              {rca && (
                <CodeBlock
                  filename={`${rca.filePath} · ${rca.astNodeType}`}
                  code={rca.vulnerableBlock}
                  maxHeight={260}
                />
              )}
            </section>

            <section className="detail-section">
              <h4>
                <Icon name="git-branch" size={13} /> Candidate patch
              </h4>
              {patch ? (
                <>
                  <div className="detail-inline">
                    <span className="mono">{patch.patchId}</span>
                    <span className="mono muted">
                      generated {formatTime(patch.generatedAtMs)}
                    </span>
                  </div>
                  <DiffView diff={patch.unifiedDiff} filename={patch.filePath} />
                  <div className="note">{patch.rationale}</div>
                </>
              ) : (
                <p className="muted small">No patch was synthesized.</p>
              )}
            </section>

            <section className="detail-section">
              <h4>
                <Icon name="check-circle" size={13} /> Staging validation
              </h4>
              {validation ? (
                <div className="check-list">
                  {validation.details.map((detail) => (
                    <div key={detail}>
                      <span className="check-list__icon">
                        <Icon name="check" size={10} />
                      </span>
                      {detail}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted small">No validation report.</p>
              )}
            </section>

            <section className="detail-section">
              <h4>
                <Icon name="server" size={13} /> Deployment receipt
              </h4>
              {deployment ? (
                <div className="receipt">
                  <div className="receipt__row">
                    <span>Status</span>
                    <b className={cn("state-chip", status.tone)}>
                      {status.label}
                    </b>
                  </div>
                  <div className="receipt__row">
                    <span>Pre-patch SHA-256</span>
                    <b className="mono">{deployment.prePatchSha256.slice(0, 20)}…</b>
                  </div>
                  <div className="receipt__row">
                    <span>Post-patch SHA-256</span>
                    <b className="mono">
                      {deployment.deployed
                        ? `${deployment.postPatchSha256.slice(0, 20)}…`
                        : "unchanged"}
                    </b>
                  </div>
                  <div className="receipt__row">
                    <span>Backup</span>
                    <b className="mono">
                      {deployment.backupPath.replace(
                        "simulation_artifacts/workspace/backups/",
                        "",
                      )}
                    </b>
                  </div>
                  <div className="receipt__row">
                    <span>Note</span>
                    <b>{deployment.notes}</b>
                  </div>
                </div>
              ) : (
                <p className="muted small">No deployment receipt.</p>
              )}
            </section>

            <section className="detail-section">
              <h4>
                <Icon name="shield-check" size={13} /> Independent verification
              </h4>
              {verification ? (
                <div
                  className={cn(
                    "verification",
                    verification.remediated ? "is-pass" : "is-fail",
                  )}
                >
                  <span className="verification__icon">
                    <Icon
                      name={verification.remediated ? "check" : "close"}
                      size={13}
                    />
                  </span>
                  <div>
                    <b>
                      {verification.remediated
                        ? "Remediation verified"
                        : "Residual risk present"}
                    </b>
                    <p>{verification.details}</p>
                    <span className="mono">
                      {verification.verificationMethod}
                    </span>
                  </div>
                </div>
              ) : (
                <p className="muted small">No verification record.</p>
              )}
            </section>
          </>
        )}
      </Drawer>
    </div>
  );
}
