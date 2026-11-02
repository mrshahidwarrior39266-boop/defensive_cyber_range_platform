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
import { CodeBlock } from "../../components/ui/code";
import { Icon } from "../../components/ui/Icon";
import { useActionLock, useDocumentTitle } from "../../lib/hooks";
import {
  latestRound,
  roundWithFindings,
  severityCounts,
} from "../../lib/simulation/engine";
import { useRange } from "../../lib/simulation/store";
import type { SecurityFinding, Severity } from "../../lib/simulation/types";
import { cn, severityClass } from "../../lib/utils";
import "../../styles/pages.css";

type Filter = "ALL" | Severity;

export default function Findings() {
  useDocumentTitle("Finding registry — Citadel");
  const { state } = useRange();
  const { push } = useToast();
  const exportLock = useActionLock();
  const navigate = useNavigate();

  const initialRound =
    roundWithFindings(state)?.roundNum ?? latestRound(state)?.roundNum ?? 1;
  const [roundNum, setRoundNum] = useState(initialRound);
  const [tab, setTab] = useState("findings");
  const [filter, setFilter] = useState<Filter>("ALL");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<SecurityFinding | null>(null);

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

  const findings = useMemo(() => {
    const source = round?.findings ?? [];
    const normalized = query.trim().toLowerCase();
    return source.filter((finding) => {
      const matchesSeverity =
        filter === "ALL" || finding.severity === filter;
      const matchesQuery =
        !normalized ||
        [
          finding.cweId,
          finding.title,
          finding.endpoint,
          finding.filePath,
          finding.functionName,
        ]
          .join(" ")
          .toLowerCase()
          .includes(normalized);
      return matchesSeverity && matchesQuery;
    });
  }, [round, filter, query]);

  const counts = severityCounts(round?.findings ?? []);
  const surfaces = round?.surfaces ?? [];
  const verification = round?.verifications.find(
    (item) => item.cweId === selected?.cweId,
  );
  const fixed = verification
    ? verification.remediated
    : selected
      ? state.remediatedCwes.includes(selected.cweId)
      : false;

  const exportSarif = () => {
    if (!round) return;
    const sarif = {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Citadel StaticVulnerabilityAuditorAgent",
              informationUri: "https://citadel.local/architecture",
              rules: round.findings.map((finding) => ({
                id: finding.cweId,
                name: finding.vulnId,
                shortDescription: { text: finding.title },
                properties: {
                  "security-severity": String(finding.cvssScore),
                },
              })),
            },
          },
          results: round.findings.map((finding) => ({
            ruleId: finding.cweId,
            level:
              finding.severity === "CRITICAL"
                ? "error"
                : finding.severity === "HIGH"
                  ? "error"
                  : "warning",
            message: { text: finding.description },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: finding.filePath },
                  region: { startLine: finding.lineNumber },
                },
                logicalLocations: [
                  { fullyQualifiedName: finding.functionName },
                ],
              },
            ],
            fixes: [
              {
                description: { text: finding.remediationGuidance },
              },
            ],
          })),
        },
      ],
    };
    const blob = new Blob([JSON.stringify(sarif, null, 2)], {
      type: "application/sarif+json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `citadel-round-${round.roundNum}.sarif.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    push({
      title: "SARIF exported",
      message: `${round.findings.length} findings written in SARIF 2.1.0 format.`,
      tone: "success",
    });
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Static audit"
        title="Finding registry"
        description="Evidence-backed findings produced by AST traversal. Open any row to inspect the vulnerable source, the remediation contract and its verification state."
        actions={
          <>
            {state.rounds.length > 0 && (
              <select
                className="select select--auto"
                value={roundNum}
                onChange={(event) => setRoundNum(Number(event.target.value))}
                aria-label="Select round"
              >
                {[...state.rounds].reverse().map((item) => (
                  <option key={item.roundNum} value={item.roundNum}>
                    Round {String(item.roundNum).padStart(2, "0")} ·{" "}
                    {item.findings.length} findings
                  </option>
                ))}
              </select>
            )}
            <Button
              variant="ghost"
              size="sm"
              icon="download"
              onClick={() => void exportLock.run(exportSarif)}
              disabled={!round?.findings.length}
            >
              Export SARIF
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
            <Pill tone="critical" icon="alert">
              {counts.CRITICAL} critical
            </Pill>
            <Pill tone="high">{counts.HIGH} high</Pill>
            <Pill tone="medium">{counts.MEDIUM} medium</Pill>
            <Pill tone="low">{counts.LOW} low</Pill>
            <span className="meta-divider" />
            <Pill icon="scan">{surfaces.length} surfaces mapped</Pill>
          </>
        }
      />

      <div className="registry-head">
        <Tabs
          active={tab}
          onChange={setTab}
          tabs={[
            {
              id: "findings",
              label: "Findings",
              count: round?.findings.length ?? 0,
              icon: "bug",
            },
            {
              id: "surfaces",
              label: "Surface map",
              count: surfaces.length,
              icon: "network",
            },
          ]}
        />
        {tab === "findings" && (
          <div className="registry-tools">
            <div className="search">
              <Icon name="search" size={14} />
              <input
                className="input"
                placeholder="Search CWE, endpoint or file…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
            <div className="segmented" role="group" aria-label="Severity filter">
              {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map(
                (value) => (
                  <button
                    key={value}
                    type="button"
                    aria-pressed={filter === value}
                    onClick={() => setFilter(value)}
                  >
                    {value === "ALL" ? "All" : value.toLowerCase()}
                  </button>
                ),
              )}
            </div>
          </div>
        )}
      </div>

      {tab === "findings" ? (
        <Panel
          flush
          title="Findings"
          subtitle={
            round
              ? `Round ${String(round.roundNum).padStart(2, "0")} · ${findings.length} shown`
              : "No round selected"
          }
          actions={
            <span className="registry-count mono">
              {filter === "ALL" ? "all severities" : filter.toLowerCase()}
            </span>
          }
        >
          {findings.length ? (
            <div className="table-wrap">
              <table className="data-table finding-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Weakness</th>
                    <th>Location</th>
                    <th>Endpoint</th>
                    <th>CVSS</th>
                    <th>State</th>
                    <th aria-label="Open" />
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => {
                    const ver = round?.verifications.find(
                      (item) => item.cweId === finding.cweId,
                    );
                    const isFixed =
                      ver?.remediated ??
                      state.remediatedCwes.includes(finding.cweId);
                    return (
                      <tr
                        key={finding.findingId}
                        className="table-click"
                        onClick={() => setSelected(finding)}
                      >
                        <td>
                          <SeverityPill severity={finding.severity} />
                        </td>
                        <td>
                          <div className="finding-cell">
                            <span className="strong">{finding.cweId}</span>
                            <span className="cell-sub">{finding.title}</span>
                          </div>
                        </td>
                        <td>
                          <span className="mono cell-file">
                            {finding.filePath.replace("mock_enterprise/", "")}
                          </span>
                          <span className="cell-sub mono">
                            line {finding.lineNumber} · {finding.functionName}
                          </span>
                        </td>
                        <td className="cell-mono">{finding.endpoint}</td>
                        <td>
                          <span className="cvss-cell">
                            {finding.cvssScore.toFixed(1)}
                          </span>
                        </td>
                        <td>
                          <span
                            className={cn(
                              "state-chip",
                              isFixed ? "is-fixed" : "is-open",
                            )}
                          >
                            {isFixed ? "remediated" : "open"}
                          </span>
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
              icon={query || filter !== "ALL" ? "filter" : "shield-check"}
              title={
                query || filter !== "ALL"
                  ? "No findings match this filter"
                  : round
                    ? "This round is clean"
                    : "No round to display"
              }
              description={
                query || filter !== "ALL"
                  ? "Try a different severity or clear the search query."
                  : "The static auditor found no remaining weaknesses in the selected round."
              }
              action={
                query || filter !== "ALL" ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setQuery("");
                      setFilter("ALL");
                    }}
                  >
                    Clear filters
                  </Button>
                ) : undefined
              }
            />
          )}
        </Panel>
      ) : (
        <Panel
          flush
          title="Surface map"
          subtitle="Mapped before remediation · guard coverage at discovery time"
          actions={
            <Pill tone="medium" icon="alert">
              {surfaces.filter((surface) => !surface.hasAuthGuard).length} missing
              guards
            </Pill>
          }
        >
          {surfaces.length ? (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Handler</th>
                    <th>Parameters</th>
                    <th>Auth guard</th>
                    <th>Source</th>
                    <th>Seeded class</th>
                  </tr>
                </thead>
                <tbody>
                  {surfaces.map((surface) => {
                    const seeded = round?.findings.filter(
                      (finding) => finding.endpoint === surface.endpoint,
                    );
                    return (
                      <tr key={surface.endpoint}>
                        <td>
                          <span className="endpoint-cell mono">
                            <span className="method">GET</span>
                            {surface.endpoint}
                          </span>
                        </td>
                        <td className="strong">{surface.functionName}</td>
                        <td>
                          <div className="param-list">
                            {surface.parameters.length ? (
                              surface.parameters.map((parameter) => (
                                <span key={parameter}>{parameter}</span>
                              ))
                            ) : (
                              <span className="muted">—</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span
                            className={cn(
                              "guard-state",
                              surface.hasAuthGuard ? "is-guarded" : "is-open",
                            )}
                          >
                            <Icon
                              name={surface.hasAuthGuard ? "shield-check" : "alert"}
                              size={11}
                            />
                            {surface.hasAuthGuard ? "guarded" : "missing"}
                          </span>
                        </td>
                        <td className="cell-mono">
                          {surface.filePath.replace("mock_enterprise/", "")}:
                          {surface.lineNumber}
                        </td>
                        <td>
                          <div className="param-list">
                            {seeded?.length
                              ? seeded.map((finding) => (
                                  <span
                                    key={finding.findingId}
                                    className={cn("tag", severityClass(finding.severity))}
                                  >
                                    {finding.cweId}
                                  </span>
                                ))
                              : <span className="muted">—</span>}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon="network"
              title="No surfaces mapped"
              description="Run a campaign to let the SurfaceMapperAgent inventory the mock enterprise."
            />
          )}
        </Panel>
      )}

      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        eyebrow={selected ? `${selected.cweId} · ${selected.vulnId}` : undefined}
        title={selected?.title ?? ""}
        subtitle={
          selected && (
            <>
              <SeverityPill severity={selected.severity} />
              <span>CVSS {selected.cvssScore.toFixed(1)}</span>
              <span>Round {String(round?.roundNum ?? 0).padStart(2, "0")}</span>
              <span
                className={cn("state-chip", fixed ? "is-fixed" : "is-open")}
              >
                {fixed ? "remediated" : "open"}
              </span>
            </>
          )
        }
        footer={
          selected && (
            <>
              <Button
                variant="quiet"
                size="sm"
                icon="server"
                onClick={() => {
                  setSelected(null);
                  navigate(
                    `/console/enterprise?file=${encodeURIComponent(
                      selected.filePath,
                    )}&line=${selected.lineNumber}`,
                  );
                }}
              >
                View source
              </Button>
              <Button
                to="/console/incidents"
                variant="primary"
                size="sm"
                iconRight="arrow-right"
                onClick={() => setSelected(null)}
              >
                Open patch ledger
              </Button>
            </>
          )
        }
      >
        {selected && (
          <>
            <div className="detail-grid">
              <div>
                <span className="label">Endpoint</span>
                <b className="mono">{selected.endpoint}</b>
              </div>
              <div>
                <span className="label">Source</span>
                <b className="mono">
                  {selected.filePath}:{selected.lineNumber}
                </b>
              </div>
              <div>
                <span className="label">Handler</span>
                <b className="mono">{selected.functionName}</b>
              </div>
              <div>
                <span className="label">Detected</span>
                <b className="mono">
                  {new Date(selected.detectedAtMs).toLocaleTimeString("en-US", {
                    hour12: false,
                  })}
                </b>
              </div>
            </div>

            <section className="detail-section">
              <h4>
                <Icon name="code" size={13} /> Evidence
              </h4>
              <CodeBlock
                code={selected.evidenceSnippet}
                markLines={[1]}
                maxHeight={200}
                language="python"
                showLineNumbers={false}
              />
            </section>

            <section className="detail-section">
              <h4>
                <Icon name="target" size={13} /> Root cause
              </h4>
              <p>{selected.description}</p>
            </section>

            <section className="detail-section">
              <h4>
                <Icon name="git-branch" size={13} /> Remediation contract
              </h4>
              <div className="note note--ice">{selected.remediationGuidance}</div>
            </section>

            <section className="detail-section">
              <h4>
                <Icon name="shield-check" size={13} /> Verification
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
                        : "Weakness remains"}
                    </b>
                    <p>{verification.details}</p>
                    <span className="mono">
                      {verification.verificationMethod} ·{" "}
                      {new Date(verification.verifiedAtMs).toLocaleTimeString(
                        "en-US",
                        { hour12: false },
                      )}
                    </span>
                  </div>
                </div>
              ) : (
                <p className="muted small">
                  No verification record in this round.
                </p>
              )}
            </section>
          </>
        )}
      </Drawer>
    </div>
  );
}
