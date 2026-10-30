import { useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  CopyButton,
  PageHeader,
  Panel,
  Pill,
} from "../../components/ui/primitives";
import { Drawer, useToast } from "../../components/ui/overlays";
import { CodeBlock } from "../../components/ui/code";
import { Icon } from "../../components/ui/Icon";
import type { IconName } from "../../components/ui/Icon";
import { useDocumentTitle } from "../../lib/hooks";
import { useRange } from "../../lib/simulation/store";
import type { AuditEntry } from "../../lib/simulation/types";
import {
  cn,
  formatDateTime,
  formatTime,
  shortSha,
} from "../../lib/utils";
import "../../styles/pages.css";

const GUARD_HOSTS = [
  "localhost",
  "127.0.0.1",
  "::1",
  "mock-enterprise",
  "cyber-range-orchestrator",
];

const CONTROLS: Array<{
  icon: IconName;
  name: string;
  state: string;
  description: string;
  facts: Array<{ label: string; value: string }>;
}> = [
  {
    icon: "network",
    name: "NetworkIsolationGuard",
    state: "enforced",
    description:
      "Every target host is validated against a closed loopback allowlist before an agent can act. Non-isolated destinations raise a SafetyViolationError.",
    facts: [
      { label: "Allowed hosts", value: GUARD_HOSTS.join(", ") },
      { label: "External egress", value: "0 destinations" },
    ],
  },
  {
    icon: "key",
    name: "ToolAllowlistGuard",
    state: "enforced",
    description:
      "Each agent may only invoke the operations registered for its role, and every path is resolved and confined to the sandbox root.",
    facts: [
      { label: "Agents", value: "12 agents · 15 operations" },
      { label: "Sandbox root", value: "simulation_artifacts/workspace" },
    ],
  },
  {
    icon: "filter",
    name: "PromptSanitizer",
    state: "enforced",
    description:
      "Untrusted code comments, telemetry and log text are scanned for injection patterns and neutralized before reaching any model context.",
    facts: [
      { label: "Patterns", value: "5 injection signatures" },
      { label: "Action", value: "redact + warn" },
    ],
  },
  {
    icon: "users",
    name: "HumanApprovalGate",
    state: "policy",
    description:
      "Validated patches only reach the workspace when policy permits. Manual mode queues every deployment for an explicit reviewer decision.",
    facts: [
      { label: "Policy", value: "configured per campaign" },
      { label: "Patch scope", value: "mock_enterprise/ only" },
    ],
  },
];

function downloadJsonl(entries: AuditEntry[]) {
  const lines = entries.map((entry) =>
    JSON.stringify({
      timestamp: entry.timestamp,
      actor: entry.actor,
      action: entry.action,
      details: entry.details,
      prev_hash: entry.prevHash,
      entry_hash: entry.entryHash,
    }),
  );
  const blob = new Blob([`${lines.join("\n")}\n`], {
    type: "application/jsonl",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "audit_ledger.jsonl";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export default function Safety() {
  useDocumentTitle("Safety & governance — Citadel");
  const { state, tripKillSwitch, resetKillSwitch, verifyChain } = useRange();
  const { push } = useToast();

  const [tripOpen, setTripOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [query, setQuery] = useState("");
  const [actor, setActor] = useState("all");
  const [selected, setSelected] = useState<AuditEntry | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [checkedAt, setCheckedAt] = useState<number | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timer.current) window.clearTimeout(timer.current);
    },
    [],
  );

  const chain = verifyChain();
  const tripped = state.killSwitch.tripped;
  const actors = useMemo(
    () => Array.from(new Set(state.audit.map((entry) => entry.actor))).sort(),
    [state.audit],
  );
  const entries = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return [...state.audit]
      .reverse()
      .filter((entry) => {
        if (actor !== "all" && entry.actor !== actor) return false;
        if (!needle) return true;
        return `${entry.id} ${entry.actor} ${entry.action} ${JSON.stringify(
          entry.details,
        )}`
          .toLowerCase()
          .includes(needle);
      });
  }, [state.audit, actor, query]);

  const head = state.audit[state.audit.length - 1];
  const tail = state.audit.slice(-22);

  const runVerify = () => {
    setVerifying(true);
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      const result = verifyChain();
      setVerifying(false);
      setCheckedAt(Date.now());
      push({
        title: result.valid ? "Ledger verified" : "Ledger integrity failure",
        message: result.valid
          ? `All ${state.audit.length} entries match their SHA-256 links from genesis.`
          : `Chain diverges at entry ${result.brokenAt}.`,
        tone: result.valid ? "success" : "error",
      });
    }, 620);
  };

  const handleTrip = () => {
    tripKillSwitch(reason.trim() || "Emergency halt requested by operator");
    setTripOpen(false);
    setReason("");
    push({
      title: "Kill switch tripped",
      message:
        "All agent execution stopped. The halt is recorded in the audit ledger.",
      tone: "error",
    });
  };

  const handleReset = () => {
    resetKillSwitch();
    push({
      title: "Kill switch reset",
      message: "The range is ready for a new campaign. Reset recorded.",
      tone: "success",
    });
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Trust boundary"
        title="Safety & governance"
        description="A defensive-only range is only credible if it can prove what it did. Every agent action passes layered guards and lands in a tamper-evident ledger."
        actions={
          <>
            <Button
              variant="quiet"
              size="sm"
              icon="download"
              onClick={() => {
                downloadJsonl(state.audit);
                push({
                  title: "Ledger exported",
                  message: `${state.audit.length} hash-chained entries written as JSONL.`,
                  tone: "success",
                });
              }}
            >
              Export JSONL
            </Button>
            {tripped ? (
              <Button
                variant="danger"
                size="sm"
                icon="refresh"
                onClick={handleReset}
              >
                Reset kill switch
              </Button>
            ) : (
              <Button
                variant="danger"
                size="sm"
                icon="power"
                onClick={() => setTripOpen(true)}
              >
                Trip kill switch
              </Button>
            )}
          </>
        }
        meta={
          <>
            <Pill tone={tripped ? "critical" : "live"} icon="power">
              kill switch {tripped ? "tripped" : "armed"}
            </Pill>
            <Pill tone={chain.valid ? "live" : "critical"} icon="fingerprint">
              {chain.valid
                ? `chain verified · ${state.audit.length} entries`
                : `chain broken at #${chain.brokenAt}`}
            </Pill>
            <Pill icon="users">
              policy{" "}
              {state.approvalMode === "manual"
                ? "strict_manual"
                : state.approvalMode === "deny"
                  ? "deny_all"
                  : "auto_low_risk"}
            </Pill>
          </>
        }
      />

      <section className={cn("killswitch-hero", tripped && "is-tripped")}>
        <div className="killswitch-hero__visual" aria-hidden="true">
          <span className="killswitch-hero__ring" />
          <span className="killswitch-hero__core">
            <Icon name={tripped ? "alert" : "power"} size={26} />
          </span>
        </div>
        <div className="killswitch-hero__copy">
          <span className="eyebrow">Emergency control · KillSwitch</span>
          <h2>{tripped ? "Execution halted" : "Kill switch armed"}</h2>
          <p>
            {tripped
              ? "All agent execution has stopped. Nothing reaches the sandbox until an operator reviews the halt and explicitly resets the switch."
              : "One action stops every agent mid-campaign. The switch is checked before each operation, so no queued tool call can slip through after a trip."}
          </p>
          {tripped ? (
            <div className="killswitch-reason">
              <span className="killswitch-reason__label">Recorded reason</span>
              <b>{state.killSwitch.reason}</b>
              {state.killSwitch.at && (
                <span className="mono">
                  {formatDateTime(state.killSwitch.at)}
                </span>
              )}
            </div>
          ) : (
            <div className="killswitch-facts">
              <span>
                <Icon name="check" size={12} /> Sentinel-file compatible
              </span>
              <span>
                <Icon name="check" size={12} /> Halts in-flight campaigns
              </span>
              <span>
                <Icon name="check" size={12} /> Halt is audited
              </span>
            </div>
          )}
        </div>
        <div className="killswitch-hero__actions">
          <span className={cn("state-chip", tripped ? "is-blocked" : "is-fixed")}>
            {tripped ? "halted" : "armed"}
          </span>
          {tripped ? (
            <Button variant="danger" size="sm" icon="refresh" onClick={handleReset}>
              Reset &amp; re-arm
            </Button>
          ) : (
            <Button
              variant="danger"
              size="sm"
              icon="power"
              onClick={() => setTripOpen(true)}
            >
              Trip now
            </Button>
          )}
          <span className="mono muted">
            {tripped && state.killSwitch.at
              ? `since ${formatTime(state.killSwitch.at)}`
              : "operator authority"}
          </span>
        </div>
      </section>

      <div className="guard-grid">
        {CONTROLS.map((control) => (
          <div className="guard-card" key={control.name}>
            <header>
              <span className="guard-card__icon">
                <Icon name={control.icon} size={16} />
              </span>
              <div>
                <b className="mono">{control.name}</b>
                <span>safety/controls.py</span>
              </div>
              <Pill
                tone={
                  control.state === "enforced" ? "live" : "medium"
                }
              >
                {control.state}
              </Pill>
            </header>
            <p>{control.description}</p>
            <dl>
              {control.facts.map((fact) => (
                <div key={fact.label}>
                  <dt>{fact.label}</dt>
                  <dd className="mono">{fact.value}</dd>
                </div>
              ))}
            </dl>
          </div>
        ))}
      </div>

      <div className="safety-lower">
        <Panel
          className="ledger-panel"
          title="Immutable audit ledger"
          subtitle="SHA-256 hash-chained JSONL · append-only"
          actions={
            <div className="ledger-actions">
              <CopyButton value={head?.entryHash ?? ""} label="Copy head" />
              <Button
                variant="quiet"
                size="sm"
                icon={verifying ? "refresh" : "shield-check"}
                loading={verifying}
                onClick={runVerify}
              >
                Verify chain
              </Button>
            </div>
          }
        >
          <div
            className={cn(
              "ledger-verdict",
              chain.valid ? "is-valid" : "is-invalid",
            )}
          >
            <span className="ledger-verdict__icon">
              <Icon name={chain.valid ? "shield-check" : "x-circle"} size={16} />
            </span>
            <div>
              <b>
                {chain.valid
                  ? "Ledger integrity verified"
                  : `Chain broken at entry #${chain.brokenAt}`}
              </b>
              <span className="mono">
                genesis {shortSha("0".repeat(64), 8)} → head{" "}
                {head ? shortSha(head.entryHash, 8) : "—"} ·{" "}
                {checkedAt
                  ? `checked ${formatTime(checkedAt)}`
                  : "live verification on every read"}
              </span>
            </div>
            <span className="ledger-verdict__count mono">
              {state.audit.length} entries
            </span>
          </div>

          <div className="chain-strip" aria-hidden="true">
            {tail.map((entry, index) => (
              <span
                key={entry.id}
                className="chain-strip__node"
                title={`#${entry.id} · ${entry.action}`}
                style={{ opacity: 0.45 + (index / tail.length) * 0.55 }}
              />
            ))}
            <span className="chain-strip__label mono">genesis → head</span>
          </div>

          <div className="ledger-toolbar">
            <div className="search">
              <Icon name="search" size={14} />
              <input
                className="input"
                placeholder="Filter by actor, action or detail…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                aria-label="Filter audit entries"
              />
            </div>
            <select
              className="select"
              value={actor}
              onChange={(event) => setActor(event.target.value)}
              aria-label="Filter by actor"
            >
              <option value="all">All actors</option>
              {actors.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
            <span className="mono ledger-toolbar__count">
              {entries.length}/{state.audit.length}
            </span>
          </div>

          <div className="ledger-table">
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Entry hash</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr
                    key={entry.id}
                    className="table-click"
                    onClick={() => setSelected(entry)}
                  >
                    <td className="cell-mono muted">
                      {String(entry.id).padStart(3, "0")}
                    </td>
                    <td className="cell-mono">{formatTime(entry.timestamp)}</td>
                    <td>
                      <span className="actor-chip">{entry.actor}</span>
                    </td>
                    <td className="cell-mono strong">{entry.action}</td>
                    <td className="cell-mono muted">
                      {shortSha(entry.entryHash, 14)}
                    </td>
                    <td className="row-action">
                      <Icon name="chevron-right" size={14} />
                    </td>
                  </tr>
                ))}
                {!entries.length && (
                  <tr>
                    <td colSpan={6}>
                      <div className="table-empty">
                        No entries match this filter.
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        <div className="safety-side">
          <Panel title="Approval policy" subtitle="HumanApprovalGate">
            <div className="policy-mode">
              <b>
                {state.approvalMode === "manual"
                  ? "Strict manual review"
                  : state.approvalMode === "deny"
                    ? "Deny all deployments"
                    : "Auto-approve low risk"}
              </b>
              <Pill
                tone={
                  state.approvalMode === "manual"
                    ? "medium"
                    : state.approvalMode === "deny"
                      ? "critical"
                      : "live"
                }
              >
                {state.approvalMode}
              </Pill>
            </div>
            <p className="policy-copy">
              {state.approvalMode === "manual"
                ? "Validated patches are held at the gate until a reviewer approves them. Decisions append two ledger entries: the evaluation and the deployment receipt."
                : state.approvalMode === "deny"
                  ? "No patch may reach the workspace, even when staging validation passes. Useful for dry runs and evidence gathering."
                  : "A patch deploys automatically only when staging tests pass completely, the path stays inside mock_enterprise/, and the kill switch is clear."}
            </p>
            <ul className="policy-rules">
              <li>
                <Icon name="check" size={11} /> 100% staging tests required
              </li>
              <li>
                <Icon name="check" size={11} /> Path must stay in module scope
              </li>
              <li>
                <Icon name="check" size={11} /> Reviewer decision is audited
              </li>
            </ul>
            <Button
              to="/console/simulation"
              variant="quiet"
              size="sm"
              icon="sliders"
            >
              Change in campaign runner
            </Button>
          </Panel>

          <Panel
            title="Enforcement chain"
            subtitle="Checked in order for every operation"
          >
            <ol className="enforce-chain">
              <li>
                <span>01</span>
                <div>
                  <b>KillSwitch.assert_active</b>
                  <p>Sentinel file and in-memory trip state.</p>
                </div>
              </li>
              <li>
                <span>02</span>
                <div>
                  <b>NetworkIsolationGuard</b>
                  <p>Target host must be loopback or a service alias.</p>
                </div>
              </li>
              <li>
                <span>03</span>
                <div>
                  <b>ToolAllowlistGuard</b>
                  <p>Agent + operation pair must be registered.</p>
                </div>
              </li>
              <li>
                <span>04</span>
                <div>
                  <b>Path confinement</b>
                  <p>Resolved path must remain inside the sandbox root.</p>
                </div>
              </li>
              <li>
                <span>05</span>
                <div>
                  <b>ImmutableAuditLogger</b>
                  <p>Canonical JSON is hashed and appended to the chain.</p>
                </div>
              </li>
            </ol>
          </Panel>
        </div>
      </div>

      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        width={620}
        eyebrow={selected ? `Audit entry · #${selected.id}` : undefined}
        title={selected?.action ?? ""}
        subtitle={
          selected && (
            <>
              <span>{selected.actor}</span>
              <span>{formatDateTime(selected.timestamp)}</span>
              <Pill tone={chain.valid ? "live" : "critical"}>
                {chain.valid ? "chain valid" : "chain broken"}
              </Pill>
            </>
          )
        }
        footer={
          selected && (
            <>
              <CopyButton value={selected.entryHash} label="Copy entry hash" />
              <Button variant="ghost" size="sm" onClick={() => setSelected(null)}>
                Close
              </Button>
            </>
          )
        }
      >
        {selected && (
          <>
            <div className="hash-chain">
              <div>
                <span className="label">Previous hash</span>
                <code className="mono">{selected.prevHash}</code>
              </div>
              <span className="hash-chain__link">
                <Icon name="link" size={13} />
              </span>
              <div>
                <span className="label">Entry hash</span>
                <code className="mono">{selected.entryHash}</code>
              </div>
            </div>
            <section className="detail-section">
              <h4>
                <Icon name="fingerprint" size={13} /> Canonical record
              </h4>
              <CodeBlock
                filename={`audit_ledger.jsonl · entry ${String(selected.id).padStart(3, "0")}`}
                code={JSON.stringify(
                  {
                    timestamp: selected.timestamp,
                    actor: selected.actor,
                    action: selected.action,
                    details: selected.details,
                    prev_hash: selected.prevHash,
                    entry_hash: selected.entryHash,
                  },
                  null,
                  2,
                )}
                maxHeight={420}
              />
            </section>
            <p className="note">
              The entry hash is the SHA-256 of the canonical payload including{" "}
              <span className="mono">prev_hash</span>. Changing any field breaks
              every subsequent link, which is what “Verify chain” detects.
            </p>
          </>
        )}
      </Drawer>

      <Drawer
        open={tripOpen}
        onClose={() => setTripOpen(false)}
        width={520}
        eyebrow="Emergency control"
        title="Trip the kill switch?"
        subtitle={
          <span>
            Stops all agent execution immediately. This action is audited and
            requires an operator reset.
          </span>
        }
        footer={
          <>
            <Button variant="quiet" size="sm" onClick={() => setTripOpen(false)}>
              Cancel
            </Button>
            <Button variant="danger" size="sm" icon="power" onClick={handleTrip}>
              Trip kill switch
            </Button>
          </>
        }
      >
        <div className="trip-warning">
          <span className="trip-warning__icon">
            <Icon name="alert" size={18} />
          </span>
          <div>
            <b>This halts the range</b>
            <p>
              In-flight campaigns stop before their next operation. The
              orchestrator refuses new rounds until the switch is reset.
            </p>
          </div>
        </div>
        <div className="field">
          <label htmlFor="kill-reason">Reason (recorded in the ledger)</label>
          <input
            id="kill-reason"
            className="input"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="e.g. Suspected policy violation in patch synthesis"
          />
        </div>
        <p className="note">
          Leave blank to record the default reason{" "}
          <span className="mono">“Emergency halt requested by operator”</span>.
        </p>
      </Drawer>
    </div>
  );
}
