import { useMemo } from "react";
import LiquidGlassCluster from "../components/glass/LiquidGlassCluster";
import { Icon } from "../components/ui/Icon";
import { Button, Pill, Reveal } from "../components/ui/primitives";
import { Gauge, LineChart, SeverityBar } from "../components/ui/viz";
import { SiteFooter, SiteNav } from "../components/landing/SiteChrome";
import { useDocumentTitle } from "../lib/hooks";
import { useRange } from "../lib/simulation/store";
import { verifyAuditChain } from "../lib/simulation/engine";
import { formatMs } from "../lib/utils";
import "../styles/landing.css";

const TRUST_ITEMS = [
  { icon: "shield-check" as const, label: "Static analysis only" },
  { icon: "lock" as const, label: "Zero external egress" },
  { icon: "fingerprint" as const, label: "SHA-256 chained ledger" },
  { icon: "git-branch" as const, label: "Atomic patch deployment" },
  { icon: "users" as const, label: "Human approval gates" },
  { icon: "power" as const, label: "Emergency kill switch" },
];

const ANALYSIS_AGENTS = [
  {
    name: "SurfaceMapperAgent",
    copy: "Maps endpoints, parameters and guard coverage from the AST.",
    chip: "AST",
  },
  {
    name: "StaticVulnerabilityAuditorAgent",
    copy: "Inspects seeded CWE classes without executing application code.",
    chip: "AUDIT",
  },
  {
    name: "RiskPrioritizerAgent",
    copy: "Ranks findings by severity, CVSS and architectural exposure.",
    chip: "CVSS",
  },
  {
    name: "ComplianceVerifierAgent",
    copy: "Re-audits every patched file as an independent check.",
    chip: "RE-AUDIT",
  },
  {
    name: "AnalysisReporterAgent",
    copy: "Emits SARIF-aligned findings and structured telemetry.",
    chip: "SARIF",
  },
];

const DEFENSE_AGENTS = [
  {
    name: "DetectionAgent",
    copy: "Correlates static findings with live application telemetry.",
    chip: "ALERT",
  },
  {
    name: "TriageAgent",
    copy: "Deduplicates incidents and assigns severity SLA targets.",
    chip: "SLA",
  },
  {
    name: "RootCauseAgent",
    copy: "Isolates the exact vulnerable AST block and contract.",
    chip: "RCA",
  },
  {
    name: "PatchGenerationAgent",
    copy: "Synthesizes a minimal, reviewable unified diff.",
    chip: "DIFF",
  },
  {
    name: "ValidationTestingAgent",
    copy: "Runs functional and security tests in a staging copy.",
    chip: "TEST",
  },
  {
    name: "DeploymentRollbackAgent",
    copy: "Deploys atomically with a cryptographic backup.",
    chip: "ATOMIC",
  },
];

const PIPELINE = [
  "Surface",
  "Audit",
  "Prioritize",
  "Detect",
  "Patch",
  "Validate",
  "Verify",
  "Score",
];

export default function Landing() {
  useDocumentTitle("Citadel — Defensive Cyber Range");
  const { state } = useRange();

  const lastRound = state.rounds[state.rounds.length - 1];
  const posture = lastRound
    ? lastRound.scorecard.securityPostureScore
    : (state.remediatedCwes.length / 4) * 100;
  const auditCheck = useMemo(
    () => verifyAuditChain(state.audit),
    [state.audit],
  );
  const ledger = [...state.audit].slice(-4).reverse();
  const auditCount = state.audit.length;
  const rounds = state.rounds;
  const trend = rounds.length
    ? rounds.map((round) => round.scorecard.securityPostureScore)
    : [100];
  const findings = state.findings ?? [];

  return (
    <div className="site">
      <SiteNav />

      <main>
        {/* ---------------------------------------------------------------- */}
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero__ambient" aria-hidden="true">
            <div className="hero__orb hero__orb--ice" />
            <div className="hero__orb hero__orb--violet" />
            <div className="hero__grid" />
            <div className="hero__beam" />
          </div>

          <div className="container hero__inner">
            <div className="hero__copy">
              <span className="eyebrow hero__eyebrow">
                Closed-loop defensive simulation
              </span>
              <h1 id="hero-title">
                See the breach
                <br />
                <span className="gradient-text">before it happens.</span>
              </h1>
              <p className="hero__sub">
                An isolated cyber range where one swarm audits your source and
                another patches it. Every fix validated in staging. Every action
                sealed in a tamper-evident ledger.
              </p>
              <div className="hero__cta">
                <Button
                  to="/console"
                  variant="primary"
                  size="lg"
                  iconRight="arrow-right"
                  transition
                >
                  Enter the range
                </Button>
                <Button
                  to="/architecture"
                  variant="ghost"
                  size="lg"
                  icon="book"
                >
                  Read the architecture
                </Button>
              </div>
              <div className="hero__meta">
                <span>
                  <Icon name="shield" size={12} /> Static analysis only
                </span>
                <span>
                  <Icon name="lock" size={12} /> Isolated sandbox
                </span>
                <span>
                  <Icon name="fingerprint" size={12} /> Tamper-evident
                </span>
              </div>
            </div>

            <div className="hero__stage">
              <div className="hero__stage-aura" aria-hidden="true" />
              <span className="hero__tag hero__tag--tl">
                <Icon name="scan" size={10} /> analysis swarm · 5 agents
              </span>
              <span className="hero__tag hero__tag--tr">
                posture · {posture.toFixed(2)}%
              </span>
              <LiquidGlassCluster
                className="hero__glass"
                shape="X"
                depth={1.25}
                speed={0.5}
                direction="Clockwise"
                glass={{ tint: "#e6feff", chromatic: 0.42, frost: 0.3 }}
                orient={{ angleX: -4, angleY: 12, angleZ: -1 }}
              />
              <span className="hero__tag hero__tag--bl">
                sandbox // 0 egress
              </span>
              <span className="hero__tag hero__tag--br">
                ledger // {String(auditCount).padStart(2, "0")} sealed
              </span>
              <span className="hero__drag">
                <Icon name="target" size={11} /> drag to orient
              </span>
            </div>

            <div className="hero__stats">
              <div>
                <b>11</b>
                <span>specialist agents</span>
              </div>
              <div>
                <b>04</b>
                <span>seeded CWE classes</span>
              </div>
              <div>
                <b>
                  {auditCheck.valid ? auditCount : "!"}
                </b>
                <span>sealed ledger entries</span>
              </div>
              <div>
                <b>{posture.toFixed(0)}%</b>
                <span>current posture</span>
              </div>
            </div>
          </div>

          <a href="#platform" className="hero__scroll" aria-label="Explore the platform">
            <span>Scroll to explore</span>
            <i />
          </a>
        </section>

        {/* ---------------------------------------------------------------- */}
        <div className="trust-strip" aria-hidden="true">
          <div className="trust-strip__track">
            {[0, 1].map((copy) => (
              <div className="trust-strip__set" key={copy}>
                {TRUST_ITEMS.map((item) => (
                  <span key={`${copy}-${item.label}`}>
                    <Icon name={item.icon} size={12} />
                    {item.label}
                  </span>
                ))}
              </div>
            ))}
          </div>
        </div>

        {/* ---------------------------------------------------------------- */}
        <section id="platform" className="section platform-section">
          <div className="container">
            <Reveal className="section-head section-head--split">
              <div className="section-head__lead">
                <span className="eyebrow">The platform</span>
                <h2 className="h2">
                  Two swarms.
                  <br />
                  One closed loop.
                </h2>
              </div>
              <p className="lede">
                A security analysis swarm finds what is wrong. A defense swarm
                proves it can be fixed. The judge scores the loop against ground
                truth, and the ledger keeps everyone honest.
              </p>
            </Reveal>

            <div className="cap-grid">
              <Reveal className="cap-card" delay={40}>
                <div className="cap-card__top">
                  <span className="cap-card__icon">
                    <Icon name="scan" size={19} />
                  </span>
                  <span className="cap-card__index">01 / OBSERVE</span>
                </div>
                <h3>Static, by design.</h3>
                <p>
                  Agents traverse ASTs, structure and configuration — never
                  weaponized payloads. Every finding carries a file, a line and
                  a remediation contract.
                </p>
                <div className="cap-card__visual cap-card__visual--surface">
                  <span className="mono">
                    mock_enterprise/service.py
                  </span>
                  <div>
                    <i className="kw">ast</i>.FunctionDef
                    <span className="muted"> · 4 surfaces · 0 guards</span>
                  </div>
                </div>
              </Reveal>

              <Reveal className="cap-card" delay={120}>
                <div className="cap-card__top">
                  <span className="cap-card__icon">
                    <Icon name="git-branch" size={19} />
                  </span>
                  <span className="cap-card__index">02 / REMEDIATE</span>
                </div>
                <h3>Patch, then prove.</h3>
                <p>
                  Every candidate fix is validated in a disposable staging copy
                  against functional and security invariants before an atomic
                  deploy — with automatic rollback on failure.
                </p>
                <div className="cap-card__visual cap-card__visual--diff">
                  <div className="diff-line diff-line--del">
                    − query = f"… WHERE username = '&#123;username&#125;'"
                  </div>
                  <div className="diff-line diff-line--add">
                    + cursor.execute(query, (username,))
                  </div>
                </div>
              </Reveal>

              <Reveal className="cap-card" delay={200}>
                <div className="cap-card__top">
                  <span className="cap-card__icon">
                    <Icon name="fingerprint" size={19} />
                  </span>
                  <span className="cap-card__index">03 / GOVERN</span>
                </div>
                <h3>Sealed by default.</h3>
                <p>
                  Six controls wrap every agent call. Path confinement, network
                  isolation, human gates and a SHA-256 chained ledger make
                  autonomy auditable.
                </p>
                <div className="cap-card__visual cap-card__visual--ledger">
                  <span className="ledger-dot" />
                  <span className="mono">entry 0042</span>
                  <span className="mono muted">
                    {state.audit[state.audit.length - 1]?.entryHash.slice(0, 14) ??
                      "genesis" }
                    …
                  </span>
                  <Icon name="check-circle" size={12} />
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        {/* ---------------------------------------------------------------- */}
        <section id="swarms" className="section swarm-section">
          <div className="container">
            <Reveal className="section-head section-head--split">
              <div className="section-head__lead">
                <span className="eyebrow">The swarms</span>
                <h2 className="h2">
                  Specialist minds.
                  <br />
                  Fixed roles.
                </h2>
              </div>
              <p className="lede">
                Eleven narrow agents beat one generalist. Each runs inside a
                tool allowlist, reports structured output, and hands the next
                agent a typed artifact.
              </p>
            </Reveal>

            <div className="swarm-grid">
              <Reveal className="swarm-panel">
                <div className="swarm-panel__head">
                  <div>
                    <span className="eyebrow">Security analysis</span>
                    <h3 className="h3">Find the truth in the source.</h3>
                  </div>
                  <Pill icon="shield">05 agents</Pill>
                </div>
                <ul className="agent-list">
                  {ANALYSIS_AGENTS.map((agent, index) => (
                    <li className="agent-row" key={agent.name}>
                      <span className="agent-row__num">
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <div>
                        <h4>{agent.name}</h4>
                        <p>{agent.copy}</p>
                      </div>
                      <span className="agent-row__chip">{agent.chip}</span>
                    </li>
                  ))}
                </ul>
              </Reveal>

              <Reveal className="swarm-panel" delay={100}>
                <div className="swarm-panel__head">
                  <div>
                    <span className="eyebrow">Defensive response</span>
                    <h3 className="h3">Heal it without breaking it.</h3>
                  </div>
                  <Pill tone="violet" icon="zap">
                    06 agents
                  </Pill>
                </div>
                <ul className="agent-list">
                  {DEFENSE_AGENTS.map((agent, index) => (
                    <li className="agent-row" key={agent.name}>
                      <span className="agent-row__num">
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <div>
                        <h4>{agent.name}</h4>
                        <p>{agent.copy}</p>
                      </div>
                      <span className="agent-row__chip">{agent.chip}</span>
                    </li>
                  ))}
                </ul>
              </Reveal>
            </div>

            <Reveal className="pipeline" delay={80}>
              {PIPELINE.map((node, index) => (
                <div className="pipeline__cell" key={node}>
                  <div className="pipeline__node">
                    <span>{String(index + 1).padStart(2, "0")}</span>
                    <b>{node}</b>
                  </div>
                  {index < PIPELINE.length - 1 && (
                    <span className="pipeline__link" aria-hidden="true">
                      <i />
                    </span>
                  )}
                </div>
              ))}
            </Reveal>
          </div>
        </section>

        {/* ---------------------------------------------------------------- */}
        <section id="governance" className="section governance-section">
          <div className="container governance">
            <Reveal className="governance__copy">
              <span className="eyebrow">Safety &amp; governance</span>
              <h2 className="h2">
                Nothing moves
                <br />
                without a receipt.
              </h2>
              <p className="lede">
                Autonomy is only useful if it is accountable. Six independent
                controls wrap every tool call, file write and approval — and the
                ledger proves it after the fact.
              </p>
              <div className="control-list">
                {[
                  ["network", "Network isolation", "Loopback targets only"],
                  ["sliders", "Tool allowlist", "Role-scoped operations"],
                  ["users", "Human gate", "Approve before deploy"],
                  ["power", "Kill switch", "Halt the whole range"],
                  ["message", "Prompt sanitizer", "Neutralize injection"],
                  ["fingerprint", "Immutable ledger", "SHA-256 hash chain"],
                ].map(([icon, title, copy]) => (
                  <div className="control-item" key={title}>
                    <Icon name={icon as "network"} size={14} />
                    <div>
                      <b>{title}</b>
                      <span>{copy}</span>
                    </div>
                  </div>
                ))}
              </div>
              <Button
                to="/console/safety"
                variant="ghost"
                iconRight="arrow-up-right"
                className="mt-20"
              >
                Open governance console
              </Button>
            </Reveal>

            <Reveal className="ledger-card" delay={120}>
              <div className="ledger-card__head">
                <div>
                  <span className="lab">Immutable audit ledger</span>
                  <h3>audit_trail.jsonl</h3>
                </div>
                <Pill
                  tone={auditCheck.valid ? "live" : "critical"}
                  icon={auditCheck.valid ? "shield-check" : "alert"}
                >
                  {auditCheck.valid ? "CHAIN VALID" : "CHAIN BROKEN"}
                </Pill>
              </div>
              <div className="ledger-card__meta">
                <span>SHA-256 · append only</span>
                <span>{auditCount} entries</span>
              </div>
              <div className="ledger-list">
                {ledger.map((entry) => (
                  <div className="ledger-entry" key={entry.id}>
                    <span className="ledger-entry__index">
                      {String(entry.id).padStart(4, "0")}
                    </span>
                    <div className="ledger-entry__body">
                      <b>{entry.actor}</b>
                      <span>{entry.action.replaceAll("_", " ")}</span>
                    </div>
                    <span className="ledger-entry__hash">
                      {entry.entryHash.slice(0, 10)}…
                    </span>
                    <Icon name="check" size={11} />
                  </div>
                ))}
              </div>
              <div className="ledger-card__foot">
                <span>
                  <Icon name="lock" size={11} /> Chained from genesis
                </span>
                <span className="mono">verify →</span>
              </div>
              <div className="ledger-card__glow" aria-hidden="true" />
            </Reveal>
          </div>
        </section>

        {/* ---------------------------------------------------------------- */}
        <section className="section proof-section">
          <div className="container">
            <Reveal className="section-head section-head--split">
              <div className="section-head__lead">
                <span className="eyebrow">The evidence</span>
                <h2 className="h2">Measured, not asserted.</h2>
              </div>
              <p className="lede">
                Every campaign is scored against ground truth — discovery
                recall, patch correctness, regression pass rate, time to detect
                and time to remediate.
              </p>
            </Reveal>

            <Reveal className="proof">
              <div className="proof__score">
                <Gauge
                  value={posture}
                  size={218}
                  label="security posture"
                  caption={`${state.remediatedCwes.length} / 4 CWE classes closed`}
                />
                <div className="proof__score-meta">
                  <SeverityBar
                    counts={{
                      CRITICAL:
                        findings.filter((f) => f.severity === "CRITICAL")
                          .length || 1,
                      HIGH:
                        findings.filter((f) => f.severity === "HIGH").length ||
                        1,
                      MEDIUM:
                        findings.filter((f) => f.severity === "MEDIUM").length ||
                        1,
                      LOW:
                        findings.filter((f) => f.severity === "LOW").length || 1,
                    }}
                    total={Math.max(findings.length, 4)}
                  />
                  <span className="proof__note">
                    Seeded weaknesses: CWE-89 · CWE-862 · CWE-79 · CWE-489
                  </span>
                </div>
              </div>

              <div className="proof__body">
                <div className="proof__metrics">
                  <div>
                    <span>Discovery recall</span>
                    <b>
                      {lastRound
                        ? `${lastRound.scorecard.discoveryRecallPct}%`
                        : "100%"}
                    </b>
                  </div>
                  <div>
                    <span>Patch correctness</span>
                    <b>
                      {lastRound
                        ? `${lastRound.scorecard.patchCorrectnessPct}%`
                        : "100%"}
                    </b>
                  </div>
                  <div>
                    <span>Mean time to remediate</span>
                    <b>
                      {lastRound
                        ? formatMs(lastRound.scorecard.meanTimeToRemediateMs)
                        : "7.2ms"}
                    </b>
                  </div>
                  <div>
                    <span>Sealed actions</span>
                    <b>{auditCount}</b>
                  </div>
                </div>

                <div className="proof__trend">
                  <div className="proof__trend-head">
                    <span>Posture across rounds</span>
                    <span className="mono">
                      {rounds.length || 2} rounds · {state.lessons.length} lessons
                    </span>
                  </div>
                  <LineChart
                    values={trend}
                    labels={rounds.length
                      ? rounds.map((round) => `R${String(round.roundNum).padStart(2, "0")}`)
                      : ["R01", "R02"]}
                    height={112}
                  />
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ---------------------------------------------------------------- */}
        <section className="section section--tight">
          <div className="container">
            <Reveal className="cta-band">
              <div className="cta-band__copy">
                <span className="eyebrow">Ready when you are</span>
                <h2>Audit. Patch. Prove. Repeat.</h2>
                <p>
                  The range is already seeded with four educational weaknesses.
                  Step inside and watch the loop close — or open the hood and
                  inspect every control first.
                </p>
              </div>
              <div className="cta-band__actions">
                <Button
                  to="/console"
                  variant="primary"
                  size="lg"
                  iconRight="arrow-right"
                  transition
                >
                  Enter the range
                </Button>
                <Button to="/architecture" variant="ghost" size="lg" icon="book">
                  System architecture
                </Button>
              </div>
              <div className="cta-band__orb" aria-hidden="true" />
            </Reveal>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
