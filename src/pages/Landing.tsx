import { useState, useMemo } from "react";
import FloatingGlassIcon, { type FloatingGlassShape } from "../components/glass/FloatingGlassIcon";
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
  { icon: "shield-check" as const, label: "Static AST analysis only" },
  { icon: "lock" as const, label: "Zero external network egress" },
  { icon: "fingerprint" as const, label: "SHA-256 chained audit ledger" },
  { icon: "git-branch" as const, label: "Atomic patch deployment & backup" },
  { icon: "users" as const, label: "Human-in-the-loop approval gates" },
  { icon: "power" as const, label: "Autonomous emergency kill switch" },
];

const ANALYSIS_AGENTS = [
  {
    name: "SurfaceMapperAgent",
    copy: "Traverses abstract syntax trees to map endpoints, parameters, and authorization guard coverage.",
    chip: "AST",
  },
  {
    name: "StaticVulnerabilityAuditorAgent",
    copy: "Inspects seeded CWE weakness archetypes without executing dangerous application payloads.",
    chip: "AUDIT",
  },
  {
    name: "RiskPrioritizerAgent",
    copy: "Scores and ranks findings by severity, CVSS impact, and architectural privilege exposure.",
    chip: "CVSS",
  },
  {
    name: "ComplianceVerifierAgent",
    copy: "Re-audits every generated patch file as an independent verification check.",
    chip: "RE-AUDIT",
  },
  {
    name: "AnalysisReporterAgent",
    copy: "Emits SARIF-compliant findings, cryptographic hashes, and structured telemetry.",
    chip: "SARIF",
  },
];

const DEFENSE_AGENTS = [
  {
    name: "DetectionAgent",
    copy: "Correlates static auditor findings with active runtime application incident events.",
    chip: "ALERT",
  },
  {
    name: "TriageAgent",
    copy: "Deduplicates reported incidents and assigns strict severity SLA resolution targets.",
    chip: "SLA",
  },
  {
    name: "RootCauseAgent",
    copy: "Isolates the exact vulnerable syntax block, parameters, and defensive invariant contract.",
    chip: "RCA",
  },
  {
    name: "PatchGenerationAgent",
    copy: "Synthesizes minimal, safe, reviewable unified diffs enforcing defensive boundaries.",
    chip: "DIFF",
  },
  {
    name: "ValidationTestingAgent",
    copy: "Executes functional and regression verification tests inside a disposable staging workspace.",
    chip: "TEST",
  },
  {
    name: "DeploymentRollbackAgent",
    copy: "Atomically deploys verified patches to disk with cryptographic rollbacks preserved.",
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
  useDocumentTitle("Citadel — Autonomous Defensive Cyber Range");
  const { state } = useRange();

  // Floating Glass Stage Interactive Controls
  const [glassShape, setGlassShape] = useState<FloatingGlassShape>("Torus");
  const [glassText, setGlassText] = useState<string>("CITADEL");

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
        {/* ================================================================
            ORIGINKIT INSPIRED SPLIT HERO WITH FLOATING GLASS TORUS
            ================================================================ */}
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero__ambient" aria-hidden="true">
            <div className="hero__orb hero__orb--ice" />
            <div className="hero__orb hero__orb--violet" />
            <div className="hero__grid" />
            <div className="hero__beam" />
          </div>

          <div className="hero__inner hero__inner--split">
            {/* Left Column: Bold Condensed Typography & Copy */}
            <div className="hero__copy hero__copy--split">
              <span className="hero__eyebrow--warm">
                <Icon name="shield-check" size={13} />
                Mode 1 &amp; Mode 2 · Autonomous Defensive Range
              </span>

              <h1 id="hero-title" className="hero__title--display">
                See the breach
                <br />
                <span className="accent">before it happens.</span>
              </h1>

              <p className="hero__sub--originkit">
                An isolated cyber range where an offensive swarm audits your code
                and a defensive swarm stages, patches, and proves the fix in real time.
                Every action is sealed in a tamper-evident cryptographic ledger.
              </p>

              <div className="hero__cta--originkit">
                <Button
                  to="/console"
                  size="lg"
                  iconRight="arrow-right"
                  className="btn--originkit-primary"
                  transition
                >
                  Enter the range
                </Button>
                <Button
                  to="/console/live"
                  size="lg"
                  icon="folder"
                  className="btn--originkit-ghost"
                  transition
                >
                  Audit Local Codebase
                </Button>
                <Button
                  to="/architecture"
                  size="lg"
                  icon="book"
                  variant="ghost"
                >
                  Architecture
                </Button>
              </div>

              <div className="hero__meta" style={{ justifyContent: "flex-start", marginTop: 8 }}>
                <span>
                  <Icon name="shield" size={12} /> Static AST analysis
                </span>
                <span>
                  <Icon name="lock" size={12} /> Isolated sandbox (0 egress)
                </span>
                <span>
                  <Icon name="fingerprint" size={12} /> SHA-256 tamper-evident
                </span>
              </div>
            </div>

            {/* Right Column: Real-time Floating Glass Torus Viewport */}
            <div className="hero__stage-wrap">
              <div className="hero__stage-box">
                <FloatingGlassIcon
                  text={glassText}
                  shape={glassShape}
                  size={0.92}
                  depth={1.05}
                  chromatic={1.0}
                  frost={0.12}
                  speed={0.9}
                />
              </div>

              {/* Interactive Control HUD for 3D Floating Glass */}
              <div className="hero__stage-bar">
                <div className="hero__stage-pills">
                  <span className="mono text-muted text-xs" style={{ alignSelf: "center", marginRight: 4 }}>
                    Shape:
                  </span>
                  <button
                    type="button"
                    className={`stage-pill-btn ${glassShape === "Torus" ? "is-active" : ""}`}
                    onClick={() => setGlassShape("Torus")}
                  >
                    Torus
                  </button>
                  <button
                    type="button"
                    className={`stage-pill-btn ${glassShape === "X" ? "is-active" : ""}`}
                    onClick={() => setGlassShape("X")}
                  >
                    Shield (X)
                  </button>
                  <button
                    type="button"
                    className={`stage-pill-btn ${glassShape === "Sphere" ? "is-active" : ""}`}
                    onClick={() => setGlassShape("Sphere")}
                  >
                    Sphere
                  </button>
                </div>

                <div className="hero__stage-pills">
                  <span className="mono text-muted text-xs" style={{ alignSelf: "center", marginRight: 4 }}>
                    Text:
                  </span>
                  {(["CITADEL", "DEFENSE", "RANGE"] as const).map((label) => (
                    <button
                      key={label}
                      type="button"
                      className={`stage-pill-btn ${glassText === label ? "is-active" : ""}`}
                      onClick={() => setGlassText(label)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              <span className="mono text-xs text-muted" style={{ fontSize: 11 }}>
                <Icon name="target" size={11} /> Real refraction shader · Drag to orient in 3D
              </span>
            </div>
          </div>
        </section>

        {/* ----------------------------------------------------------------
            Continuous Trust & Isolation Marquee
            ---------------------------------------------------------------- */}
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

        {/* ================================================================
            ORIGINKIT 3-UP FEATURE ROW WITH COLOR ACCENT BARS
            ================================================================ */}
        <section id="features" className="section platform-section" style={{ borderTop: "1px solid #232834" }}>
          <div className="container">
            <Reveal className="section-head section-head--split">
              <div className="section-head__lead">
                <span className="hero__eyebrow--warm">Engine Core Invariants</span>
                <h2 className="h2" style={{ fontFamily: "var(--font-display-hero)", textTransform: "uppercase", fontSize: "clamp(2.4rem, 5vw, 3.8rem)" }}>
                  Made for Autonomous Defense
                </h2>
              </div>
              <p className="lede">
                Built from the ground up for strict educational and enterprise research.
                Offensive analysis swarms and defensive response swarms interact inside isolated
                sandboxes with zero external connectivity.
              </p>
            </Reveal>

            <div className="originkit-features">
              <Reveal className="originkit-feature-card" delay={40}>
                <span className="k" />
                <h3>Closed-Loop Simulation</h3>
                <p>
                  Offensive analysis swarms probe synthetic vulnerabilities (CWE-89, CWE-295, CWE-502, CWE-489)
                  inside an isolated mock enterprise without executing dangerous payloads.
                </p>
              </Reveal>

              <Reveal className="originkit-feature-card" delay={120}>
                <span className="k" />
                <h3>Live Folder Auto-Remediation</h3>
                <p>
                  Point Citadel at your local codebase via browser AST sandbox or the local Python REST daemon.
                  Multi-pass safe remediation automatically generates unified diffs, applies fixes, and verifies resolution.
                </p>
              </Reveal>

              <Reveal className="originkit-feature-card" delay={200}>
                <span className="k" />
                <h3>Cryptographic Proof Chain</h3>
                <p>
                  Every triage verdict, patch diff, staging test run, and rollback backup is SHA-256 chained in
                  a tamper-evident audit ledger with human-in-the-loop governance gates.
                </p>
              </Reveal>
            </div>
          </div>
        </section>

        {/* ----------------------------------------------------------------
            Platform Capabilities Deep Dive
            ---------------------------------------------------------------- */}
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

        {/* ----------------------------------------------------------------
            Specialist Minds Swarms Section
            ---------------------------------------------------------------- */}
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

        {/* ----------------------------------------------------------------
            Safety & Governance Section
            ---------------------------------------------------------------- */}
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

        {/* ----------------------------------------------------------------
            Evidence & Live Posture HUD Section
            ---------------------------------------------------------------- */}
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

        {/* ================================================================
            ORIGINKIT STYLE CLOSING CALL TO ACTION
            ================================================================ */}
        <section className="section section--tight">
          <div className="container">
            <Reveal className="originkit-cta">
              <div>
                <h2>Audit. Patch. Prove. Repeat.</h2>
                <p>
                  The Citadel range is live and ready. Step inside to run a closed-loop simulation
                  campaign on the synthetic mock enterprise, or connect your local folder for
                  deterministic automated vulnerability remediation.
                </p>
              </div>

              <div className="originkit-cta__action">
                <div className="row gap-12 flex-wrap">
                  <Button
                    to="/console"
                    size="lg"
                    iconRight="arrow-right"
                    className="btn--originkit-primary"
                    transition
                  >
                    Enter the range
                  </Button>
                  <Button
                    to="/console/live"
                    size="lg"
                    icon="folder"
                    className="btn--originkit-ghost"
                    transition
                  >
                    Live Codebase
                  </Button>
                </div>
                <div className="originkit-cli-pill">
                  <Icon name="terminal" size={13} />
                  <span>python -m defensive_cyber_range.live.server --root . --allow-write</span>
                </div>
              </div>
            </Reveal>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
