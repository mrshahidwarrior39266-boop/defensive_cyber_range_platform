import { useMemo, useState } from "react";
import FloatingGlassIcon from "../components/glass/FloatingGlassIcon";
import { Icon } from "../components/ui/Icon";
import { Button, Pill, Reveal } from "../components/ui/primitives";
import { Gauge, LineChart, SeverityBar } from "../components/ui/viz";
import { SiteFooter, SiteNav } from "../components/landing/SiteChrome";
import { useDocumentTitle } from "../lib/hooks";
import { useRange } from "../lib/simulation/store";
import { verifyAuditChain } from "../lib/simulation/engine";
import { cn, formatMs } from "../lib/utils";
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
    name: "Surface Mapper",
    role: "AST Traversal",
    copy: "Walks the abstract syntax tree to map every endpoint, parameter, and authorization guard in the codebase.",
    chip: "AST",
  },
  {
    name: "Static Auditor",
    role: "Vulnerability Detection",
    copy: "Inspects seeded CWE weakness archetypes against the source without executing any live payloads.",
    chip: "AUDIT",
  },
  {
    name: "Risk Prioritizer",
    role: "CVSS Scoring",
    copy: "Ranks each finding by exploitability, impact, and architectural exposure so the defense swarm knows what to fix first.",
    chip: "CVSS",
  },
  {
    name: "Compliance Verifier",
    role: "Independent Re-audit",
    copy: "Acts as a second set of eyes — re-audits every generated patch file as an independent verification step.",
    chip: "RE-AUDIT",
  },
  {
    name: "Analysis Reporter",
    role: "SARIF Output",
    copy: "Emits SARIF-compliant findings, cryptographic hashes, and structured telemetry for downstream tooling.",
    chip: "SARIF",
  },
];

const DEFENSE_AGENTS = [
  {
    name: "Detection",
    role: "Alert Correlation",
    copy: "Correlates static auditor findings with active runtime incident events to confirm real exploitability.",
    chip: "ALERT",
  },
  {
    name: "Triage",
    role: "SLA Assignment",
    copy: "Deduplicates reported incidents and assigns severity-based SLA resolution targets to each confirmed issue.",
    chip: "SLA",
  },
  {
    name: "Root Cause",
    role: "Isolation",
    copy: "Pinpoints the exact vulnerable code block, the parameters involved, and the defensive contract that was broken.",
    chip: "RCA",
  },
  {
    name: "Patch Generator",
    role: "Unified Diff",
    copy: "Synthesizes minimal, safe, reviewable unified diffs that enforce defensive boundaries without breaking existing behaviour.",
    chip: "DIFF",
  },
  {
    name: "Validation",
    role: "Regression Testing",
    copy: "Runs functional and security regression tests inside a disposable staging workspace before any production touch.",
    chip: "TEST",
  },
  {
    name: "Deploy & Rollback",
    role: "Atomic Apply",
    copy: "Atomically applies verified patches to disk. If anything fails, a cryptographic rollback restores the prior state.",
    chip: "ATOMIC",
  },
];

const ATTACK_SCENARIOS = [
  {
    id: "cwe-89",
    name: "SQL Injection Probe",
    cwe: "CWE-89",
    target: "database.py : execute_query()",
    payload: "' OR 1=1; --",
    response: "Parameterized query boundary enforced; dynamic string interpolation blocked.",
    diff: "+ cursor.execute(query, (user_id,))",
    status: "SEALED",
  },
  {
    id: "cwe-502",
    name: "Insecure Deserialization",
    cwe: "CWE-502",
    target: "telemetry.py : load_state()",
    payload: "pickle.loads(malicious_stream)",
    response: "Pickle deserialization denied; safe schema JSON parsing substituted.",
    diff: "+ json.loads(payload.decode('utf-8'))",
    status: "SEALED",
  },
  {
    id: "cwe-79",
    name: "Cross-Site Scripting (XSS)",
    cwe: "CWE-79",
    target: "service.py : render_profile()",
    payload: "<script>alert(1)</script>",
    response: "Raw HTML output sanitized with contextual escape invariants.",
    diff: "+ html.escape(user_input, quote=True)",
    status: "SEALED",
  },
  {
    id: "cwe-489",
    name: "Debug Route Exposure",
    cwe: "CWE-489",
    target: "config.py : get_app_settings()",
    payload: "GET /_debug/env_dump",
    response: "Production flag set to False; internal debug handlers stripped.",
    diff: "- DEBUG = True\n+ DEBUG = False",
    status: "SEALED",
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

  // Hero showcase state
  const [heroTab, setHeroTab] = useState<"3d" | "terminal">("3d");
  const [hero3dShape, setHero3dShape] = useState<"Sphere" | "Torus" | "X">("Sphere");

  // Interactive 3D Arena state
  const [arenaShape, setArenaShape] = useState<"Torus" | "Sphere" | "X">("Torus");
  const [activeScenario, setActiveScenario] = useState(ATTACK_SCENARIOS[0]);
  const [isProbing, setIsProbing] = useState(false);

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

  const triggerProbe = (scenario: typeof ATTACK_SCENARIOS[0]) => {
    setIsProbing(true);
    setActiveScenario(scenario);
    setTimeout(() => {
      setIsProbing(false);
    }, 450);
  };

  return (
    <div className="site">
      <SiteNav />

      <main>
        {/* ================================================================
            HERO SECTION WITH 3D CYBER PERIMETER
            ================================================================ */}
        <section className="landing-hero" aria-labelledby="hero-title">
          {/* Background grid */}
          <div className="landing-hero__grid" aria-hidden="true" />

          {/* Ambient glow orbs */}
          <div className="landing-hero__ambient" aria-hidden="true">
            <div className="landing-hero__orb landing-hero__orb--a" />
            <div className="landing-hero__orb landing-hero__orb--b" />
          </div>

          <div className="container">
            <div className="landing-hero__inner">
              {/* Left: copy */}
              <div className="landing-hero__copy">
                <div className="landing-hero__eyebrow">
                  <span className="dot-pulse" />
                  <span>Defensive cyber range · online</span>
                </div>

                <h1 id="hero-title" className="landing-hero__title">
                  Security testing that doesn't{" "}
                  <span className="landing-hero__title-accent">leave the sandbox.</span>
                </h1>

                <p className="landing-hero__sub">
                  Citadel runs two autonomous agent swarms in an air-gapped closed loop — one finds
                  vulnerabilities in your code, the other synthesizes verified patches and proves them fixed.
                  Zero external egress.
                </p>

                <div className="landing-hero__ctas">
                  <Button
                    to="/console"
                    size="lg"
                    variant="primary"
                    iconRight="arrow-right"
                  >
                    Open the console
                  </Button>
                  <Button
                    to="/console/live"
                    size="lg"
                    variant="ghost"
                    icon="folder"
                  >
                    Scan a codebase
                  </Button>
                  <Button
                    to="/architecture"
                    size="lg"
                    variant="ghost"
                    icon="book"
                  >
                    System design
                  </Button>
                </div>

                <div className="landing-hero__proof">
                  <div>
                    <b>11</b>
                    <span>Specialist agents</span>
                  </div>
                  <div>
                    <b>4</b>
                    <span>CWE classes covered</span>
                  </div>
                  <div>
                    <b>SHA-256</b>
                    <span>Chained audit ledger</span>
                  </div>
                  <div>
                    <b>Zero</b>
                    <span>External network egress</span>
                  </div>
                </div>
              </div>

              {/* Right: Interactive 3D Cyber Core & Terminal Showcase */}
              <div className="landing-hero__terminal">
                <div className="hero-showcase-card">
                  <div className="hero-showcase-header">
                    <div className="hero-showcase-tabs">
                      <button
                        type="button"
                        className={cn("hero-showcase-tab", heroTab === "3d" && "is-active")}
                        onClick={() => setHeroTab("3d")}
                      >
                        <Icon name="shield-check" size={13} />
                        <span>3D Defense Core</span>
                      </button>
                      <button
                        type="button"
                        className={cn("hero-showcase-tab", heroTab === "terminal" && "is-active")}
                        onClick={() => setHeroTab("terminal")}
                      >
                        <Icon name="terminal" size={13} />
                        <span>Live AST Terminal</span>
                      </button>
                    </div>
                    <Pill tone="live" icon="shield-check">Air-Gapped</Pill>
                  </div>

                  {heroTab === "3d" ? (
                    <div className="hero-3d-stage">
                      <div className="hero-3d-canvas-wrap">
                        <FloatingGlassIcon
                          text="CITADEL"
                          shape={hero3dShape}
                          size={1.1}
                          depth={1.15}
                          chromatic={0.85}
                          frost={0.12}
                          speed={0.65}
                          tint={[0.96, 0.9, 0.84]}
                        />
                      </div>

                      <div className="hero-3d-overlay">
                        <div className="hero-3d-controls">
                          <button
                            type="button"
                            className={cn("hero-3d-btn", hero3dShape === "Sphere" && "is-active")}
                            onClick={() => setHero3dShape("Sphere")}
                            title="Sandbox Isolation Sphere"
                          >
                            <Icon name="shield" size={11} />
                            <span>Sandbox</span>
                          </button>
                          <button
                            type="button"
                            className={cn("hero-3d-btn", hero3dShape === "Torus" && "is-active")}
                            onClick={() => setHero3dShape("Torus")}
                            title="Dual-Swarm Invariant Loop"
                          >
                            <Icon name="workflow" size={11} />
                            <span>Swarm Loop</span>
                          </button>
                          <button
                            type="button"
                            className={cn("hero-3d-btn", hero3dShape === "X" && "is-active")}
                            onClick={() => setHero3dShape("X")}
                            title="Air-Gap Boundary"
                          >
                            <Icon name="lock" size={11} />
                            <span>Air-Gap</span>
                          </button>
                        </div>
                        <div className="hero-3d-cue">
                          <Icon name="scan" size={10} />
                          <span>Interactive 3D · Drag to rotate perimeter</span>
                        </div>
                      </div>

                      <div className="hero-3d-footer">
                        <div>
                          <span className="mono">ISOLATION</span>
                          <b>Enforced (0 egress)</b>
                        </div>
                        <div>
                          <span className="mono">LEDGER</span>
                          <b>SHA-256 Sealed</b>
                        </div>
                        <div>
                          <span className="mono">ANALYSIS</span>
                          <b>Static AST only</b>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="terminal-card__body">
                      <div className="terminal-line terminal-line--done">
                        <Icon name="check-circle" size={12} />
                        <span className="terminal-line__agent">SurfaceMapper</span>
                        <span className="terminal-line__msg">mapped 47 endpoints, 12 auth guards</span>
                      </div>
                      <div className="terminal-line terminal-line--done">
                        <Icon name="check-circle" size={12} />
                        <span className="terminal-line__agent">StaticAuditor</span>
                        <span className="terminal-line__msg">found CWE-89 · CWE-502 · CWE-79</span>
                      </div>
                      <div className="terminal-line terminal-line--done">
                        <Icon name="check-circle" size={12} />
                        <span className="terminal-line__agent">RiskPrioritizer</span>
                        <span className="terminal-line__msg">CRITICAL: SQLi in /api/users</span>
                      </div>
                      <div className="terminal-line terminal-line--active">
                        <span className="terminal-spinner" aria-hidden="true" />
                        <span className="terminal-line__agent">PatchGenerator</span>
                        <span className="terminal-line__msg">synthesizing parameterised query…</span>
                      </div>
                      <div className="terminal-line terminal-line--pending">
                        <span className="terminal-dot" aria-hidden="true" />
                        <span className="terminal-line__agent">ValidationTesting</span>
                        <span className="terminal-line__msg">waiting for patch diff…</span>
                      </div>
                      <div className="terminal-line terminal-line--pending">
                        <span className="terminal-dot" aria-hidden="true" />
                        <span className="terminal-line__agent">Deploy & Rollback</span>
                        <span className="terminal-line__msg">standby · atomic apply queued</span>
                      </div>

                      <div className="terminal-card__diff">
                        <div className="diff-line diff-line--del">
                          − query = f"SELECT * WHERE id = '{"{id}"}'
                        </div>
                        <div className="diff-line diff-line--add">
                          + cursor.execute(query, ({"{id}"},))
                        </div>
                      </div>

                      <div className="terminal-card__footer">
                        <Icon name="lock" size={11} />
                        <span>Isolated workspace · no external calls</span>
                        <span className="terminal-card__hash">
                          sha256:{state.audit[state.audit.length - 1]?.entryHash?.slice(0, 10) ?? "genesis"}…
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Scroll hint */}
          <a href="#overview" className="landing-hero__scroll" aria-label="Scroll to learn more">
            <span>Explore defensive architecture</span>
            <Icon name="chevron-down" size={14} />
          </a>
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
            HOW IT WORKS — 3-UP FEATURE ROW
            ================================================================ */}
        <section id="overview" className="section platform-section" style={{ borderTop: "1px solid var(--line)" }}>
          <div className="container">
            <Reveal className="section-head section-head--split">
              <div className="section-head__lead">
                <span className="eyebrow">Defensive engineering</span>
                <h2 className="h2">
                  Built for security teams who need proof, not promises.
                </h2>
              </div>
              <p className="lede">
                Citadel runs offensive analysis and defensive remediation in a
                closed loop, inside a sandboxed environment. Every decision is
                logged in a tamper-evident audit chain.
              </p>
            </Reveal>

            <div className="originkit-features">
              <Reveal className="originkit-feature-card" delay={40}>
                <span className="k" />
                <h3>Closed-loop simulation</h3>
                <p>
                  Five analysis agents traverse your ASTs to surface seeded
                  vulnerabilities — SQLi, deserialisation, XSS, debug exposure —
                  inside an isolated mock enterprise. Nothing touches live systems.
                </p>
              </Reveal>

              <Reveal className="originkit-feature-card" delay={120}>
                <span className="k" />
                <h3>Live workspace remediation</h3>
                <p>
                  Attach your project folder and six defense agents handle the
                  rest: root-cause analysis, patch generation, staged validation,
                  and atomic deployment — with automatic rollback on failure.
                </p>
              </Reveal>

              <Reveal className="originkit-feature-card" delay={200}>
                <span className="k" />
                <h3>Cryptographic audit chain</h3>
                <p>
                  Every finding, diff, test result, and approval is SHA-256
                  chained in a tamper-evident ledger. If a single entry changes,
                  the chain breaks and you'll know about it.
                </p>
              </Reveal>
            </div>
          </div>
        </section>

        {/* ================================================================
            INTERACTIVE 3D DEFENSIVE PERIMETER ARENA
            ================================================================ */}
        <section id="arena-3d" className="section arena-3d-section">
          <div className="container">
            <Reveal className="section-head section-head--split">
              <div className="section-head__lead">
                <span className="eyebrow">Interactive 3D range node</span>
                <h2 className="h2">
                  Test the sovereign perimeter.
                </h2>
              </div>
              <p className="lede">
                Simulate adversarial attack probes against the range in real time.
                Observe how the dual-swarm architecture traps, synthesizes, and seals
                defenses without letting any request touch the external host.
              </p>
            </Reveal>

            <div className="arena-3d-grid">
              {/* Left: 3D interactive model */}
              <Reveal className="arena-3d-card" delay={40}>
                <div className="arena-3d-card__head">
                  <div className="row gap-8">
                    <span className="score-dot bg-mint" />
                    <span className="mono tiny">CITADEL_PERIMETER_v1</span>
                  </div>
                  <div className="row gap-6">
                    <button
                      type="button"
                      className={cn("arena-shape-btn", arenaShape === "Torus" && "is-active")}
                      onClick={() => setArenaShape("Torus")}
                    >
                      Torus (Loop)
                    </button>
                    <button
                      type="button"
                      className={cn("arena-shape-btn", arenaShape === "Sphere" && "is-active")}
                      onClick={() => setArenaShape("Sphere")}
                    >
                      Sphere (Sandbox)
                    </button>
                    <button
                      type="button"
                      className={cn("arena-shape-btn", arenaShape === "X" && "is-active")}
                      onClick={() => setArenaShape("X")}
                    >
                      X (Air Gap)
                    </button>
                  </div>
                </div>

                <div className="arena-3d-viewport">
                  <FloatingGlassIcon
                    text="SOVEREIGN"
                    shape={arenaShape}
                    size={1.12}
                    depth={1.2}
                    chromatic={1.05}
                    frost={0.14}
                    speed={0.6}
                    tint={[0.92, 0.84, 0.78]}
                  />
                  <div className="arena-3d-badge">
                    <Icon name="scan" size={11} />
                    <span>Drag 3D model to inspect refractive dispersion</span>
                  </div>
                </div>

                <div className="arena-3d-card__foot">
                  <div className="arena-stat">
                    <span>HOST EGRESS</span>
                    <b>0.00 KB (BLOCKED)</b>
                  </div>
                  <div className="arena-stat">
                    <span>INVARIANT</span>
                    <b>STRICT CONFINEMENT</b>
                  </div>
                  <div className="arena-stat">
                    <span>LEDGER CHAIN</span>
                    <b>VERIFIED HASH</b>
                  </div>
                </div>
              </Reveal>

              {/* Right: Attack probe scenario console */}
              <Reveal className="arena-probe-console" delay={120}>
                <div className="arena-probe-header">
                  <div>
                    <span className="eyebrow">Interactive probe tester</span>
                    <h3>Simulate attack vector</h3>
                  </div>
                  <Pill tone={isProbing ? "high" : "live"} icon="shield-check">
                    {isProbing ? "Intercepting..." : "Perimeter Armed"}
                  </Pill>
                </div>

                <div className="arena-probe-selector">
                  {ATTACK_SCENARIOS.map((scenario) => (
                    <button
                      key={scenario.id}
                      type="button"
                      className={cn(
                        "arena-scenario-btn",
                        activeScenario.id === scenario.id && "is-active",
                      )}
                      onClick={() => triggerProbe(scenario)}
                    >
                      <div className="row spread align-center">
                        <span className="arena-scenario-cwe">{scenario.cwe}</span>
                        <span className="arena-scenario-tag">Probe</span>
                      </div>
                      <b>{scenario.name}</b>
                    </button>
                  ))}
                </div>

                <div className="arena-probe-result">
                  <div className="arena-result-row">
                    <span className="mono muted">TARGET SURFACE</span>
                    <span className="mono">{activeScenario.target}</span>
                  </div>
                  <div className="arena-result-row">
                    <span className="mono muted">SIMULATED PAYLOAD</span>
                    <span className="mono arena-payload">{activeScenario.payload}</span>
                  </div>
                  <div className="arena-result-row">
                    <span className="mono muted">REMEDIATION OUTCOME</span>
                    <span>{activeScenario.response}</span>
                  </div>

                  <div className="arena-diff-box">
                    <div className="mono tiny muted mb-4">SYNTHESIZED SAFE CONTRACT</div>
                    <pre className="mono">{activeScenario.diff}</pre>
                  </div>

                  <div className="arena-receipt">
                    <Icon name="check-circle" size={13} />
                    <span>
                      Intercepted by AST guard · Sealed into SHA-256 chained audit trail · 0 host egress
                    </span>
                  </div>
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        {/* ----------------------------------------------------------------
            Platform capabilities deep dive
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
                An analysis swarm finds what's wrong. A defense swarm proves
                it can be fixed. A scoring judge evaluates the loop against
                ground truth. The ledger keeps everyone honest.
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
                  weaponised payloads. Every finding carries a file, a line and
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
            Specialist agents
            ---------------------------------------------------------------- */}
        <section id="swarms" className="section swarm-section">
          <div className="container">
            <Reveal className="section-head section-head--split">
              <div className="section-head__lead">
                <span className="eyebrow">The agents</span>
                <h2 className="h2">
                  Eleven focused agents.<br />One shared goal.
                </h2>
              </div>
              <p className="lede">
                Narrow agents outperform generalists because they can't
                overstep. Each agent has a typed input, a typed output, and
                a strict tool allowlist. No agent touches what it doesn't own.
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
                        <h4>
                          {agent.name}
                          <span className="agent-row__role"> · {agent.role}</span>
                        </h4>
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
                    <h3 className="h3">Fix it without breaking it.</h3>
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
                        <h4>
                          {agent.name}
                          <span className="agent-row__role"> · {agent.role}</span>
                        </h4>
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
            Safety & governance
            ---------------------------------------------------------------- */}
        <section id="governance" className="section governance-section">
          <div className="container governance">
            <Reveal className="governance__copy">
              <span className="eyebrow">Safety & governance</span>
              <h2 className="h2">
                Nothing moves
                <br />
                without a receipt.
              </h2>
              <p className="lede">
                Autonomous systems need accountability. Six independent controls
                wrap every tool call, file write, and approval step. The ledger
                proves what happened after the fact — not just what was intended.
              </p>
              <div className="control-list">
                {[
                  ["network", "Network isolation", "Loopback targets only"],
                  ["sliders", "Tool allowlist", "Role-scoped operations"],
                  ["users", "Human gate", "Approve before deploy"],
                  ["power", "Kill switch", "Halt the entire range"],
                  ["message", "Prompt sanitizer", "Block injection attempts"],
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
            Evidence / live posture
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
                      LOW: findings.filter((f) => f.severity === "LOW").length || 1,
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
            CLOSING CALL TO ACTION
            ================================================================ */}
        <section className="section section--tight">
          <div className="container">
            <Reveal className="originkit-cta">
              <div>
                <h2>Audit. Patch. Prove. Repeat.</h2>
                <p>
                  The range is live. Run a closed-loop simulation on the mock
                  enterprise, or connect your local codebase for deterministic
                  automated remediation.
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
                    Open the console
                  </Button>
                  <Button
                    to="/console/live"
                    size="lg"
                    icon="folder"
                    className="btn--originkit-ghost"
                    transition
                  >
                    Scan a codebase
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
