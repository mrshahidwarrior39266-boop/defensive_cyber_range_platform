import { SiteFooter, SiteNav } from "../components/landing/SiteChrome";
import { Icon } from "../components/ui/Icon";
import { Button, Pill, Reveal } from "../components/ui/primitives";
import { CodeBlock } from "../components/ui/code";
import { useDocumentTitle } from "../lib/hooks";
import { useRange } from "../lib/simulation/store";
import "../styles/docs.css";

const ANALYSIS_AGENTS = [
  ["SurfaceMapperAgent", "AST surface inventory"],
  ["StaticVulnerabilityAuditorAgent", "CWE pattern audit"],
  ["RiskPrioritizerAgent", "CVSS + exposure ranking"],
  ["ComplianceVerifierAgent", "Independent re-audit"],
  ["AnalysisReporterAgent", "SARIF-aligned report"],
];

const DEFENSE_AGENTS = [
  ["DetectionAgent", "Telemetry correlation"],
  ["TriageAgent", "Dedupe + SLA targets"],
  ["RootCauseAgent", "Vulnerable AST block"],
  ["PatchGenerationAgent", "Minimal unified diff"],
  ["ValidationTestingAgent", "Functional + security tests"],
  ["DeploymentRollbackAgent", "Atomic deploy / backup"],
];

const CONTROLS = [
  {
    name: "NetworkIsolationGuard",
    mech: "Allowlists loopback and container hostnames only. External egress is blocked.",
    scope: "Target resolution",
  },
  {
    name: "ToolAllowlistGuard",
    mech: "Per-agent operation allowlist plus Path.resolve().is_relative_to(sandbox).",
    scope: "Every tool call",
  },
  {
    name: "HumanApprovalGate",
    mech: "Evaluates each patch against staging results and module scope.",
    scope: "Pre-deployment",
  },
  {
    name: "KillSwitch",
    mech: "In-memory flag, signal and KILL_SWITCH.lock sentinel stop all agent loops.",
    scope: "Global",
  },
  {
    name: "PromptSanitizer",
    mech: "Redacts instruction-override patterns before untrusted text reaches an LLM.",
    scope: "Untrusted context",
  },
  {
    name: "ImmutableAuditLogger",
    mech: "Append-only JSONL; each entry hashes the previous entry with SHA-256.",
    scope: "Every action",
  },
];

const SCORING = [
  ["Discovery recall", "found CWEs ÷ active ground truth", "100%"],
  ["Mean time to detect", "alert time − finding time", "2.5 ms"],
  ["Mean time to remediate", "deploy time − alert time", "7.17 ms"],
  ["Patch correctness", "verified fixes ÷ generated patches", "100%"],
  ["Regression pass rate", "passed validations ÷ all validations", "100%"],
  ["Security posture", "remediated CWEs ÷ 4 seeded classes", "100%"],
];

const MEMORY_TABLES = [
  {
    name: "rounds",
    columns: "round_num · recorded_at · findings_discovered · patches_deployed · verified_remediated · posture_score",
  },
  {
    name: "lessons_learned",
    columns: "id · round_num · cwe_id · file_path · patch_id · remediated · lesson_summary",
  },
];

const SECTIONS = [
  ["overview", "Overview"],
  ["map", "System map"],
  ["lifecycle", "Round lifecycle"],
  ["evidence", "Evidence model"],
  ["memory", "State & memory"],
  ["safety", "Safety model"],
  ["reality", "Interface layer"],
];

export default function Architecture() {
  useDocumentTitle("Architecture — Citadel");
  const { state } = useRange();

  return (
    <div className="site docs">
      <SiteNav solid />

      <main>
        <section className="docs-hero">
          <div className="container docs-hero__grid">
            <Reveal className="docs-hero__copy">
              <span className="eyebrow">System design · v1.0</span>
              <h1>
                A closed loop,
                <br />
                <span className="gradient-text">by construction.</span>
              </h1>
              <p className="lede">
                Citadel is a defensive cyber range built from typed artefacts,
                fixed agent roles and an append-only ledger. This is the map of
                how the analysis and defense swarms meet — and where the
                guardrails live.
              </p>
              <div className="docs-hero__meta">
                <Pill icon="code">Python 3.10+</Pill>
                <Pill icon="layers">11 specialist agents</Pill>
                <Pill icon="database">SQLite memory</Pill>
                <Pill icon="fingerprint">SHA-256 chain</Pill>
              </div>
              <div className="docs-hero__actions">
                <Button to="/console" variant="primary" transition>
                  Open the live console
                </Button>
                <Button to="/#platform" variant="ghost">
                  Platform overview
                </Button>
              </div>
            </Reveal>

            <Reveal className="docs-hero__blueprint" delay={120}>
              <div className="blueprint-card">
                <div className="blueprint-card__head">
                  <span className="blueprint-card__badge">
                    <Icon name="layers" size={12} /> ARCH-SYSTEM · v1.0
                  </span>
                  <span className="blueprint-card__status">AIR-GAPPED RUNTIME</span>
                </div>
                <div className="blueprint-card__layers">
                  <div className="blueprint-layer blueprint-layer--offensive">
                    <div className="blueprint-layer__tag">01 · Static Analysis Plane (Read-Only)</div>
                    <div className="blueprint-layer__items">
                      <span>AST Walker</span>
                      <span>CWE Auditor</span>
                      <span>CVSS Scorer</span>
                    </div>
                  </div>
                  <div className="blueprint-divider">
                    <span className="blueprint-divider__label">
                      <Icon name="lock" size={11} /> Isolated Sandbox Boundary · Zero Egress
                    </span>
                  </div>
                  <div className="blueprint-layer blueprint-layer--defensive">
                    <div className="blueprint-layer__tag">02 · Autonomous Defense Plane</div>
                    <div className="blueprint-layer__items">
                      <span>Telemetry Correlator</span>
                      <span>Unified Diff Engine</span>
                      <span>Staging Sandbox</span>
                    </div>
                  </div>
                  <div className="blueprint-layer blueprint-layer--ledger">
                    <div className="blueprint-layer__tag">03 · Cryptographic Attestation</div>
                    <div className="blueprint-layer__items">
                      <span>SHA-256 Hash Chain</span>
                      <span>Atomic Rollback</span>
                      <span>Human Gate</span>
                    </div>
                  </div>
                </div>
                <div className="blueprint-card__foot">
                  <Icon name="shield-check" size={12} />
                  <span>Protected by 6 non-bypassable security controls</span>
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        <div className="container arch-layout">
          <article className="arch-article">
            <section id="overview" className="arch-section">
              <span className="arch-kicker">01 / Overview</span>
              <h2>Two teams, one immutable history.</h2>
              <p>
                The platform separates discovery from remediation. The analysis
                swarm reads code — it never executes it. The defense swarm reads
                findings and telemetry, then writes candidate patches into an
                isolated staging copy. An orchestrator serialises every phase,
                and a scoring engine compares the outcome with the seeded ground
                truth. The only shared truth is the hash-chained audit log.
              </p>
              <div className="arch-pillars">
                <div>
                  <Icon name="scan" size={17} />
                  <b>Observe</b>
                  <span>AST inventories and static CWE audits, with zero payloads.</span>
                </div>
                <div>
                  <Icon name="git-branch" size={17} />
                  <b>Remediate</b>
                  <span>Minimal patches proven in staging before atomic deploy.</span>
                </div>
                <div>
                  <Icon name="fingerprint" size={17} />
                  <b>Attest</b>
                  <span>Every agent call sealed into a tamper-evident ledger.</span>
                </div>
              </div>
            </section>

            <section id="map" className="arch-section">
              <span className="arch-kicker">02 / System map</span>
              <h2>The shape of the range.</h2>
              <p>
                Six typed agent outputs flow through the orchestrator. Safety
                controls wrap every edge of the graph, not just the perimeter.
              </p>

              <div className="arch-map">
                <div className="arch-map__safety">
                  <span className="arch-map__label">
                    <Icon name="shield-check" size={12} /> Safety &amp; governance
                  </span>
                  <div className="arch-map__chips">
                    {[
                      "Kill switch",
                      "Network isolation",
                      "Tool allowlist",
                      "Path confinement",
                      "Prompt sanitizer",
                      "Human gate",
                      "SHA-256 ledger",
                    ].map((chip) => (
                      <span key={chip}>{chip}</span>
                    ))}
                  </div>
                </div>

                <div className="arch-map__body">
                  <div className="arch-swarm">
                    <header>
                      <span>01</span>
                      <b>Analysis swarm</b>
                      <em>READ ONLY</em>
                    </header>
                    {ANALYSIS_AGENTS.map(([name, role]) => (
                      <div className="arch-agent" key={name}>
                        <span className="arch-agent__dot" />
                        <b>{name}</b>
                        <span>{role}</span>
                      </div>
                    ))}
                  </div>

                  <div className="arch-core">
                    <div className="arch-core__node">
                      <Icon name="workflow" size={15} />
                      <b>SimulationOrchestrator</b>
                      <span>round controller</span>
                    </div>
                    <div className="arch-core__line">
                      <i />
                      <span>typed artefacts</span>
                    </div>
                    <div className="arch-core__node">
                      <Icon name="gauge" size={15} />
                      <b>Judge &amp; memory</b>
                      <span>score · persist</span>
                    </div>
                  </div>

                  <div className="arch-swarm arch-swarm--defense">
                    <header>
                      <span>02</span>
                      <b>Defense swarm</b>
                      <em>STAGED WRITE</em>
                    </header>
                    {DEFENSE_AGENTS.map(([name, role]) => (
                      <div className="arch-agent" key={name}>
                        <span className="arch-agent__dot" />
                        <b>{name}</b>
                        <span>{role}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="arch-map__target">
                  <span className="arch-map__label">
                    <Icon name="server" size={12} /> Synthetic target
                  </span>
                  <div>
                    {[
                      "config.py",
                      "database.py",
                      "service.py",
                      "telemetry.py",
                      "ground_truth.json",
                    ].map((file) => (
                      <span className="arch-file mono" key={file}>
                        {file}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </section>

            <section id="lifecycle" className="arch-section">
              <span className="arch-kicker">03 / Round lifecycle</span>
              <h2>Six phases. No shortcuts.</h2>
              <ol className="lifecycle">
                {[
                  [
                    "Initialize sandbox",
                    "The orchestrator clones mock_enterprise into simulation_artifacts/workspace. The source template is never mutated.",
                    "orchestrator",
                  ],
                  [
                    "Map & audit",
                    "SurfaceMapperAgent inventories endpoints and guards; StaticVulnerabilityAuditorAgent traverses the AST and emits structured findings.",
                    "analysis",
                  ],
                  [
                    "Detect & triage",
                    "DetectionAgent correlates findings with telemetry spans. TriageAgent de-duplicates, ranks and assigns an SLA target.",
                    "defense",
                  ],
                  [
                    "Isolate & synthesize",
                    "RootCauseAgent extracts the vulnerable AST block. PatchGenerationAgent emits a minimal unified diff with a remediation rationale.",
                    "defense",
                  ],
                  [
                    "Validate & deploy",
                    "ValidationTestingAgent runs functional and security tests in a staging copy. DeploymentRollbackAgent snapshots, deploys and verifies syntax.",
                    "defense",
                  ],
                  [
                    "Verify & score",
                    "ComplianceVerifierAgent re-audits independently. ScoringEngine compares against ground truth, writes memory and seals the round.",
                    "judge",
                  ],
                ].map(([title, copy, tag], index) => (
                  <li key={title}>
                    <span className="lifecycle__num">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <div>
                      <h3>{title}</h3>
                      <p>{copy}</p>
                    </div>
                    <span className="lifecycle__tag">{tag}</span>
                  </li>
                ))}
              </ol>
            </section>

            <section id="evidence" className="arch-section">
              <span className="arch-kicker">04 / Evidence model</span>
              <h2>Typed artefacts, not vibes.</h2>
              <p>
                Every hand-off is a dataclass. The UI mirrors the same contract,
                so a finding can be traced to its alert, incident, patch,
                validation report, deployment receipt and verification result.
              </p>
              <CodeBlock
                filename="agents/models.py"
                code={`@dataclass
class SecurityFinding:
    finding_id: str
    vuln_id: str
    cwe_id: str
    title: str
    severity: str
    cvss_score: float
    file_path: str
    function_name: str
    endpoint: str
    line_number: int
    evidence_snippet: str
    description: str
    remediation_guidance: str
    detected_at_ms: float`}
                maxHeight={300}
              />
              <div className="metric-grid">
                {SCORING.map(([label, formula, value]) => (
                  <div key={label}>
                    <span>{label}</span>
                    <b>{value}</b>
                    <em>{formula}</em>
                  </div>
                ))}
              </div>
            </section>

            <section id="memory" className="arch-section">
              <span className="arch-kicker">05 / State &amp; memory</span>
              <h2>The loop remembers.</h2>
              <p>
                Cross-round state lives in a SQLite database. Round outcomes and
                lessons learned survive process restarts, while JSON and
                Markdown scorecards are written beside the workspace.
              </p>
              <div className="memory-grid">
                {MEMORY_TABLES.map((table) => (
                  <div className="memory-card" key={table.name}>
                    <div className="memory-card__head">
                      <Icon name="database" size={14} />
                      <b>{table.name}</b>
                      <span className="tag">SQLite</span>
                    </div>
                    <p className="mono">{table.columns}</p>
                  </div>
                ))}
                <div className="memory-card">
                  <div className="memory-card__head">
                    <Icon name="file-code" size={14} />
                    <b>simulation_artifacts/</b>
                  </div>
                  <p className="mono">
                    simulation_report.json · SIMULATION_SUMMARY.md ·
                    audit_trail.jsonl · prometheus_metrics.prom ·
                    workspace/backups/
                  </p>
                </div>
              </div>
              <div className="arch-command">
                <CodeBlock
                  language="python"
                  showLineNumbers={false}
                  code={`python3 run_simulation.py --rounds 2 --output-dir ./simulation_artifacts\npython3 -m unittest discover -s tests -v`}
                />
              </div>
            </section>

            <section id="safety" className="arch-section">
              <span className="arch-kicker">06 / Safety model</span>
              <h2>Safe to be autonomous.</h2>
              <p>
                The range is designed for defensive research. There is no live
                exploit generation, no external egress and no unreviewed write
                path into the template source.
              </p>
              <div className="table-wrap safety-table">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Control</th>
                      <th>Enforcement</th>
                      <th>Scope</th>
                    </tr>
                  </thead>
                  <tbody>
                    {CONTROLS.map((control) => (
                      <tr key={control.name}>
                        <td>
                          <span className="strong mono">{control.name}</span>
                        </td>
                        <td>{control.mech}</td>
                        <td className="cell-mono">{control.scope}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="arch-note">
                <Icon name="info" size={15} />
                <div>
                  <b>Non-destructive by design</b>
                  <p>
                    The seeded weaknesses are educational. Analysis agents never
                    construct weaponized payloads; validation uses functional
                    assertions and source invariants inside the sandbox.
                  </p>
                </div>
              </div>
            </section>

            <section id="reality" className="arch-section">
              <span className="arch-kicker">07 / Interface layer</span>
              <h2>How this console connects.</h2>
              <p>
                The Python package remains the reference implementation. This
                web console ships with a deterministic campaign engine that
                mirrors the orchestrator in TypeScript and reads the real
                ground truth, mock-enterprise sources and persisted artifacts.
                That keeps the entire experience explorable without a backend,
                while preserving an honest seam for a live API.
              </p>
              <div className="arch-split">
                <div className="arch-note arch-note--flat">
                  <Icon name="server" size={15} />
                  <div>
                    <b>Source of truth</b>
                    <p>
                      <span className="mono">
                        defensive_cyber_range/
                      </span>{" "}
                      contains the Python orchestrator, agents, safety controls
                      and tests. {state.audit.length} of its ledger entries are
                      loaded live in this interface.
                    </p>
                  </div>
                </div>
                <div className="arch-note arch-note--flat">
                  <Icon name="terminal" size={15} />
                  <div>
                    <b>Runtime seam</b>
                    <p>
                      Replace the store's campaign runner with an API adapter to
                      drive the Python orchestrator. The pages consume the same
                      domain types either way.
                    </p>
                  </div>
                </div>
              </div>
              <div className="docs-cta">
                <div>
                  <span className="eyebrow">Continue</span>
                  <h3>Watch the loop close.</h3>
                </div>
                <Button
                  to="/console/simulation"
                  variant="primary"
                  iconRight="arrow-right"
                  transition
                >
                  Launch a campaign
                </Button>
              </div>
            </section>
          </article>

          <aside className="arch-toc" aria-label="On this page">
            <span className="arch-toc__label">On this page</span>
            {SECTIONS.map(([id, label], index) => (
              <a href={`#${id}`} key={id}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                {label}
              </a>
            ))}
            <div className="arch-toc__status">
              <span className="pill pill--live">
                <span className="dot" /> v1.0 · {state.audit.length} sealed
              </span>
            </div>
          </aside>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
