# Defensive Cyber Range Simulation Platform

An isolated, closed-loop multi-agent security auditing, detection, automated patching, and verification simulation platform designed for defensive cybersecurity research and engineering education.

## Key Capabilities

- **Isolated Synthetic Enterprise (`mock_enterprise/`)**: A self-contained corporate microservice and SQLite data layer containing 4 seeded, educational code weaknesses (CWE-89 SQL string interpolation, CWE-862 missing role authorization guard, CWE-79 unescaped HTML rendering, and CWE-489/CWE-209 insecure debug & secret exposure configuration) alongside a ground-truth manifest and OpenTelemetry/Prometheus-compatible structured telemetry.
- **Security Analysis Swarm (`agents/analysis_swarm.py`)**: Non-destructive static AST and configuration analysis agents (`SurfaceMapperAgent`, `StaticVulnerabilityAuditorAgent`, `RiskPrioritizerAgent`, `ComplianceVerifierAgent`, `AnalysisReporterAgent`) that inspect source code and configurations to produce structured SARIF-like security findings without generating or executing live exploit payloads.
- **Defensive Response Swarm (`agents/defense_swarm.py`)**: Automated Blue Team agents (`DetectionAgent`, `TriageAgent`, `RootCauseAgent`, `PatchGenerationAgent`, `ValidationTestingAgent`, `DeploymentRollbackAgent`) that ingest telemetry and findings, isolate root causes in the AST, synthesize minimal code fixes, run functional and security regression tests in a staging workspace, and atomically deploy patches with automatic rollback on failure.
- **Closed-Loop Orchestrator & Scoring Engine (`orchestrator/`)**: Coordinates multi-round simulations, tracks shared cross-round memory in SQLite, and computes quantitative metrics (`Time-to-Detect`, `Time-to-Remediate`, `Patch Correctness Rate`, `Regression Pass Rate`, and `Posture Score`).
- **Safety & Governance Controls (`safety/controls.py`)**: Enforces sandbox path confinement, network isolation checks, tool allowlists, prompt-injection sanitization, human approval gates, an emergency kill switch, and a SHA-256 hash-chained immutable audit log.

## Project Layout

```text
defensive_cyber_range/
├── README.md
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── run_simulation.py              # CLI entrypoint for full closed-loop simulation
├── docs/
│   ├── ARCHITECTURE.md            # System architecture, Mermaid diagrams, memory & state model
│   └── SAFETY_AND_GOVERNANCE.md   # Isolation boundaries, human gates, audit chain verification
├── infra/
│   ├── prometheus.yml             # Prometheus scrape configuration
│   ├── loki-config.yaml           # Loki log aggregation configuration
│   └── k8s-deployment.yaml        # Optional Kubernetes isolated namespace & network policy manifest
├── mock_enterprise/
│   ├── __init__.py
│   ├── config.py                  # Seeded configuration file (CWE-489 / CWE-209)
│   ├── database.py                # SQLite database bootstrap & seeded query service (CWE-89)
│   ├── service.py                 # Web/API request handlers (CWE-862, CWE-79)
│   ├── telemetry.py               # Structured JSON logs, metrics counter, and trace spans
│   └── ground_truth.json          # Ground-truth catalog of seeded weaknesses for scoring
├── agents/
│   ├── __init__.py
│   ├── models.py                  # Shared dataclasses for findings, alerts, patches, and state
│   ├── llm_adapter.py             # Optional LLM / LangGraph bridge with deterministic offline fallback
│   ├── analysis_swarm.py          # 5 security analysis & compliance verification agents
│   └── defense_swarm.py           # 6 detection, triage, patching, testing & rollback agents
├── orchestrator/
│   ├── __init__.py
│   ├── engine.py                  # Closed-loop round controller & LangGraph-compatible workflow
│   ├── memory.py                  # SQLite + JSON shared memory store for lessons learned
│   └── scoring.py                 # Judge & quantitative scoring engine
├── safety/
│   ├── __init__.py
│   └── controls.py                # KillSwitch, NetworkIsolationGuard, ImmutableAuditLogger, etc.
└── tests/
    └── test_platform.py           # End-to-end unit & integration test suite
```

## Quick Start (Local Python — Zero External Dependencies Required)

1. **Extract the ZIP archive** on your laptop:
   ```bash
   unzip defensive_cyber_range_platform.zip
   cd defensive_cyber_range
   ```

2. **Run the full closed-loop simulation**:
   ```bash
   python3 run_simulation.py --rounds 2 --output-dir ./simulation_artifacts
   ```
   This initializes an isolated sandbox copy of `mock_enterprise/`, runs Round 1 (discovers all 4 seeded weaknesses, triages alerts, generates code patches, validates functional + security unit tests, deploys patches, and verifies fixes) followed by Round 2 (confirms 0 remaining vulnerabilities and 100/100 posture score), and writes the audit log, memory DB, and Markdown/JSON scorecards to `./simulation_artifacts/`.

3. **Run the automated verification & test suite**:
   ```bash
   python3 -m unittest discover -s tests -v
   ```

## Running with Docker Compose

To run the simulation inside isolated containers alongside the observability config:

```bash
docker compose up --build
```

## Safety Notice

This platform is strictly designed for **defensive security engineering, static code auditing, and automated patch validation** inside a self-contained synthetic workspace. The `SafetyController` enforces strict path confinement (`workspace/`), blocks external network calls, and maintains a tamper-evident SHA-256 hash-chained audit trail of every agent action.
