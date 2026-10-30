# Citadel — Defensive Cyber Range Simulation & Auto-Remediation Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![React 18](https://img.shields.io/badge/react-18.3-61dafb.svg)](https://react.dev/)
[![TypeScript 5](https://img.shields.io/badge/typescript-5.6-3178c6.svg)](https://www.typescriptlang.org/)
[![Vite 5](https://img.shields.io/badge/vite-5.4-646cff.svg)](https://vitejs.dev/)

**Citadel** is an enterprise-grade, closed-loop defensive cybersecurity research and educational platform designed to simulate multi-agent adversarial auditing and automated remediation inside safe, strictly isolated synthetic environments.

The platform provides **two primary operating modes**:

1. **Simulation Mode (Closed-Loop Synthetic Enterprise)**: Multi-agent swarms (Red-style static/architectural analysis swarms and Blue-style detection, patching, and testing swarms) autonomously audit, triage, remediate, validate, and verify seeded weaknesses inside an isolated mock microservice workspace.
2. **Live Folder Mode (Continuous Codebase Auto-Remediation)**: Connects to a real local project repository, executes static AST and configuration analysis across 16 security rules, reports detailed findings with CVSS/CWE mappings, and performs safe, multi-pass automated remediation loops with cryptographic rollback protection.

---

## Architecture Overview

```mermaid
flowchart TB
    subgraph Governance["Safety & Governance Layer"]
        KS["Emergency Kill Switch"]
        NI["Network Isolation Guard"]
        PC["Sandbox Path Confinement"]
        HG["Human Approval Gate"]
        AL["SHA-256 Hash-Chained Audit Ledger"]
    end

    subgraph SimulationMode["Mode 1: Closed-Loop Simulation"]
        direction TB
        ORCH["Simulation Orchestrator & Round Controller"]
        MEM[("Shared Memory SQLite + JSON")]
        JUDGE["Scoring Engine (TTD / TTR / Posture)"]
        
        subgraph AnalysisSwarm["Analysis Swarm (Non-Destructive Red Team)"]
            A1["SurfaceMapperAgent"]
            A2["StaticVulnerabilityAuditorAgent"]
            A3["RiskPrioritizerAgent"]
            A4["ComplianceVerifierAgent"]
            A5["AnalysisReporterAgent"]
        end
        
        subgraph DefenseSwarm["Defensive Swarm (Automated Blue Team)"]
            B1["DetectionAgent"]
            B2["TriageAgent"]
            B3["RootCauseAgent"]
            B4["PatchGenerationAgent"]
            B5["ValidationTestingAgent"]
            B6["DeploymentRollbackAgent"]
        end

        MOCK["Mock Enterprise Sandbox (CWE-89, CWE-862, CWE-79, CWE-489)"]
        
        ORCH --> AnalysisSwarm
        AnalysisSwarm -->|SARIF Findings| ORCH
        ORCH --> DefenseSwarm
        DefenseSwarm -->|Staging Tests & Patches| MOCK
        DefenseSwarm -->|Verify Fixes| AnalysisSwarm
        AnalysisSwarm --> JUDGE
        JUDGE --> MEM
    end

    subgraph LiveMode["Mode 2: Live Folder Auto-Remediation"]
        direction TB
        LSVC["LiveService (Safety-Gated Host Engine)"]
        LSCAN["LiveScanner (AST & Rule Catalog)"]
        LREST["Local Loopback REST Daemon (:8765)"]
        LCLI["CLI Auto-Remediator (run_live_remediation.py)"]
        
        TARGET["Target Local Project Folder"]
        BACKUPS[".cyberrange/backups/ (Timestamped .bak)"]
        
        LCLI --> LSVC
        LREST --> LSVC
        LSVC --> LSCAN
        LSCAN --> TARGET
        LSVC -->|Atomic Write + Verify| TARGET
        LSVC -->|Snapshot on Mutate| BACKUPS
    end

    subgraph Console["Citadel Web Interface (React + Vite)"]
        DASH["Mission Control Dashboard"]
        CRUN["Campaign Runner"]
        LREP["Live Folder Mode UI"]
        FIND["Findings & Incidents Registry"]
        ENTP["Mock Enterprise Code Explorer"]
        SAFE["Safety & Audit Log Explorer"]
    end

    Console -->|REST (:8765)| LREST
    Console -->|In-Browser Virtual Sandbox| LSCAN
    Governance -.->|Wraps All Operations| SimulationMode
    Governance -.->|Wraps All Operations| LiveMode
```

---

## Core Capabilities

### A. Closed-Loop Multi-Agent Simulation
- **Synthetic Enterprise (`defensive_cyber_range/mock_enterprise/`)**: Self-contained web service, SQLite database, and configuration with 4 seeded vulnerability classes:
  - **CWE-89**: SQL injection via raw string interpolation in database queries
  - **CWE-862**: Missing authorization role guard on privileged admin endpoints
  - **CWE-79**: Reflected Cross-Site Scripting via unescaped HTML template rendering
  - **CWE-489 / CWE-209**: Active debug mode, verbose stack trace exposure, and static secret fallback
- **Analysis Swarm (`agents/analysis_swarm.py`)**: 5 specialized agents that map AST surfaces and audit weaknesses without generating weaponized exploits.
- **Defensive Swarm (`agents/defense_swarm.py`)**: 6 automated agents that correlate telemetry, isolate root causes in the AST, synthesize minimal unified diffs, run staging validation tests, and apply patches with automated rollback.
- **Scoring Engine (`orchestrator/scoring.py`)**: Quantitatively grades Time-To-Detect (TTD), Time-To-Remediate (TTR), Patch Correctness Rate, Regression Pass Rate, and Security Posture Score (0–100%).

### B. Live Folder Vulnerability Remediation
- **Universal Rule Catalog**: 16 AST-driven and regex rules covering Python, JavaScript, TypeScript, YAML, and configuration files:
  - SQL Injection (`PY-SQLI-001`, CWE-89)
  - Shell Command Injection (`PY-CMD-001`, `JS-CMD-001`, CWE-78)
  - Dynamic Code Evaluation (`PY-EVAL-001`, `JS-EVAL-001`, CWE-95)
  - Unsafe Deserialization (`PY-DESER-001`, `PY-YAML-001`, CWE-502)
  - TLS Verification Disabled (`PY-TLS-001`, `JS-TLS-001`, CWE-295)
  - Hardcoded Secrets & API Keys (`PY-SECRET-001`, `CFG-SECRET-001`, CWE-798)
  - Active Debug & Stack Dumps (`PY-DEBUG-001`, `CFG-DEBUG-001`, CWE-489)
  - Weak Hashes (`PY-HASH-001`, CWE-327)
  - DOM Cross-Site Scripting (`JS-XSS-001`, CWE-79)
- **Closed-Loop Auto-Remediation**:
  1. Scans all source files below the user-specified directory
  2. Synthesizes deterministic, narrow code patches for auto-fixable findings
  3. Pre-validates syntax and AST structure
  4. Takes a timestamped backup into `.cyberrange/backups/`
  5. Applies atomic file update
  6. Re-scans to verify vulnerability elimination; automatically rolls back if finding persists
  7. Loops through passes until folder is completely clean

---

## Quick Start Guide

### Prerequisites
- Python 3.10+ (standard library only; zero external pip dependencies required for core simulation)
- Node.js 18+ & npm (for web console dashboard)

### 1. Run Closed-Loop Simulation (Mode 1)
```bash
# Clone the repository
git clone https://github.com/mrshahidwarrior39266-boop/defensive_cyber_range_platform.git
cd defensive_cyber_range_platform

# Run the 2-round autonomous simulation
python defensive_cyber_range/run_simulation.py --rounds 2 --output-dir ./simulation_artifacts
```

Expected output:
```text
========================================================================
 DEFENSIVE CYBER RANGE SIMULATION PLATFORM — STARTING CLOSED LOOP
========================================================================
[Round 1] Findings=4 | Alerts=4 | PatchesDeployed=4 | VerifiedFixed=4 | PostureScore=100.0%
[Round 2] Findings=0 | Alerts=0 | PatchesDeployed=0 | VerifiedFixed=0 | PostureScore=100.0%
------------------------------------------------------------------------
Final Security Posture Score : 100.0%
Remediated Vulnerability Set : CWE-489, CWE-79, CWE-862, CWE-89
Immutable Audit Chain Status : VALID (84 entries)
========================================================================
```

### 2. Run Live Folder Mode via CLI (Mode 2)
```bash
# Audit a local project folder (Read-only mode)
python defensive_cyber_range/run_live_remediation.py --folder /path/to/my_project

# Audit and automatically execute the multi-pass auto-remediation loop
python defensive_cyber_range/run_live_remediation.py --folder /path/to/my_project --auto-fix --max-passes 5

# Preview a unified patch diff for a specific finding
python defensive_cyber_range/run_live_remediation.py --folder /path/to/my_project --preview LF-SQLI-8

# List supported detection and remediation rules
python defensive_cyber_range/run_live_remediation.py --list-rules
```

### 3. Launch Local Live Daemon for Web Dashboard
```bash
python -m defensive_cyber_range.live.server --root /path/to/my_project --allow-write --port 8765
```

### 4. Run the Citadel Web Console (Dashboard)
```bash
# Install frontend dependencies
npm install

# Start development server
npm run dev

# Open http://localhost:5173 in your browser
```

---

## Safety & Governance Controls

Every action performed by agents in Citadel is subject to strict deterministic policy controls:

| Control | Mechanism | Guarantee |
| :--- | :--- | :--- |
| **Path Confinement** | `SandboxPathConfinement` | Prevents path escapes (`../`), blocks symlink traversal, limits writes strictly to designated sandbox workspace. |
| **Network Isolation** | `NetworkIsolationGuard` | Blocks socket connections to non-loopback hosts; ensures zero external egress. |
| **Tamper-Evident Ledger**| `ImmutableAuditLogger` | Every agent invocation, parameter, and hash is recorded in a SHA-256 cryptographic chain. |
| **Human Approval Gate** | `HumanApprovalGate` | Enforces optional human review in loop prior to deployment in high-assurance environments. |
| **Emergency Kill Switch**| `KillSwitch` | Single-call instant halt to all active agents, preserving state and audit trails. |
| **Automatic Rollback** | `DeploymentRollbackAgent` | Pre-patch file hash snapshot; automatically reverts file if post-patch verification fails. |

---

## Running Test Suites

Run the complete backend integration and unit tests:
```bash
python -m unittest discover -s defensive_cyber_range/tests -v
```

All 13 unit tests verify:
- End-to-end multi-round autonomous simulation remediation
- Safety controls (path confinement, unauthorized host blocking, prompt injection sanitization)
- Live folder scanning and auto-remediation loop
- Local daemon origin checks, loopback binding, read-only protection, and stale-file rejection

Run frontend typechecking and production build:
```bash
npm run typecheck
npm run build
```

---

## Docker Deployment

To run the simulation platform alongside observability tooling (Prometheus & Loki):

```bash
docker compose up --build
```

---

## Project Structure

```text
defensive_cyber_range_platform/
├── README.md                      # Primary documentation & quickstart
├── ARCHITECTURE.md                # Detailed system architecture specification
├── SAFETY_AND_GOVERNANCE.md       # Security controls & audit chain specification
├── package.json                   # Web console dependencies & scripts
├── vite.config.ts                 # Vite bundler configuration
├── tsconfig.json                  # TypeScript compiler settings
├── src/                           # React 18 / TypeScript Web Console
│   ├── App.tsx                    # Routes & console layout
│   ├── components/
│   │   ├── layout/                # AppShell, Sidebar, Topbar
│   │   ├── ui/                    # Primitives, Viz, CodeViewer, DiffViewer, Overlays
│   │   └── landing/               # Public site navigation & hero components
│   ├── pages/
│   │   ├── Landing.tsx            # Interactive landing page
│   │   ├── Architecture.tsx       # System architecture documentation page
│   │   └── console/               # Mission Control, Simulation, LiveFolder, Findings, etc.
│   └── lib/                       # Simulation state store, engine, SHA-256, utilities
└── defensive_cyber_range/         # Python Backend & Multi-Agent Swarms
    ├── run_simulation.py          # CLI entrypoint for closed-loop simulation (Mode 1)
    ├── run_live_remediation.py    # CLI entrypoint for live folder remediation (Mode 2)
    ├── agents/                    # Analysis & Defensive Swarms
    │   ├── analysis_swarm.py      # 5 Red-style non-destructive audit agents
    │   ├── defense_swarm.py       # 6 Blue-style detection, patching & testing agents
    │   └── models.py              # Shared dataclasses & typed schemas
    ├── mock_enterprise/          # Seeded synthetic microservice (CWE-89, 862, 79, 489)
    ├── orchestrator/              # Multi-round engine, SQLite memory, scoring judge
    ├── live/                      # Mode 2 scanner, safe service & loopback REST daemon
    ├── safety/                    # KillSwitch, network guard, audit logger, sanitizer
    └── tests/                     # Unit & integration test suites
```

---

## Research & Educational Intent

Citadel is built exclusively for **defensive security engineering, educational training, and automated remediation research**. Analysis swarms strictly evaluate AST patterns and source code structures to guide safe patching, with zero functional exploit weaponization or offensive payload delivery.
