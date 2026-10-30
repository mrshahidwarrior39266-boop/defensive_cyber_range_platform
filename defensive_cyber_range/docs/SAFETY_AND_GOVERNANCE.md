# Safety, Isolation & Governance Controls

The Defensive Cyber Range Simulation Platform enforces defense-in-depth safety controls (`safety/controls.py`) across every stage of execution.

## 1. Non-Weaponization Guarantee

- **Static & Structural Analysis Only**: Analysis agents inspect source code ASTs, route metadata, and configuration structures. They **never** generate live exploit payloads, shellcode, or destructive network traffic.
- **Sandboxed Execution**: All file inspections, patches, and regression tests run strictly inside a disposable sandbox copy (`simulation_artifacts/workspace/`).

## 2. Six Core Safety Controls

| Control | Implementation Class | Enforcement Mechanism |
| :--- | :--- | :--- |
| **1. Network Isolation** | `NetworkIsolationGuard` | Validates that target hosts belong strictly to the allowlisted local loopback/container names (`localhost`, `127.0.0.1`, `mock-enterprise`) and blocks outbound socket connections when isolation mode is active. |
| **2. Tool & Path Allowlists** | `ToolAllowlistGuard` | Verifies every agent tool invocation against an explicit role-based allowlist and enforces `Path.resolve().is_relative_to(sandbox_root)` to prevent directory traversal (`../`) outside the workspace. |
| **3. Human Approval Gates** | `HumanApprovalGate` | Evaluates every candidate patch before deployment. Supports `auto_low_risk` (auto-approves patches that pass 100% of staging tests and touch only allowlisted application files), `callback` (custom policy hook), and `strict_manual` modes. |
| **4. Emergency Kill Switch** | `KillSwitch` | Monitors an in-memory atomic flag, environment signal (`SIGINT`/`SIGTERM`), and kill-file sentinel (`KILL_SWITCH.lock`). Immediately halts all agent loops and triggers safe rollback if tripped. |
| **5. Immutable Hash-Chained Audit Log** | `ImmutableAuditLogger` | Records every agent action in an append-only JSONL ledger (`audit_trail.jsonl`) where each record includes `prev_hash` and `entry_hash = SHA256(prev_hash + canonical_json)`. Includes `verify_chain()` to detect any tampering. |
| **6. Prompt-Injection Defense** | `PromptSanitizer` | Scans source code comments, log entries, and external strings for adversarial instruction overrides (e.g., `"Ignore previous instructions"`, `"SYSTEM OVERRIDE"`, role-spoofing markers) and neutralizes them before context reaches any LLM prompt. |
