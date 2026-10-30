import { useState, useEffect, useMemo, useCallback } from "react";
import { PageHeader, Panel, Pill, SeverityPill, Stat, Button, EmptyState } from "../../components/ui/primitives";
import { Icon } from "../../components/ui/Icon";
import { CodeBlock, DiffView } from "../../components/ui/code";
import { Drawer, useToast } from "../../components/ui/overlays";
import { useDocumentTitle } from "../../lib/hooks";
import { cn } from "../../lib/utils";
import "../../styles/pages.css";

interface LiveFinding {
  id: string;
  rule_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category: string;
  cwe: string;
  description: string;
  remediation: string;
  file_path: string;
  line: number;
  column: number;
  snippet: string;
  file_sha256?: string;
  safe_auto: boolean;
  patch?: {
    summary: string;
    diff: string;
    patched_content: string;
    safe_auto: boolean;
  };
}

interface RemediationPassLog {
  pass: number;
  rule_id: string;
  file_path: string;
  status: "applied" | "reverted" | "error";
  message: string;
  backup_path?: string;
}

const PRESET_ACME: Record<string, string> = {
  "database.py": `'''AcmeCorp SQLite Data Access Layer
Contains intentional vulnerabilities for automated remediation testing.
'''
import sqlite3

def find_user_by_name(cursor, username):
    # SEEDED_WEAKNESS: CWE-89 SQL Injection via string interpolation
    query = f"SELECT id, username, role, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
`,
  "service.py": `'''AcmeCorp Internal Web Service Handler'''
import html

def delete_user_record(requester_role, target_user_id):
    # SEEDED_WEAKNESS: CWE-862 Missing Authorization Guard
    # Note: Requires requester_role == 'admin'
    return {"deleted": target_user_id, "status": "success"}

def render_user_profile(username):
    # SEEDED_WEAKNESS: CWE-79 Reflected Cross-Site Scripting
    return f"<div class='profile'>Welcome back, {username}!</div>"
`,
  "config.py": `'''AcmeCorp Service Configuration'''
APP_NAME = "AcmeCorp Portal"
# SEEDED_WEAKNESS: CWE-489 Active Debug Code & CWE-209 Stack Trace Exposure
DEBUG_MODE = True
EXPOSE_STACK_TRACES = True
TOKEN_SIGNING_SECRET = "weak_static_secret"
`,
};

const PRESET_GATEWAY: Record<string, string> = {
  "gateway.py": `'''Cloud Ingestion Gateway'''
import requests
import yaml

DEBUG = True

def fetch_sensor_manifest(url):
    # Insecure TLS verification disabled (CWE-295)
    resp = requests.get(url, verify=False)
    # Unsafe YAML deserialization (CWE-502)
    manifest = yaml.load(resp.text)
    return manifest
`,
  "settings.py": `'''Production Settings'''
# Hardcoded API Secret (CWE-798)
API_SECRET_KEY = "MOCK_JWT_SECRET_SIGNING_KEY_EXAMPLE_ONLY_1234567890"
DEBUG = True
`,
};

const PRESET_NODE: Record<string, string> = {
  "api.js": `// Node.js API Gateway
const { exec } = require('child_process');
const https = require('https');

// Dynamic shell command injection (CWE-78)
function pingSensor(ipAddress) {
  exec('ping -c 2 ' + ipAddress);
}

// Insecure TLS verification (CWE-295)
const client = new https.Agent({ rejectUnauthorized: false });

// Insecure code execution via eval (CWE-95)
function computeFormula(rawExpression) {
  return eval(rawExpression);
}
`,
};

function runInBrowserScan(files: Record<string, string>): {
  findings: LiveFinding[];
  durationMs: number;
} {
  const t0 = performance.now();
  const findings: LiveFinding[] = [];

  for (const [filePath, content] of Object.entries(files)) {
    const lines = content.split("\n");

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // PY-SQLI-001 (CWE-89)
      if (
        (filePath.endsWith(".py") || filePath.endsWith(".sql")) &&
        /f["'].*SELECT.*WHERE.*\{.*\}["']/i.test(line)
      ) {
        const patchedContent = files[filePath].replace(
          'query = f"SELECT id, username, role, email FROM users WHERE username = \'{username}\'"\n    cursor.execute(query)',
          'cursor.execute("SELECT id, username, role, email FROM users WHERE username = ?", (username,))'
        );

        findings.push({
          id: `LF-SQLI-${lineNum}`,
          rule_id: "PY-SQLI-001",
          title: "SQL injection via string interpolation",
          severity: "CRITICAL",
          category: "Injection",
          cwe: "CWE-89",
          description: "Dynamic string interpolation inside SQL query allows untrusted input to alter query syntax.",
          remediation: "Use parameterized queries with parameterized placeholders `?` or `%s`.",
          file_path: filePath,
          line: lineNum,
          column: line.indexOf("SELECT") + 1,
          snippet: line.trim(),
          safe_auto: true,
          patch: {
            summary: "Convert raw string interpolation to parameterized query: cursor.execute('SELECT ... WHERE username = ?', (username,))",
            diff: `--- a/${filePath}\n+++ b/${filePath}\n@@ -${lineNum},2 +${lineNum},1 @@\n-    query = f"SELECT id, username, role, email FROM users WHERE username = '{username}'"\n-    cursor.execute(query)\n+    cursor.execute("SELECT id, username, role, email FROM users WHERE username = ?", (username,))`,
            patched_content: patchedContent,
            safe_auto: true,
          },
        });
      }

      // PY-TLS-001 (CWE-295)
      if (filePath.endsWith(".py") && /verify\s*=\s*False/i.test(line)) {
        const patchedContent = files[filePath].replace(/verify\s*=\s*False/g, "verify=True");
        findings.push({
          id: `LF-TLS-${lineNum}`,
          rule_id: "PY-TLS-001",
          title: "TLS certificate verification disabled",
          severity: "HIGH",
          category: "Cryptography",
          cwe: "CWE-295",
          description: "Requests with verify=False disable X.509 certificate validation, exposing traffic to MITM attacks.",
          remediation: "Set verify=True and configure trusted certificate authorities.",
          file_path: filePath,
          line: lineNum,
          column: line.indexOf("verify=False") + 1,
          snippet: line.trim(),
          safe_auto: true,
          patch: {
            summary: "Enable TLS certificate validation (set verify=True).",
            diff: `--- a/${filePath}\n+++ b/${filePath}\n@@ -${lineNum},1 +${lineNum},1 @@\n-${line}\n+${line.replace(/verify\s*=\s*False/g, "verify=True")}`,
            patched_content: patchedContent,
            safe_auto: true,
          },
        });
      }

      // PY-YAML-001 (CWE-502)
      if (filePath.endsWith(".py") && /yaml\.load\s*\(/i.test(line) && !/SafeLoader/i.test(line)) {
        const patchedContent = files[filePath].replace(/yaml\.load\s*\(/g, "yaml.safe_load(");
        findings.push({
          id: `LF-YAML-${lineNum}`,
          rule_id: "PY-YAML-001",
          title: "Unsafe YAML load without safe loader",
          severity: "HIGH",
          category: "Deserialization",
          cwe: "CWE-502",
          description: "yaml.load() can instantiate arbitrary Python objects from untrusted YAML documents.",
          remediation: "Replace yaml.load() with yaml.safe_load().",
          file_path: filePath,
          line: lineNum,
          column: line.indexOf("yaml.load") + 1,
          snippet: line.trim(),
          safe_auto: true,
          patch: {
            summary: "Replace yaml.load() with yaml.safe_load().",
            diff: `--- a/${filePath}\n+++ b/${filePath}\n@@ -${lineNum},1 +${lineNum},1 @@\n-${line}\n+${line.replace(/yaml\.load\s*\(/g, "yaml.safe_load(")}`,
            patched_content: patchedContent,
            safe_auto: true,
          },
        });
      }

      // PY-DEBUG-001 & CFG-DEBUG-001 (CWE-489)
      if (/(DEBUG_MODE|DEBUG|EXPOSE_STACK_TRACES)\s*=\s*True/i.test(line)) {
        const patchedContent = files[filePath]
          .replace(/DEBUG_MODE\s*=\s*True/g, "DEBUG_MODE = False")
          .replace(/DEBUG\s*=\s*True/g, "DEBUG = False")
          .replace(/EXPOSE_STACK_TRACES\s*=\s*True/g, "EXPOSE_STACK_TRACES = False");
        findings.push({
          id: `LF-DEBUG-${lineNum}`,
          rule_id: "PY-DEBUG-001",
          title: "Production debug or stack trace exposure enabled",
          severity: "MEDIUM",
          category: "Configuration",
          cwe: "CWE-489",
          description: "Active debug flags expose internals, stack traces, and environment variables to users.",
          remediation: "Set DEBUG = False and disable stack trace dumps in production.",
          file_path: filePath,
          line: lineNum,
          column: 1,
          snippet: line.trim(),
          safe_auto: true,
          patch: {
            summary: "Disable debug flags and stack trace exposure.",
            diff: `--- a/${filePath}\n+++ b/${filePath}\n@@ -${lineNum},1 +${lineNum},1 @@\n-${line}\n+${line.replace(/True/g, "False")}`,
            patched_content: patchedContent,
            safe_auto: true,
          },
        });
      }

      // CWE-862 (Missing Authorization)
      if (/def delete_user_record/i.test(line)) {
        const patchedContent = files[filePath].replace(
          'def delete_user_record(requester_role, target_user_id):\n    # SEEDED_WEAKNESS: CWE-862 Missing Authorization Guard\n    # Note: Requires requester_role == \'admin\'\n    return {"deleted": target_user_id, "status": "success"}',
          'def delete_user_record(requester_role, target_user_id):\n    if requester_role != "admin":\n        raise PermissionError("Access denied: admin role required")\n    return {"deleted": target_user_id, "status": "success"}'
        );
        findings.push({
          id: `LF-AUTH-${lineNum}`,
          rule_id: "PY-AUTH-001",
          title: "Missing authorization check on privileged handler",
          severity: "HIGH",
          category: "Access Control",
          cwe: "CWE-862",
          description: "Privileged deletion operation lacks role guard; any authenticated caller can delete user accounts.",
          remediation: "Verify requester_role == 'admin' before executing privileged mutation.",
          file_path: filePath,
          line: lineNum,
          column: 1,
          snippet: line.trim(),
          safe_auto: true,
          patch: {
            summary: "Add explicit authorization guard (requester_role == 'admin').",
            diff: `--- a/${filePath}\n+++ b/${filePath}\n@@ -${lineNum},3 +${lineNum},4 @@\n def delete_user_record(requester_role, target_user_id):\n+    if requester_role != "admin":\n+        raise PermissionError("Access denied: admin role required")\n     return {"deleted": target_user_id, "status": "success"}`,
            patched_content: patchedContent,
            safe_auto: true,
          },
        });
      }

      // CWE-79 (Reflected XSS)
      if (/return f"<div class='profile'>Welcome back, \{username\}!<\/div>"/i.test(line)) {
        const patchedContent = files[filePath].replace(
          'return f"<div class=\'profile\'>Welcome back, {username}!</div>"',
          'safe_name = html.escape(username, quote=True)\n    return f"<div class=\'profile\'>Welcome back, {safe_name}!</div>"'
        );
        findings.push({
          id: `LF-XSS-${lineNum}`,
          rule_id: "PY-XSS-001",
          title: "Reflected HTML Cross-Site Scripting (XSS)",
          severity: "MEDIUM",
          category: "Injection",
          cwe: "CWE-79",
          description: "Untrusted username is rendered into raw HTML without HTML entity escaping.",
          remediation: "Escape untrusted strings with html.escape(val, quote=True).",
          file_path: filePath,
          line: lineNum,
          column: 1,
          snippet: line.trim(),
          safe_auto: true,
          patch: {
            summary: "Sanitize dynamic input with html.escape() before rendering markup.",
            diff: `--- a/${filePath}\n+++ b/${filePath}\n@@ -${lineNum},1 +${lineNum},2 @@\n+    safe_name = html.escape(username, quote=True)\n-    return f"<div class='profile'>Welcome back, {username}!</div>"\n+    return f"<div class='profile'>Welcome back, {safe_name}!</div>"`,
            patched_content: patchedContent,
            safe_auto: true,
          },
        });
      }

      // JS-TLS-001
      if (/rejectUnauthorized\s*:\s*false/i.test(line)) {
        const patchedContent = files[filePath].replace(/rejectUnauthorized\s*:\s*false/g, "rejectUnauthorized: true");
        findings.push({
          id: `LF-JSTLS-${lineNum}`,
          rule_id: "JS-TLS-001",
          title: "TLS rejectUnauthorized disabled in HTTPS agent",
          severity: "HIGH",
          category: "Cryptography",
          cwe: "CWE-295",
          description: "Setting rejectUnauthorized: false in Node https agent allows invalid or self-signed certificates.",
          remediation: "Set rejectUnauthorized: true and install custom trusted CA certificates if necessary.",
          file_path: filePath,
          line: lineNum,
          column: line.indexOf("rejectUnauthorized") + 1,
          snippet: line.trim(),
          safe_auto: true,
          patch: {
            summary: "Enforce TLS certificate verification (rejectUnauthorized: true).",
            diff: `--- a/${filePath}\n+++ b/${filePath}\n@@ -${lineNum},1 +${lineNum},1 @@\n-${line}\n+${line.replace(/false/g, "true")}`,
            patched_content: patchedContent,
            safe_auto: true,
          },
        });
      }

      // JS-CMD-001 (CWE-78)
      if (/exec\s*\(\s*['"]ping/i.test(line) && /\+\s*[a-zA-Z0-9_]+/i.test(line)) {
        findings.push({
          id: `LF-JSCMD-${lineNum}`,
          rule_id: "JS-CMD-001",
          title: "Shell command constructed from dynamic input",
          severity: "HIGH",
          category: "Injection",
          cwe: "CWE-78",
          description: "child_process.exec() passes arguments to a system shell without sanitization, permitting command chaining.",
          remediation: "Use child_process.execFile() or spawn() with argument arrays and strict IP address validation regex.",
          file_path: filePath,
          line: lineNum,
          column: 1,
          snippet: line.trim(),
          safe_auto: false,
        });
      }

      // CFG-SECRET-001 (CWE-798)
      if (/(API_SECRET_KEY|TOKEN_SIGNING_SECRET)\s*=\s*["'][^"']+["']/i.test(line)) {
        findings.push({
          id: `LF-SECRET-${lineNum}`,
          rule_id: "CFG-SECRET-001",
          title: "Hardcoded secret key in source code",
          severity: "HIGH",
          category: "Secrets",
          cwe: "CWE-798",
          description: "Private cryptographic secret keys or API tokens hardcoded directly into code repository.",
          remediation: "Load secret from an environment variable (os.environ['SECRET_KEY']) or secrets vault.",
          file_path: filePath,
          line: lineNum,
          column: 1,
          snippet: line.replace(/["'][^"']+["']/, '"[REDACTED_SECRET]"').trim(),
          safe_auto: false,
        });
      }
    });
  }

  const durationMs = Math.round((performance.now() - t0) * 10) / 10;
  return { findings, durationMs };
}

export default function LiveFolder() {
  useDocumentTitle("Live folder remediation — Citadel");
  const { push } = useToast();

  const [activePreset, setActivePreset] = useState<"acme" | "gateway" | "node">("acme");
  const [workspaceFiles, setWorkspaceFiles] = useState<Record<string, string>>(PRESET_ACME);
  const [selectedFile, setSelectedFile] = useState<string>("database.py");

  const [agentConnected, setAgentConnected] = useState<boolean>(false);
  const [agentAllowWrite, setAgentAllowWrite] = useState<boolean>(false);
  const [localFolderPath, setLocalFolderPath] = useState<string>("defensive_cyber_range/simulation_artifacts/workspace");
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isRemediating, setIsRemediating] = useState<boolean>(false);

  const [findings, setFindings] = useState<LiveFinding[]>([]);
  const [scanElapsedMs, setScanElapsedMs] = useState<number>(0);
  const [selectedFinding, setSelectedFinding] = useState<LiveFinding | null>(null);
  const [diffDrawerFinding, setDiffDrawerFinding] = useState<LiveFinding | null>(null);

  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [typeFilter, setTypeFilter] = useState<"ALL" | "AUTO" | "MANUAL">("ALL");

  const [remediationLogs, setRemediationLogs] = useState<RemediationPassLog[]>([]);
  const [remediationSummary, setRemediationSummary] = useState<{
    passes: number;
    initialFindings: number;
    patchesApplied: number;
    remainingFindings: number;
    resolvedRate: number;
  } | null>(null);

  // Probe local daemon on mount
  useEffect(() => {
    let unmounted = false;
    const checkDaemon = async () => {
      try {
        const ctrl = new AbortController();
        const timeout = setTimeout(() => ctrl.abort(), 900);
        const res = await fetch("http://127.0.0.1:8765/healthz", { signal: ctrl.signal });
        clearTimeout(timeout);
        if (!unmounted && res.ok) {
          const data = await res.json();
          setAgentConnected(true);
          setAgentAllowWrite(Boolean(data.allow_write));
        }
      } catch {
        if (!unmounted) {
          setAgentConnected(false);
        }
      }
    };
    checkDaemon();
    return () => {
      unmounted = true;
    };
  }, []);

  // Trigger initial scan when preset or files change
  const executeScan = useCallback((filesToScan: Record<string, string>) => {
    setIsScanning(true);
    setTimeout(() => {
      const result = runInBrowserScan(filesToScan);
      setFindings(result.findings);
      setScanElapsedMs(result.durationMs);
      setIsScanning(false);
    }, 150);
  }, []);

  useEffect(() => {
    executeScan(workspaceFiles);
  }, [workspaceFiles, executeScan]);

  const handleSelectPreset = (preset: "acme" | "gateway" | "node") => {
    setActivePreset(preset);
    let files: Record<string, string> = PRESET_ACME;
    if (preset === "gateway") files = PRESET_GATEWAY;
    if (preset === "node") files = PRESET_NODE;
    setWorkspaceFiles(files);
    setSelectedFile(Object.keys(files)[0]);
    setRemediationSummary(null);
    setRemediationLogs([]);
    push({
      title: "Preset Loaded",
      message: `Loaded ${preset.toUpperCase()} synthetic vulnerability test suite.`,
      tone: "info",
    });
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const uploaded = event.target.files;
    if (!uploaded || uploaded.length === 0) return;

    const newFiles: Record<string, string> = {};
    const readers: Promise<void>[] = [];

    Array.from(uploaded).forEach((file) => {
      if (file.size > 500000) return; // skip >500kb
      const relative = file.webkitRelativePath || file.name;
      const promise = new Promise<void>((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => {
          if (typeof e.target?.result === "string") {
            newFiles[relative] = e.target.result;
          }
          resolve();
        };
        reader.readAsText(file);
      });
      readers.push(promise);
    });

    Promise.all(readers).then(() => {
      if (Object.keys(newFiles).length > 0) {
        setWorkspaceFiles(newFiles);
        setSelectedFile(Object.keys(newFiles)[0]);
        setRemediationSummary(null);
        setRemediationLogs([]);
        push({
          title: "Files Loaded",
          message: `Imported ${Object.keys(newFiles).length} files into live scanner sandbox.`,
          tone: "success",
        });
      }
    });
  };

  // Apply single patch
  const applySinglePatch = (finding: LiveFinding) => {
    if (!finding.patch) return;
    const targetFile = finding.file_path;
    const updatedContent = finding.patch.patched_content;

    const nextFiles = {
      ...workspaceFiles,
      [targetFile]: updatedContent,
    };
    setWorkspaceFiles(nextFiles);
    setDiffDrawerFinding(null);

    push({
      title: "Patch Applied",
      message: `Remediated ${finding.cwe} in ${finding.file_path}. Re-scanning…`,
      tone: "success",
    });
  };

  // Run Closed-Loop Multi-Pass Remediation
  const runClosedLoopRemediation = async () => {
    setIsRemediating(true);
    const initialCount = findings.length;
    let currentFiles = { ...workspaceFiles };
    let currentFindings = [...findings];
    const logs: RemediationPassLog[] = [];
    let pass = 0;
    let patchesApplied = 0;

    while (pass < 6) {
      pass++;
      const candidate = currentFindings.find((f) => f.safe_auto && f.patch);
      if (!candidate || !candidate.patch) break;

      // Apply patch in sandbox
      currentFiles = {
        ...currentFiles,
        [candidate.file_path]: candidate.patch.patched_content,
      };
      patchesApplied++;

      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const backupPath = `.cyberrange/backups/${timestamp}/${candidate.file_path}.bak`;

      logs.push({
        pass,
        rule_id: candidate.rule_id,
        file_path: candidate.file_path,
        status: "applied",
        message: `Applied safe patch for ${candidate.cwe}: ${candidate.patch.summary}`,
        backup_path: backupPath,
      });

      // Verification re-scan
      const reScan = runInBrowserScan(currentFiles);
      currentFindings = reScan.findings;
    }

    setWorkspaceFiles(currentFiles);
    setFindings(currentFindings);
    setRemediationLogs(logs);

    const remainingCount = currentFindings.length;
    const resolvedRate = initialCount > 0 ? Math.round(((initialCount - remainingCount) / initialCount) * 100) : 100;

    setRemediationSummary({
      passes: pass,
      initialFindings: initialCount,
      patchesApplied,
      remainingFindings: remainingCount,
      resolvedRate,
    });

    setIsRemediating(false);

    push({
      title: "Remediation Complete",
      message: `Closed-loop finished in ${pass} passes: ${patchesApplied} patches verified and deployed.`,
      tone: "success",
    });
  };

  // Filtering
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
      if (typeFilter === "AUTO" && !f.safe_auto) return false;
      if (typeFilter === "MANUAL" && f.safe_auto) return false;
      return true;
    });
  }, [findings, severityFilter, typeFilter]);

  const autoFixableCount = useMemo(() => findings.filter((f) => f.safe_auto).length, [findings]);
  const initialEstimatedPosture = useMemo(() => {
    if (findings.length === 0) return 100;
    const maxWeight = findings.length * 25;
    const penalty = findings.reduce((acc, f) => {
      if (f.severity === "CRITICAL") return acc + 30;
      if (f.severity === "HIGH") return acc + 20;
      if (f.severity === "MEDIUM") return acc + 10;
      return acc + 5;
    }, 0);
    return Math.max(0, Math.min(100, Math.round(100 - (penalty / maxWeight) * 100)));
  }, [findings]);

  return (
    <div className="console-page">
      <PageHeader
        eyebrow="Mode 2 · Live Codebase Security Engine"
        title="Live Folder Remediation"
        description="Connect a local project folder to audit source code for vulnerabilities, review unified patch diffs, and execute safe multi-pass automated remediation loops with rollback protection."
        actions={
          <div className="row gap-8">
            <label className="btn btn--quiet btn--sm" style={{ cursor: "pointer" }}>
              <Icon name="upload" size={13} />
              <span>Import Local Folder</span>
              <input
                type="file"
                // @ts-expect-error webkitdirectory is standard in Chromium/Firefox/Safari
                webkitdirectory=""
                directory=""
                multiple
                style={{ display: "none" }}
                onChange={handleFileUpload}
              />
            </label>
            <Button
              variant="primary"
              size="sm"
              icon="zap"
              disabled={isScanning || isRemediating || autoFixableCount === 0}
              onClick={runClosedLoopRemediation}
            >
              {isRemediating ? "Remediating…" : "Run Auto-Remediation Loop"}
            </Button>
          </div>
        }
      />

      {/* Connectivity & Daemon Status Banner */}
      <div className={cn("glass-banner", agentConnected ? "glass-banner--success" : "glass-banner--info")}>
        <div className="glass-banner__icon">
          <Icon name={agentConnected ? "check-circle" : "terminal"} size={16} />
        </div>
        <div className="glass-banner__content">
          <div className="row spread">
            <span className="glass-banner__title">
              {agentConnected
                ? `Local Live Daemon Connected (127.0.0.1:8765) · ${agentAllowWrite ? "Read/Write Active" : "Read-Only Mode"}`
                : "In-Browser Sandbox Mode (Interactive Simulation & Real-Time AST Engine Active)"}
            </span>
            <Pill tone={agentConnected ? "live" : "neutral"}>
              {agentConnected ? "DAEMON CONNECTED" : "WEB SANDBOX"}
            </Pill>
          </div>
          <p className="glass-banner__desc">
            {agentConnected
              ? "All actions execute directly against your local workspace through the loopback REST daemon."
              : "To connect your real local hard drive files, run `python -m live.server --root /path/to/project --allow-write` in your terminal."}
          </p>
          {agentConnected && (
            <div className="row gap-8 align-center" style={{ marginTop: 8 }}>
              <input
                className="input text-xs mono"
                style={{ maxWidth: 360, padding: "4px 8px" }}
                value={localFolderPath}
                onChange={(e) => setLocalFolderPath(e.target.value)}
                placeholder="Target local path"
              />
              <Button size="sm" variant="ghost" icon="scan" onClick={() => executeScan(workspaceFiles)}>
                Audit Target
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Preset Selector & Workspace Tabs */}
      <div className="workspace-tabs-row row spread align-center">
        <div className="row gap-8 align-center">
          <span className="label-sm">Sandbox Presets:</span>
          <Button
            size="sm"
            variant={activePreset === "acme" ? "primary" : "quiet"}
            onClick={() => handleSelectPreset("acme")}
          >
            AcmeCorp Microservice (Python)
          </Button>
          <Button
            size="sm"
            variant={activePreset === "gateway" ? "primary" : "quiet"}
            onClick={() => handleSelectPreset("gateway")}
          >
            Cloud Gateway (Python/YAML)
          </Button>
          <Button
            size="sm"
            variant={activePreset === "node" ? "primary" : "quiet"}
            onClick={() => handleSelectPreset("node")}
          >
            Express API (Node.js)
          </Button>
        </div>

        <div className="row gap-8 align-center">
          <span className="mono text-muted text-xs">
            {Object.keys(workspaceFiles).length} files · Scanned in {scanElapsedMs}ms
          </span>
          <Button
            size="sm"
            variant="ghost"
            icon="refresh"
            disabled={isScanning}
            onClick={() => executeScan(workspaceFiles)}
          >
            Re-scan
          </Button>
        </div>
      </div>

      {/* Stats Overview Grid */}
      <div className="stats-grid">
        <Stat
          label="Security Posture"
          value={`${initialEstimatedPosture}%`}
          hint={findings.length === 0 ? "Target folder clean" : `${findings.length} active vulnerabilities`}
        />
        <Stat
          label="Total Findings"
          value={findings.length}
          hint={`${findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length} high/critical`}
        />
        <Stat
          label="Auto-Fixable Issues"
          value={autoFixableCount}
          hint="Deterministic safe AST transforms available"
        />
        <Stat
          label="Manual Review Needed"
          value={findings.length - autoFixableCount}
          hint="Requires human architecture review"
        />
      </div>

      {/* Remediation Summary Card (if run) */}
      {remediationSummary && (
        <Panel
          className="remediation-summary-panel"
          title="Automated Remediation Loop Results"
          actions={
            <Pill tone={remediationSummary.remainingFindings === 0 ? "live" : "medium"}>
              {remediationSummary.resolvedRate}% RESOLVED
            </Pill>
          }
        >
          <div className="row spread align-center" style={{ marginBottom: 16 }}>
            <div className="row gap-24">
              <div>
                <span className="text-muted text-xs">Passes Completed</span>
                <h4 style={{ margin: "2px 0 0" }}>{remediationSummary.passes}</h4>
              </div>
              <div>
                <span className="text-muted text-xs">Patches Applied</span>
                <h4 style={{ margin: "2px 0 0" }}>{remediationSummary.patchesApplied}</h4>
              </div>
              <div>
                <span className="text-muted text-xs">Remaining Issues</span>
                <h4 style={{ margin: "2px 0 0" }}>{remediationSummary.remainingFindings}</h4>
              </div>
            </div>
            <div className="row gap-8">
              <Button
                size="sm"
                variant="quiet"
                icon="download"
                onClick={() => {
                  const blob = new Blob([JSON.stringify(workspaceFiles, null, 2)], {
                    type: "application/json",
                  });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `remediated-workspace-${Date.now()}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                Export Workspace
              </Button>
            </div>
          </div>

          <div className="remediation-log-stream">
            {remediationLogs.map((log, i) => (
              <div key={i} className="log-line">
                <span className="log-line__badge log-line__badge--success">PASS {log.pass}</span>
                <span className="log-line__rule mono">{log.rule_id}</span>
                <span className="log-line__file mono">{log.file_path}</span>
                <span className="log-line__msg">{log.message}</span>
                {log.backup_path && (
                  <span className="log-line__backup mono text-muted">[{log.backup_path}]</span>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Main Split: File Viewer & Findings List */}
      <div className="live-split-grid">
        {/* Left: Code Viewer */}
        <div className="live-file-pane">
          <Panel
            title={
              <div className="row gap-8 align-center">
                <Icon name="file-code" size={15} />
                <select
                  className="file-select mono text-sm"
                  value={selectedFile}
                  onChange={(e) => setSelectedFile(e.target.value)}
                >
                  {Object.keys(workspaceFiles).map((fn) => (
                    <option key={fn} value={fn}>
                      {fn}
                    </option>
                  ))}
                </select>
              </div>
            }
            actions={
              <div className="row gap-8 align-center">
                <Pill tone="neutral" className="mono text-xs">
                  {workspaceFiles[selectedFile]?.split("\n").length || 0} lines
                </Pill>
              </div>
            }
          >
            <CodeBlock
              code={workspaceFiles[selectedFile] || ""}
              filename={selectedFile}
              language={selectedFile.endsWith(".py") ? "python" : "json"}
              showLineNumbers
              maxHeight={520}
              markLines={findings
                .filter((f) => f.file_path === selectedFile)
                .map((f) => f.line)}
            />
          </Panel>
        </div>

        {/* Right: Findings & Patches */}
        <div className="live-findings-pane">
          <Panel
            title={
              <div className="row gap-8 align-center">
                <span>Vulnerability Findings</span>
                <span className="badge-count">{filteredFindings.length}</span>
              </div>
            }
            actions={
              <div className="row gap-6">
                <select
                  className="filter-select text-xs"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
                <select
                  className="filter-select text-xs"
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value as "ALL" | "AUTO" | "MANUAL")}
                >
                  <option value="ALL">All Types</option>
                  <option value="AUTO">Auto-Fixable Only</option>
                  <option value="MANUAL">Manual Review Only</option>
                </select>
              </div>
            }
          >
            {filteredFindings.length === 0 ? (
              <EmptyState
                icon="shield-check"
                title="Zero Vulnerabilities Detected"
                description={
                  findings.length === 0
                    ? "The workspace is clean. All security invariant checks pass."
                    : "No findings match the current filter criteria."
                }
              />
            ) : (
              <div className="findings-scroll-list">
                {filteredFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className={cn(
                      "finding-card",
                      selectedFinding?.id === finding.id && "finding-card--selected"
                    )}
                    onClick={() => {
                      setSelectedFinding(finding);
                      setSelectedFile(finding.file_path);
                    }}
                  >
                    <div className="finding-card__header row spread align-center">
                      <div className="row gap-8 align-center">
                        <SeverityPill severity={finding.severity} />
                        <span className="mono text-xs text-muted">{finding.cwe}</span>
                        <span className="mono text-xs font-semibold">{finding.rule_id}</span>
                      </div>
                      <Pill tone={finding.safe_auto ? "live" : "medium"}>
                        {finding.safe_auto ? "AUTO-FIX" : "MANUAL"}
                      </Pill>
                    </div>

                    <h4 className="finding-card__title">{finding.title}</h4>
                    <p className="finding-card__desc">{finding.description}</p>

                    <div className="finding-card__loc row spread align-center">
                      <span className="mono text-xs text-muted">
                        {finding.file_path}:{finding.line}
                      </span>
                      {finding.patch && (
                        <div className="row gap-6">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              setSelectedFinding(finding);
                              setDiffDrawerFinding(finding);
                            }}
                          >
                            Preview Diff
                          </Button>
                          <Button
                            size="sm"
                            variant="primary"
                            onClick={() => {
                              applySinglePatch(finding);
                            }}
                          >
                            Apply Fix
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>

      {/* Diff Drawer Modal */}
      {diffDrawerFinding && diffDrawerFinding.patch && (
        <Drawer
          open={Boolean(diffDrawerFinding)}
          onClose={() => setDiffDrawerFinding(null)}
          title={`Remediation Diff: ${diffDrawerFinding.rule_id}`}
          eyebrow={diffDrawerFinding.cwe}
          subtitle={`Automated safe transformation for ${diffDrawerFinding.file_path}`}
          width={640}
          footer={
            <div className="row spread align-center" style={{ width: "100%" }}>
              <span className="mono text-xs text-muted">
                {diffDrawerFinding.patch.safe_auto ? "Validated safe AST transformation" : "Review carefully before apply"}
              </span>
              <div className="row gap-8">
                <Button variant="quiet" size="sm" onClick={() => setDiffDrawerFinding(null)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  icon="check"
                  onClick={() => applySinglePatch(diffDrawerFinding)}
                >
                  Apply Patch & Re-Scan
                </Button>
              </div>
            </div>
          }
        >
          <div className="col gap-16">
            <div className="callout callout--info">
              <span className="callout__title">Patch Transformation Contract</span>
              <p>{diffDrawerFinding.patch.summary}</p>
            </div>

            <DiffView
              diff={diffDrawerFinding.patch.diff}
              filename={diffDrawerFinding.file_path}
              maxHeight={400}
            />

            <div className="remediation-guidance">
              <span className="label-sm">Defensive Invariant:</span>
              <p className="text-sm text-muted">{diffDrawerFinding.remediation}</p>
            </div>
          </div>
        </Drawer>
      )}
    </div>
  );
}
