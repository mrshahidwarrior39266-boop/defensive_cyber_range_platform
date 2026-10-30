import configSource from "../../../defensive_cyber_range/mock_enterprise/config.py?raw";
import databaseSource from "../../../defensive_cyber_range/mock_enterprise/database.py?raw";
import serviceSource from "../../../defensive_cyber_range/mock_enterprise/service.py?raw";
import telemetrySource from "../../../defensive_cyber_range/mock_enterprise/telemetry.py?raw";
import groundTruthSource from "../../../defensive_cyber_range/mock_enterprise/ground_truth.json?raw";
import groundTruthJson from "../../../defensive_cyber_range/mock_enterprise/ground_truth.json";
import type { CweId, Severity } from "./types";

export interface VulnerabilityBlueprint {
  vulnId: string;
  cweId: CweId;
  title: string;
  severity: Severity;
  cvssScore: number;
  filePath: string;
  functionName: string;
  endpoint: string;
  nodeType: string;
  description: string;
  remediationGuidance: string;
  remediationContract: string;
  locator: string;
  evidenceLocator?: string;
}

export interface ProjectFile {
  path: string;
  name: string;
  language: "python" | "json";
  summary: string;
  source: string;
  seededCwes: CweId[];
}

export const GROUND_TRUTH = groundTruthJson as unknown as {
  application: string;
  version: string;
  seeded_vulnerabilities: Array<{
    vuln_id: string;
    cwe_id: CweId;
    title: string;
    file_path: string;
    function_name: string;
    endpoint: string;
    severity: Severity;
    cvss_score: number;
    remediation_requirement: string;
  }>;
};

export const BLUEPRINTS: Record<CweId, VulnerabilityBlueprint> = {
  "CWE-89": {
    vulnId: "VULN-001",
    cweId: "CWE-89",
    title: "Unparameterized SQL Query in User Directory Lookup",
    severity: "CRITICAL",
    cvssScore: 9.8,
    filePath: "mock_enterprise/database.py",
    functionName: "lookup_user_by_username",
    endpoint: "/api/v1/users/search",
    nodeType: "FunctionDef",
    description:
      "SQL query string is constructed dynamically using a Python f-string (ast.JoinedStr) with user input `username` rather than DB-API parameterized `?` placeholders.",
    remediationGuidance:
      'Use parameterized SQL execution: cursor.execute("SELECT ... WHERE username = ?", (username,))',
    remediationContract:
      'Use parameterized SQL execution: cursor.execute("SELECT ... WHERE username = ?", (username,))',
    locator: 'query = f"SELECT',
    evidenceLocator: 'query = f"SELECT',
  },
  "CWE-862": {
    vulnId: "VULN-002",
    cweId: "CWE-862",
    title: "Missing Role Authorization in Confidential Document Export",
    severity: "HIGH",
    cvssScore: 8.6,
    filePath: "mock_enterprise/service.py",
    functionName: "export_confidential_documents",
    endpoint: "/api/v1/admin/export-confidential",
    nodeType: "FunctionDef",
    description:
      "Administrative export method accepts `requester_role` but never validates that the caller holds the 'admin' role before querying confidential records.",
    remediationGuidance:
      "Enforce an explicit authorization guard at the start of the method and raise PermissionError or return HTTP 403 when requester_role != 'admin'.",
    remediationContract:
      "Enforce explicit role check ensuring requester_role == 'admin' before querying confidential documents.",
    locator: "def export_confidential_documents",
    evidenceLocator: "def export_confidential_documents",
  },
  "CWE-79": {
    vulnId: "VULN-003",
    cweId: "CWE-79",
    title: "Unescaped HTML Output in Directory Search Banner",
    severity: "MEDIUM",
    cvssScore: 6.5,
    filePath: "mock_enterprise/service.py",
    functionName: "render_search_banner",
    endpoint: "/ui/search-banner",
    nodeType: "FunctionDef",
    description:
      "render_search_banner interpolates filter_label directly into an HTML <div> element without calling html.escape().",
    remediationGuidance:
      "Escape untrusted input with safe_label = html.escape(filter_label, quote=True) before rendering inside HTML markup.",
    remediationContract:
      "Sanitize filter_label with html.escape(filter_label, quote=True) prior to HTML interpolation.",
    locator: "def render_search_banner",
    evidenceLocator: "Active Directory Filter: {filter_label}",
  },
  "CWE-489": {
    vulnId: "VULN-004",
    cweId: "CWE-489",
    title:
      "Production Debug Mode, Verbose Stack Traces, and Static Secret Mode Enabled",
    severity: "MEDIUM",
    cvssScore: 6.1,
    filePath: "mock_enterprise/config.py",
    functionName: "module_config",
    endpoint: "/api/v1/health",
    nodeType: "Module",
    description:
      "Production configuration enables active debug flags, stack trace exposure, and a static token signing mode.",
    remediationGuidance:
      'Set DEBUG_MODE = False, EXPOSE_STACK_TRACES = False, and TOKEN_SIGNING_MODE = "ephemeral_rotatable_key".',
    remediationContract:
      "Disable DEBUG_MODE and EXPOSE_STACK_TRACES in production and set TOKEN_SIGNING_MODE to 'ephemeral_rotatable_key'.",
    locator: "DEBUG_MODE = True",
    evidenceLocator: "DEBUG_MODE = True",
  },
};

export const CWE_ORDER: CweId[] = [
  "CWE-89",
  "CWE-862",
  "CWE-79",
  "CWE-489",
];

export const PROJECT_FILES: ProjectFile[] = [
  {
    path: "mock_enterprise/config.py",
    name: "config.py",
    language: "python",
    summary: "Application configuration and production flags.",
    source: configSource,
    seededCwes: ["CWE-489"],
  },
  {
    path: "mock_enterprise/database.py",
    name: "database.py",
    language: "python",
    summary: "SQLite schema bootstrap and seeded directory lookup.",
    source: databaseSource,
    seededCwes: ["CWE-89"],
  },
  {
    path: "mock_enterprise/service.py",
    name: "service.py",
    language: "python",
    summary: "Corporate API and UI request handlers.",
    source: serviceSource,
    seededCwes: ["CWE-862", "CWE-79"],
  },
  {
    path: "mock_enterprise/telemetry.py",
    name: "telemetry.py",
    language: "python",
    summary: "OpenTelemetry-style events and Prometheus counters.",
    source: telemetrySource,
    seededCwes: [],
  },
  {
    path: "mock_enterprise/ground_truth.json",
    name: "ground_truth.json",
    language: "json",
    summary: "Judge ground truth for the four seeded weaknesses.",
    source: groundTruthSource,
    seededCwes: ["CWE-89", "CWE-862", "CWE-79", "CWE-489"],
  },
];

export const SURFACES = [
  {
    filePath: "mock_enterprise/service.py",
    functionName: "get_health",
    endpoint: "/api/v1/health",
    parameters: [] as string[],
    hasAuthGuard: false,
    lineNumber: 25,
  },
  {
    filePath: "mock_enterprise/service.py",
    functionName: "search_directory",
    endpoint: "/api/v1/users/search",
    parameters: ["username_query", "actor"],
    hasAuthGuard: false,
    lineNumber: 36,
  },
  {
    filePath: "mock_enterprise/service.py",
    functionName: "render_search_banner",
    endpoint: "/ui/search-banner",
    parameters: ["filter_label", "actor"],
    hasAuthGuard: false,
    lineNumber: 42,
  },
  {
    filePath: "mock_enterprise/service.py",
    functionName: "export_confidential_documents",
    endpoint: "/api/v1/admin/export-confidential",
    parameters: ["requester_role", "actor"],
    hasAuthGuard: false,
    lineNumber: 51,
  },
];

const FIXES: Record<
  CweId,
  { filePath: string; replacements: Array<[string, string]> }
> = {
  "CWE-89": {
    filePath: "mock_enterprise/database.py",
    replacements: [
      [
        `    query = f"SELECT id, username, email, role, department FROM users WHERE username = '{username}'"\n    cursor.execute(query)`,
        `    query = "SELECT id, username, email, role, department FROM users WHERE username = ?"\n    cursor.execute(query, (username,))`,
      ],
    ],
  },
  "CWE-862": {
    filePath: "mock_enterprise/service.py",
    replacements: [
      [
        `        self.telemetry.record_request("/api/v1/admin/export-confidential", actor=actor, status=200)\n        cursor = self.conn.cursor()`,
        `        if requester_role != 'admin':\n            self.telemetry.record_request("/api/v1/admin/export-confidential", actor=actor, status=403)\n            raise PermissionError("Admin role required to export confidential documents.")\n        self.telemetry.record_request("/api/v1/admin/export-confidential", actor=actor, status=200)\n        cursor = self.conn.cursor()`,
      ],
    ],
  },
  "CWE-79": {
    filePath: "mock_enterprise/service.py",
    replacements: [
      [
        `        self.telemetry.record_request("/ui/search-banner", actor=actor, status=200)\n        return f"<div class='search-banner'>Active Directory Filter: {filter_label}</div>"`,
        `        self.telemetry.record_request("/ui/search-banner", actor=actor, status=200)\n        safe_label = html.escape(filter_label, quote=True)\n        return f"<div class='search-banner'>Active Directory Filter: {safe_label}</div>"`,
      ],
    ],
  },
  "CWE-489": {
    filePath: "mock_enterprise/config.py",
    replacements: [
      ["DEBUG_MODE = True", "DEBUG_MODE = False"],
      ["EXPOSE_STACK_TRACES = True", "EXPOSE_STACK_TRACES = False"],
      [
        'TOKEN_SIGNING_MODE = "weak_static_secret"',
        'TOKEN_SIGNING_MODE = "ephemeral_rotatable_key"',
      ],
    ],
  },
};

export function applyFix(source: string, cwe: CweId): string {
  let next = source;
  for (const [from, to] of FIXES[cwe].replacements) {
    next = next.replace(from, to);
  }
  return next;
}

export function fileSourceFor(path: string, remediated: CweId[]): string {
  const file = PROJECT_FILES.find((item) => item.path === path);
  if (!file) return "";
  let source = file.source;
  for (const cwe of remediated) {
    if (BLUEPRINTS[cwe].filePath === path) source = applyFix(source, cwe);
  }
  return source;
}

export function vulnerableFiles(): Record<string, string> {
  return Object.fromEntries(PROJECT_FILES.map((file) => [file.path, file.source]));
}

export function locateLine(source: string, needle: string, fallback: number) {
  const index = source.split("\n").findIndex((line) => line.includes(needle));
  return index >= 0 ? index + 1 : fallback;
}

export function extractFunction(source: string, functionName: string): string {
  const lines = source.split("\n");
  const start = lines.findIndex((line) =>
    line.startsWith(`def ${functionName}`),
  );
  if (start < 0) return source;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^(def |class )/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n").trimEnd();
}

export const CWE_LABELS: Record<CweId, string> = {
  "CWE-89": "SQL Injection",
  "CWE-862": "Missing Authorization",
  "CWE-79": "Cross-site Scripting",
  "CWE-489": "Active Debug Code",
};
