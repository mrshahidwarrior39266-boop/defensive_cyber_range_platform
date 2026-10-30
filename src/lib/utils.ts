import type { CweId, Severity } from "./simulation/types";

export function cn(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

export function formatMs(value: number) {
  if (!Number.isFinite(value)) return "—";
  if (value >= 1000) return `${(value / 1000).toFixed(2)}s`;
  if (value >= 10) return `${value.toFixed(1)}ms`;
  return `${value.toFixed(1)}ms`;
}

export function formatNumber(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatPct(value: number, digits = 0) {
  if (!Number.isFinite(value)) return "—";
  return `${value.toFixed(digits)}%`;
}

export function formatDateTime(value: number | string) {
  const date = typeof value === "string" ? new Date(value) : new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function formatTime(value: number | string) {
  const date = typeof value === "string" ? new Date(value) : new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function relativeTime(value: number | string) {
  const date = typeof value === "string" ? new Date(value) : new Date(value);
  const delta = Date.now() - date.getTime();
  if (Number.isNaN(delta)) return "—";
  const minutes = Math.round(delta / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export function formatDuration(from: number, to: number) {
  const seconds = Math.max(0, Math.round((to - from) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${minutes}m ${rest}s`;
}

export function severityClass(severity: Severity) {
  return `pill--${severity.toLowerCase()}`;
}

export const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

export function severityColor(severity: Severity) {
  return {
    CRITICAL: "#ff97a4",
    HIGH: "#ffb98a",
    MEDIUM: "#ffd9a3",
    LOW: "#9ad9ff",
  }[severity];
}

export function cweName(cwe: CweId) {
  return {
    "CWE-89": "SQL Injection",
    "CWE-862": "Missing Authorization",
    "CWE-79": "Cross-site Scripting",
    "CWE-489": "Active Debug Code",
  }[cwe];
}

export function shortSha(value: string, length = 10) {
  return value.slice(0, length);
}

export function percentOf(part: number, total: number) {
  if (!total) return 0;
  return Math.round((part / total) * 100);
}

/** Use the View Transitions API when it is available and motion is welcome. */
export function beginViewTransition(callback: () => void) {
  const doc = document as Document & {
    startViewTransition?: (cb: () => void) => unknown;
  };
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduced && typeof doc.startViewTransition === "function") {
    doc.startViewTransition(callback);
    return;
  }
  callback();
}

export async function copyText(value: string) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}
