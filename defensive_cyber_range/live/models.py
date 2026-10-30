"""Typed data structures shared by the live scanner, patcher, service and API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TextEdit:
    """A single non-overlapping replacement inside a source file."""

    start: int
    end: int
    replacement: str


@dataclass
class PatchPlan:
    """A reviewable, deterministic patch for one finding."""

    finding_id: str
    file_path: str
    original_sha256: str
    patched_content: str
    diff: str
    summary: str
    safe_auto: bool

    def to_public(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "safe_auto": self.safe_auto,
            "diff": self.diff,
        }


@dataclass
class Finding:
    """A source-backed security finding and its optional remediation.

    ``file_path`` is always relative to the scan root. The raw file content is
    never included in API responses; ``snippet`` is limited to the evidence
    needed to understand the issue.
    """

    id: str
    rule_id: str
    title: str
    severity: str
    category: str
    cwe: str
    description: str
    remediation: str
    file_path: str
    line: int
    column: int
    snippet: str
    file_sha256: str
    confidence: str = "high"
    patch: PatchPlan | None = None

    @property
    def auto_fixable(self) -> bool:
        return self.patch is not None

    @property
    def safe_auto(self) -> bool:
        return bool(self.patch and self.patch.safe_auto)

    def to_dict(self, include_patch: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "cwe": self.cwe,
            "description": self.description,
            "remediation": self.remediation,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "file_sha256": self.file_sha256,
            "confidence": self.confidence,
            "auto_fixable": self.auto_fixable,
            "safe_auto": self.safe_auto,
        }
        if include_patch and self.patch:
            data["patch"] = self.patch.to_public()
        return data


@dataclass
class ScanError:
    file_path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"file_path": self.file_path, "message": self.message}


@dataclass
class ScanResult:
    scan_id: str
    root: str
    findings: list[Finding]
    files_scanned: int
    files_skipped: int
    errors: list[ScanError]
    elapsed_ms: float
    generated_at: str
    allow_write: bool
    patches: dict[str, PatchPlan] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {
            "scan_id": self.scan_id,
            "root": self.root,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": {
                "total": len(self.findings),
                "severity": counts,
                "auto_fixable": sum(1 for f in self.findings if f.auto_fixable),
                "safe_auto": sum(1 for f in self.findings if f.safe_auto),
                "unresolved": sum(1 for f in self.findings if not f.auto_fixable),
            },
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "errors": [error.to_dict() for error in self.errors],
            "elapsed_ms": self.elapsed_ms,
            "generated_at": self.generated_at,
            "allow_write": self.allow_write,
        }
