"""Safety-gated Live Folder service.

This layer is the only place that writes to the connected folder. Every write
is preceded by an optimistic file-hash check, copied to a local backup, applied
atomically, and followed by a verification re-scan. If the original finding is
still present, the backup is restored automatically.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Iterable

from .models import Finding, ScanResult
from .scanner import LiveScanner, rule_catalog


class ServiceError(RuntimeError):
    """An expected, user-facing service failure with an HTTP-ish status."""

    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.status = status
        self.code = code


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_file_hash(target: Path) -> tuple[bytes, str]:
    raw = target.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
        return raw, hashlib.sha256(text.encode("utf-8")).hexdigest()
    except UnicodeDecodeError:
        return raw, hashlib.sha256(raw).hexdigest()


class LiveService:
    """Coordinates scans, previews and the controlled remediation loop."""

    def __init__(
        self,
        allowed_roots: Iterable[str | Path],
        allow_write: bool = False,
        max_file_bytes: int = 512_000,
    ) -> None:
        self.scanner = LiveScanner(
            allowed_roots=allowed_roots,
            allow_write=allow_write,
            max_file_bytes=max_file_bytes,
        )
        self.allow_write = allow_write

    # ---------------------------------------------------------------- config

    def config(self) -> dict[str, Any]:
        return {
            "mode": "live",
            "allow_write": self.allow_write,
            "allowed_roots": [str(root) for root in self.scanner.allowed_roots],
            "rules": rule_catalog(),
            "rule_count": len(rule_catalog()),
            "max_file_bytes": self.scanner.max_file_bytes,
            "excluded_directories": sorted(
                [
                    ".git",
                    "node_modules",
                    "dist",
                    "build",
                    "venv",
                    ".venv",
                    "__pycache__",
                    ".cyberrange",
                ]
            ),
            "write_policy": (
                "Approved-root only; atomic writes; automatic backup; "
                "verification re-scan; auto-revert when the finding remains."
                if self.allow_write
                else "Read-only. Start the local service with --allow-write to enable fixes."
            ),
        }

    # ---------------------------------------------------------------- scan

    def scan(self, root: str | Path | None = None) -> ScanResult:
        return self.scanner.scan(root)

    def _find(self, scan: ScanResult, finding_id: str) -> Finding:
        for finding in scan.findings:
            if finding.id == finding_id:
                return finding
        raise ServiceError(
            "That finding is no longer present. The file may have changed; "
            "run a fresh scan.",
            status=409,
            code="stale_finding",
        )

    def preview(self, root: str | Path | None, finding_id: str) -> dict[str, Any]:
        scan = self.scan(root)
        finding = self._find(scan, finding_id)
        if not finding.patch:
            raise ServiceError(
                "This finding has no deterministic automatic patch. Review the "
                "remediation guidance and edit the file manually.",
                status=409,
                code="not_patchable",
            )
        return {
            "finding": finding.to_dict(),
            "patch": finding.patch.to_public(),
            "root": scan.root,
            "allow_write": self.allow_write,
        }

    # ---------------------------------------------------------------- apply

    def apply(
        self,
        root: str | Path | None,
        finding_id: str,
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        if not self.allow_write:
            raise ServiceError(
                "The local service is read-only. Restart it with --allow-write "
                "to apply patches.",
                status=403,
                code="read_only",
            )

        scan = self.scan(root)
        root_path = Path(scan.root)
        finding = self._find(scan, finding_id)
        patch = finding.patch
        if patch is None:
            raise ServiceError(
                "This finding has no deterministic automatic patch.",
                status=409,
                code="not_patchable",
            )

        unresolved = root_path / finding.file_path
        target = self._safe_target(root_path, unresolved)
        current_bytes, current_hash = _read_file_hash(target)
        if expected_sha256 and expected_sha256 != current_hash:
            raise ServiceError(
                "The file changed since the scan. Re-scan before applying this fix.",
                status=409,
                code="stale_file",
            )
        if current_hash != finding.file_sha256:
            raise ServiceError(
                "The file checksum does not match the scan. Re-scan before applying.",
                status=409,
                code="stale_file",
            )

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_path = root_path / ".cyberrange" / "backups" / timestamp / finding.file_path
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, backup_path)

        try:
            self._atomic_write(target, patch.patched_content.encode("utf-8"))
            verification = self.scan(root)
            still_present = any(item.id == finding.id for item in verification.findings)
            if still_present:
                self._atomic_write(target, current_bytes)
                return {
                    "status": "reverted",
                    "message": (
                        "The patch did not clear the finding, so the original file "
                        "was restored automatically."
                    ),
                    "finding_id": finding.id,
                    "file_path": finding.file_path,
                    "backup_path": backup_path.relative_to(root_path).as_posix(),
                    "verified": False,
                    "remaining": len(verification.findings),
                    "scan_id": verification.scan_id,
                }
        except Exception as exc:
            try:
                self._atomic_write(target, current_bytes)
            except Exception:
                pass
            raise ServiceError(
                f"Patch failed and the original content was restored: {exc}",
                status=500,
                code="patch_failed",
            ) from exc

        return {
            "status": "applied",
            "message": (
                f"Applied {finding.rule_id} to {finding.file_path} and verified "
                "the finding is gone."
            ),
            "finding_id": finding.id,
            "file_path": finding.file_path,
            "backup_path": backup_path.relative_to(root_path).as_posix(),
            "verified": not still_present,
            "remaining": len(verification.findings),
            "scan_id": verification.scan_id,
            "diff": patch.diff,
            "summary": patch.summary,
        }

    def remediate(
        self,
        root: str | Path | None,
        max_passes: int = 8,
        max_patches: int = 30,
    ) -> dict[str, Any]:
        if not self.allow_write:
            raise ServiceError(
                "The local service is read-only. Restart it with --allow-write "
                "to apply fixes.",
                status=403,
                code="read_only",
            )
        root_path = self.scanner.resolve_root(root)
        first_scan = self.scan(root_path)
        initial = len(first_scan.findings)
        log: list[dict[str, Any]] = []
        applied = 0
        passes = 0

        for _ in range(max(1, min(max_passes, 20))):
            passes += 1
            scan = self.scan(root_path)
            candidate = next(
                (finding for finding in scan.findings if finding.safe_auto),
                None,
            )
            if candidate is None or applied >= max_patches:
                break
            try:
                result = self.apply(root_path, candidate.id, candidate.file_sha256)
            except ServiceError as exc:
                log.append(
                    {
                        "finding_id": candidate.id,
                        "rule_id": candidate.rule_id,
                        "file_path": candidate.file_path,
                        "status": "error",
                        "message": str(exc),
                    }
                )
                break
            log.append(
                {
                    "finding_id": candidate.id,
                    "rule_id": candidate.rule_id,
                    "file_path": candidate.file_path,
                    "status": result["status"],
                    "message": result["message"],
                    "backup_path": result.get("backup_path"),
                }
            )
            if result["status"] != "applied":
                break
            applied += 1

        final_scan = self.scan(root_path)
        return {
            "root": str(root_path),
            "initial_findings": initial,
            "applied": applied,
            "passes": passes,
            "log": log,
            "remaining": len(final_scan.findings),
            "remaining_safe_auto": sum(
                1 for finding in final_scan.findings if finding.safe_auto
            ),
            "final_scan": final_scan.to_dict(),
        }

    # ---------------------------------------------------------------- writes

    @staticmethod
    def _safe_target(root: Path, unresolved: Path) -> Path:
        if unresolved.is_symlink():
            raise ServiceError(
                "Refusing to write through a symbolic link.", status=400
            )
        target = unresolved.resolve()
        if not target.is_relative_to(root):
            raise ServiceError(
                "Refusing to write outside the scan root.", status=400
            )
        if not target.exists() or not target.is_file():
            raise ServiceError("Target file no longer exists.", status=409)
        return target

    @staticmethod
    def _atomic_write(target: Path, data: bytes) -> None:
        original_mode = target.stat().st_mode if target.exists() else 0o644
        temp_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                "wb",
                dir=str(target.parent),
                prefix=".cyberrange-tmp-",
                delete=False,
            ) as handle:
                temp_name = handle.name
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, original_mode & 0o777)
            os.replace(temp_name, target)
        finally:
            if temp_name and os.path.exists(temp_name):
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
