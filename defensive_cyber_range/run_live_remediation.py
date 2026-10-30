#!/usr/bin/env python3
"""CLI Entrypoint for Live Folder Vulnerability Scanning and Auto-Remediation.

This utility scans a real local codebase folder for common security vulnerabilities,
reports detailed findings (CWE, severity, line numbers, code snippets, remediation guidance),
and safely executes an automated multi-pass remediation loop to generate and apply
verified patches with automatic rollback on regression.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from live.service import LiveService, ServiceError
from live.scanner import rule_catalog, RULE_CATALOG


def _format_severity(severity: str) -> str:
    colors = {
        "CRITICAL": "\033[91m[CRITICAL]\033[0m",
        "HIGH": "\033[93m[HIGH]    \033[0m",
        "MEDIUM": "\033[94m[MEDIUM]  \033[0m",
        "LOW": "\033[90m[LOW]     \033[0m",
    }
    # Fallback to plain text if stdout is not a tty
    if not sys.stdout.isatty():
        return f"[{severity:<8}]"
    return colors.get(severity, f"[{severity}]")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a local folder for vulnerabilities and automatically apply safe patches."
    )
    parser.add_argument(
        "--folder",
        "-f",
        type=str,
        default=".",
        help="Path to the local directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--auto-fix",
        action="store_true",
        help="Automatically apply safe patches in a closed multi-pass remediation loop.",
    )
    parser.add_argument(
        "--max-passes",
        type=int,
        default=5,
        help="Maximum remediation passes in the closed loop (default: 5).",
    )
    parser.add_argument(
        "--max-patches",
        type=int,
        default=25,
        help="Maximum patches to apply across passes (default: 25).",
    )
    parser.add_argument(
        "--preview",
        type=str,
        default=None,
        metavar="FINDING_ID",
        help="Preview unified diff for a specific finding ID.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON scan or remediation results.",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Display the catalog of supported security detection and patching rules.",
    )
    args = parser.parse_args()

    if args.list_rules:
        rules = rule_catalog()
        if args.json:
            print(json.dumps(rules, indent=2))
            return 0
        print("=" * 80)
        print(" CITADEL CYBER RANGE — LIVE SCANNER RULE CATALOG")
        print("=" * 80)
        for r in rules:
            print(f"{r['id']:<14} | {r['severity']:<8} | {r['cwe']:<8} | Auto-Fix: {r['auto']:<12} | {r['title']}")
        print("=" * 80)
        print(f"Total Rules: {len(rules)}")
        return 0

    target_path = Path(args.folder).expanduser().resolve()
    if not target_path.exists():
        print(f"Error: Target directory does not exist: {target_path}", file=sys.stderr)
        return 1
    if not target_path.is_dir():
        print(f"Error: Target path is not a directory: {target_path}", file=sys.stderr)
        return 1

    service = LiveService(allowed_roots=[target_path], allow_write=args.auto_fix)

    # Mode A: Preview specific finding diff
    if args.preview:
        try:
            preview_data = service.preview(target_path, args.preview)
            if args.json:
                print(json.dumps(preview_data, indent=2))
            else:
                patch = preview_data["patch"]
                print(f"Patch Preview for Finding: {args.preview}")
                print(f"File: {patch['file_path']}")
                print(f"Summary: {patch['summary']}")
                print("-" * 60)
                print(patch["diff"])
            return 0
        except ServiceError as exc:
            print(f"Preview error: {exc}", file=sys.stderr)
            return 1

    # Mode B: Run Scan
    print("=" * 80)
    print(" CITADEL LIVE FOLDER VULNERABILITY SCANNER & AUTO-REMEDIATION")
    print("=" * 80)
    print(f"Target Folder : {target_path}")
    print(f"Mode          : {'READ / WRITE (Auto-Remediation Active)' if args.auto_fix else 'AUDIT ONLY (Read-Only)'}")
    print("-" * 80)

    try:
        initial_scan = service.scan(target_path)
    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    findings = initial_scan.findings
    print(f"Scanned Files : {initial_scan.files_scanned} source files ({initial_scan.files_skipped} skipped)")
    print(f"Findings Total: {len(findings)} discovered in {initial_scan.elapsed_ms:.1f}ms")
    print(f"Auto-Fixable  : {len([f for f in findings if f.safe_auto])}")
    print("-" * 80)

    if findings:
        for idx, f in enumerate(findings, 1):
            sev_badge = _format_severity(f.severity)
            auto_badge = "[AUTO-FIX]" if f.safe_auto else "[MANUAL]  "
            print(f"{idx:2d}. {sev_badge} {auto_badge} {f.rule_id} ({f.cwe}) - {f.title}")
            print(f"    Location   : {f.file_path}:{f.line}:{f.column}")
            print(f"    Description: {f.description}")
            if f.snippet:
                print(f"    Snippet    : {f.snippet.strip()}")
            print(f"    Remediation: {f.remediation}")
            if f.patch:
                print(f"    Safe Patch : {f.patch.summary}")
            print()

    # Mode C: Closed-Loop Auto-Remediation
    if args.auto_fix:
        if not any(f.safe_auto for f in findings):
            print("No auto-fixable findings present. Review manual remediation guidance above.")
            return 0 if not findings else 1

        print("=" * 80)
        print(" EXECUTING CLOSED-LOOP AUTOMATED REMEDIATION")
        print("=" * 80)

        rem_result = service.remediate(
            target_path,
            max_passes=args.max_passes,
            max_patches=args.max_patches,
        )

        initial_count = rem_result["initial_findings"]
        applied_count = rem_result["applied"]
        remaining_count = rem_result["remaining"]
        resolved_pct = ((initial_count - remaining_count) / initial_count * 100) if initial_count else 100.0

        print(f"Remediation Passes : {rem_result['passes']}")
        print(f"Patches Applied    : {applied_count} / {initial_count} initial issues")
        print(f"Remaining Findings : {remaining_count} ({rem_result['remaining_safe_auto']} auto-fixable)")
        print(f"Resolved Rate      : {resolved_pct:.1f}%")
        print(f"Backups Directory  : {target_path / '.cyberrange' / 'backups'}")
        print("-" * 80)

        for step in rem_result.get("log", []):
            st = step.get("status", "unknown").upper()
            rule = step.get("rule_id", "PATCH")
            fp = step.get("file_path", "")
            msg = step.get("message", "")
            print(f"  [{st:<7}] {rule} in {fp}: {msg}")

        if args.json:
            print("\n--- JSON OUTPUT ---")
            print(json.dumps(rem_result, indent=2))

        return 0 if remaining_count == 0 else 1

    if args.json:
        print(json.dumps(initial_scan.to_dict(), indent=2))

    return 0 if len(findings) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
