#!/usr/bin/env python3
'''CLI Entrypoint for running the Defensive Cyber Range Simulation Platform.'''

import argparse
from pathlib import Path
import sys

from orchestrator.engine import SimulationOrchestrator


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the closed-loop Defensive Cyber Range Simulation Platform."
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=2,
        help="Number of closed-loop simulation rounds to execute (default: 2).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./simulation_artifacts",
        help="Directory to store sandbox workspace, audit logs, and scorecards.",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    output_dir = Path(args.output_dir).resolve()

    print("=" * 72)
    print(" DEFENSIVE CYBER RANGE SIMULATION PLATFORM — STARTING CLOSED LOOP")
    print("=" * 72)

    orchestrator = SimulationOrchestrator(
        project_root=project_root,
        output_dir=output_dir,
    )
    summary = orchestrator.run_simulation(max_rounds=args.rounds)

    for round_data in summary["rounds"]:
        sc = round_data["scorecard"]
        print(
            f"[Round {sc['round_num']}] Findings={sc['findings_discovered']} | "
            f"Alerts={sc['alerts_triggered']} | PatchesDeployed={sc['patches_deployed']} | "
            f"VerifiedFixed={sc['verified_remediated']} | PostureScore={sc['security_posture_score']}%"
        )

    print("-" * 72)
    print(f"Final Security Posture Score : {summary['final_posture_score']}%")
    print(f"Remediated Vulnerability Set : {', '.join(summary['remediated_cwes'])}")
    print(
        f"Immutable Audit Chain Status : {'VALID' if summary['audit_chain_valid'] else 'INVALID'} "
        f"({summary['audit_entries_count']} entries)"
    )
    print(f"Artifacts Written To         : {output_dir}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
