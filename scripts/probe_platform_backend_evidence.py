#!/usr/bin/env python3
"""Capture platform backend execution evidence for Standard v3."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from target_evidence_common import (  # noqa: E402
    CheckResult,
    CommandResult,
    parse_json_command,
    run_command,
    utc_now,
    write_artifact,
)


def run_probe(
    *,
    backend: str,
    apply_commands: list[list[str]],
    rollback_commands: list[list[str]],
    verify_commands: list[list[str]],
    narrowed_claim_file: Path | None,
    captured_at_utc: str,
    command_runner: Callable[[list[str], int], CommandResult] = run_command,
) -> dict[str, object]:
    """Capture backend apply/rollback or narrowed-claim evidence."""
    checks: list[CheckResult] = []

    apply_results = [
        command_runner(command, 300) for command in apply_commands
    ]
    rollback_results = [
        command_runner(command, 300) for command in rollback_commands
    ]
    verify_results = [
        command_runner(command, 120) for command in verify_commands
    ]

    narrowed_claim_text = None
    if narrowed_claim_file is not None:
        narrowed_claim_text = narrowed_claim_file.read_text(encoding="utf-8")[
            :5000
        ]
        checks.append(
            CheckResult(
                "narrowed_claim_attached",
                bool(narrowed_claim_text.strip()),
                "narrowed production claim document was attached",
                {
                    "path": str(narrowed_claim_file),
                    "excerpt": narrowed_claim_text,
                },
            )
        )
    else:
        checks.append(
            CheckResult(
                "backend_apply_executed",
                bool(apply_results)
                and all(result.passed for result in apply_results),
                "backend apply commands exited successfully",
                [result.as_dict() for result in apply_results],
            )
        )
        checks.append(
            CheckResult(
                "backend_rollback_executed",
                bool(rollback_results)
                and all(result.passed for result in rollback_results),
                "backend rollback commands exited successfully",
                [result.as_dict() for result in rollback_results],
            )
        )
        if verify_results:
            checks.append(
                CheckResult(
                    "backend_verification_executed",
                    all(result.passed for result in verify_results),
                    "backend verification commands exited successfully",
                    [result.as_dict() for result in verify_results],
                )
            )

    passed = all(check.passed for check in checks)
    return {
        "schema_version": 1,
        "evidence_type": "platform_backend_execution",
        "captured_at_utc": captured_at_utc,
        "backend": backend,
        "summary": {
            "passed": passed,
            "checks_passed": sum(1 for check in checks if check.passed),
            "checks_total": len(checks),
        },
        "checks": [check.as_dict() for check in checks],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture platform backend execution evidence."
    )
    parser.add_argument("--backend", required=True)
    parser.add_argument(
        "--apply-command",
        action="append",
        default=[],
        type=parse_json_command,
        help="Backend apply command as JSON array.",
    )
    parser.add_argument(
        "--rollback-command",
        action="append",
        default=[],
        type=parse_json_command,
        help="Backend rollback command as JSON array.",
    )
    parser.add_argument(
        "--verify-command",
        action="append",
        default=[],
        type=parse_json_command,
        help="Backend verification command as JSON array.",
    )
    parser.add_argument("--narrowed-claim-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--captured-at-utc", default=utc_now())
    args = parser.parse_args(argv)

    if args.narrowed_claim_file is not None:
        if args.apply_command or args.rollback_command:
            raise SystemExit(
                "--narrowed-claim-file cannot be combined with apply/rollback"
            )
        if not args.narrowed_claim_file.is_file():
            raise SystemExit("--narrowed-claim-file does not exist")
    elif not args.apply_command or not args.rollback_command:
        raise SystemExit(
            "platform backend evidence requires apply and rollback commands, "
            "or --narrowed-claim-file"
        )

    artifact = run_probe(
        backend=args.backend,
        apply_commands=args.apply_command,
        rollback_commands=args.rollback_command,
        verify_commands=args.verify_command,
        narrowed_claim_file=args.narrowed_claim_file,
        captured_at_utc=args.captured_at_utc,
    )
    write_artifact(args.output, artifact)
    print(json.dumps({"artifact": str(args.output), **artifact["summary"]}))
    return 0 if artifact["summary"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
