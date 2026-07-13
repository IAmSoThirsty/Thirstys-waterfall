"""Shared helpers for Standard v3 target evidence probes."""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CommandResult:
    """Captured command result."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def passed(self) -> bool:
        return self.returncode == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "args": self.args,
            "returncode": self.returncode,
            "stdout": limit_text(self.stdout),
            "stderr": limit_text(self.stderr),
        }


@dataclass(frozen=True)
class CheckResult:
    """One evidence check."""

    name: str
    passed: bool
    detail: str
    data: Any = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
        }
        if self.data is not None:
            result["data"] = self.data
        return result


def utc_now() -> str:
    """Return current UTC timestamp in ISO format."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def limit_text(value: str, limit: int = 5000) -> str:
    """Keep evidence output bounded."""
    if len(value) <= limit:
        return value
    return value[:limit] + "\n<truncated>"


def parse_json_command(raw: str) -> list[str]:
    """Parse a JSON command array."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(
            "command must be a JSON array of strings"
        ) from exc
    if (
        not isinstance(parsed, list)
        or not parsed
        or not all(isinstance(item, str) and item for item in parsed)
    ):
        raise argparse.ArgumentTypeError(
            "command must be a non-empty JSON array of non-empty strings"
        )
    return parsed


def run_command(args: list[str], timeout: int = 120) -> CommandResult:
    """Run a command with shell disabled and capture output."""
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CommandResult(
            args=args,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            args=args,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\ncommand timed out",
        )
    except OSError as exc:
        return CommandResult(
            args=args, returncode=1, stdout="", stderr=str(exc)
        )


def write_artifact(output_path: Path, artifact: dict[str, Any]) -> None:
    """Write a JSON evidence artifact."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
