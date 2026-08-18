"""Command-line interface for the phishing email detector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishing_detector import AnalysisResult, analyze_email


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explain the phishing signals found in an email message."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--text", help="Email text to analyze.")
    source.add_argument(
        "--file",
        type=Path,
        help="UTF-8 text file containing the email to analyze.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Return machine-readable JSON instead of the human summary.",
    )
    parser.add_argument(
        "--fail-on-high-risk",
        action="store_true",
        help="Exit with status 2 when the result is High or Critical.",
    )
    return parser


def _read_message(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.file is not None:
        return args.file.read_text(encoding="utf-8")
    if sys.stdin.isatty():
        return input("Paste the email message, then press Enter:\n")
    return sys.stdin.read()


def _format_summary(result: AnalysisResult) -> str:
    # Presentation stays here so the engine is reusable by the GUI and tests.
    lines = [
        f"Risk: {result.severity} ({result.score}/100)",
        f"Summary: {result.summary}",
    ]
    if result.indicators:
        lines.append("\nIndicators:")
        lines.extend(
            f"- {indicator.title} (+{indicator.weight}): {indicator.evidence}"
            for indicator in result.indicators
        )
    else:
        lines.append("\nIndicators: none detected")
    lines.append("\nRecommended next steps:")
    lines.extend(f"- {item}" for item in result.recommendations)
    lines.append(
        "\nNote: This is explainable rule-based triage, not proof that a message "
        "is safe or malicious."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        message = _read_message(args)
    except (OSError, UnicodeError) as exc:
        parser.error(f"could not read the input: {exc}")

    if not message.strip():
        parser.error("the email message cannot be empty")

    result = analyze_email(message)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_format_summary(result))

    if args.fail_on_high_risk and result.severity in {"High", "Critical"}:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
