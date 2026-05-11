"""CLI for the Password Strength Analyzer."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from project_04.core import PasswordAnalysis, analyze_password

_SCORE_INDICATORS = ["██░░░", "████░", "██████", "████████", "██████████"]
_SCORE_COLORS = {0: "31", 1: "33", 2: "33", 3: "32", 4: "32"}  # ANSI color codes


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-analyze",
        description="Analyze password strength and get improvement suggestions.",
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("password", nargs="?", help="Password to analyze (omit for interactive prompt)")
    src.add_argument("--stdin", action="store_true", help="Read password from stdin")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output as JSON")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color output"
    )
    return parser


def _get_password(args: argparse.Namespace) -> str:
    """Obtain the password from args, stdin, or interactive prompt."""
    if args.password:
        return args.password
    if args.stdin:
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Password: ")


def _format_text(analysis: PasswordAnalysis, *, color: bool) -> str:
    """Render a human-readable report."""
    lines: list[str] = []
    score = analysis.score
    label = analysis.strength_label
    bar = _SCORE_INDICATORS[min(score, 4)]

    if color:
        code = _SCORE_COLORS.get(score, "0")
        label_str = f"\033[{code}m{label}\033[0m"
    else:
        label_str = label

    lines.append(f"Strength : {label_str}  {bar}  ({score}/4)")
    lines.append(f"Length   : {analysis.password_length} characters")
    lines.append(f"Entropy  : {analysis.entropy_bits:.1f} bits")
    char_classes = ", ".join(
        cls
        for cls, present in [
            ("lower", analysis.has_lower),
            ("upper", analysis.has_upper),
            ("digits", analysis.has_digits),
            ("special", analysis.has_special),
        ]
        if present
    )
    lines.append(f"Classes  : {char_classes or 'none'}")
    if analysis.warnings:
        lines.append("\nWarnings:")
        for w in analysis.warnings:
            lines.append(f"  ! {w}")
    if analysis.suggestions:
        lines.append("\nSuggestions:")
        for s in analysis.suggestions:
            lines.append(f"  • {s}")
    return "\n".join(lines)


def main() -> None:
    """Entry point for the password-analyze CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    password = _get_password(args)

    analysis = analyze_password(password)

    if args.as_json:
        print(json.dumps({
            "length": analysis.password_length,
            "entropy_bits": analysis.entropy_bits,
            "score": analysis.score,
            "strength": analysis.strength_label,
            "character_classes": {
                "lower": analysis.has_lower,
                "upper": analysis.has_upper,
                "digits": analysis.has_digits,
                "special": analysis.has_special,
            },
            "warnings": analysis.warnings,
            "suggestions": analysis.suggestions,
        }, indent=2))
    else:
        print(_format_text(analysis, color=not args.no_color))

    # Exit 0 for strong/very-strong, 1 for anything weaker
    sys.exit(0 if analysis.score >= 3 else 1)
