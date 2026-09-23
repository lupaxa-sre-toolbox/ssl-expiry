"""Command-line interface for TLS certificate expiration checks."""

from __future__ import annotations

import argparse
import math
import os
import sys
from datetime import datetime
from pathlib import Path

from prettytable import PrettyTable

from .lookup import DEFAULT_TIMEOUT, DEFAULT_WARN_DAYS, ExpiryResult, lookup
from .version import get_version


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than 0")
    return timeout


def _sort_order(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"asc", "ascending"}:
        return "ascending"
    if normalized in {"desc", "descending"}:
        return "descending"
    raise argparse.ArgumentTypeError("order must be ascending or descending")


def _non_negative_days(value: str) -> int:
    try:
        days = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("warn days must be an integer") from exc
    if days < 0:
        raise argparse.ArgumentTypeError("warn days must be 0 or greater")
    return days


def _read_error_detail(exc: OSError | UnicodeDecodeError) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    text = str(exc).strip() or exc.__class__.__name__
    return " ".join(text.split())


def _exit_code(exc: SystemExit) -> int:
    code = exc.code
    if code is None:
        return 0
    return code if isinstance(code, int) else 1


def _program_name(argv0: str) -> str:
    name = os.path.basename(argv0)
    return "ssl-expiry" if name == "__main__.py" else name


def build_parser() -> argparse.ArgumentParser:
    """Build the ``ssl-expiry`` argument parser."""
    parser = argparse.ArgumentParser(
        description="Check TLS certificate expiration dates on port 443.",
    )
    parser.add_argument(
        "hosts",
        nargs="*",
        metavar="HOST",
        help="Hostname to check; repeat for more than one",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        default=[],
        metavar="PATH",
        help="File of hostnames, one per line (`-` reads stdin)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=_positive_timeout,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "-w",
        "--warn-days",
        type=_non_negative_days,
        default=DEFAULT_WARN_DAYS,
        metavar="DAYS",
        help=(
            "Exit 1 when a certificate expires within this many days "
            f"(default: {DEFAULT_WARN_DAYS})"
        ),
    )
    parser.add_argument(
        "-s",
        "--sort",
        choices=("host", "issuer", "date", "days"),
        help="Sort the table by host, issuer, date, or days",
    )
    parser.add_argument(
        "--order",
        type=_sort_order,
        default=None,
        metavar="DIRECTION",
        help="Sort ascending or descending (default: ascending)",
    )
    parser.add_argument("--version", action="version", version=get_version())
    return parser


def expand_domains(values: list[str]) -> list[str]:
    """Split host tokens on commas and drop empty pieces."""
    hosts: list[str] = []
    for value in values:
        hosts.extend(part.strip() for part in value.split(",") if part.strip())
    return hosts


def read_domains(path: str) -> list[str]:
    """Return hostnames from a text file, skipping blanks and ``#`` comments."""
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    hosts: list[str] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            hosts.append(stripped)
    return hosts


_HEADERS = ("Host", "Issuer", "Date", "Days")
_MISSING = "—"
_MONTHS = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)


def _ordinal(day: int) -> str:
    suffix = "th" if 11 <= day % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
    return f"{day}{suffix}"


def format_expiration(expiration: datetime, days_remaining: int) -> str:
    """Return an ordinal date, or ``Expired`` when the date is in the past."""
    if days_remaining < 0:
        return "Expired"
    when = expiration.date()
    return f"{_ordinal(when.day)} {_MONTHS[when.month - 1]} {when.year}"


def result_cells(result: ExpiryResult) -> tuple[str, str, str, str]:
    """Return the host, issuer, date, and days cells for one result."""
    issuer = result.issuer or _MISSING
    if (
        result.status == "expires"
        and result.expiration is not None
        and result.days_remaining is not None
    ):
        date = format_expiration(result.expiration, result.days_remaining)
        return (result.host, issuer, date, str(result.days_remaining))
    if result.status == "invalid":
        return (result.host, _MISSING, "Invalid Host", _MISSING)
    return (result.host, _MISSING, result.error or "lookup failed", _MISSING)


def format_table(results: list[ExpiryResult]) -> str:
    """Return a PrettyTable of host, issuer, date, and days."""
    table = PrettyTable()
    table.field_names = list(_HEADERS)
    table.align["Host"] = "l"
    table.align["Issuer"] = "l"
    table.align["Date"] = "l"
    table.align["Days"] = "r"
    for result in results:
        table.add_row(list(result_cells(result)))
    return str(table)


def _sort_results(results: list[ExpiryResult], column: str, *, descending: bool) -> None:
    """Sort ``results`` in place. Rows with no issuer, date, or day count stay last."""
    if column == "host":
        results.sort(key=lambda item: item.host.casefold(), reverse=descending)
        return
    if column == "issuer":
        present = [item for item in results if item.issuer]
        missing = [item for item in results if not item.issuer]
        present.sort(
            key=lambda item: (item.issuer or "").casefold(),
            reverse=descending,
        )
        results[:] = present + missing
        return

    def value(item: ExpiryResult) -> tuple[int, float]:
        if column == "days":
            if item.days_remaining is None:
                return (1, 0.0)
            days = float(item.days_remaining)
            return (0, -days if descending else days)
        if item.expiration is None:
            return (1, 0.0)
        stamp = item.expiration.timestamp()
        return (0, -stamp if descending else stamp)

    results.sort(key=value)


def _needs_attention(result: ExpiryResult, warn_days: int) -> bool:
    if result.status != "expires" or result.days_remaining is None:
        return result.status != "error"
    return result.days_remaining <= warn_days


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return _exit_code(exc)

    name = _program_name(sys.argv[0])
    hosts = expand_domains(args.hosts)
    for path in args.file:
        try:
            hosts.extend(expand_domains(read_domains(path)))
        except (OSError, UnicodeDecodeError) as exc:
            detail = _read_error_detail(exc)
            print(f"{name}: {detail}: {path}", file=sys.stderr)
            return 2
    if not hosts:
        parser.print_help()
        return 2
    if args.order is not None and args.sort is None:
        print(f"{name}: --order requires --sort", file=sys.stderr)
        return 2

    attention = False
    failed = False
    results: list[ExpiryResult] = []
    for host in hosts:
        result = lookup(host, timeout=args.timeout)
        results.append(result)
        if result.status == "error":
            failed = True
        elif _needs_attention(result, args.warn_days):
            attention = True
    if args.sort:
        _sort_results(results, args.sort, descending=args.order == "descending")
    print(format_table(results))
    if attention:
        return 1
    if failed:
        return 2
    return 0
