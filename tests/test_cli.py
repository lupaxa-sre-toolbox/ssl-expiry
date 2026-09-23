"""Command-line interface."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from lupaxa.ssl_expiry.cli import (
    expand_domains,
    format_expiration,
    format_table,
    main,
    read_domains,
)
from lupaxa.ssl_expiry.lookup import ExpiryResult


def _expires(host: str, days: int, issuer: str | None = "Let's Encrypt") -> ExpiryResult:
    expiration = datetime(2026, 9, 22, tzinfo=UTC)
    return ExpiryResult(
        host,
        "expires",
        issuer=issuer,
        expiration=expiration,
        days_remaining=days,
    )


def test_format_table() -> None:
    when = datetime(2026, 1, 2, tzinfo=UTC)
    table = format_table(
        [
            ExpiryResult(
                "example.com",
                "expires",
                issuer="Let's Encrypt",
                expiration=datetime(2027, 3, 15, tzinfo=UTC),
                days_remaining=173,
            ),
            ExpiryResult(
                "example.org",
                "expires",
                issuer="DigiCert Inc",
                expiration=when,
                days_remaining=-12,
            ),
            ExpiryResult("slow.test", "error", error="timed out"),
            ExpiryResult("nope.invalid", "invalid"),
        ]
    )
    assert table.splitlines() == [
        "+--------------+---------------+-----------------+------+",
        "| Host         | Issuer        | Date            | Days |",
        "+--------------+---------------+-----------------+------+",
        "| example.com  | Let's Encrypt | 15th March 2027 |  173 |",
        "| example.org  | DigiCert Inc  | Expired         |  -12 |",
        "| slow.test    | —             | timed out       |    — |",
        "| nope.invalid | —             | Invalid Host    |    — |",
        "+--------------+---------------+-----------------+------+",
    ]


def test_ordinal_dates() -> None:
    assert format_expiration(datetime(2026, 11, 11, tzinfo=UTC), 10) == "11th November 2026"
    assert format_expiration(datetime(2026, 1, 1, tzinfo=UTC), 1) == "1st January 2026"
    assert format_expiration(datetime(2026, 1, 2, tzinfo=UTC), 1) == "2nd January 2026"
    assert format_expiration(datetime(2026, 1, 3, tzinfo=UTC), 1) == "3rd January 2026"
    assert format_expiration(datetime(2026, 11, 12, tzinfo=UTC), 1) == "12th November 2026"
    assert format_expiration(datetime(2026, 11, 13, tzinfo=UTC), 1) == "13th November 2026"
    assert format_expiration(datetime(2026, 1, 2, tzinfo=UTC), -3) == "Expired"


def test_missing_issuer_still_prints_the_date() -> None:
    table = format_table([_expires("example.com", 90, issuer=None)])
    assert "| example.com | —      | 22nd September 2026 |   90 |" in table.splitlines()


def test_read_domains_skips_comments(tmp_path: Path) -> None:
    path = tmp_path / "hosts.txt"
    path.write_text("# note\n\nexample.com  # prod\n", encoding="utf-8")
    assert read_domains(str(path)) == ["example.com"]


def test_help_version_and_missing_host(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    help_text = capsys.readouterr().out
    assert "HOST" in help_text
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip()
    assert main([]) == 2
    assert "usage:" in capsys.readouterr().out.lower()


def test_multiple_hosts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[str] = []

    def fake(host: str, **_kwargs: object) -> ExpiryResult:
        seen.append(host)
        return _expires(host, 90)

    monkeypatch.setattr("lupaxa.ssl_expiry.cli.lookup", fake)
    assert main(["example.com", "example.org", "example.net"]) == 0
    assert seen == ["example.com", "example.org", "example.net"]
    assert "Let's Encrypt" in capsys.readouterr().out
    assert expand_domains(["example.com,example.org", " example.net "]) == [
        "example.com",
        "example.org",
        "example.net",
    ]


def test_bad_timeout_and_warn_days() -> None:
    assert main(["example.com", "--timeout", "0"]) == 2
    assert main(["example.com", "--timeout", "nope"]) == 2
    assert main(["example.com", "--warn-days", "-1"]) == 2


def test_exit_codes(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    answers = {
        "safe.example": _expires("safe.example", 90),
        "soon.example": _expires("soon.example", 30),
        "old.example": _expires("old.example", -1),
        "bad.example": ExpiryResult("bad.example", "invalid"),
        "slow.example": ExpiryResult("slow.example", "error", error="timed out"),
    }

    def fake(host: str, **_kwargs: object) -> ExpiryResult:
        return answers[host]

    monkeypatch.setattr("lupaxa.ssl_expiry.cli.lookup", fake)
    assert main(["safe.example"]) == 0
    assert "Host" in capsys.readouterr().out
    assert main(["soon.example", "--warn-days", "30"]) == 1
    assert main(["soon.example", "--warn-days", "29"]) == 0
    assert main(["old.example", "--warn-days", "0"]) == 1
    assert main(["bad.example"]) == 1
    assert main(["slow.example"]) == 2
    assert main(["soon.example", "slow.example"]) == 1


def test_file_hosts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "hosts.txt"
    path.write_text("safe.example,other.example\n", encoding="utf-8")
    seen: list[str] = []

    def fake(host: str, **_kwargs: object) -> ExpiryResult:
        seen.append(host)
        return _expires(host, 90)

    monkeypatch.setattr("lupaxa.ssl_expiry.cli.lookup", fake)
    assert main(["--file", str(path)]) == 0
    assert seen == ["safe.example", "other.example"]
    assert "safe.example" in capsys.readouterr().out


def test_invalid_and_timeout_stay_in_the_table(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake(host: str, **_kwargs: object) -> ExpiryResult:
        if host == "slow.com":
            return ExpiryResult(host, "error", error="connect timed out")
        return ExpiryResult(host, "invalid")

    monkeypatch.setattr("lupaxa.ssl_expiry.cli.lookup", fake)
    assert main(["slow.com", "example.bobthrfish", "not a host"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert "| slow.com           | —      | connect timed out |    — |" in lines
    assert "| example.bobthrfish | —      | Invalid Host      |    — |" in lines
    assert "| not a host         | —      | Invalid Host      |    — |" in lines


def _row_hosts(output: str) -> list[str]:
    names: list[str] = []
    for line in output.splitlines():
        if line.startswith("| ") and not line.startswith("| Host"):
            names.append(line.split("|")[1].strip())
    return names


def test_sort_by_host_issuer_date_and_days(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    later = ExpiryResult(
        "later.com",
        "expires",
        issuer="Zulu",
        expiration=datetime(2027, 3, 1, tzinfo=UTC),
        days_remaining=100,
    )
    sooner = ExpiryResult(
        "sooner.com",
        "expires",
        issuer="Alpha",
        expiration=datetime(2026, 6, 1, tzinfo=UTC),
        days_remaining=10,
    )
    gone = ExpiryResult(
        "gone.com",
        "expires",
        issuer=None,
        expiration=datetime(2025, 1, 1, tzinfo=UTC),
        days_remaining=-20,
    )
    answers = {item.host: item for item in (later, sooner, gone)}

    def fake(host: str, **_kwargs: object) -> ExpiryResult:
        return answers[host]

    monkeypatch.setattr("lupaxa.ssl_expiry.cli.lookup", fake)
    names = ["later.com", "sooner.com", "gone.com"]

    assert main([*names, "--sort", "host"]) == 1
    assert _row_hosts(capsys.readouterr().out) == ["gone.com", "later.com", "sooner.com"]
    assert main([*names, "--sort", "issuer"]) == 1
    assert _row_hosts(capsys.readouterr().out) == ["sooner.com", "later.com", "gone.com"]
    assert main([*names, "--sort", "issuer", "--order", "descending"]) == 1
    assert _row_hosts(capsys.readouterr().out) == ["later.com", "sooner.com", "gone.com"]
    assert main([*names, "--sort", "date"]) == 1
    assert _row_hosts(capsys.readouterr().out) == ["gone.com", "sooner.com", "later.com"]
    assert main([*names, "--sort", "date", "--order", "descending"]) == 1
    assert _row_hosts(capsys.readouterr().out) == ["later.com", "sooner.com", "gone.com"]
    assert main([*names, "--sort", "days", "--order", "descending"]) == 1
    assert _row_hosts(capsys.readouterr().out) == ["later.com", "sooner.com", "gone.com"]


def test_sort_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["example.com", "--order", "descending"]) == 2
    assert "--order requires --sort" in capsys.readouterr().err
    assert main(["example.com", "--sort", "weeks"]) == 2
    assert main(["example.com", "--sort", "days", "--order", "sideways"]) == 2


def test_missing_file() -> None:
    assert main(["--file", "does-not-exist.txt"]) == 2


def test_non_utf8_hosts_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "hosts.bin"
    path.write_bytes(b"\xff\xfe\x00\x00")
    assert main(["--file", str(path)]) == 2
    captured = capsys.readouterr()
    assert str(path) in captured.err
    assert "Traceback" not in captured.err
