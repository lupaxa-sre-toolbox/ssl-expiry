"""TLS certificate expiration lookup."""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from lupaxa.ssl_expiry.lookup import LeafCert, lookup, probe_certificate


def _leaf(
    when: datetime,
    organization: str | None = "Let's Encrypt",
    common_name: str | None = "R3",
) -> LeafCert:
    return LeafCert(when, organization, common_name)


def test_future_certificate() -> None:
    when = datetime(2027, 3, 15, tzinfo=UTC)
    result = lookup(
        "Example.COM.",
        now=datetime(2026, 9, 22, tzinfo=UTC),
        probe=lambda _host, _timeout: _leaf(when),
    )
    assert result.host == "example.com"
    assert result.status == "expires"
    assert result.issuer == "Let's Encrypt"
    assert result.expiration == when
    assert result.days_remaining == 174


def test_expired_certificate_keeps_a_negative_count() -> None:
    when = datetime(2026, 9, 10, tzinfo=UTC)
    result = lookup(
        "example.org",
        now=datetime(2026, 9, 22, tzinfo=UTC),
        probe=lambda _host, _timeout: _leaf(when),
    )
    assert result.status == "expires"
    assert result.days_remaining == -12


def test_naive_expiration_is_utc() -> None:
    result = lookup(
        "example.org",
        now=datetime(2026, 9, 22, 23, 30, tzinfo=UTC),
        probe=lambda _host, _timeout: _leaf(datetime(2026, 9, 23)),
    )
    assert result.days_remaining == 1
    assert result.expiration is not None
    assert result.expiration.tzinfo is UTC


def test_organization_is_preferred_over_common_name() -> None:
    result = lookup(
        "example.com",
        probe=lambda _host, _timeout: _leaf(datetime(2027, 1, 1, tzinfo=UTC), "DigiCert Inc", "R3"),
    )
    assert result.issuer == "DigiCert Inc"


def test_common_name_fallback() -> None:
    result = lookup(
        "example.com",
        probe=lambda _host, _timeout: _leaf(datetime(2027, 1, 1, tzinfo=UTC), None, "R3"),
    )
    assert result.issuer == "R3"


def test_missing_issuer_still_expires() -> None:
    result = lookup(
        "example.com",
        probe=lambda _host, _timeout: _leaf(datetime(2027, 1, 1, tzinfo=UTC), None, None),
    )
    assert result.status == "expires"
    assert result.issuer is None
    assert result.days_remaining is not None


def test_invalid_host_does_not_call_the_probe() -> None:
    def probe(_host: str, _timeout: float) -> LeafCert:
        raise AssertionError("invalid hosts are not probed")

    for host in (
        "https://example.com",
        "example.com:443",
        "  ",
        "not a host",
        "[192.0.2.1]",
        "fe80::1%eth0",
        "[fe80::1%eth0]",
    ):
        result = lookup(host, probe=probe)
        assert result.status == "invalid"
    blank = lookup("   ", probe=probe)
    assert blank.host == "   "
    spaced = lookup("  example.com:443  ", probe=probe)
    assert spaced.host == "example.com:443"


def test_ip_and_idna_hosts_are_normalized() -> None:
    seen: list[str] = []

    def probe(host: str, _timeout: float) -> LeafCert:
        seen.append(host)
        return _leaf(datetime(2027, 1, 1, tzinfo=UTC), "Org", None)

    assert lookup("192.0.2.10", probe=probe).host == "192.0.2.10"
    assert lookup("[2001:0db8:0000::1]", probe=probe).host == "2001:db8::1"
    assert lookup("2001:db8::1", probe=probe).host == "2001:db8::1"
    assert lookup("münchen.de", probe=probe).host == "xn--mnchen-3ya.de"
    assert lookup("localhost", probe=probe).host == "localhost"
    assert seen == [
        "192.0.2.10",
        "2001:db8::1",
        "2001:db8::1",
        "xn--mnchen-3ya.de",
        "localhost",
    ]


def test_probe_error_collapses_whitespace() -> None:
    def probe(_host: str, _timeout: float) -> LeafCert:
        raise TimeoutError("timed   out")

    result = lookup("slow.test", probe=probe)
    assert result.status == "error"
    assert result.host == "slow.test"
    assert result.error == "timed out"
    assert result.issuer is None


def test_timeout_must_be_positive() -> None:
    def probe(_host: str, _timeout: float) -> LeafCert:
        raise AssertionError("bad timeouts are not probed")

    with pytest.raises(ValueError, match="timeout"):
        lookup("example.com", timeout=0, probe=probe)


def _write_cert(tmp_path: Path) -> tuple[Path, Path, datetime]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    not_after = datetime(2027, 3, 15, tzinfo=UTC)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, not_after


def test_probe_reads_localhost_leaf(tmp_path: Path) -> None:
    cert_path, key_path, not_after = _write_cert(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        conn, _addr = listener.accept()
        try:
            with context.wrap_socket(conn, server_side=True):
                pass
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        leaf = probe_certificate("127.0.0.1", 5.0, port=port)
    finally:
        thread.join(timeout=5)
        listener.close()
    assert leaf.issuer_organization == "Example Org"
    assert leaf.issuer_common_name == "localhost"
    assert leaf.not_after == not_after


class _FakeIO:
    def __enter__(self) -> _FakeIO:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def settimeout(self, _timeout: float) -> None:
        return None

    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form
        return b""


def test_empty_peer_certificate_and_sni(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    lookup_mod = sys.modules["lupaxa.ssl_expiry.lookup"]

    seen: list[str | None] = []

    def connect(*_args: object, **_kwargs: object) -> _FakeIO:
        return _FakeIO()

    def wrap(
        self: ssl.SSLContext,
        _sock: object,
        server_hostname: str | None = None,
    ) -> _FakeIO:
        seen.append(server_hostname)
        assert self.minimum_version == ssl.TLSVersion.TLSv1_2
        return _FakeIO()

    monkeypatch.setattr(lookup_mod.socket, "create_connection", connect)
    monkeypatch.setattr(lookup_mod.ssl.SSLContext, "wrap_socket", wrap)
    empty = lookup("example.com")
    assert empty.status == "error"
    assert empty.error == "no peer certificate"
    ip = lookup("127.0.0.1")
    assert ip.status == "error"
    assert seen == ["example.com", None]
