"""TLS leaf-certificate expiration lookup for one host."""

from __future__ import annotations

import ipaddress
import math
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from cryptography import x509
from cryptography.x509.oid import NameOID

DEFAULT_TIMEOUT = 10.0
DEFAULT_WARN_DAYS = 30

Status = Literal["expires", "invalid", "error"]


@dataclass(frozen=True)
class LeafCert:
    """Leaf certificate fields needed for an expiry row."""

    not_after: datetime
    issuer_organization: str | None
    issuer_common_name: str | None


@dataclass(frozen=True)
class ExpiryResult:
    """Expiration lookup for one host."""

    host: str
    status: Status
    issuer: str | None = None
    expiration: datetime | None = None
    days_remaining: int | None = None
    error: str | None = None


Probe = Callable[[str, float], LeafCert]


def probe_certificate(host: str, timeout: float, *, port: int = 443) -> LeafCert:
    """Connect to ``host`` and return the presented leaf certificate.

    Parameters
    ----------
    host:
        Normalized DNS name or IP address.
    timeout:
        Socket timeout in seconds for the TCP connect and the handshake.
    port:
        TCP port. The CLI always uses 443.

    Returns
    -------
    LeafCert
        Issuer organization, issuer common name, and ``notAfter`` in UTC.

    Raises
    ------
    ValueError
        If ``timeout`` is not greater than 0.
    RuntimeError
        If the handshake yields no certificate bytes. The message is
        ``no peer certificate``.
    """
    _require_timeout(timeout)
    server_hostname = None if _is_ip(host) else host
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with context.wrap_socket(sock, server_hostname=server_hostname) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError("no peer certificate")
    cert = x509.load_der_x509_certificate(der)
    return LeafCert(
        not_after=cert.not_valid_after_utc,
        issuer_organization=_name_text(cert.issuer, NameOID.ORGANIZATION_NAME),
        issuer_common_name=_name_text(cert.issuer, NameOID.COMMON_NAME),
    )


def lookup(
    host: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    now: datetime | None = None,
    probe: Probe | None = None,
) -> ExpiryResult:
    """Return the TLS expiration status of one host.

    Parameters
    ----------
    host:
        DNS name or IP address. International DNS names are converted to ASCII.
    timeout:
        Socket timeout in seconds. Must be greater than 0.
    now:
        Clock used for ``days_remaining``. Defaults to the current UTC time.
        A naive value is treated as UTC.
    probe:
        Callable ``(host, timeout) -> LeafCert``. Defaults to
        :func:`probe_certificate`.

    Returns
    -------
    ExpiryResult
        ``expires`` when a leaf certificate is read, ``invalid`` when the
        host is not a DNS name or IP address, or ``error`` when the probe
        fails.

    Raises
    ------
    ValueError
        If ``timeout`` is not greater than 0.
    """
    _require_timeout(timeout)
    try:
        normalized = _normalize_host(host)
    except ValueError:
        shown = host.strip() or host
        return ExpiryResult(shown, "invalid")
    moment = _as_utc(now or datetime.now(UTC))
    query = probe or probe_certificate
    try:
        leaf = query(normalized, timeout)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        return ExpiryResult(normalized, "error", error=_error_text(exc))
    expiration = _as_utc(leaf.not_after)
    issuer = leaf.issuer_organization or leaf.issuer_common_name or None
    remaining = (expiration.date() - moment.date()).days
    return ExpiryResult(
        normalized,
        "expires",
        issuer=issuer,
        expiration=expiration,
        days_remaining=remaining,
    )


def _normalize_host(host: str) -> str:
    raw = host.strip()
    if not raw:
        raise ValueError("host must be a hostname")
    if raw.startswith("[") and raw.endswith("]"):
        try:
            v6_addr = ipaddress.IPv6Address(raw[1:-1])
        except ValueError as exc:
            raise ValueError("host must be a hostname") from exc
        if v6_addr.scope_id is not None:
            raise ValueError("host must be a hostname")
        return str(v6_addr)
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        if isinstance(addr, ipaddress.IPv6Address) and addr.scope_id is not None:
            raise ValueError("host must be a hostname")
        return str(addr)
    value = raw.lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or any(char in value for char in " /\\:@?#"):
        raise ValueError("host must be a hostname")
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("host must be a hostname") from exc
    labels = ascii_name.split(".")
    if not labels or any(not _is_label(label) for label in labels):
        raise ValueError("host must be a hostname")
    if len(ascii_name) > 253:
        raise ValueError("host must be a hostname")
    return ascii_name


def _is_label(label: str) -> bool:
    if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
        return False
    return all(char.isalnum() or char == "-" for char in label)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _require_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be greater than 0")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be greater than 0")
    return float(timeout)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _name_text(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    for attr in name.get_attributes_for_oid(oid):
        text = str(attr.value).strip()
        if text:
            return text
    return None


def _error_text(exc: BaseException) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    return " ".join(text.split())
