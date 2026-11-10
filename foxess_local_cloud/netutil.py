"""Network, TLS and systemd helpers used by the local cloud server."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import socket
import ssl
import struct

FOXESS_UPSTREAM_CERT_SHA256 = "0ff6d2d0b548f0a03dced31ce7621a8c9497bdc074d723bc152094e4d299c1b7"

_EXPECTED_TLS_DISCONNECT_ERRORS = (
    "application data after close notify",
    "eof occurred in violation of protocol",
    "ssl shutdown timed out",
)


def systemd_watchdog_interval_seconds(environ: dict[str, str] | None = None) -> float | None:
    """Return a safe systemd watchdog heartbeat interval, if enabled.

    systemd supplies ``WATCHDOG_USEC`` only when WatchdogSec is configured for
    this service. Respect WATCHDOG_PID so a stale inherited environment cannot
    accidentally notify for a different process.
    """
    env = os.environ if environ is None else environ
    watchdog_pid = env.get("WATCHDOG_PID")
    if watchdog_pid and watchdog_pid != str(os.getpid()):
        return None
    try:
        timeout_seconds = int(env.get("WATCHDOG_USEC", "0")) / 1_000_000
    except ValueError:
        return None
    if timeout_seconds <= 0:
        return None
    # Notify at least twice per systemd timeout, without needlessly waking the
    # Pi more often than every 30 seconds for a long timeout.
    return min(timeout_seconds / 2, 30.0)

def notify_systemd(message: str, environ: dict[str, str] | None = None) -> bool:
    """Send a notification datagram to systemd when NOTIFY_SOCKET is set."""
    env = os.environ if environ is None else environ
    path = env.get("NOTIFY_SOCKET")
    if not path:
        return False
    address = "\0" + path[1:] if path.startswith("@") else path
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify_socket:
        notify_socket.connect(address)
        notify_socket.sendall(message.encode("ascii"))
    return True

def expected_disconnect_reason(exc: BaseException) -> str | None:
    message = str(exc).lower()
    if isinstance(exc, TimeoutError) and "ssl shutdown timed out" in message:
        return "ssl_shutdown_timeout"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "connection_lost"
    if isinstance(exc, ssl.SSLError) and any(
        expected in message for expected in _EXPECTED_TLS_DISCONNECT_ERRORS
    ):
        return "tls_connection_lost"
    return None

RELAY_DRAIN_TIMEOUT_SECONDS = 30.0

async def drain_with_timeout(writer: asyncio.StreamWriter, timeout: float = RELAY_DRAIN_TIMEOUT_SECONDS) -> None:
    """Drain a relay writer, failing (rather than blocking forever) if the peer stops reading."""
    await asyncio.wait_for(writer.drain(), timeout)

def upstream_ssl_context() -> ssl.SSLContext:
    """TLS client context for the FoxESS upstream.

    FoxESS uses a self-signed certificate, so CA/hostname validation cannot
    apply; the peer is authenticated instead by SHA-256 pinning in
    ``check_upstream_cert`` immediately after the handshake."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def apply_inverter_keepalive(writer: asyncio.StreamWriter, idle_seconds: int) -> None:
    """Enable TCP keepalive on the inverter connection so a marginal Wi-Fi link
    is kept warm and a dropped session is detected within ~a minute (feeding the
    ActivePowerLimit retry-on-reconnect). ``idle_seconds <= 0`` disables it. The
    per-idle/-interval/-count knobs are Linux-only; missing ones are skipped, so
    this is a safe no-op on platforms (or sockets) that don't support them."""
    if idle_seconds <= 0:
        return
    sock = writer.get_extra_info("socket")
    if sock is None or not hasattr(sock, "setsockopt"):
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        tunables = (
            ("TCP_KEEPIDLE", idle_seconds),
            ("TCP_KEEPINTVL", min(idle_seconds, 10)),
            ("TCP_KEEPCNT", 3),
        )
        for name, value in tunables:
            opt = getattr(socket, name, None)
            if opt is not None:
                sock.setsockopt(socket.IPPROTO_TCP, opt, value)
    except OSError:
        pass

def original_destination_ip(writer: asyncio.StreamWriter) -> str | None:
    """Best-effort Linux SO_ORIGINAL_DST lookup for redirected IPv4 sockets."""

    sock = writer.get_extra_info("socket")
    if sock is None:
        return None
    try:
        data = sock.getsockopt(socket.SOL_IP, 80, 16)
    except OSError:
        return None
    if len(data) < 8:
        return None
    _family, _port, raw_addr = struct.unpack_from("!HH4s", data)
    return socket.inet_ntoa(raw_addr)

def check_upstream_cert(writer: asyncio.StreamWriter) -> str | None:
    """Return the peer cert's SHA-256 if it does not match the pinned FoxESS fingerprint."""

    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return "no_ssl_object"
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return "no_peer_cert"
    actual = hashlib.sha256(der).hexdigest()
    if actual.lower() == FOXESS_UPSTREAM_CERT_SHA256.lower():
        return None
    return actual

def is_public_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and address.is_global
