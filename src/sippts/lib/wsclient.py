#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.2"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2026, SIPPTS"
__email__ = "pepeluxx@gmail.com"

"""Shared SIP-over-WebSocket client (RFC 7118) used by scan, enumerate and send.

It wraps websocket-client's synchronous API, which is what a one-shot
request/response needs: WebSocketApp + rel left the tool hanging on a server
that accepts the connection and never answers, and it swallowed the reason a
WSS handshake failed.
"""

import ssl
import socket

import websocket
from websocket._exceptions import (
    WebSocketBadStatusException,
    WebSocketException,
    WebSocketTimeoutException,
)

# the subprotocol a SIP WebSocket server expects (RFC 7118 section 4)
SIP_SUBPROTOCOL = "sip"

# tried in order when no path is given: Asterisk serves SIP on /ws, Kamailio
# and FreeSWITCH usually on /, and some deployments put it on the root of a
# reverse proxy
DEFAULT_PATHS = ["/ws", "/", "/sip"]


def ws_url(proto, host, port, ws_path):
    """Build the ws(s):// URL for a target."""
    scheme = "wss" if str(proto).upper() == "WSS" else "ws"
    ws_path = "" if ws_path is None else str(ws_path)

    if ws_path != "" and not ws_path.startswith("/"):
        ws_path = "/" + ws_path

    if ":" in str(host) and not str(host).startswith("["):
        host = "[%s]" % host

    return "%s://%s:%s%s" % (scheme, host, port, ws_path)


def ws_sslopt(sni=""):
    """TLS options for a WSS connection.

    No cipher list and no fixed protocol version on purpose: the previous
    code opened a probe connection with ssl.PROTOCOL_TLSv1_2 and forced the
    negotiated cipher back. That broke twice - the constant is gone in
    Python 3.13+, and a TLS 1.3 only server has no cipher that set_ciphers()
    accepts, so every WSS target answered "Socket error".
    """
    sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}

    if sni not in ("", None):
        sslopt["server_hostname"] = str(sni)

    return sslopt


def handshake_status(error):
    """HTTP status of a rejected WebSocket handshake, or 0."""
    if not isinstance(error, WebSocketBadStatusException):
        return 0

    return int(getattr(error, "status_code", 0) or 0)


def ws_connect(
    proto,
    host,
    port,
    ws_path="",
    timeout=5,
    sni="",
    subprotocol=SIP_SUBPROTOCOL,
    header=None,
    origin=None,
):
    """Open a SIP WebSocket connection.

    Returns (connection, url). When ws_path is empty the usual SIP paths are
    tried in turn, because a server answering 404 on / is the normal case
    (Asterisk) and the tool used to stop there.
    """
    if ws_path in ("", None):
        candidates = list(DEFAULT_PATHS)
    else:
        candidates = [ws_path]

    sslopt = ws_sslopt(sni) if str(proto).upper() == "WSS" else None
    last_error = None

    for candidate in candidates:
        url = ws_url(proto, host, port, candidate)

        kwargs = {
            "timeout": timeout,
            "subprotocols": [subprotocol],
            "enable_multithread": True,
        }

        if header:
            kwargs["header"] = list(header)
        if sslopt is not None:
            kwargs["sslopt"] = sslopt
        if origin in ("", None):
            kwargs["suppress_origin"] = True
        else:
            kwargs["origin"] = origin

        try:
            return websocket.create_connection(url, **kwargs), url
        except WebSocketBadStatusException as error:
            # wrong path: keep trying. Any other rejection (401, 403, 426...)
            # is the server talking to us, so report it instead of hiding it
            # behind the next 404
            last_error = error

            if handshake_status(error) != 404 or len(candidates) == 1:
                raise
        except (OSError, socket.error, ssl.SSLError, WebSocketException):
            # connection refused, TLS failure, timeout: the path is not the
            # problem, do not retry it 3 times
            raise

    if last_error is not None:
        raise last_error

    raise WebSocketException("no WebSocket path to try")


def is_timeout(error):
    """Whether a failure is just 'the server said nothing'.

    websocket-client raises its own WebSocketTimeoutException, not
    socket.timeout, so an `except socket.timeout` never caught it and a silent
    answer looked like an error.
    """
    if isinstance(error, (WebSocketTimeoutException, socket.timeout, TimeoutError)):
        return True

    return isinstance(error, OSError) and getattr(error, "errno", 0) == 60


def ws_send_recv(conn, message, timeout=5, tries=10):
    """Send a SIP message and return the first SIP answer as text.

    Non-SIP frames (a server that pings or sends its own keepalive first) are
    skipped instead of being printed as the answer.
    """
    conn.settimeout(timeout)
    conn.send(message)

    for _ in range(tries):
        answer = conn.recv()

        if isinstance(answer, (bytes, bytearray)):
            answer = answer.decode("utf-8", errors="replace")

        if answer is None:
            continue

        if answer.strip() == "":
            continue

        if answer.startswith("SIP/2.0") or " SIP/2.0" in answer.split("\r\n")[0]:
            return answer

    return ""


def ws_error_text(error):
    """One-line, actually useful description of a WebSocket failure."""
    status = handshake_status(error)

    if status in (400, 404):
        return (
            "WebSocket handshake rejected with HTTP %d: wrong path, try -path /ws"
            % status
        )

    if status in (401, 403):
        return (
            "WebSocket handshake rejected with HTTP %d: the server wants credentials or a valid Origin"
            % status
        )

    if status == 426:
        return "WebSocket handshake rejected with HTTP 426: the server wants another subprotocol or version"

    if status != 0:
        return "WebSocket handshake rejected with HTTP %d" % status

    if isinstance(error, ssl.SSLError):
        return "TLS error: %s (is the port plain WS? try -p ws)" % error

    if is_timeout(error):
        return "Timeout: no answer from the WebSocket server"

    if isinstance(error, ConnectionRefusedError):
        return "Connection refused"

    if isinstance(error, OSError) and getattr(error, "strerror", None):
        return "%s" % error.strerror

    text = str(error)

    return text if text != "" else type(error).__name__
