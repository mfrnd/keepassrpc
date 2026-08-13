"""WebSocket transport, behind a protocol narrow enough to fake in tests.

The client talks to the plugin over a loopback WebSocket. Keeping that behind
:class:`Transport` means the whole handshake can be exercised against a scripted fake,
which is how the pairing and reconnect paths get tested without a running KeePass.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any, Protocol

import websocket

from .errors import ConnectionFailed, ProtocolError

DEFAULT_URL = 'ws://127.0.0.1:12546'

# The server rejects any connection whose Origin is not on its allowlist
# (`KeePassRPCServer.ValidateOrigin`, prefix match). Its default list is browser extension
# schemes only, so a non-browser client has to borrow one of those prefixes. The
# alternative is to set `KeePassRPC.webSocket.permittedOrigins` in the KeePass config,
# which is cleaner but requires the user to edit config; see this package's README.
DEFAULT_ORIGIN = 'chrome-extension://keepassrpc-python-client'

DEFAULT_TIMEOUT = 10.0


class Transport(Protocol):
    """The socket operations the client needs, and nothing more."""

    def send(self, message: str) -> None:
        """Send one text frame."""
        ...

    def receive(self) -> str:
        """Block for the next text frame."""
        ...

    def close(self) -> None:
        """Close the connection. Must be safe to call more than once."""
        ...

    def set_timeout(self, timeout: float) -> None:
        """Change the read timeout for subsequent operations.

        Needed because some calls wait on a human: the plugin raises a confirmation dialog
        for attachment content and for writes, and a person takes longer to answer than any
        sane default read timeout.
        """
        ...


class RawSocket(Protocol):
    """The four socket methods this transport actually uses.

    Narrower than ``websocket.WebSocket`` on purpose. Depending on the concrete class
    would mean a test double had to either subclass a third-party socket or be excused by
    a type ignore at every call site, and neither says anything true: what the transport
    needs is these four methods.
    """

    def send(self, message: str) -> Any:
        """Send one text frame."""

    def recv(self) -> str | bytes:
        """Receive one frame. The library hands back either, so both are declared."""

    def settimeout(self, timeout: float) -> Any:
        """Set the socket timeout in seconds."""

    def close(self) -> Any:
        """Close the connection."""


class WebSocketTransport:
    """A :class:`Transport` backed by ``websocket-client``."""

    def __init__(self, socket: RawSocket) -> None:
        """
        :param socket: An already-connected socket. Prefer :meth:`connect`.
        """
        self._socket = socket

    @classmethod
    def connect(
        cls,
        url: str = DEFAULT_URL,
        origin: str = DEFAULT_ORIGIN,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> WebSocketTransport:
        """Open a connection to the plugin.

        :param url: The endpoint, loopback by default.
        :param origin: An Origin the server's allowlist accepts.
        :param timeout: Socket timeout in seconds, applied to connect and to every read.
        :return: The connected transport.
        :raises ConnectionFailed: On any failure to connect, with the likely cause named
            rather than the raw exception, since "KeePass is not running" and "the Origin
            was rejected" both surface here as a refused or closed socket.
        """
        try:
            socket = websocket.create_connection(url, timeout=timeout, origin=origin, enable_multithread=False)
        except Exception as exc:
            raise ConnectionFailed(
                f'cannot connect to KeePassRPC at {url}: {exc}. '
                'Check that KeePass is running with the plugin loaded, and that the Origin '
                f'{origin!r} is permitted.'
            ) from exc
        return cls(socket)

    def send(self, message: str) -> None:
        """Send one text frame.

        :raises ConnectionFailed: If the socket is gone.
        """
        try:
            self._socket.send(message)
        except Exception as exc:
            raise ConnectionFailed(f'failed to send to KeePassRPC: {exc}') from exc

    def receive(self) -> str:
        """Block for the next text frame.

        :raises ConnectionFailed: On timeout or a dropped connection.
        """
        try:
            frame = self._socket.recv()
        except Exception as exc:
            raise ConnectionFailed(f'failed to read from KeePassRPC: {exc}') from exc
        if isinstance(frame, bytes):
            return frame.decode('utf-8')
        return frame

    def set_timeout(self, timeout: float) -> None:
        """Change the read timeout on the live socket.

        :raises ConnectionFailed: If the socket will not accept the change.
        """
        try:
            self._socket.settimeout(timeout)
        except Exception as exc:
            raise ConnectionFailed(f'failed to set the socket timeout: {exc}') from exc

    def close(self) -> None:
        """Close the socket, ignoring an already-closed one."""
        # Closing is best effort: the caller is finished with the session either way, and
        # a failure here must not mask whatever they were actually doing.
        with contextlib.suppress(Exception):
            self._socket.close()


def send_json(transport: Transport, message: dict[str, Any]) -> None:
    """Serialise and send one protocol message."""
    transport.send(json.dumps(message))


def receive_json(transport: Transport) -> dict[str, Any]:
    """Receive one protocol message and raise on a server-level error.

    ``error`` at the top level of a message is the server refusing the conversation
    (rejected version, failed authentication), as distinct from a JSON-RPC ``error``
    inside an encrypted reply, which is a method that failed.

    :return: The decoded message.
    :raises ProtocolError: If the frame is not a JSON object, or carries an ``error``.
    """
    raw = transport.receive()
    try:
        message = json.loads(raw)
    except ValueError as exc:
        raise ProtocolError(f'server sent a frame that is not JSON: {raw[:200]!r}') from exc
    if not isinstance(message, dict):
        raise ProtocolError(f'server sent {type(message).__name__}, expected an object')
    if message.get('error'):
        raise ProtocolError(f'server rejected the exchange: {message["error"]!r}')
    return message
