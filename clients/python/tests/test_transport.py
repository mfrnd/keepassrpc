"""Transport framing and its failure handling."""

from __future__ import annotations

from typing import Any

import pytest

from keepassrpc_client.errors import ConnectionFailed, ProtocolError
from keepassrpc_client.transport import (
    DEFAULT_ORIGIN,
    DEFAULT_URL,
    WebSocketTransport,
    receive_json,
    send_json,
)


class FakeSocket:
    """Stands in for a ``websocket.WebSocket``."""

    def __init__(self, incoming: list[Any] | None = None, fail: bool = False) -> None:
        self.incoming = list(incoming or [])
        self.fail = fail
        self.sent: list[str] = []
        self.closed = False

    def send(self, message: str) -> None:
        if self.fail:
            raise OSError('socket is gone')
        self.sent.append(message)

    def recv(self) -> Any:
        if self.fail:
            raise OSError('timed out')
        return self.incoming.pop(0)

    def close(self) -> None:
        if self.fail:
            raise OSError('cannot close')
        self.closed = True

    def settimeout(self, timeout: float) -> None:
        if self.fail:
            raise OSError('cannot set timeout')
        self.timeout = timeout


def test_defaults_point_at_loopback() -> None:
    """The plugin binds 127.0.0.1 only, per its bindOnlyToLoopback default."""
    assert DEFAULT_URL == 'ws://127.0.0.1:12546'


def test_default_origin_matches_the_servers_allowlist() -> None:
    """The server prefix-matches Origin against browser extension schemes by default.

    A client presenting anything else is dropped at connect time, which is why this looks
    like an extension despite not being one.
    """
    permitted = (
        'resource://gre-resources',
        'ms-browser-extension://',
        'safari-web-extension://',
        'moz-extension://',
        'chrome-extension://',
    )
    assert DEFAULT_ORIGIN.startswith(permitted)


def test_send_and_receive_roundtrip() -> None:
    """Frames are JSON objects in both directions."""
    socket = FakeSocket(incoming=['{"protocol":"setup"}'])
    transport = WebSocketTransport(socket)

    send_json(transport, {'protocol': 'setup', 'version': 0})
    assert socket.sent == ['{"protocol": "setup", "version": 0}']
    assert receive_json(transport) == {'protocol': 'setup'}


def test_receive_decodes_binary_frames() -> None:
    """Some stacks hand back bytes; treat them as UTF-8 rather than failing."""
    transport = WebSocketTransport(FakeSocket(incoming=[b'{"protocol":"setup"}']))
    assert receive_json(transport) == {'protocol': 'setup'}


def test_receive_raises_on_a_server_error_member() -> None:
    """A top-level error is the server refusing the conversation."""
    transport = WebSocketTransport(FakeSocket(incoming=['{"error":{"code":"AUTH_FAILED"}}']))
    with pytest.raises(ProtocolError, match='rejected the exchange'):
        receive_json(transport)


def test_receive_raises_on_non_json() -> None:
    """Garbage on the wire fails cleanly and quotes only a bounded prefix."""
    transport = WebSocketTransport(FakeSocket(incoming=['not json at all']))
    with pytest.raises(ProtocolError, match='not JSON'):
        receive_json(transport)


def test_receive_raises_on_a_json_non_object() -> None:
    """A bare array is well-formed JSON but not a protocol message."""
    transport = WebSocketTransport(FakeSocket(incoming=['[1,2,3]']))
    with pytest.raises(ProtocolError, match='expected an object'):
        receive_json(transport)


def test_send_failure_is_wrapped() -> None:
    """Socket errors surface as this package's exception type."""
    transport = WebSocketTransport(FakeSocket(fail=True))
    with pytest.raises(ConnectionFailed, match='failed to send'):
        transport.send('{}')


def test_receive_failure_is_wrapped() -> None:
    """A read timeout is a connection failure, not a protocol error."""
    transport = WebSocketTransport(FakeSocket(fail=True))
    with pytest.raises(ConnectionFailed, match='failed to read'):
        transport.receive()


def test_close_is_best_effort() -> None:
    """Closing a broken socket must not raise over whatever the caller was doing."""
    WebSocketTransport(FakeSocket(fail=True)).close()


def test_close_closes_a_healthy_socket() -> None:
    """The ordinary path still closes."""
    socket = FakeSocket()
    WebSocketTransport(socket).close()
    assert socket.closed is True


def test_set_timeout_reaches_the_socket() -> None:
    """Prompted calls raise the read timeout, so it has to actually apply."""
    socket = FakeSocket()
    WebSocketTransport(socket).set_timeout(300.0)
    assert socket.timeout == 300.0


def test_set_timeout_failure_is_wrapped() -> None:
    """A socket that refuses the change is a connection failure, not a silent no-op."""
    with pytest.raises(ConnectionFailed, match='timeout'):
        WebSocketTransport(FakeSocket(fail=True)).set_timeout(1.0)


def test_connect_failure_names_the_likely_causes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The error has to be actionable: KeePass down, or Origin rejected."""

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise OSError('connection refused')

    monkeypatch.setattr('websocket.create_connection', refuse)
    with pytest.raises(ConnectionFailed, match='Origin'):
        WebSocketTransport.connect()


def test_connect_passes_url_origin_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Origin in particular must reach the server or the connection is dropped."""
    captured: dict[str, Any] = {}

    def capture(url: str, **kwargs: Any) -> FakeSocket:
        captured['url'] = url
        captured.update(kwargs)
        return FakeSocket()

    monkeypatch.setattr('websocket.create_connection', capture)
    WebSocketTransport.connect('ws://127.0.0.1:9999', 'moz-extension://x', 3.5)

    assert captured['url'] == 'ws://127.0.0.1:9999'
    assert captured['origin'] == 'moz-extension://x'
    assert captured['timeout'] == 3.5
