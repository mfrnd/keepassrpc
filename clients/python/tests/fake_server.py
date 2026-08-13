"""A fake KeePassRPC server, implemented from the C# rather than from the client.

This is the point of the test suite. The client's maths is only interesting if it
interoperates with an independent implementation of the other side, so the SRP and
key-challenge logic here is written straight from `SRP.cs` and `KeyChallengeResponse.cs`:

* ``M = H(A || B || S)`` with the hex spellings as sent, and ``B`` deliberately not
  reduced modulo N, matching `SRP.Setup`.
* ``M2 = H(A || M.lower() || S)``.
* ``cr = H('1' + key + sc + cc)`` and ``sr = H('0' + key + sc + cc)``.

If the client and this file were derived from each other, agreement between them would
prove nothing. They are both derived from the C#.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from keepassrpc_client import crypto, crypto_v2
from keepassrpc_client.srp import (
    LEGACY_512,
    SrpGroup,
    group_for_features,
    int_from_bytes,
    sha256_bytes,
    sha256_hex,
    to_hex,
)


class FakeTransportClosed(RuntimeError):
    """Raised when the client reads past the end of a scripted exchange."""


class ScriptedTransport:
    """A transport that replays a fixed list of server frames.

    :ivar sent: Everything the client sent, decoded, in order. Assert against it.
    """

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        """
        :param responses: Frames to hand back, one per :meth:`receive`.
        """
        self._responses = list(responses)
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    def send(self, message: str) -> None:
        """Record a frame from the client."""
        self.sent.append(json.loads(message))

    def receive(self) -> str:
        """Return the next scripted frame."""
        if not self._responses:
            raise FakeTransportClosed('the client asked for more frames than the script provides')
        return json.dumps(self._responses.pop(0))

    def close(self) -> None:
        """Mark the transport closed."""
        self.closed = True

    def set_timeout(self, timeout: float) -> None:
        """Record the requested timeout; there is no socket to apply it to."""
        self.timeout = timeout


class FakeServer:
    """The server half of the protocol, driven by whatever the client sends.

    Unlike :class:`ScriptedTransport` this actually computes, so it catches a client whose
    maths is wrong rather than merely one whose message shapes are wrong.
    """

    def __init__(
        self,
        password: str = '123456',
        private_key: int = 0x5EED,
        salt: str = '12345678901234567890',
        group: SrpGroup | None = None,
    ) -> None:
        """
        :param password: The authorisation code the "dialog" is showing.
        :param private_key: The server's ephemeral exponent ``b``. Fixed so tests are
            reproducible.
        :param salt: The salt ``s``, a decimal string as `CalculatePasswordHash` produces.
        :param group: Pin the group instead of negotiating it, which is how a test forces
            a mismatch. Left None, this picks the group from the features the client
            declares, exactly as the plugin does in `SRPIdentifyToServer`.
        """
        self.password = password
        self.salt = salt
        self._pinned_group = group
        self._b = private_key
        self._use_group(group or LEGACY_512)
        self.session_key: bytes | None = None
        self.sent: list[dict[str, Any]] = []
        self.received: list[dict[str, Any]] = []
        # Key-challenge state.
        self.server_nonce = '987654321098765432109876543210'
        self.stored_key_hex: str | None = None
        self.rpc_results: dict[str, Any] = {}
        self.rpc_errors: dict[str, Any] = {}
        # How many Signals to push ahead of the next reply. The real plugin emits these
        # whenever the database is saved, framed as requests rather than responses.
        self.signals_before_reply = 0
        self._callback_id = 0
        # The negotiated session crypto, once agreed. None means the original suite, which
        # is what a client that does not declare the feature keeps using.
        self.secure: crypto_v2.SessionCrypto | None = None
        self.client_declared_crypto_v2 = True

    def _use_group(self, group: SrpGroup) -> None:
        """Settle the group and derive everything that depends on N.

        Separate from __init__ because the plugin does not know the group until the
        client's first message either: A has already been computed in whichever group the
        client chose, and every value from there on is relative to N.
        """
        self.group = group
        self._x = int_from_bytes(sha256_bytes((self.salt + self.password).encode('utf-8')))
        self._v = pow(group.g, self._x, group.n)
        # B = k*v + g^b, deliberately not reduced mod N, exactly as SRP.cs leaves it.
        self._B = (group.k * self._v) + pow(group.g, self._b, group.n)

    @property
    def public_key_hex(self) -> str:
        """``B`` in the hex spelling the client will hash."""
        return to_hex(self._B)

    def _compute(self, a_hex: str) -> tuple[str, str, str]:
        """Run the server-side SRP calculation for a given ``A``.

        :return: ``(shared_hex, M, M2)``.
        """
        a_value = int(a_hex, 16)
        u = int_from_bytes(sha256_bytes((a_hex + self.public_key_hex).encode('utf-8')))
        shared = pow(a_value * pow(self._v, u, self.group.n), self._b, self.group.n)
        shared_hex = to_hex(shared)
        m = sha256_hex(a_hex + self.public_key_hex + shared_hex)
        m2 = sha256_hex(a_hex + m.lower() + shared_hex)
        return shared_hex, m, m2

    def respond(self, message: dict[str, Any]) -> dict[str, Any]:
        """Produce the reply to one client message."""
        self.received.append(message)
        self._last_setup = message
        reply = self._respond(message)
        self.sent.append(reply)
        return reply

    def _negotiate(self, message: dict[str, Any], paired_key: bytes) -> dict[str, Any] | None:
        """Complete the key agreement the client attached to its final auth message.

        Mirrors `CryptoV2.cs`: the session key is derived from the agreed secret AND the
        paired key, so a peer without the latter cannot reach it.
        """
        offered = message.get('crypto') or {}
        if not offered.get('cpub') or not self.client_declared_crypto_v2:
            return None

        client_public = base64.b64decode(offered['cpub'])
        exchange = crypto_v2.Exchange()
        agreed = exchange.agree_with(client_public)
        session_key = crypto_v2.derive_session_key(paired_key, client_public, exchange.public_key, agreed)
        self.secure = crypto_v2.SessionCrypto(session_key=session_key)
        return {
            'spub': base64.b64encode(exchange.public_key).decode('ascii'),
            'proof': base64.b64encode(
                crypto_v2.kex_confirmation(session_key, client_public, exchange.public_key)
            ).decode('ascii'),
        }

    def _seal(self, plaintext: str) -> dict[str, str]:
        assert self.session_key is not None
        if self.secure is None:
            return crypto.encrypt(plaintext, self.session_key)
        sealed = crypto_v2.encrypt(plaintext, self.secure.session_key, self.secure.outgoing)
        self.secure.outgoing += 1
        return sealed

    def _unseal(self, container: Any) -> str:
        assert self.session_key is not None
        if self.secure is None:
            return crypto.decrypt(container, self.session_key)
        plaintext = crypto_v2.decrypt(container, self.secure.session_key, self.secure.incoming)
        self.secure.incoming += 1
        return plaintext

    def _respond(self, message: dict[str, Any]) -> dict[str, Any]:
        if message.get('protocol') == 'jsonrpc':
            return self._respond_jsonrpc(message)
        if 'srp' in message:
            return self._respond_srp(message['srp'], message.get('features'))
        if 'key' in message:
            return self._respond_key(message['key'])
        return {'protocol': 'setup', 'version': 0, 'error': {'code': 'UNRECOGNISED'}}

    def _respond_srp(self, srp_message: dict[str, Any], features: Any = None) -> dict[str, Any]:
        stage = srp_message.get('stage')
        if stage == 'identifyToServer':
            if self._pinned_group is None:
                self._use_group(group_for_features(features))
            self._a_hex = str(srp_message['A'])
            return {
                'protocol': 'setup',
                'version': 0,
                'srp': {'stage': 'identifyToClient', 's': self.salt, 'B': self.public_key_hex},
            }
        if stage == 'proofToServer':
            shared_hex, m, m2 = self._compute(self._a_hex)
            if str(srp_message.get('M', '')).lower() != m.lower():
                return {'protocol': 'setup', 'version': 0, 'error': {'code': 'AUTH_FAILED'}}
            self.session_key = sha256_bytes(shared_hex.encode('utf-8'))
            self.stored_key_hex = self.session_key.hex()
            reply: dict[str, Any] = {
                'protocol': 'setup',
                'version': 0,
                'srp': {'stage': 'proofToClient', 'M2': m2},
            }
            agreed = self._negotiate(self._last_setup, self.session_key)
            if agreed:
                reply['crypto'] = agreed
            return reply
        return {'protocol': 'setup', 'version': 0, 'error': {'code': 'UNEXPECTED_STAGE'}}

    def _respond_key(self, key_message: dict[str, Any]) -> dict[str, Any]:
        if 'username' in key_message:
            return {'protocol': 'setup', 'version': 0, 'key': {'sc': self.server_nonce}}
        assert self.stored_key_hex is not None, 'the fake server was not paired first'
        client_nonce = str(key_message['cc'])
        expected = sha256_hex('1' + self.stored_key_hex + self.server_nonce + client_nonce)
        if str(key_message.get('cr', '')).lower() != expected.lower():
            return {'protocol': 'setup', 'version': 0, 'error': {'code': 'AUTH_FAILED'}}
        self.session_key = bytes.fromhex(self.stored_key_hex)
        reply: dict[str, Any] = {
            'protocol': 'setup',
            'version': 0,
            'key': {'sr': sha256_hex('0' + self.stored_key_hex + self.server_nonce + client_nonce)},
        }
        agreed = self._negotiate(self._last_setup, self.session_key)
        if agreed:
            reply['crypto'] = agreed
        return reply

    def next_signal(self) -> dict[str, Any]:
        """One Signal frame, shaped exactly as `KeePassRPCClient.Signal` builds it."""
        assert self.session_key is not None
        self._callback_id += 1
        body = {'id': self._callback_id, 'method': 'KPRPCListener', 'params': [8]}
        return {
            'protocol': 'jsonrpc',
            'version': 0,
            'jsonrpc': self._seal(json.dumps(body)),
        }

    def _respond_jsonrpc(self, message: dict[str, Any]) -> dict[str, Any]:
        assert self.session_key is not None, 'a jsonrpc call arrived before authentication'
        request = json.loads(self._unseal(message['jsonrpc']))
        method = request['method']
        self.last_request = request
        if method in self.rpc_errors:
            body: dict[str, Any] = {'id': request['id'], 'error': self.rpc_errors[method]}
        else:
            body = {'id': request['id'], 'result': self.rpc_results.get(method)}
        return {
            'protocol': 'jsonrpc',
            'version': 0,
            'jsonrpc': self._seal(json.dumps(body)),
        }


class LiveTransport:
    """A transport wired directly to a :class:`FakeServer`, with no sockets involved."""

    def __init__(self, server: FakeServer) -> None:
        """
        :param server: The server to drive.
        """
        self.server = server
        self._queue: list[str] = []
        self.closed = False

    def send(self, message: str) -> None:
        """Hand a frame to the server and queue any signals ahead of its reply.

        Signals only accompany an authorised jsonrpc exchange, matching the plugin:
        `KeePassRPCClient.Signal` returns early when there is no key container, so an
        unauthenticated connection never receives one.
        """
        decoded = json.loads(message)

        # Signals are sealed BEFORE the reply, not after, because they are sent first and
        # the sequence numbers have to match the order they arrive in. Getting this backwards
        # made the fake emit a reply numbered ahead of the signals in front of it, which the
        # client correctly refused as reordered.
        if decoded.get('protocol') == 'jsonrpc' and self.server.session_key is not None:
            for _ in range(self.server.signals_before_reply):
                self._queue.append(json.dumps(self.server.next_signal()))

        self._queue.append(json.dumps(self.server.respond(decoded)))

    def receive(self) -> str:
        """Return the next queued frame: signals first, then the reply."""
        if not self._queue:
            raise FakeTransportClosed('receive() with no pending reply')
        return self._queue.pop(0)

    def close(self) -> None:
        """Mark the transport closed."""
        self.closed = True

    def set_timeout(self, timeout: float) -> None:
        """Record the requested timeout; there is no socket to apply it to."""
        self.timeout = timeout
