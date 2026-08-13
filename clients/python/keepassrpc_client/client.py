"""The client itself: pairing, headless reconnect, and encrypted JSON-RPC calls.

Two entry points, matching the two things a caller ever does:

* :func:`pair`: interactive, once per identity. KeePass shows a code, a human types it,
  and the resulting session key goes into a :class:`~keepassrpc_client.keystore.KeyStore`.
* :meth:`KeePassRpcClient.connect`: headless, every run after that. Uses the stored key
  and pops no dialog, which is what makes unattended use possible.

Both verify the server's proof before returning. A client that skipped that check would
happily talk to anything listening on the port.

Three generations are wrapped: v1 and v2 as upstream serves them, and V3, the full-entry
API this repository adds. Anything unwrapped is reachable through
:meth:`KeePassRpcClient.call`.

The V3 methods differ from the rest in two ways that matter to a caller. They are guarded,
so a call can be refused because the subject's profile does not grant the method or because
the ACL does not grant the entry; and several of them raise a confirmation dialog in
KeePass, so they block on a person and use :data:`PROMPT_TIMEOUT` rather than the session's
read timeout.
"""

from __future__ import annotations

import base64
import hmac
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import TracebackType
from typing import Any

from . import crypto_v2, srp
from .crypto import decrypt, encrypt
from .errors import AuthenticationError, ProtocolError, RpcError
from .keystore import KeyStore, StoredKey
from .transport import (
    DEFAULT_ORIGIN,
    DEFAULT_TIMEOUT,
    DEFAULT_URL,
    Transport,
    WebSocketTransport,
    receive_json,
    send_json,
)

# The version field of every protocol message. The server derives its own from the plugin
# version and does not require the client to match it.
PROTOCOL_VERSION = 0

# The securityLevel the client claims, re-sent on every setup message as the server
# re-checks it. 2 is what a general client is expected to offer.
SECURITY_LEVEL = 2

# How long to wait on a call that raises a confirmation dialog in KeePass. It is not a
# network timeout at all: it is how long a person might reasonably take to notice a dialog
# and answer it. Measured against the real plugin, the ordinary read timeout is far too
# short and turns a working prompt into a spurious connection failure.
PROMPT_TIMEOUT = 300.0

# How many server-initiated messages to step over while waiting for one reply. A save emits
# two, so this is enormous slack; it exists only so that a confused server cannot hold a
# client in a read loop for ever.
MAX_SIGNALS_PER_CALL = 64

# Features offered to the server. The first two are in the plugin's `featuresRequired`
# list, so omitting either gets the connection rejected outright; the rest unlock v1
# behaviour a general (non-browser) client needs.
DEFAULT_FEATURES: tuple[str, ...] = (
    'KPRPC_FEATURE_VERSION_1_6',
    'KPRPC_FEATURE_WARN_USER_WHEN_FEATURE_MISSING',
    'KPRPC_GENERAL_CLIENTS',
    'KPRPC_FEATURE_KEE_BRAND',
    'KPRPC_ENTRIES_WITH_NO_URL',
    # The full-entry API. Declaring it is not the same as being allowed to use it: the
    # plugin still refuses every V3 call unless this client's subject holds a profile
    # granting those methods, and then refuses each entry the ACL does not allow.
    'KPRPC_FEATURE_DTO_V3',
    # Ephemeral per-session keys, HMAC-SHA256 and replay protection. The plugin falls back
    # to the original suite for any client that does not ask, so declaring this is the only
    # way to get it, and asking for it and silently not getting it is refused rather than
    # downgraded, since a client that believes it has forward secrecy and does not is worse
    # off than one that knows it does not.
    crypto_v2.FEATURE_NAME,
    # Pair in the 2048-bit RFC 5054 group rather than upstream's 512-bit one. Unlike the
    # flags above this one changes a calculation rather than unlocking a call, so both
    # ends have to agree before either computes anything: declaring it against a plugin
    # that does not offer it makes pairing fail the proof. Reconnects are unaffected --
    # the group only matters while pairing.
    srp.STRONG_GROUP_FEATURE,
)


class LoginSearchType(StrEnum):
    """Upstream's `LoginSearchType`, kept because the DTO still carries it.

    Upstream marks it unused and retained for backwards compatibility, so pass
    :attr:`ALL` unless you are reproducing an old client's behaviour exactly.

    The values are the C# enum's MEMBER NAMES, not its ordinals. Jayrock imports an enum
    from a JSON string and refuses a number outright, reporting "Cannot import
    LoginSearchType from a JSON Number value", so sending the ordinal fails the whole call. Found by calling
    `FindLogins` against a real plugin for the first time.
    """

    ALL = 'LSTall'
    NO_FORMS = 'LSTnoForms'
    NO_REALMS = 'LSTnoRealms'


@dataclass(frozen=True)
class ClientConfig:
    """Connection settings.

    :ivar url: The plugin endpoint. Loopback; the plugin does not listen off-host.
    :ivar origin: An Origin the server's allowlist accepts. See
        :data:`~keepassrpc_client.transport.DEFAULT_ORIGIN` for why this looks like a
        browser extension.
    :ivar timeout: Socket timeout in seconds, applied to connect and to every read. A
        pairing dialog waits on a human, so raise this when calling :func:`pair`.
    :ivar features: Feature flags offered to the server.
    :ivar security_level: The claimed security level.
    :ivar protocol_version: The version field on every message.
    """

    url: str = DEFAULT_URL
    origin: str = DEFAULT_ORIGIN
    timeout: float = DEFAULT_TIMEOUT
    features: tuple[str, ...] = DEFAULT_FEATURES
    security_level: int = SECURITY_LEVEL
    protocol_version: int = PROTOCOL_VERSION


@dataclass(frozen=True)
class ClientIdentity:
    """How this client introduces itself during pairing.

    The display name and description are shown in the KeePass authorisation dialog, so
    they are what a human reads when deciding whether to approve the pairing. Make them
    say which agent is asking.

    :ivar username: The SRP identity. The plugin stores one key per identity, and the ACL
        work in this repository assumes one identity per agent.
    :ivar display_name: Shown in the dialog.
    :ivar description: Shown in the dialog, beneath the name.
    :ivar type_id: The client type. ``general`` is the non-browser case, and requires the
        ``KPRPC_GENERAL_CLIENTS`` feature.
    """

    username: str
    display_name: str = 'KeePassRPC Python client'
    description: str = 'Test and automation client for the KeePassRPC v3 work'
    type_id: str = 'general'


@dataclass
class _Session:
    """An authorised transport and the key that protects traffic over it."""

    transport: Transport
    session_key: bytes
    username: str
    timeout: float = field(default=DEFAULT_TIMEOUT)
    next_id: int = field(default=1)
    # Present once the newer suite has been agreed; None means the original one.
    secure: crypto_v2.SessionCrypto | None = field(default=None)


def _setup_message(config: ClientConfig, body: dict[str, Any]) -> dict[str, Any]:
    """Build a ``setup`` message with the fields every one of them carries."""
    return {
        'protocol': 'setup',
        'version': config.protocol_version,
        'features': list(config.features),
        **body,
    }


def _complete_key_agreement(
    exchange: crypto_v2.Exchange,
    reply: dict[str, Any],
    paired_key: bytes,
    config: ClientConfig,
) -> crypto_v2.SessionCrypto | None:
    """Finish the ephemeral exchange the handshake carried, if the server took part.

    :param reply: The server message that completed authentication.
    :return: The negotiated session, or None if this client did not ask for the newer suite.
    :raises AuthenticationError: If we asked and the server did not answer, or answered with
        a proof that does not verify. Never falls back to the original suite: a client that
        believes it has forward secrecy and quietly does not is worse off than one that knows
        it does not have it.
    """
    if crypto_v2.FEATURE_NAME not in config.features:
        return None

    offered = reply.get('crypto') or {}
    server_public_b64 = offered.get('spub')
    proof_b64 = offered.get('proof')
    if not server_public_b64 or not proof_b64:
        raise AuthenticationError(
            'the server did not complete the key agreement this client asked for; refusing to '
            'continue on the weaker session crypto'
        )

    server_public = base64.b64decode(server_public_b64)
    agreed = exchange.agree_with(server_public)
    session_key = crypto_v2.derive_session_key(paired_key, exchange.public_key, server_public, agreed)

    expected = crypto_v2.kex_confirmation(session_key, exchange.public_key, server_public)
    if not hmac.compare_digest(expected, base64.b64decode(proof_b64)):
        raise AuthenticationError('key agreement proof mismatch; refusing to trust this session')

    return crypto_v2.SessionCrypto(session_key=session_key)


def pair(
    identity: ClientIdentity,
    get_code: Callable[[], str],
    key_store: KeyStore,
    config: ClientConfig | None = None,
    transport: Transport | None = None,
) -> StoredKey:
    """Perform the one-time SRP pairing and store the resulting session key.

    KeePass shows an authorisation dialog as soon as the first message arrives; ``get_code``
    is called to collect what it displays. The server's proof is verified before the key is
    stored, so a failed pairing leaves nothing behind.

    The socket is closed on return. Call :meth:`KeePassRpcClient.connect` to get a usable
    session, which keeps the interactive and headless paths from sharing state.

    :param identity: How to introduce this client.
    :param get_code: Called to obtain the authorisation code. Blocking is fine and
        expected; set a generous ``config.timeout`` to match.
    :param key_store: Where to persist the key on success.
    :param config: Connection settings; defaults are loopback.
    :param transport: An already-open transport, for tests. One is created when omitted.
    :return: The stored key.
    :raises AuthenticationError: If no code is supplied or the server proof fails.
    :raises ProtocolError: If the server answers out of sequence.
    """
    config = config or ClientConfig()
    session = srp.SrpClientSession(group=srp.group_for_features(config.features))
    owned = transport is None
    transport = transport or WebSocketTransport.connect(config.url, config.origin, config.timeout)
    try:
        send_json(
            transport,
            _setup_message(
                config,
                {
                    'clientTypeId': identity.type_id,
                    'clientDisplayName': identity.display_name,
                    'clientDisplayDescription': identity.description,
                    'srp': {
                        'stage': 'identifyToServer',
                        'I': identity.username,
                        'A': session.public_key_hex,
                        'securityLevel': config.security_level,
                    },
                },
            ),
        )
        response = receive_json(transport).get('srp') or {}
        if response.get('stage') != 'identifyToClient':
            raise ProtocolError(f'expected stage identifyToClient, got {response.get("stage")!r}')
        salt, server_public = response.get('s'), response.get('B')
        if not salt or not server_public:
            raise ProtocolError('server did not send both s and B')

        code = get_code()
        if not code:
            raise AuthenticationError('no authorisation code supplied; pairing abandoned')

        secrets_ = session.derive(salt, server_public, code)
        exchange = crypto_v2.Exchange()
        body: dict[str, Any] = {
            'srp': {
                'stage': 'proofToServer',
                'M': secrets_.client_proof,
                'securityLevel': config.security_level,
            }
        }
        if crypto_v2.FEATURE_NAME in config.features:
            # Carried on the proof rather than in a round of its own: the plugin refuses
            # setup messages once authorised, and before this point there is no shared key
            # to authenticate an exchange with.
            body['crypto'] = {'cpub': base64.b64encode(exchange.public_key).decode('ascii')}

        send_json(transport, _setup_message(config, body))
        reply = receive_json(transport)
        response = reply.get('srp') or {}
        if response.get('stage') != 'proofToClient':
            raise ProtocolError(f'expected stage proofToClient, got {response.get("stage")!r}')
        session.verify_server_proof(secrets_, response.get('M2') or '')
        _complete_key_agreement(exchange, reply, secrets_.session_key, config)

        stored = StoredKey(username=identity.username, key_hex=secrets_.session_key.hex())
        key_store.save(stored)
        return stored
    finally:
        if owned:
            transport.close()


class KeePassRpcClient:
    """An authorised session. Use as a context manager, or call :meth:`close`."""

    def __init__(self, session: _Session) -> None:
        """
        :param session: An authorised transport. Prefer :meth:`connect`.
        """
        self._session = session
        self._signals: list[dict[str, Any]] = []

    @classmethod
    def connect(
        cls,
        key_store: KeyStore,
        config: ClientConfig | None = None,
        transport: Transport | None = None,
    ) -> KeePassRpcClient:
        """Re-establish a session from a stored key, without any dialog.

        This is the path unattended workloads take. It verifies the server's ``sr``
        response before returning, so the caller never holds a session it has not
        authenticated.

        :param key_store: Where the paired key lives.
        :param config: Connection settings.
        :param transport: An already-open transport, for tests.
        :return: A ready client.
        :raises NotPaired: If no key is stored.
        :raises AuthenticationError: If the key is rejected or the server proof fails. An
            expired key surfaces here; the fix is to pair again.
        :raises ProtocolError: If the server answers out of sequence.
        """
        config = config or ClientConfig()
        stored = key_store.load()
        owned = transport is None
        transport = transport or WebSocketTransport.connect(config.url, config.origin, config.timeout)
        try:
            send_json(
                transport,
                _setup_message(
                    config,
                    {'key': {'username': stored.username, 'securityLevel': config.security_level}},
                ),
            )
            challenge = receive_json(transport).get('key') or {}
            server_nonce = challenge.get('sc')
            if not server_nonce:
                raise AuthenticationError('no server challenge; the stored key is unknown or expired, so pair again')

            client_nonce = srp.new_client_nonce()
            exchange = crypto_v2.Exchange()
            body: dict[str, Any] = {
                'key': {
                    'cc': client_nonce,
                    'cr': srp.client_challenge_response(stored.key_hex, server_nonce, client_nonce),
                    'securityLevel': config.security_level,
                }
            }
            if crypto_v2.FEATURE_NAME in config.features:
                # Carried on the challenge response for the same reason as in pair(): the
                # plugin refuses setup messages once authorised.
                body['crypto'] = {'cpub': base64.b64encode(exchange.public_key).decode('ascii')}

            send_json(transport, _setup_message(config, body))
            reply = receive_json(transport)
            confirmation = reply.get('key') or {}
            srp.verify_server_response(stored.key_hex, server_nonce, client_nonce, confirmation.get('sr') or '')
            secure = _complete_key_agreement(exchange, reply, bytes.fromhex(stored.key_hex), config)
        except Exception:
            if owned:
                transport.close()
            raise
        return cls(
            _Session(
                transport=transport,
                session_key=bytes.fromhex(stored.key_hex),
                username=stored.username,
                timeout=config.timeout,
                secure=secure,
            )
        )

    @property
    def username(self) -> str:
        """The identity this session is authenticated as."""
        return self._session.username

    def call(self, method: str, params: Sequence[Any] | None = None, timeout: float | None = None) -> Any:
        """Make one encrypted JSON-RPC call.

        :param method: The method name, spelled as upstream spells it.
        :param params: Positional parameters, in the order the C# signature declares them.
        :param timeout: A read timeout for this call only, restored afterwards. Needed for
            the calls that raise a confirmation dialog in KeePass, since those do not return
            until a person answers and no ordinary timeout should accommodate that.
        :return: The decoded ``result``.
        :raises RpcError: If the server returns a JSON-RPC error.
        :raises ProtocolError: If the reply is not a well-formed encrypted response.
        """
        if timeout is not None:
            self._session.transport.set_timeout(timeout)
            try:
                return self._call(method, params)
            finally:
                self._session.transport.set_timeout(self._session.timeout)

        return self._call(method, params)

    def _call(self, method: str, params: Sequence[Any] | None = None) -> Any:
        """Make one call at the session's current timeout."""
        session = self._session
        request = {'id': session.next_id, 'method': method, 'params': list(params or [])}
        session.next_id += 1
        send_json(
            session.transport,
            {
                'protocol': 'jsonrpc',
                'version': PROTOCOL_VERSION,
                'jsonrpc': self._seal(json.dumps(request)),
            },
        )
        # Read until our reply arrives, stepping over anything the server sent of its own
        # accord. The plugin pushes Signals such as DATABASE_SAVING and DATABASE_SAVED,
        # down the same socket, framed as jsonrpc REQUESTS rather than responses. Anything
        # that saves the database therefore emits one or two of them, so a client that
        # assumed the next frame was its answer would read a signal instead: the call that
        # triggered the save appears to succeed, and the NEXT call silently returns None.
        # The discriminator is the `method` member, which a response never carries.
        for _ in range(MAX_SIGNALS_PER_CALL):
            message = receive_json(session.transport)
            if 'jsonrpc' not in message:
                raise ProtocolError(f'expected a jsonrpc reply, got keys {sorted(message)}')

            body = json.loads(self._unseal(message['jsonrpc']))
            if 'method' in body:
                self._signals.append(body)
                continue

            if body.get('error'):
                raise RpcError(method, body['error'])
            return body.get('result')

        raise ProtocolError(f'{method}: gave up after {MAX_SIGNALS_PER_CALL} server-initiated messages with no reply')

    def _seal(self, plaintext: str) -> dict[str, str]:
        """Encrypt one outgoing message with whichever suite was negotiated."""
        session = self._session
        if session.secure is None:
            return encrypt(plaintext, session.session_key)

        sealed = crypto_v2.encrypt(plaintext, session.secure.session_key, session.secure.outgoing)
        session.secure.outgoing += 1
        return sealed

    def _unseal(self, container: Any) -> str:
        """Verify and decrypt one incoming message.

        The counter advances for signals as well as replies, because the plugin encrypts
        those through the same path and they consume sequence numbers on the way.
        """
        session = self._session
        if session.secure is None:
            return decrypt(container, session.session_key)

        plaintext = crypto_v2.decrypt(container, session.secure.session_key, session.secure.incoming)
        session.secure.incoming += 1
        return plaintext

    @property
    def secure_session(self) -> bool:
        """Whether this session negotiated the stronger crypto suite."""
        return self._session.secure is not None

    @property
    def signals(self) -> list[dict[str, Any]]:
        """Server-initiated messages seen so far, oldest first.

        The plugin uses these to announce database lifecycle events. Nothing here acts on
        them; they are collected rather than discarded so that a caller who cares can look,
        and so that stepping over them is visible rather than silent.
        """
        return self._signals

    # --- metadata and databases ---------------------------------------------------

    def get_application_metadata(self) -> Any:
        """Return the plugin's metadata, including its version."""
        return self.call('GetApplicationMetadata')

    def get_current_config(self) -> Any:
        """Return the plugin's current client-facing configuration."""
        return self.call('GetCurrentKFConfig')

    def get_database_name(self) -> str:
        """Return the active database's display name."""
        return str(self.call('GetDatabaseName'))

    def get_database_file_name(self) -> str:
        """Return the active database's file path."""
        return str(self.call('GetDatabaseFileName'))

    def get_all_databases(self, full_details: bool = False) -> Any:
        """List every open database (v1 DTO).

        :param full_details: Include each database's full group and entry tree. Expensive,
            and on a large database it returns a great deal of secret material, so leave it
            off unless the caller genuinely needs the tree.
        """
        return self.call('GetAllDatabases', [full_details])

    def all_databases(self, full_details: bool = False) -> Any:
        """List every open database (v2 DTO)."""
        return self.call('AllDatabases', [full_details])

    # --- reading entries and groups -----------------------------------------------

    def get_root(self) -> Any:
        """Return the active database's root group."""
        return self.call('GetRoot')

    def get_parent(self, uuid: str) -> Any:
        """Return the parent group of an entry or group."""
        return self.call('GetParent', [uuid])

    def get_child_groups(self, uuid: str) -> Any:
        """Return the immediate child groups of a group."""
        return self.call('GetChildGroups', [uuid])

    def get_child_entries(self, uuid: str) -> Any:
        """Return the immediate child entries of a group."""
        return self.call('GetChildEntries', [uuid])

    def get_all_child_entries(self, uuid: str) -> Any:
        """Return every entry beneath a group, recursively."""
        return self.call('GetAllChildEntries', [uuid])

    def get_all_logins(self) -> Any:
        """Return every entry that has a URL, across open databases."""
        return self.call('GetAllLogins')

    def get_all_entries(self) -> Any:
        """Return every entry, including those with no URL."""
        return self.call('GetAllEntries')

    def find_logins(
        self,
        urls: Sequence[str] | None = None,
        action_url: str = '',
        http_realm: str = '',
        search_type: LoginSearchType = LoginSearchType.ALL,
        require_full_url_matches: bool = False,
        unique_id: str = '',
        db_file_name: str = '',
        free_text_search: str = '',
        username: str = '',
    ) -> Any:
        """Search for entries (v1 DTO).

        The parameters are upstream's, in upstream's order. Note that a title search goes
        through ``free_text_search`` and matches case-sensitively across every open
        database, which is exactly the addressing weakness the V3 work in this repository
        replaces with UUID-first lookup. Prefer ``unique_id`` where you have it.

        :param urls: URLs to match.
        :param action_url: Form action URL.
        :param http_realm: HTTP auth realm.
        :param search_type: Retained for DTO compatibility; upstream ignores it.
        :param require_full_url_matches: Require the whole URL to match, not just the host.
        :param unique_id: An entry UUID. The only unambiguous way to name an entry.
        :param db_file_name: Restrict to one open database by file path.
        :param free_text_search: Free-text search, including titles.
        :param username: Restrict to a username.
        """
        return self.call(
            'FindLogins',
            [
                list(urls or []),
                action_url,
                http_realm,
                search_type.value,
                require_full_url_matches,
                unique_id,
                db_file_name,
                free_text_search,
                username,
            ],
        )

    # --- V3: the full-entry API ------------------------------------------------------

    def get_entry3(self, identifier: str) -> Any:
        """Read one entry in full, through the V3 API.

        Unlike the v1 and v2 reads, this returns the entry as KeePass holds it: real custom
        strings from the entry's own string list, the notes, and the names of attachments.
        Empty values are present rather than dropped, so a deliberately blank placeholder
        survives the round trip.

        :param identifier: A 32 character hex UUID, or an exact title. Prefer the UUID: a
            title that matches more than one entry is refused rather than guessed at.
        :raises RpcError: If the entry does not exist, the identifier is ambiguous, or the
            ACL does not grant this subject ``read`` on it.
        """
        return self.call('GetEntry3', [identifier])

    def list_group3(self, identifier: str) -> Any:
        """List the entries directly inside a group, titles and UUIDs only.

        Entries this subject may not even list are omitted rather than reported as
        forbidden, so the result is not a way to discover what exists behind a denial.

        :param identifier: A 32 character hex UUID, or an exact slash-separated path.
        """
        return self.call('ListGroup3', [identifier])

    def get_attachment3(self, identifier: str, name: str, timeout: float = PROMPT_TIMEOUT) -> bytes:
        """Fetch one attachment's content.

        Needs ``read`` plus the ``attachments`` flag, and unless the subject's grant says
        ``unattended`` it also raises a confirmation dialog in KeePass that a human has to
        accept. This call therefore blocks for as long as that takes, which is why it uses
        :data:`PROMPT_TIMEOUT` rather than the session's ordinary read timeout, with the
        default ten seconds it reliably times out on a prompt that is working correctly.

        :param identifier: A 32 character hex UUID, or an exact title.
        :param name: The attachment name, as reported by :meth:`get_entry3`.
        :param timeout: How long to wait. Pass the session default explicitly if you would
            rather fail fast than wait on a person.
        :return: The decoded content.
        """
        encoded = self.call('GetAttachment3', [identifier, name], timeout=timeout)
        return base64.b64decode(str(encoded))

    def add_entry3(self, group: str, entry: dict[str, Any], timeout: float = PROMPT_TIMEOUT) -> Any:
        """Create an entry in a group.

        :param group: A 32 character hex UUID, or an exact slash-separated group path.
        :param entry: An ``Entry3``. Omitted members become empty. Any ``uuid`` is ignored,
            and so are ``attachments``, which have their own methods.
        :param timeout: Prompts by default, so this waits on a person.
        :return: The entry as stored, including its assigned UUID.
        """
        return self.call('AddEntry3', [group, entry], timeout=timeout)

    def update_entry3(self, identifier: str, entry: dict[str, Any], timeout: float = PROMPT_TIMEOUT) -> Any:
        """Update an entry in place.

        Mind the two different meanings of "not supplied", because they are the difference
        between a partial update and a destructive one:

        * A standard member that is **absent or None** is left alone; an **empty string**
          sets it empty.
        * ``fields`` **absent or None** leaves the custom strings alone. A **list**, even an
          empty one, REPLACES them, so any name not in it is deleted.

        The natural safe shape is read-modify-write: take what :meth:`get_entry3` returned,
        change what you mean to change, send it back. KeePass keeps the previous state in
        entry history either way.

        :param identifier: A 32 character hex UUID, or an exact title.
        :param entry: The changes. ``group`` is ignored; the plugin will not move an entry.
        """
        return self.call('UpdateEntry3', [identifier, entry], timeout=timeout)

    def remove_entry3(self, identifier: str, timeout: float = PROMPT_TIMEOUT) -> bool:
        """Delete an entry, to the recycle bin where the database has one.

        Needs the ``delete`` verb, which is the top of the ladder and above ``write``.

        :param identifier: A 32 character hex UUID, or an exact title.
        """
        return bool(self.call('RemoveEntry3', [identifier], timeout=timeout))

    def set_attachment3(self, identifier: str, name: str, content: bytes, timeout: float = PROMPT_TIMEOUT) -> Any:
        """Add or replace an attachment.

        Needs ``write`` plus the ``attachments`` flag: a subject trusted to change a password
        is not thereby trusted to plant a key file.

        :param identifier: A 32 character hex UUID, or an exact title.
        :param name: The attachment name; replaces any existing one.
        :param content: Raw bytes, encoded for the wire here.
        """
        encoded = base64.b64encode(content).decode('ascii')
        return self.call('SetAttachment3', [identifier, name, encoded], timeout=timeout)

    def remove_attachment3(self, identifier: str, name: str, timeout: float = PROMPT_TIMEOUT) -> bool:
        """Remove an attachment.

        Needs ``write`` plus the ``attachments`` flag. This modifies an entry rather than
        removing one, so it does not need ``delete``, and the previous state goes into entry
        history.
        """
        return bool(self.call('RemoveAttachment3', [identifier, name], timeout=timeout))

    # --- writing ------------------------------------------------------------------

    def add_login(self, entry: dict[str, Any], parent_uuid: str, db_file_name: str = '') -> Any:
        """Create an entry from a v1 DTO.

        :param entry: A v1 ``Entry`` DTO.
        :param parent_uuid: The group to create it in.
        :param db_file_name: Which open database, by file path. Defaults to the active one.
        """
        return self.call('AddLogin', [entry, parent_uuid, db_file_name])

    def update_login(
        self,
        entry: dict[str, Any],
        old_entry_uuid: str,
        url_merge_mode: int = 4,
        db_file_name: str = '',
    ) -> Any:
        """Update an entry from a v1 DTO.

        Be aware of what this does upstream: the v1 update path replaces the entry's field
        set wholesale rather than merging it, so a partial DTO loses fields. That behaviour
        is why V3 writes in this repository deliberately do not route through it.

        :param entry: A v1 ``Entry`` DTO.
        :param old_entry_uuid: The entry to replace.
        :param url_merge_mode: Upstream's URL merge mode; 4 leaves existing URLs untouched.
        :param db_file_name: Which open database, by file path.
        """
        return self.call('UpdateLogin', [entry, old_entry_uuid, url_merge_mode, db_file_name])

    def add_group(self, name: str, parent_uuid: str) -> Any:
        """Create a group."""
        return self.call('AddGroup', [name, parent_uuid])

    def remove_entry(self, uuid: str) -> bool:
        """Delete an entry.

        :return: Whether the entry was removed.
        """
        return bool(self.call('RemoveEntry', [uuid]))

    def remove_group(self, uuid: str) -> bool:
        """Delete a group and everything in it.

        :return: Whether the group was removed.
        """
        return bool(self.call('RemoveGroup', [uuid]))

    def generate_password(self, profile_name: str = '', url: str = '') -> str:
        """Ask KeePass to generate a password using one of its profiles."""
        return str(self.call('GeneratePassword', [profile_name, url]))

    def get_password_profiles(self) -> Any:
        """List the available password generator profiles."""
        return self.call('GetPasswordProfiles')

    # --- lifecycle ------------------------------------------------------------------

    def close(self) -> None:
        """Close the session."""
        self._session.transport.close()

    def __enter__(self) -> KeePassRpcClient:
        """Return self, so the client can be used in a ``with`` block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the session on the way out."""
        self.close()
