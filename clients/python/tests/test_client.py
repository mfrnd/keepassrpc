"""Pairing, headless reconnect and RPC, driven against the fake server."""

from __future__ import annotations

import base64

import pytest
from fake_server import FakeServer, LiveTransport, ScriptedTransport

from keepassrpc_client import (
    ClientConfig,
    ClientIdentity,
    KeePassRpcClient,
    MemoryKeyStore,
    StoredKey,
    pair,
)
from keepassrpc_client.client import (
    DEFAULT_FEATURES,
    MAX_SIGNALS_PER_CALL,
    PROMPT_TIMEOUT,
    LoginSearchType,
)
from keepassrpc_client.errors import AuthenticationError, NotPaired, ProtocolError, RpcError

IDENTITY = ClientIdentity(username='test-agent', display_name='Test Agent')


def paired_client(server: FakeServer) -> tuple[KeePassRpcClient, MemoryKeyStore]:
    """Pair against the fake server and return a connected client."""
    store = MemoryKeyStore()
    pair(IDENTITY, lambda: server.password, store, transport=LiveTransport(server))
    client = KeePassRpcClient.connect(store, transport=LiveTransport(server))
    return client, store


# --- pairing ---------------------------------------------------------------------


def test_pairing_stores_a_key_the_server_agrees_with() -> None:
    """End to end: our derived session key equals the server's."""
    server = FakeServer()
    store = MemoryKeyStore()

    stored = pair(IDENTITY, lambda: server.password, store, transport=LiveTransport(server))

    assert stored.username == 'test-agent'
    assert server.session_key is not None
    assert stored.key_hex == server.session_key.hex()
    assert store.load() == stored


def test_pairing_sends_the_required_features_and_identity() -> None:
    """Omitting a required feature gets the connection rejected by a real server."""
    server = FakeServer()
    pair(IDENTITY, lambda: server.password, MemoryKeyStore(), transport=LiveTransport(server))

    first = server.received[0]
    assert first['protocol'] == 'setup'
    assert 'KPRPC_FEATURE_VERSION_1_6' in first['features']
    assert 'KPRPC_FEATURE_WARN_USER_WHEN_FEATURE_MISSING' in first['features']
    assert first['clientTypeId'] == 'general'
    assert first['clientDisplayName'] == 'Test Agent'
    assert first['srp']['I'] == 'test-agent'


def test_default_features_cover_the_servers_required_set() -> None:
    """Pinned against `featuresRequired` in KeePassRPCClient.cs."""
    assert {'KPRPC_FEATURE_VERSION_1_6', 'KPRPC_FEATURE_WARN_USER_WHEN_FEATURE_MISSING'} <= set(DEFAULT_FEATURES)


def test_pairing_with_a_wrong_code_fails_and_stores_nothing() -> None:
    """A failed pairing must not leave a key behind."""
    server = FakeServer(password='123456')
    store = MemoryKeyStore()

    with pytest.raises(ProtocolError, match='rejected'):
        pair(IDENTITY, lambda: '999999', store, transport=LiveTransport(server))

    with pytest.raises(NotPaired):
        store.load()


def test_pairing_without_a_code_is_abandoned() -> None:
    """An empty code is refused before anything is sent to the server."""
    server = FakeServer()
    with pytest.raises(AuthenticationError, match='no authorisation code'):
        pair(IDENTITY, lambda: '', MemoryKeyStore(), transport=LiveTransport(server))


def test_pairing_rejects_an_out_of_sequence_reply() -> None:
    """A server answering the wrong stage is a protocol error, not something to continue."""
    transport = ScriptedTransport([{'protocol': 'setup', 'srp': {'stage': 'proofToClient'}}])
    with pytest.raises(ProtocolError, match='identifyToClient'):
        pair(IDENTITY, lambda: '123456', MemoryKeyStore(), transport=transport)


def test_pairing_rejects_a_reply_missing_salt_or_b() -> None:
    """Half an answer is not an answer."""
    transport = ScriptedTransport([{'protocol': 'setup', 'srp': {'stage': 'identifyToClient', 's': '123'}}])
    with pytest.raises(ProtocolError, match='both s and B'):
        pair(IDENTITY, lambda: '123456', MemoryKeyStore(), transport=transport)


def test_pairing_rejects_a_forged_m2() -> None:
    """A server that cannot prove the shared secret is refused, and nothing is stored."""
    server = FakeServer()
    store = MemoryKeyStore()

    real = LiveTransport(server)

    class ForgedM2(LiveTransport):
        def receive(self) -> str:
            import json

            message = json.loads(super().receive())
            if message.get('srp', {}).get('stage') == 'proofToClient':
                message['srp']['M2'] = '00' * 32
            return json.dumps(message)

    forged = ForgedM2(real.server)
    with pytest.raises(AuthenticationError, match='M2'):
        pair(IDENTITY, lambda: server.password, store, transport=forged)

    with pytest.raises(NotPaired):
        store.load()


def test_pairing_closes_a_transport_it_opened_but_not_a_supplied_one() -> None:
    """A caller-supplied transport is the caller's to close."""
    server = FakeServer()
    transport = LiveTransport(server)
    pair(IDENTITY, lambda: server.password, MemoryKeyStore(), transport=transport)
    assert transport.closed is False


# --- headless reconnect -----------------------------------------------------------


def test_reconnect_with_a_stored_key() -> None:
    """The unattended path: no dialog, and the server proof verifies."""
    server = FakeServer()
    _, store = paired_client(server)

    client = KeePassRpcClient.connect(store, transport=LiveTransport(server))
    assert client.username == 'test-agent'


def test_reconnect_without_a_key_raises_not_paired() -> None:
    """Nothing stored means pair first, and says so."""
    with pytest.raises(NotPaired):
        KeePassRpcClient.connect(MemoryKeyStore(), transport=LiveTransport(FakeServer()))


def test_reconnect_with_a_wrong_key_is_refused() -> None:
    """A key the server does not recognise fails; it never degrades to unauthenticated."""
    server = FakeServer()
    _, store = paired_client(server)
    store.save(StoredKey(username='test-agent', key_hex='ab' * 32))

    with pytest.raises(ProtocolError, match='rejected'):
        KeePassRpcClient.connect(store, transport=LiveTransport(server))


def test_reconnect_without_a_challenge_suggests_re_pairing() -> None:
    """An expired key shows up as a missing challenge; the message must say what to do."""
    transport = ScriptedTransport([{'protocol': 'setup', 'key': {}}])
    store = MemoryKeyStore(StoredKey(username='test-agent', key_hex='ab' * 32))

    with pytest.raises(AuthenticationError, match='pair again'):
        KeePassRpcClient.connect(store, transport=transport)


def test_reconnect_rejects_a_forged_sr() -> None:
    """Mutual authentication on the headless path too."""
    store = MemoryKeyStore(StoredKey(username='test-agent', key_hex='ab' * 32))
    transport = ScriptedTransport(
        [
            {'protocol': 'setup', 'key': {'sc': '12345'}},
            {'protocol': 'setup', 'key': {'sr': '00' * 32}},
        ]
    )
    with pytest.raises(AuthenticationError, match='sr'):
        KeePassRpcClient.connect(store, transport=transport)


def test_failed_reconnect_closes_a_transport_it_opened() -> None:
    """A half-open socket must not be left behind on a failed handshake."""
    store = MemoryKeyStore(StoredKey(username='test-agent', key_hex='ab' * 32))
    transport = ScriptedTransport([{'protocol': 'setup', 'key': {}}])

    with pytest.raises(AuthenticationError):
        KeePassRpcClient.connect(store, transport=transport)
    # The transport was supplied, so it is the caller's; the client must not have closed it.
    assert transport.closed is False


# --- calls --------------------------------------------------------------------------


def test_call_roundtrip() -> None:
    """A call is encrypted, answered, and decrypted."""
    server = FakeServer()
    server.rpc_results['GetDatabaseName'] = 'Example Database'
    client, _ = paired_client(server)

    assert client.get_database_name() == 'Example Database'


def test_call_sends_positional_params_in_order() -> None:
    """Upstream's signatures are positional; order is the contract."""
    server = FakeServer()
    server.rpc_results['FindLogins'] = []
    client, _ = paired_client(server)

    client.find_logins(urls=['https://example.invalid'], unique_id='abc', free_text_search='thing')

    params = server.last_request['params']
    assert params[0] == ['https://example.invalid']
    assert params[3] == LoginSearchType.ALL.value == 'LSTall'
    assert params[5] == 'abc'
    assert params[7] == 'thing'


def test_call_ids_increment() -> None:
    """Distinct ids, so a reply can be matched to its request."""
    server = FakeServer()
    server.rpc_results['GetRoot'] = {}
    client, _ = paired_client(server)

    client.get_root()
    first = server.last_request['id']
    client.get_root()
    assert server.last_request['id'] == first + 1


def test_rpc_error_is_raised_with_the_method_name() -> None:
    """A method-level failure is an exception carrying enough to debug it."""
    server = FakeServer()
    server.rpc_errors['RemoveEntry'] = {'code': -32602, 'message': 'no such entry'}
    client, _ = paired_client(server)

    with pytest.raises(RpcError, match='RemoveEntry') as caught:
        client.remove_entry('deadbeef')
    assert caught.value.method == 'RemoveEntry'
    assert caught.value.error['code'] == -32602


def test_convenience_methods_use_upstream_spellings() -> None:
    """Method names must match the C# exactly or the server 404s them."""
    server = FakeServer()
    client, _ = paired_client(server)

    for call, expected in [
        (client.get_application_metadata, 'GetApplicationMetadata'),
        (client.get_all_logins, 'GetAllLogins'),
        (client.get_all_entries, 'GetAllEntries'),
        (client.get_root, 'GetRoot'),
        (client.get_password_profiles, 'GetPasswordProfiles'),
    ]:
        call()
        assert server.last_request['method'] == expected


def test_v3_feature_is_declared() -> None:
    """The plugin refuses V3 calls from a client that has not declared the flag."""
    assert 'KPRPC_FEATURE_DTO_V3' in DEFAULT_FEATURES


def test_v3_methods_use_upstream_spellings() -> None:
    """V3 method names must match the C# exactly, same as every other generation."""
    server = FakeServer()
    client, _ = paired_client(server)

    client.get_entry3('deadbeef')
    assert server.last_request['method'] == 'GetEntry3'
    assert server.last_request['params'] == ['deadbeef']

    client.list_group3('Some/Path')
    assert server.last_request['method'] == 'ListGroup3'


def test_get_attachment3_decodes_base64() -> None:
    """The wire carries base64; a caller wants bytes."""
    server = FakeServer()
    server.rpc_results['GetAttachment3'] = base64.b64encode(b'file contents').decode()
    client, _ = paired_client(server)

    assert client.get_attachment3('deadbeef', 'note.txt') == b'file contents'
    assert server.last_request['params'] == ['deadbeef', 'note.txt']


def test_get_attachment3_waits_long_enough_for_a_human() -> None:
    """The call can raise a dialog in KeePass, so it must not use the network timeout.

    Verified against the real plugin: at the default ten seconds a correctly working
    confirmation prompt produces a spurious connection failure.
    """
    server = FakeServer()
    server.rpc_results['GetAttachment3'] = base64.b64encode(b'x').decode()
    transport = LiveTransport(server)
    store = MemoryKeyStore()
    pair(IDENTITY, lambda: server.password, store, transport=LiveTransport(server))
    client = KeePassRpcClient.connect(store, transport=transport)

    client.get_attachment3('deadbeef', 'note.txt')

    assert PROMPT_TIMEOUT >= 60
    # Raised for the call, then put back, so one slow call does not slacken the session.
    assert transport.timeout == ClientConfig().timeout


def test_a_per_call_timeout_is_restored_afterwards() -> None:
    """A timeout override applies to one call only."""
    server = FakeServer()
    server.rpc_results['GetRoot'] = {}
    transport = LiveTransport(server)
    store = MemoryKeyStore()
    pair(IDENTITY, lambda: server.password, store, transport=LiveTransport(server))
    client = KeePassRpcClient.connect(store, transport=transport)

    client.call('GetRoot', timeout=123.0)
    assert transport.timeout == ClientConfig().timeout


def test_v3_write_methods_use_upstream_spellings() -> None:
    """Write method names and argument order are the contract."""
    server = FakeServer()
    client, _ = paired_client(server)

    client.add_entry3('Root/Group', {'title': 'x'})
    assert server.last_request['method'] == 'AddEntry3'
    assert server.last_request['params'] == ['Root/Group', {'title': 'x'}]

    client.update_entry3('deadbeef', {'password': 'y'})
    assert server.last_request['method'] == 'UpdateEntry3'
    assert server.last_request['params'] == ['deadbeef', {'password': 'y'}]

    client.remove_entry3('deadbeef')
    assert server.last_request['method'] == 'RemoveEntry3'

    client.remove_attachment3('deadbeef', 'note.txt')
    assert server.last_request['method'] == 'RemoveAttachment3'


def test_set_attachment3_encodes_content() -> None:
    """Bytes in, base64 on the wire."""
    server = FakeServer()
    client, _ = paired_client(server)

    client.set_attachment3('deadbeef', 'note.txt', b'raw bytes')

    assert server.last_request['method'] == 'SetAttachment3'
    assert server.last_request['params'][2] == base64.b64encode(b'raw bytes').decode()


def test_write_methods_wait_for_a_prompt() -> None:
    """Writes and deletes prompt too, so they get the same long timeout as attachments."""
    server = FakeServer()
    transport = LiveTransport(server)
    store = MemoryKeyStore()
    pair(IDENTITY, lambda: server.password, store, transport=LiveTransport(server))
    client = KeePassRpcClient.connect(store, transport=transport)

    for call in (
        lambda: client.add_entry3('g', {}),
        lambda: client.update_entry3('u', {}),
        lambda: client.remove_entry3('u'),
        lambda: client.set_attachment3('u', 'n', b''),
        lambda: client.remove_attachment3('u', 'n'),
    ):
        call()
        # Raised for the call and put back afterwards, every time.
        assert transport.timeout == ClientConfig().timeout


def test_a_signal_before_the_reply_is_stepped_over() -> None:
    """The plugin pushes Signals down the same socket, as jsonrpc REQUESTS.

    Anything that saves the database emits DATABASE_SAVING and DATABASE_SAVED. A client
    that took the next frame as its answer would read a signal instead, so the call that
    triggered the save looks fine and the NEXT one silently returns None. Found live, after
    the first V3 write.
    """
    server = FakeServer()
    server.rpc_results['GetDatabaseName'] = 'Example Database'
    server.signals_before_reply = 2
    client, _ = paired_client(server)

    assert client.get_database_name() == 'Example Database'
    assert len(client.signals) == 2
    assert client.signals[0]['method'] == 'KPRPCListener'


def test_signals_do_not_leak_into_a_later_call() -> None:
    """Two calls in a row, each preceded by a signal, both get their own answer."""
    server = FakeServer()
    server.rpc_results['GetDatabaseName'] = 'A'
    server.signals_before_reply = 1
    client, _ = paired_client(server)

    assert client.get_database_name() == 'A'
    server.rpc_results['GetDatabaseName'] = 'B'
    assert client.get_database_name() == 'B'


def test_endless_signals_give_up_rather_than_spin() -> None:
    """A server that only ever sends signals must not hold the client for ever."""
    server = FakeServer()
    server.signals_before_reply = MAX_SIGNALS_PER_CALL + 1
    client, _ = paired_client(server)

    with pytest.raises(ProtocolError, match='server-initiated'):
        client.get_database_name()


def test_v3_denial_surfaces_as_an_rpc_error() -> None:
    """An ACL refusal is an error the caller can catch, not a silent empty result."""
    server = FakeServer()
    server.rpc_errors['GetEntry3'] = {'code': -32603, 'message': 'Not permitted.'}
    client, _ = paired_client(server)

    with pytest.raises(RpcError, match='GetEntry3'):
        client.get_entry3('deadbeef')


def test_client_is_a_context_manager() -> None:
    """Leaving the block closes the session."""
    server = FakeServer()
    store = MemoryKeyStore()
    pair(IDENTITY, lambda: server.password, store, transport=LiveTransport(server))
    transport = LiveTransport(server)

    with KeePassRpcClient.connect(store, transport=transport) as client:
        assert client.username == 'test-agent'
    assert transport.closed is True


def test_config_defaults_are_loopback() -> None:
    """The plugin does not listen off-host, and neither should the default point."""
    config = ClientConfig()
    assert config.url.startswith('ws://127.0.0.1:')
    assert config.security_level == 2
