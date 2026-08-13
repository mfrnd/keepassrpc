"""Key storage and the command line surface."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from keepassrpc_client import cli
from keepassrpc_client.errors import KeePassRpcError, NotPaired
from keepassrpc_client.keystore import DpapiKeyStore, MemoryKeyStore, StoredKey, default_key_path

windows_only = pytest.mark.skipif(sys.platform != 'win32', reason='DPAPI is Windows only')

KEY = StoredKey(username='test-agent', key_hex='ab' * 32)


# --- key storage --------------------------------------------------------------------


def test_memory_store_roundtrip() -> None:
    """Save, load, delete."""
    store = MemoryKeyStore()
    with pytest.raises(NotPaired):
        store.load()

    store.save(KEY)
    assert store.load() == KEY

    store.delete()
    with pytest.raises(NotPaired):
        store.load()


@windows_only
def test_dpapi_store_roundtrip(tmp_path: Path) -> None:
    """A protected blob written and read back by the same account."""
    store = DpapiKeyStore(tmp_path / 'nested' / 'agent.key')
    store.save(KEY)

    assert store.path.exists()
    assert store.path.read_bytes() != KEY.key_hex.encode()  # actually protected
    assert store.load() == KEY

    store.delete()
    with pytest.raises(NotPaired):
        store.load()


@windows_only
def test_dpapi_delete_is_idempotent(tmp_path: Path) -> None:
    """Deleting nothing is not an error."""
    DpapiKeyStore(tmp_path / 'absent.key').delete()


@windows_only
def test_dpapi_rejects_a_different_entropy(tmp_path: Path) -> None:
    """Entropy domain-separates this blob from other DPAPI blobs of the same user."""
    path = tmp_path / 'agent.key'
    DpapiKeyStore(path, entropy=b'one').save(KEY)

    with pytest.raises(KeePassRpcError, match='DPAPI unprotect failed'):
        DpapiKeyStore(path, entropy=b'two').load()


@windows_only
def test_dpapi_reports_a_corrupt_blob(tmp_path: Path) -> None:
    """A damaged file says what to do about it."""
    path = tmp_path / 'agent.key'
    path.write_bytes(b'not a dpapi blob')

    with pytest.raises(KeePassRpcError):
        DpapiKeyStore(path).load()


@pytest.mark.skipif(sys.platform == 'win32', reason='checks the non-Windows guard')
def test_dpapi_store_refuses_non_windows() -> None:
    """No silent fallback to something weaker."""
    with pytest.raises(KeePassRpcError, match='requires Windows'):
        DpapiKeyStore(Path('unused'))


def test_default_key_path_is_per_identity() -> None:
    """One key file per identity, so revoking one does not disturb the others."""
    assert default_key_path('agent-a') != default_key_path('agent-b')


def test_default_key_path_sanitises_the_identity() -> None:
    """An identity is not a filename; path separators must not escape the directory."""
    path = default_key_path('../../evil name')
    assert '..' not in path.name
    assert path.parent.name == 'keepassrpc-client'


# --- CLI ------------------------------------------------------------------------------


def test_parser_requires_a_username() -> None:
    """Every command acts as an identity, so it is not optional."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(['info'])


def test_parser_requires_a_command() -> None:
    """No default command; doing nothing beats guessing."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(['--username', 'a'])


def test_parser_defaults_to_loopback() -> None:
    """The default endpoint matches where the plugin listens."""
    arguments = cli.build_parser().parse_args(['--username', 'a', 'info'])
    assert arguments.url == 'ws://127.0.0.1:12546'
    assert arguments.command == 'info'


def test_parser_accepts_call_with_params() -> None:
    """Arbitrary methods are reachable without adding a wrapper for each."""
    arguments = cli.build_parser().parse_args(['--username', 'a', 'call', 'GetAllDatabases', 'true'])
    assert arguments.method == 'GetAllDatabases'
    assert arguments.params == ['true']


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [('true', True), ('42', 42), ('"text"', 'text'), ('["a"]', ['a']), ('bare', 'bare'), ('', '')],
)
def test_parse_param(raw: str, expected: object) -> None:
    """JSON where it parses, a plain string otherwise."""
    assert cli.parse_param(raw) == expected


def test_main_reports_errors_without_a_traceback() -> None:
    """Operational failures are messages and exit 1, not stack traces."""

    class Failing(MemoryKeyStore):
        def load(self) -> StoredKey:
            raise NotPaired('not paired')

    original = cli._key_store
    cli._key_store = lambda arguments: Failing()
    try:
        assert cli.main(['--username', 'a', 'info']) == 1
    finally:
        cli._key_store = original


def test_revoke_only_removes_the_local_key(capsys: pytest.CaptureFixture[str]) -> None:
    """Revoke does not unpair in KeePass, and must not claim to."""
    store = MemoryKeyStore(KEY)
    arguments = cli.build_parser().parse_args(['--username', 'test-agent', 'revoke'])

    assert cli.command_revoke(arguments, store) == 0
    with pytest.raises(NotPaired):
        store.load()
    assert 'untouched' in capsys.readouterr().out
