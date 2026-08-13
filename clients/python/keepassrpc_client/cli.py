"""A thin command line over the library, for smoke-testing against a live KeePass.

This is a test harness, not a secret-delivery tool. It deliberately has no command that
prints a password: reading secrets belongs to the caller's own code, where the handling of
the value is that caller's decision rather than a side effect of a convenience command.
``call`` is the escape hatch, and what it prints is whatever the server returned.

    keepassrpc-client pair --username my-agent
    keepassrpc-client info --username my-agent
    keepassrpc-client call --username my-agent GetDatabaseName
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .client import ClientConfig, ClientIdentity, KeePassRpcClient, pair
from .errors import KeePassRpcError
from .keystore import DpapiKeyStore, KeyStore, default_key_path
from .transport import DEFAULT_ORIGIN, DEFAULT_TIMEOUT, DEFAULT_URL

# Pairing waits for a human to read a code off a dialog and type it, so the usual socket
# timeout is far too short.
PAIRING_TIMEOUT = 300.0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser.

    Split out from :func:`main` so the argument surface can be tested without running any
    command.
    """
    parser = argparse.ArgumentParser(
        prog='keepassrpc-client',
        description='Smoke-test client for the KeePassRPC plugin.',
    )
    parser.add_argument('--url', default=DEFAULT_URL, help='plugin endpoint (default: %(default)s)')
    parser.add_argument('--origin', default=DEFAULT_ORIGIN, help='Origin to present (default: %(default)s)')
    parser.add_argument(
        '--username',
        required=True,
        help='the client identity; one per agent, since the plugin keys its stored keys on this',
    )
    parser.add_argument(
        '--key-file',
        type=Path,
        default=None,
        help='where the DPAPI-protected session key lives (default: a per-identity path under LOCALAPPDATA)',
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=DEFAULT_TIMEOUT,
        help='socket timeout in seconds (default: %(default)s)',
    )

    commands = parser.add_subparsers(dest='command', required=True)

    pair_command = commands.add_parser('pair', help='pair this identity; KeePass shows a code')
    pair_command.add_argument(
        '--display-name',
        default=ClientIdentity('').display_name,
        help='name shown in the KeePass authorisation dialog (default: %(default)s)',
    )
    pair_command.add_argument(
        '--code',
        default=None,
        help='the authorisation code, if you would rather not be prompted. Prefer the prompt: '
        'a code on the command line lands in your shell history',
    )

    commands.add_parser('info', help='connect and print plugin and database metadata')
    commands.add_parser('revoke', help='delete the locally stored key (does not unpair in KeePass)')

    call_command = commands.add_parser('call', help='make one JSON-RPC call and print the result')
    call_command.add_argument('method', help='the method name, spelled as upstream spells it')
    call_command.add_argument(
        'params',
        nargs='*',
        help='positional parameters, each parsed as JSON, falling back to a string',
    )
    return parser


def parse_param(raw: str) -> Any:
    """Parse one CLI parameter as JSON, falling back to the literal string.

    So ``true``, ``42`` and ``["a"]`` arrive as the types the server expects, while a bare
    word arrives as a string rather than failing.
    """
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _key_store(arguments: argparse.Namespace) -> KeyStore:
    """Build the key store for the requested identity."""
    path = arguments.key_file or default_key_path(arguments.username)
    return DpapiKeyStore(path)


def _config(arguments: argparse.Namespace, timeout: float | None = None) -> ClientConfig:
    """Build the connection config from parsed arguments."""
    return ClientConfig(url=arguments.url, origin=arguments.origin, timeout=timeout or arguments.timeout)


def command_pair(arguments: argparse.Namespace, store: KeyStore) -> int:
    """Run the interactive pairing.

    :return: A process exit code.
    """
    identity = ClientIdentity(username=arguments.username, display_name=arguments.display_name)

    def get_code() -> str:
        if arguments.code:
            return str(arguments.code)
        print('KeePass is showing an authorisation dialog. Enter the code it displays.', file=sys.stderr)
        # getpass rather than input: the code authorises access to the database, so it
        # should not be echoed or land in a terminal scrollback.
        return getpass.getpass('authorisation code: ')

    stored = pair(identity, get_code, store, _config(arguments, PAIRING_TIMEOUT))
    print(f'paired as {stored.username!r}; session key stored')
    return 0


def command_info(arguments: argparse.Namespace, store: KeyStore) -> int:
    """Connect and print metadata, proving the stored key still works."""
    with KeePassRpcClient.connect(store, _config(arguments)) as client:
        payload = {
            'username': client.username,
            'applicationMetadata': client.get_application_metadata(),
            'databaseName': client.get_database_name(),
            'databaseFileName': client.get_database_file_name(),
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_call(arguments: argparse.Namespace, store: KeyStore) -> int:
    """Make one arbitrary call and print its result as JSON."""
    with KeePassRpcClient.connect(store, _config(arguments)) as client:
        result = client.call(arguments.method, [parse_param(item) for item in arguments.params])
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


def command_revoke(arguments: argparse.Namespace, store: KeyStore) -> int:
    """Delete the local key.

    This removes only this machine's copy. The pairing itself stays in KeePass until it is
    removed there, so this is not a revocation in the security sense and does not claim to
    be one.
    """
    store.delete()
    print(f'local key for {arguments.username!r} deleted; the pairing in KeePass is untouched')
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.

    :param argv: Arguments, defaulting to ``sys.argv[1:]``.
    :return: A process exit code. Errors print to stderr and return 1 rather than dumping
        a traceback, since the failure modes here are operational rather than bugs.
    """
    arguments = build_parser().parse_args(argv)
    handlers = {
        'pair': command_pair,
        'info': command_info,
        'call': command_call,
        'revoke': command_revoke,
    }
    try:
        store = _key_store(arguments)
        return handlers[arguments.command](arguments, store)
    except KeePassRpcError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
