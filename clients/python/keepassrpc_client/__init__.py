"""Python client for the KeePassRPC plugin protocol.

Speaks the same wire protocol as the plugin in this repository: SRP-6a pairing, a
key-challenge reconnect for headless use, and AES-encrypted JSON-RPC on top. It exists to
test the plugin, and to be consumed by unattended workloads once the V3 API lands.

Typical unattended use, after pairing once::

    from keepassrpc_client import KeePassRpcClient, DpapiKeyStore, default_key_path

    store = DpapiKeyStore(default_key_path('my-agent'))
    with KeePassRpcClient.connect(store) as client:
        print(client.get_database_name())

See this package's README for pairing, and for the Origin the plugin requires.
"""

from __future__ import annotations

from .client import (
    DEFAULT_FEATURES,
    PROMPT_TIMEOUT,
    PROTOCOL_VERSION,
    SECURITY_LEVEL,
    ClientConfig,
    ClientIdentity,
    KeePassRpcClient,
    LoginSearchType,
    pair,
)
from .errors import (
    AuthenticationError,
    ConnectionFailed,
    KeePassRpcError,
    NotPaired,
    ProtocolError,
    RpcError,
)
from .keystore import (
    DEFAULT_ENTROPY,
    DpapiKeyStore,
    KeyStore,
    MemoryKeyStore,
    StoredKey,
    default_key_path,
)
from .transport import DEFAULT_ORIGIN, DEFAULT_TIMEOUT, DEFAULT_URL, Transport, WebSocketTransport

__all__ = [
    'DEFAULT_ENTROPY',
    'DEFAULT_FEATURES',
    'DEFAULT_ORIGIN',
    'DEFAULT_TIMEOUT',
    'DEFAULT_URL',
    'PROMPT_TIMEOUT',
    'PROTOCOL_VERSION',
    'SECURITY_LEVEL',
    'AuthenticationError',
    'ClientConfig',
    'ClientIdentity',
    'ConnectionFailed',
    'DpapiKeyStore',
    'KeePassRpcClient',
    'KeePassRpcError',
    'KeyStore',
    'LoginSearchType',
    'MemoryKeyStore',
    'NotPaired',
    'ProtocolError',
    'RpcError',
    'StoredKey',
    'Transport',
    'WebSocketTransport',
    'default_key_path',
    'pair',
]

__version__ = '0.1.0'
