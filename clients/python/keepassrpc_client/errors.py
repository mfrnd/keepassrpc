"""Exception hierarchy.

Every failure path in this package raises one of these. Nothing is swallowed and nothing
degrades to a partial result: the plugin guards secrets, so an ambiguous outcome is an
error, not a best guess.
"""

from __future__ import annotations

from typing import Any


class KeePassRpcError(RuntimeError):
    """Base class for every failure raised by this package."""


class ConnectionFailed(KeePassRpcError):
    """The WebSocket could not be opened, or it dropped mid-conversation."""


class ProtocolError(KeePassRpcError):
    """The server sent something the protocol does not allow at this point."""


class AuthenticationError(KeePassRpcError):
    """Pairing or reconnect failed, including a server proof that did not verify.

    Raised rather than returned so that a caller cannot accidentally continue with an
    unauthenticated session.
    """


class NotPaired(KeePassRpcError):
    """No stored key for this identity, so a headless reconnect is impossible."""


class RpcError(KeePassRpcError):
    """The server accepted the call and answered with a JSON-RPC ``error``."""

    def __init__(self, method: str, error: Any) -> None:
        """
        :param method: The method that failed.
        :param error: The raw ``error`` member from the JSON-RPC reply.
        """
        super().__init__(f'{method} failed: {error!r}')
        self.method = method
        self.error = error
