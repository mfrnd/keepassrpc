"""Where the session key lives between runs.

Pairing is interactive by design: KeePass shows a code and a human types it. Unattended
workloads therefore pair once and reconnect afterwards from a stored key, which makes that
stored key exactly as sensitive as the access it buys.

Two stores ship here:

* :class:`DpapiKeyStore`: Windows DPAPI, CurrentUser scope, with app entropy. The blob is
  decryptable only by the same Windows account, which is the same boundary the plugin
  itself assumes.
* :class:`MemoryKeyStore`: for tests and for callers who pair on every run.

There is deliberately no plaintext-file store. A key on disk in the clear is a bearer
token for the database, and offering it as a convenience would make the insecure option
the easy one. A caller who truly needs one on another platform can implement
:class:`KeyStore` themselves and own that decision explicitly.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .errors import KeePassRpcError, NotPaired

# DPAPI secondary entropy. Not a secret. It only domain-separates this blob from other
# DPAPI blobs belonging to the same Windows user, so that a key protected for this client
# cannot be unprotected by an unrelated program that merely runs as the same account.
DEFAULT_ENTROPY = b'keepassrpc-python-client-v1'


@dataclass(frozen=True)
class StoredKey:
    """A paired identity and its session key.

    :ivar username: The SRP identity registered with the plugin.
    :ivar key_hex: The session key as lowercase hex, matching `KeyContainerClass.Key`.
    """

    username: str
    key_hex: str


class KeyStore(Protocol):
    """Persistence for a paired session key."""

    def load(self) -> StoredKey:
        """Return the stored key.

        :raises NotPaired: If nothing is stored.
        """
        ...

    def save(self, key: StoredKey) -> None:
        """Persist the key, replacing anything already there."""
        ...

    def delete(self) -> None:
        """Remove the stored key. Must succeed when nothing is stored."""
        ...


class MemoryKeyStore:
    """A key store that keeps the key in the process only."""

    def __init__(self, key: StoredKey | None = None) -> None:
        """
        :param key: An initial key, for tests that start from a paired state.
        """
        self._key = key

    def load(self) -> StoredKey:
        """Return the in-memory key.

        :raises NotPaired: If nothing has been stored.
        """
        if self._key is None:
            raise NotPaired('no session key in memory; pair first')
        return self._key

    def save(self, key: StoredKey) -> None:
        """Replace the in-memory key."""
        self._key = key

    def delete(self) -> None:
        """Forget the in-memory key."""
        self._key = None


def _dpapi(protect: bool, data: bytes, entropy: bytes) -> bytes:
    """Call CryptProtectData or CryptUnprotectData through ctypes.

    ctypes rather than pywin32 to keep the dependency list to the two libraries that carry
    real cryptographic weight.

    :param protect: True to encrypt, False to decrypt.
    :param data: The payload.
    :param entropy: Secondary entropy, which must match between protect and unprotect.
    :return: The transformed bytes.
    :raises KeePassRpcError: If the Windows call fails, which for unprotect usually means
        the blob belongs to a different user or the entropy changed.
    """
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = (('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char)))

    def blob_in(payload: bytes) -> Blob:
        buffer = ctypes.create_string_buffer(payload, len(payload))
        return Blob(len(payload), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

    out = Blob()
    crypt32 = ctypes.windll.crypt32
    function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = function(
        ctypes.byref(blob_in(data)),
        None,
        ctypes.byref(blob_in(entropy)),
        None,
        None,
        0,
        ctypes.byref(out),
    )
    if not ok:
        verb = 'protect' if protect else 'unprotect'
        raise KeePassRpcError(
            f'DPAPI {verb} failed. A stored key can only be read back by the Windows account that wrote it.'
        )
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


class DpapiKeyStore:
    """A key store backed by a DPAPI-protected file, CurrentUser scope.

    Windows only. Constructing this elsewhere raises rather than silently falling back to
    something weaker.
    """

    def __init__(self, path: Path, entropy: bytes = DEFAULT_ENTROPY) -> None:
        """
        :param path: Where to write the protected blob. Parent directories are created on
            save.
        :param entropy: Secondary entropy. Changing it invalidates existing blobs, so a
            caller sharing a key with another tool must pass that tool's value.
        :raises KeePassRpcError: If the platform is not Windows.
        """
        if sys.platform != 'win32':
            raise KeePassRpcError(f'DpapiKeyStore requires Windows; this is {sys.platform}')
        self._path = path
        self._entropy = entropy

    @property
    def path(self) -> Path:
        """Where the protected blob lives."""
        return self._path

    def load(self) -> StoredKey:
        """Read and unprotect the stored key.

        :raises NotPaired: If the file does not exist.
        :raises KeePassRpcError: If the blob cannot be unprotected or parsed.
        """
        if not self._path.exists():
            raise NotPaired(f'not paired: no key at {self._path}. Run pairing once, interactively.')
        try:
            document = json.loads(_dpapi(False, self._path.read_bytes(), self._entropy).decode('utf-8'))
            return StoredKey(username=document['username'], key_hex=document['keyHex'])
        except (ValueError, KeyError) as exc:
            raise KeePassRpcError(f'stored key at {self._path} is corrupt; delete it and re-pair') from exc

    def save(self, key: StoredKey) -> None:
        """Protect and write the key."""
        payload = json.dumps({'username': key.username, 'keyHex': key.key_hex}).encode('utf-8')
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_bytes(_dpapi(True, payload, self._entropy))

    def delete(self) -> None:
        """Remove the stored key if present."""
        self._path.unlink(missing_ok=True)


def default_key_path(username: str) -> Path:
    """Suggest a per-identity location under the user's local app data.

    Per identity because the plugin issues one key per client identity, and the ACL work
    this repo is building assumes one identity per agent. Sharing a file between identities
    would make revoking one of them mean re-pairing all of them.

    :param username: The client identity.
    :return: A path under ``%LOCALAPPDATA%`` on Windows, or ``~/.local/state`` elsewhere.
    """
    safe = ''.join(character if character.isalnum() or character in '-_' else '_' for character in username)
    if sys.platform == 'win32':
        import os

        base = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local'))
    else:
        base = Path.home() / '.local' / 'state'
    return base / 'keepassrpc-client' / f'{safe}.key'
