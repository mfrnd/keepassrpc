"""Session crypto for the ``jsonrpc`` message envelope.

Ported from `KeePassRPCClient.Encrypt` / `Decrypt`. The scheme is AES-256-CBC with PKCS7
padding, authenticated by::

    mac = SHA1(SHA1(key) || ciphertext || iv)

That is a hash of a concatenation, not an HMAC, despite travelling in a field named
``hmac``, and it is SHA-1 rather than SHA-256 even though the rest of the protocol is
SHA-256. Both are upstream's choices; upstream's own source carries a TODO about
strengthening it. Reimplementing it faithfully is the job here, so do not "fix" it. A
client that computes a real HMAC simply fails to talk to KeePass.

The construction is encrypt-then-MAC over the ciphertext and IV, so a tampered message is
rejected before any padding is removed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import ProtocolError

_IV_BYTES = 16
_BLOCK_BITS = 128


def _mac(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """Compute the wire MAC: ``SHA1(SHA1(key) || ciphertext || iv)``."""
    # SHA-1 here is upstream's wire format for the v1 envelope, not a choice this client
    # gets to make. See the module docstring: a client that substitutes anything stronger
    # cannot talk to KeePass at all. The replacement is negotiated rather than substituted,
    # and it lives in `crypto_v2`, which this suppression deliberately does not cover.
    # The annotation has to sit on the line directly above the alert to take effect.
    # codeql[py/weak-sensitive-data-hashing]
    return hashlib.sha1(hashlib.sha1(key).digest() + ciphertext + iv).digest()


def encrypt(plaintext: str, key: bytes, iv: bytes | None = None) -> dict[str, str]:
    """Wrap a JSON-RPC body in the encrypted container the server expects.

    :param plaintext: The JSON-RPC request body.
    :param key: The 32-byte session key.
    :param iv: The CBC IV. Randomly generated when omitted; pass one only in tests, since
        a reused IV leaks plaintext structure.
    :return: The container with base64 ``iv``, ``message`` and ``hmac`` members.
    """
    if iv is None:
        iv = secrets.token_bytes(_IV_BYTES)
    padder = padding.PKCS7(_BLOCK_BITS).padder()
    padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return {
        'iv': base64.b64encode(iv).decode('ascii'),
        'message': base64.b64encode(ciphertext).decode('ascii'),
        'hmac': base64.b64encode(_mac(key, ciphertext, iv)).decode('ascii'),
    }


def decrypt(container: Any, key: bytes) -> str:
    """Verify and unwrap an encrypted container from the server.

    :param container: The ``jsonrpc`` member of a server message.
    :param key: The 32-byte session key.
    :return: The decrypted JSON-RPC reply body.
    :raises ProtocolError: If the container is malformed or the MAC does not verify. The
        MAC is checked before decryption, so a forged message never reaches the unpadder.
    """
    if not isinstance(container, dict):
        raise ProtocolError(f'expected an encrypted container, got {type(container).__name__}')
    try:
        ciphertext = base64.b64decode(container['message'])
        iv = base64.b64decode(container['iv'])
    except (KeyError, ValueError, TypeError) as exc:
        raise ProtocolError('encrypted container is missing or has malformed iv/message') from exc

    expected = base64.b64encode(_mac(key, ciphertext, iv)).decode('ascii')
    if not hmac.compare_digest(expected, str(container.get('hmac', ''))):
        raise ProtocolError('response MAC mismatch; discarding the message')

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(_BLOCK_BITS).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        # Reachable only if the MAC verified over a body the far end padded wrongly.
        raise ProtocolError('decrypted message has invalid padding') from exc
    return plaintext.decode('utf-8')
