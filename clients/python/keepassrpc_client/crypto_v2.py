"""The negotiated session crypto: ephemeral keys, HMAC-SHA256, replay protection.

Ported from `CryptoV2.cs` in this repository, and like the original suite it has to match
that C# exactly rather than follow anyone's preference. The differences from
:mod:`keepassrpc_client.crypto` are the point of the exercise:

* **A fresh key per session.** The original suite encrypts with the key established at
  pairing and never rotates it, so every message of every session shares one AES key for the
  life of the pairing. Since that key also sits in a DPAPI blob any local process can read,
  traffic captured today is decryptable by anyone who obtains the key later. Here an
  ephemeral P-256 exchange produces a session key that exists only for the connection.
* **HMAC-SHA256** instead of ``SHA1(SHA1(key) || ciphertext || iv)``, which is a
  length-extendable construction on a broken hash.
* **A counter per direction**, inside the encrypted envelope, so a replayed or reordered
  message is refused.

The exchange is authenticated by the paired key: the session key derives from that as well
as the agreed secret, so it is secure if either is. A peer that cannot read the paired key
cannot reach the same session key, and one that can was already able to impersonate the
subject outright.

AES-256-CBC with explicit encrypt-then-MAC rather than an AEAD, because .NET Framework 4.5
has no AEAD to match against.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import ProtocolError

FEATURE_NAME = 'KPRPC_FEATURE_CRYPTO_V2'

_CURVE = ec.SECP256R1()
_COORDINATE_BYTES = 32
_PUBLIC_KEY_BYTES = _COORDINATE_BYTES * 2
_IV_BYTES = 16
_BLOCK_BITS = 128

_SESSION_LABEL = b'KPRPC-CRYPTO-V2 session'
_CONFIRM_LABEL = b'KPRPC-CRYPTO-V2 kex-confirm'
_ENCRYPTION_LABEL = b'KPRPC-CRYPTO-V2 enc'
_MAC_LABEL = b'KPRPC-CRYPTO-V2 mac'


@dataclass
class SessionCrypto:
    """A negotiated session: the key, and where each direction's counter has reached."""

    session_key: bytes
    outgoing: int = 1
    incoming: int = 1


class Exchange:
    """One ephemeral key agreement. Single use, per connection."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        """
        :param private_key: An ephemeral key. Generated when omitted; pass one only in tests.
        """
        self._private = private_key or ec.generate_private_key(_CURVE)

    @property
    def public_key(self) -> bytes:
        """This side's public key as raw X||Y.

        Raw coordinates rather than any library's encoding, because the other end builds the
        Windows CNG blob around exactly these 64 bytes.
        """
        numbers = self._private.public_key().public_numbers()
        return numbers.x.to_bytes(_COORDINATE_BYTES, 'big') + numbers.y.to_bytes(_COORDINATE_BYTES, 'big')

    def agree_with(self, peer_public: bytes) -> bytes:
        """The agreed secret, hashed the way the CNG key derivation hashes it.

        .NET's ``DeriveKeyMaterial`` applies its configured KDF rather than handing back the
        raw point, and the plugin configures a plain SHA-256. Matching that here is what lets
        the two sides meet without either using a platform-specific format.

        :raises ProtocolError: If the peer's key is not a well-formed point on the curve.
        """
        if len(peer_public) != _PUBLIC_KEY_BYTES:
            raise ProtocolError(f'peer public key is {len(peer_public)} bytes, expected {_PUBLIC_KEY_BYTES}')

        try:
            peer = ec.EllipticCurvePublicNumbers(
                int.from_bytes(peer_public[:_COORDINATE_BYTES], 'big'),
                int.from_bytes(peer_public[_COORDINATE_BYTES:], 'big'),
                _CURVE,
            ).public_key()
        except ValueError as exc:
            # A point off the curve is a broken or hostile peer, never something to continue
            # past: the agreed value would be attacker-influenced.
            raise ProtocolError(f'peer public key is not a valid P-256 point: {exc}') from exc

        return hashlib.sha256(self._private.exchange(ec.ECDH(), peer)).digest()


def derive_session_key(paired_key: bytes, client_public: bytes, server_public: bytes, agreed: bytes) -> bytes:
    """Bind the session key to the ephemeral secret and to the long-lived paired key.

    Both public keys go into the derivation so that neither side can steer the result by
    choosing its own key after seeing the other's.
    """
    return hmac.new(paired_key, _SESSION_LABEL + client_public + server_public + agreed, hashlib.sha256).digest()


def kex_confirmation(session_key: bytes, client_public: bytes, server_public: bytes) -> bytes:
    """The proof the server sends that it reached the same session key."""
    return hmac.new(session_key, _CONFIRM_LABEL + client_public + server_public, hashlib.sha256).digest()


def _subkey(session_key: bytes, label: bytes) -> bytes:
    """Separate encryption and authentication keys from the one session key."""
    return hmac.new(session_key, label, hashlib.sha256).digest()


def _mac(session_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(_subkey(session_key, _MAC_LABEL), iv + ciphertext, hashlib.sha256).digest()


def encrypt(plaintext: str, session_key: bytes, sequence: int, iv: bytes | None = None) -> dict[str, str]:
    """Encrypt one message.

    :param sequence: This direction's counter, starting at 1 and rising by one per message.
    :param iv: The CBC IV. Random when omitted; pass one only in tests.
    :return: The same three-member container the original suite uses. The counter travels
        inside the ciphertext, so the wire shape is unchanged and nothing a legacy client
        parses is affected.
    """
    if iv is None:
        iv = secrets.token_bytes(_IV_BYTES)

    envelope = json.dumps({'seq': sequence, 'payload': plaintext}, separators=(',', ':'))
    padder = padding.PKCS7(_BLOCK_BITS).padder()
    padded = padder.update(envelope.encode('utf-8')) + padder.finalize()

    encryptor = Cipher(algorithms.AES(_subkey(session_key, _ENCRYPTION_LABEL)), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {
        'iv': base64.b64encode(iv).decode('ascii'),
        'message': base64.b64encode(ciphertext).decode('ascii'),
        'hmac': base64.b64encode(_mac(session_key, iv, ciphertext)).decode('ascii'),
    }


def decrypt(container: Any, session_key: bytes, expected_sequence: int) -> str:
    """Verify and decrypt one message.

    :param expected_sequence: The counter this direction must next produce. A mismatch means
        a replayed, reordered or dropped message and is refused rather than tolerated.
    :raises ProtocolError: On any failure, including a sequence mismatch.
    """
    if not isinstance(container, dict):
        raise ProtocolError(f'expected an encrypted container, got {type(container).__name__}')

    try:
        iv = base64.b64decode(container['iv'])
        ciphertext = base64.b64decode(container['message'])
        presented = base64.b64decode(container['hmac'])
    except (KeyError, ValueError, TypeError) as exc:
        raise ProtocolError('encrypted container is missing or has malformed members') from exc

    # Checked before decryption, in constant time, so a forged message never reaches the
    # unpadder.
    if not hmac.compare_digest(_mac(session_key, iv, ciphertext), presented):
        raise ProtocolError('response MAC mismatch; discarding the message')

    decryptor = Cipher(algorithms.AES(_subkey(session_key, _ENCRYPTION_LABEL)), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(_BLOCK_BITS).unpadder()
    try:
        envelope = (unpadder.update(padded) + unpadder.finalize()).decode('utf-8')
    except ValueError as exc:
        raise ProtocolError('decrypted message has invalid padding') from exc

    try:
        parsed = json.loads(envelope)
        sequence = int(parsed['seq'])
        payload = parsed['payload']
    except (ValueError, KeyError, TypeError) as exc:
        raise ProtocolError('malformed message envelope') from exc

    if not isinstance(payload, str):
        raise ProtocolError('message envelope payload is not a string')

    if sequence != expected_sequence:
        raise ProtocolError(
            f'message sequence {sequence} where {expected_sequence} was expected; replayed, reordered or lost'
        )

    return payload
