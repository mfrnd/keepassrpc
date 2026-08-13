"""Session crypto: the container format, and that tampering is rejected."""

from __future__ import annotations

import base64
import hashlib

import pytest

from keepassrpc_client.crypto import decrypt, encrypt
from keepassrpc_client.errors import ProtocolError

KEY = bytes(range(32))
IV = bytes(range(16))


def test_roundtrip() -> None:
    """What we encrypt, we can decrypt."""
    assert decrypt(encrypt('{"id":1}', KEY), KEY) == '{"id":1}'


def test_roundtrip_of_non_ascii() -> None:
    """Bodies are UTF-8, not latin-1."""
    plaintext = '{"title":"café ✓"}'
    assert decrypt(encrypt(plaintext, KEY), KEY) == plaintext


def test_container_shape() -> None:
    """The server expects exactly these three base64 members."""
    container = encrypt('hello', KEY, iv=IV)
    assert set(container) == {'iv', 'message', 'hmac'}
    assert base64.b64decode(container['iv']) == IV


def test_mac_construction_matches_upstream() -> None:
    """MAC is SHA1(SHA1(key) || ciphertext || iv).

    Not an HMAC despite the field name, and SHA-1 not SHA-256. Pinned here because a
    "corrected" implementation would be unable to talk to KeePass at all.
    """
    container = encrypt('hello', KEY, iv=IV)
    ciphertext = base64.b64decode(container['message'])
    expected = hashlib.sha1(hashlib.sha1(KEY).digest() + ciphertext + IV).digest()
    assert base64.b64decode(container['hmac']) == expected


def test_encryption_is_randomised_by_default() -> None:
    """A fresh IV per message, so identical plaintexts do not produce identical frames."""
    assert encrypt('same', KEY)['message'] != encrypt('same', KEY)['message']


def test_tampered_ciphertext_is_rejected() -> None:
    """Flipping a ciphertext byte must fail the MAC, not surface as garbage plaintext."""
    container = encrypt('hello', KEY, iv=IV)
    raw = bytearray(base64.b64decode(container['message']))
    raw[0] ^= 0x01
    container['message'] = base64.b64encode(bytes(raw)).decode()

    with pytest.raises(ProtocolError, match='MAC mismatch'):
        decrypt(container, KEY)


def test_tampered_iv_is_rejected() -> None:
    """The IV is covered by the MAC, so it cannot be swapped either."""
    container = encrypt('hello', KEY, iv=IV)
    container['iv'] = base64.b64encode(bytes(16)).decode()

    with pytest.raises(ProtocolError, match='MAC mismatch'):
        decrypt(container, KEY)


def test_wrong_key_is_rejected_at_the_mac() -> None:
    """A wrong key fails the MAC check before any decryption is attempted."""
    with pytest.raises(ProtocolError, match='MAC mismatch'):
        decrypt(encrypt('hello', KEY), bytes(32))


def test_missing_hmac_is_rejected() -> None:
    """An absent MAC is a failure, not an empty-string match."""
    container = encrypt('hello', KEY, iv=IV)
    del container['hmac']

    with pytest.raises(ProtocolError, match='MAC mismatch'):
        decrypt(container, KEY)


@pytest.mark.parametrize('container', [None, 'string', 42, []])
def test_non_object_container_is_rejected(container: object) -> None:
    """A reply that is not a container fails cleanly."""
    with pytest.raises(ProtocolError, match='expected an encrypted container'):
        decrypt(container, KEY)


def test_missing_members_are_rejected() -> None:
    """A truncated container fails cleanly rather than with a KeyError."""
    with pytest.raises(ProtocolError, match='malformed'):
        decrypt({'iv': base64.b64encode(IV).decode()}, KEY)
