"""The negotiated session crypto: key agreement, envelope, and replay refusal.

These check internal consistency and the fail-closed behaviour. Whether the two
implementations actually agree is a question no unit test can answer. Only a live
handshake against the plugin can, and that is what the interop script in the scratchpad
does.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from keepassrpc_client import crypto_v2
from keepassrpc_client.errors import ProtocolError

KEY = bytes(range(32))
IV = bytes(range(16))
PAIRED = bytes(range(32, 64))


# --- key agreement ------------------------------------------------------------------


def test_both_sides_reach_the_same_secret() -> None:
    """The whole point of the exchange."""
    client = crypto_v2.Exchange()
    server = crypto_v2.Exchange()

    assert client.agree_with(server.public_key) == server.agree_with(client.public_key)


def test_public_keys_are_raw_coordinates() -> None:
    """64 bytes of X||Y, because the other end wraps exactly these in a CNG blob."""
    assert len(crypto_v2.Exchange().public_key) == 64


def test_a_malformed_peer_key_is_refused() -> None:
    with pytest.raises(ProtocolError, match='expected 64'):
        crypto_v2.Exchange().agree_with(b'too short')


def test_a_point_off_the_curve_is_refused() -> None:
    """The agreed value would otherwise be attacker-influenced."""
    bogus = (7).to_bytes(32, 'big') + (11).to_bytes(32, 'big')
    with pytest.raises(ProtocolError, match='not a valid P-256 point'):
        crypto_v2.Exchange().agree_with(bogus)


def test_the_session_key_depends_on_the_paired_key() -> None:
    """Authentication of the exchange: without the paired key you reach a different key.

    This is what stops a local process that cannot read the paired key from completing a
    handshake, and it is why the derivation mixes both secrets rather than the agreed one
    alone.
    """
    client, server = crypto_v2.Exchange(), crypto_v2.Exchange()
    agreed = client.agree_with(server.public_key)

    mine = crypto_v2.derive_session_key(PAIRED, client.public_key, server.public_key, agreed)
    theirs = crypto_v2.derive_session_key(b'\x00' * 32, client.public_key, server.public_key, agreed)
    assert mine != theirs


def test_the_session_key_depends_on_both_public_keys() -> None:
    """So neither side can steer the result after seeing the other's key."""
    a, b = crypto_v2.Exchange(), crypto_v2.Exchange()
    agreed = a.agree_with(b.public_key)

    assert crypto_v2.derive_session_key(PAIRED, a.public_key, b.public_key, agreed) != crypto_v2.derive_session_key(
        PAIRED, b.public_key, a.public_key, agreed
    )


def test_every_session_gets_a_different_key() -> None:
    """Forward secrecy rests on this: two connections with the same paired key differ."""

    def session() -> bytes:
        client, server = crypto_v2.Exchange(), crypto_v2.Exchange()
        return crypto_v2.derive_session_key(
            PAIRED, client.public_key, server.public_key, client.agree_with(server.public_key)
        )

    assert session() != session()


def test_the_confirmation_is_bound_to_the_exchange() -> None:
    proof = crypto_v2.kex_confirmation(KEY, b'c' * 64, b's' * 64)
    assert proof != crypto_v2.kex_confirmation(KEY, b'c' * 64, b'x' * 64)
    assert proof != crypto_v2.kex_confirmation(b'\x00' * 32, b'c' * 64, b's' * 64)


# --- the message envelope -------------------------------------------------------------


def test_roundtrip() -> None:
    assert crypto_v2.decrypt(crypto_v2.encrypt('{"id":1}', KEY, 1), KEY, 1) == '{"id":1}'


def test_roundtrip_of_non_ascii() -> None:
    plaintext = '{"title":"café ✓"}'
    assert crypto_v2.decrypt(crypto_v2.encrypt(plaintext, KEY, 7), KEY, 7) == plaintext


def test_the_container_shape_is_unchanged() -> None:
    """Same three members as the original suite, so nothing a legacy client parses moves.

    The counter rides inside the ciphertext precisely to keep this true.
    """
    assert set(crypto_v2.encrypt('x', KEY, 1)) == {'iv', 'message', 'hmac'}


def test_the_mac_is_hmac_sha256_not_the_old_construction() -> None:
    """A 32 byte tag, and not the SHA-1 hash-of-concatenation the original suite uses."""
    import hashlib

    container = crypto_v2.encrypt('x', KEY, 1, iv=IV)
    tag = base64.b64decode(container['hmac'])
    ciphertext = base64.b64decode(container['message'])

    assert len(tag) == 32
    legacy = hashlib.sha1(hashlib.sha1(KEY).digest() + ciphertext + IV).digest()
    assert tag[: len(legacy)] != legacy


def test_a_replayed_message_is_refused() -> None:
    """The counter's reason for existing."""
    message = crypto_v2.encrypt('{"id":1}', KEY, 1)
    assert crypto_v2.decrypt(message, KEY, 1) == '{"id":1}'

    with pytest.raises(ProtocolError, match='replayed, reordered or lost'):
        crypto_v2.decrypt(message, KEY, 2)


def test_a_reordered_message_is_refused() -> None:
    with pytest.raises(ProtocolError, match='replayed, reordered or lost'):
        crypto_v2.decrypt(crypto_v2.encrypt('x', KEY, 5), KEY, 4)


def test_tampering_is_refused() -> None:
    container = crypto_v2.encrypt('hello', KEY, 1, iv=IV)
    raw = bytearray(base64.b64decode(container['message']))
    raw[0] ^= 0x01
    container['message'] = base64.b64encode(bytes(raw)).decode()

    with pytest.raises(ProtocolError, match='MAC mismatch'):
        crypto_v2.decrypt(container, KEY, 1)


def test_a_tampered_iv_is_refused() -> None:
    container = crypto_v2.encrypt('hello', KEY, 1, iv=IV)
    container['iv'] = base64.b64encode(bytes(16)).decode()

    with pytest.raises(ProtocolError, match='MAC mismatch'):
        crypto_v2.decrypt(container, KEY, 1)


def test_the_wrong_key_is_refused_at_the_mac() -> None:
    with pytest.raises(ProtocolError, match='MAC mismatch'):
        crypto_v2.decrypt(crypto_v2.encrypt('hello', KEY, 1), bytes(32), 1)


def test_encryption_and_mac_use_different_keys() -> None:
    """Reusing one key for both is the classic way to weaken encrypt-then-MAC."""
    from keepassrpc_client.crypto_v2 import _ENCRYPTION_LABEL, _MAC_LABEL, _subkey

    assert _subkey(KEY, _ENCRYPTION_LABEL) != _subkey(KEY, _MAC_LABEL)


@pytest.mark.parametrize('container', [None, 'string', 42, []])
def test_a_non_object_container_is_refused(container: object) -> None:
    with pytest.raises(ProtocolError, match='expected an encrypted container'):
        crypto_v2.decrypt(container, KEY, 1)


def test_a_truncated_container_is_refused() -> None:
    with pytest.raises(ProtocolError, match='missing or has malformed'):
        crypto_v2.decrypt({'iv': base64.b64encode(IV).decode()}, KEY, 1)


def test_a_fixed_private_key_makes_the_exchange_reproducible() -> None:
    """Tests need determinism; production must never pass one."""
    private = ec.generate_private_key(ec.SECP256R1())
    assert crypto_v2.Exchange(private).public_key == crypto_v2.Exchange(private).public_key
