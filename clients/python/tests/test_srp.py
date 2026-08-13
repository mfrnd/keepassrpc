"""SRP maths, checked against upstream's constants and against the fake server."""

from __future__ import annotations

import pytest
from fake_server import FakeServer

from keepassrpc_client import srp
from keepassrpc_client.errors import AuthenticationError, ProtocolError
from keepassrpc_client.srp import (
    K_MULT,
    G,
    N,
    SrpClientSession,
    client_challenge_response,
    expected_server_response,
    new_client_nonce,
    sha256_hex,
    to_hex,
    verify_server_response,
)


def test_group_constants_match_upstream() -> None:
    """The group is copied from SRP.cs; a typo here fails every handshake."""
    assert (
        int(
            'd4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea'
            '2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43',
            16,
        )
        == N
    )
    assert G == 2
    assert int('b7867f1299da8cc24ab93e08986ebc4d6a478ad0', 16) == K_MULT
    assert N.bit_length() == 512


@pytest.mark.parametrize(
    ('value', 'expected'),
    [(0, '0'), (10, 'A'), (255, 'FF'), (4096, '1000')],
)
def test_to_hex_matches_csharp_biginteger(value: int, expected: str) -> None:
    """Uppercase, no leading zeros, and a bare 0 for zero."""
    assert to_hex(value) == expected


def test_sha256_hex_is_lowercase_utf8() -> None:
    """Hashing is over UTF-8 bytes and the hex is lowercase."""
    assert sha256_hex('abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


def test_derive_agrees_with_the_server() -> None:
    """The whole point: an independent server implementation accepts our proof."""
    server = FakeServer()
    session = SrpClientSession(private_key=0xC0FFEE)

    secrets = session.derive(server.salt, server.public_key_hex, server.password)
    shared_hex, m, m2 = server._compute(session.public_key_hex)

    assert secrets.shared_secret_hex == shared_hex
    assert secrets.client_proof.lower() == m.lower()
    session.verify_server_proof(secrets, m2)


def test_proof_includes_the_server_public_key() -> None:
    """M is H(A || B || S), not H(A || S).

    Dropping B still produces a plausible-looking hex proof, and the failure only shows up
    against a real server, so pin the composition here.
    """
    server = FakeServer()
    session = SrpClientSession(private_key=0xC0FFEE)
    secrets = session.derive(server.salt, server.public_key_hex, server.password)

    without_b = sha256_hex(session.public_key_hex + secrets.shared_secret_hex)
    assert secrets.client_proof != without_b
    assert secrets.client_proof == sha256_hex(
        session.public_key_hex + server.public_key_hex + secrets.shared_secret_hex
    )


def test_wrong_code_produces_a_different_proof() -> None:
    """A mistyped authorisation code must not authenticate."""
    server = FakeServer(password='123456')
    session = SrpClientSession(private_key=0xC0FFEE)

    secrets = session.derive(server.salt, server.public_key_hex, ' 654321')
    _, m, _ = server._compute(session.public_key_hex)
    assert secrets.client_proof.lower() != m.lower()


def test_verify_server_proof_rejects_a_bad_m2() -> None:
    """A server that cannot produce M2 does not hold the shared secret."""
    server = FakeServer()
    session = SrpClientSession(private_key=0xC0FFEE)
    secrets = session.derive(server.salt, server.public_key_hex, server.password)

    with pytest.raises(AuthenticationError, match='M2'):
        session.verify_server_proof(secrets, '00' * 32)


def test_verify_server_proof_rejects_an_empty_m2() -> None:
    """An absent proof is a failure, never a pass."""
    server = FakeServer()
    session = SrpClientSession(private_key=0xC0FFEE)
    secrets = session.derive(server.salt, server.public_key_hex, server.password)

    with pytest.raises(AuthenticationError):
        session.verify_server_proof(secrets, '')


def test_derive_rejects_a_degenerate_server_key() -> None:
    """B congruent to 0 mod N would collapse the shared secret."""
    session = SrpClientSession(private_key=0xC0FFEE)
    with pytest.raises(ProtocolError, match='multiple of N'):
        session.derive('salt', to_hex(N), 'code')


def test_derive_rejects_a_non_hex_server_key() -> None:
    """Malformed input fails closed rather than raising something unexpected."""
    session = SrpClientSession(private_key=0xC0FFEE)
    with pytest.raises(ProtocolError, match='not hex'):
        session.derive('salt', 'not-a-number', 'code')


def test_public_key_is_generated_when_not_supplied() -> None:
    """The default path uses secrets, and two sessions differ."""
    assert SrpClientSession().public_key != SrpClientSession().public_key


def test_challenge_response_differs_from_server_response() -> None:
    """The '1' and '0' prefixes are what stop a reflection attack.

    If both sides hashed the same string, echoing our own cr back would pass as sr.
    """
    key_hex, sc, cc = 'ab' * 32, '12345', '67890'
    assert client_challenge_response(key_hex, sc, cc) != expected_server_response(key_hex, sc, cc)


def test_verify_server_response_accepts_the_right_answer() -> None:
    """The happy path of the headless reconnect."""
    key_hex, sc, cc = 'ab' * 32, '12345', '67890'
    verify_server_response(key_hex, sc, cc, expected_server_response(key_hex, sc, cc))


def test_verify_server_response_rejects_a_reflected_cr() -> None:
    """Echoing the client's own answer back must not authenticate the server."""
    key_hex, sc, cc = 'ab' * 32, '12345', '67890'
    with pytest.raises(AuthenticationError, match='sr'):
        verify_server_response(key_hex, sc, cc, client_challenge_response(key_hex, sc, cc))


def test_client_nonce_is_decimal() -> None:
    """cc is BigInteger.ToString(), which is decimal; hex would break the proof."""
    nonce = new_client_nonce()
    assert nonce.isdigit()
    assert new_client_nonce() != nonce


class TestSrpGroups:
    """The 2048-bit group, and that asking for it is what selects it."""

    def test_the_strong_group_is_the_rfc_5054_one(self) -> None:
        # Checkable against RFC 5054 Appendix A by eye, which is the reason for using a
        # published group rather than generating one.
        assert len(srp.RFC5054_2048.n_hex) == 512
        assert srp.RFC5054_2048.n.bit_length() == 2048
        assert srp.RFC5054_2048.g == 2

    def test_the_strong_group_is_a_safe_prime_with_a_valid_generator(self) -> None:
        n = srp.RFC5054_2048.n
        # g^((N-1)/2) == N-1 means 2 generates the prime-order subgroup rather than a
        # small one, which is the property that makes the discrete log hard.
        assert pow(2, (n - 1) // 2, n) == n - 1

    def test_the_hex_spelling_round_trips(self) -> None:
        # The protocol hashes hex strings, so the spelling is part of the wire format and
        # has to match what the C# BigInteger renders.
        assert srp.to_hex(srp.RFC5054_2048.n) == srp.RFC5054_2048.n_hex

    def test_the_multiplier_is_what_it_claims_to_be(self) -> None:
        # Same assertion as SrpGroupTest on the C# side. The literal exists so nothing is
        # derived at runtime; this proves it is SHA-256 over N and g.
        derived = srp.sha256_hex(srp.RFC5054_2048.n_hex + str(srp.RFC5054_2048.g))
        assert format(srp.RFC5054_2048.k, 'x').rjust(64, '0') == derived

    def test_the_legacy_multiplier_is_not_derived(self) -> None:
        # Inherited from the JavaScript implementation on the other side of this protocol.
        # Asserted so nobody "fixes" it and breaks every existing pairing.
        derived = srp.sha256_hex(srp.LEGACY_512.n_hex + str(srp.LEGACY_512.g))
        assert format(srp.LEGACY_512.k, 'x') != derived

    def test_declaring_the_feature_selects_the_strong_group(self) -> None:
        assert srp.group_for_features(['a', srp.STRONG_GROUP_FEATURE]) is srp.RFC5054_2048

    @pytest.mark.parametrize('features', [None, (), ('KPRPC_FEATURE_VERSION_1_6',), ('kprpc_feature_srp_2048',)])
    def test_everything_else_gets_the_legacy_group(self, features: object) -> None:
        # Including the lower-cased spelling: feature names are compared exactly
        # everywhere in this protocol.
        assert srp.group_for_features(features) is srp.LEGACY_512  # type: ignore[arg-type]

    @pytest.mark.parametrize('group', [srp.LEGACY_512, srp.RFC5054_2048])
    def test_a_full_exchange_agrees_with_an_independent_server(self, group: srp.SrpGroup) -> None:
        # The server here is implemented from the C# rather than from this client, so
        # agreement is evidence about the protocol and not just self-consistency.
        server = FakeServer(password='abc123', group=group)
        session = srp.SrpClientSession(group=group)

        secrets_ = session.derive(server.salt, server.public_key_hex, 'abc123')
        expected_shared, expected_m, expected_m2 = server._compute(session.public_key_hex)

        assert secrets_.shared_secret_hex == expected_shared
        assert secrets_.client_proof.lower() == expected_m.lower()
        session.verify_server_proof(secrets_, expected_m2)

    def test_the_two_groups_do_not_interoperate(self) -> None:
        # What happens when a client asks for a group the server does not offer. A clean
        # mismatch is the point: the alternative anyone would fear is one side quietly
        # continuing in the weaker group, which would look identical from outside.
        server = FakeServer(password='abc123', group=srp.LEGACY_512)
        session = srp.SrpClientSession(group=srp.RFC5054_2048)

        secrets_ = session.derive(server.salt, server.public_key_hex, 'abc123')
        _, expected_m, _ = server._compute(session.public_key_hex)

        assert secrets_.client_proof.lower() != expected_m.lower()
