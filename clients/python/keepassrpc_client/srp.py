"""Client half of the KeePassRPC SRP-6a handshake, and the key-challenge reconnect.

Ported from `SRP.cs` and `KeyChallengeResponse.cs` in this repository. Every constant and
construction below was read off that C# rather than off the SRP-6a specification, because
the two differ in ways that matter:

* All hashing is SHA-256 (`Utils.Hash`), including where the spec permits another hash.
* Integers cross the wire as C# `BigInteger.ToString(16)`: uppercase hex, no leading
  zeros, and a bare ``0`` for zero. Fixed-width or lowercase hex will not verify.
* The client and server nonces of the reconnect (`cc`, `sc`) are `BigInteger.ToString()`,
  which is *decimal*, not hex. Mixing the two silently breaks only the proof check.

This module is pure: no sockets, no clock, no key storage. That is what lets the maths be
tested offline against known vectors, which is the only part of the protocol that can be
checked without a running KeePass.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .errors import AuthenticationError, ProtocolError

#: Declared by a client that wants the 2048-bit group. Mirrors
#: `SrpGroup.StrongGroupFeatureName` in the plugin.
STRONG_GROUP_FEATURE = 'KPRPC_FEATURE_SRP_2048'


@dataclass(frozen=True)
class SrpGroup:
    """The discrete log group an exchange runs in.

    N and g are never sent: both ends hold them as constants and a feature flag is the
    whole of the negotiation. A client that asks for a group the server does not offer
    computes its public value in the wrong group and fails the proof, which is a clean
    failure rather than a silent downgrade.

    :ivar n_hex: The modulus in the hex spelling both ends hash. Part of the wire format.
    :ivar n: The modulus.
    :ivar g: The generator.
    :ivar k: The SRP-6a multiplier.
    """

    n_hex: str
    g: int
    k: int

    @property
    def n(self) -> int:
        """The modulus as an integer."""
        return int(self.n_hex, 16)


#: Upstream's group, and still the default. A 512-bit modulus is weak by modern standards
#: and upstream's mitigation is that pairing only ever happened over loopback. It stays
#: because the Kee browser extension is on the other side of it and cannot be changed.
#: Its ``k`` is a 160-bit constant inherited from the JavaScript implementation this
#: protocol was written against; it is not a hash of anything.
LEGACY_512 = SrpGroup(
    n_hex=(
        'd4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea'
        '2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43'
    ),
    g=2,
    k=int('b7867f1299da8cc24ab93e08986ebc4d6a478ad0', 16),
)

#: The 2048-bit group from RFC 5054 Appendix A. Published rather than freshly generated,
#: so a reviewer can check it against the RFC. ``k`` is SHA-256 over the hex spelling of N
#: followed by the hex spelling of g, which is this protocol's idiom, because it hashes hex
#: strings throughout rather than bytes, so the RFC's ``k = H(N | PAD(g))`` would be the
#: odd one out. ``test_srp`` recomputes it to keep the literal honest.
RFC5054_2048 = SrpGroup(
    n_hex=(
        'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050'
        'A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50'
        'E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8'
        '55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B'
        'CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748'
        '544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6'
        'AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6'
        '94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'
    ),
    g=2,
    k=int('2ab2340a74f7464acf31c2a60a5cd67d5cd640bba595902523bbd05aa24934c5', 16),
)


def group_for_features(features: tuple[str, ...] | list[str] | None) -> SrpGroup:
    """Pick the group a set of declared features asks for.

    :param features: What this client declares. Compared exactly, as everywhere else.
    :return: :data:`RFC5054_2048` if the strong group was asked for, else
        :data:`LEGACY_512`.
    """
    return RFC5054_2048 if features and STRONG_GROUP_FEATURE in features else LEGACY_512


# Module-level aliases for the default group, kept because they read well at call sites
# and because the legacy group is still what an unconfigured client uses.
N = LEGACY_512.n
G = LEGACY_512.g
K_MULT = LEGACY_512.k

_PRIVATE_KEY_BYTES = 32


def sha256_bytes(data: bytes) -> bytes:
    """Hash raw bytes with SHA-256 (`Utils.Hash(byte[])`).

    The one-time authorisation code reaches this function, so CodeQL reads it as password
    hashing and asks for a computationally expensive KDF. SRP-6a does not have that choice:
    the verifier exponent is ``x = H(salt || H(user || ':' || pass))`` with a plain hash by
    RFC 5054, and the peer computing the other half is KeePass's own implementation. A KDF
    on this side alone produces a client that fails to authenticate. What limits the value
    of the code is that it is single use and short lived, not the cost of hashing it.
    """
    # codeql[py/weak-sensitive-data-hashing]
    return hashlib.sha256(data).digest()


def sha256_hex(text: str) -> str:
    """Hash UTF-8 text with SHA-256 and return lowercase hex (`Utils.Hash(string)`)."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def to_hex(value: int) -> str:
    """Format an integer the way C# ``BigInteger.ToString(16)`` does.

    Uppercase, no leading zeros, and ``0`` for zero. The hex string is fed straight into
    hashes on both sides, so its exact spelling is part of the protocol.

    :param value: A non-negative integer.
    :return: Uppercase hex without a ``0x`` prefix.
    """
    return format(value, 'X')


def int_from_bytes(data: bytes) -> int:
    """Read bytes as a big-endian unsigned integer (`new BigInteger(byte[])`)."""
    return int.from_bytes(data, 'big')


@dataclass(frozen=True)
class SrpSecrets:
    """What a completed client-side SRP computation yields.

    :ivar session_key: The AES-256 session key, SHA-256 of the shared secret's hex form.
    :ivar client_proof: ``M``, the proof sent to the server.
    :ivar shared_secret_hex: ``S`` in C# hex form, needed to check the server's ``M2``.
    """

    session_key: bytes
    client_proof: str
    shared_secret_hex: str


class SrpClientSession:
    """One client-side SRP-6a exchange.

    Single use: construct, send :attr:`public_key_hex`, then call :meth:`derive` once with
    the server's salt and public key.
    """

    def __init__(self, private_key: int | None = None, group: SrpGroup = LEGACY_512) -> None:
        """
        :param private_key: The ephemeral private exponent ``a``. Generated from
            :mod:`secrets` when omitted; pass one only in tests, where a fixed exponent is
            what makes the exchange reproducible.
        :param group: The group to compute in. Must match what the server will use, which
            is decided by whether this client declared :data:`STRONG_GROUP_FEATURE`.
        """
        self._group = group
        if private_key is None:
            private_key = int_from_bytes(secrets.token_bytes(_PRIVATE_KEY_BYTES)) % group.n
        self._private_key = private_key
        self._public_key = pow(group.g, private_key, group.n)
        if self._public_key % group.n == 0:
            # The server rejects A % N == 0; refuse to send it rather than be rejected.
            raise AuthenticationError('generated an invalid SRP public key; retry pairing')

    @property
    def group(self) -> SrpGroup:
        """The group this exchange is running in."""
        return self._group

    @property
    def public_key(self) -> int:
        """The ephemeral public value ``A``."""
        return self._public_key

    @property
    def public_key_hex(self) -> str:
        """``A`` in the hex spelling the server expects."""
        return to_hex(self._public_key)

    def derive(self, salt: str, server_public_hex: str, password: str) -> SrpSecrets:
        """Complete the exchange against the server's response.

        :param salt: ``s`` exactly as the server sent it. It is concatenated with the
            password before hashing, so it is used as a string and never re-encoded.
        :param server_public_hex: ``B`` in hex, as sent.
        :param password: The authorisation code KeePass is displaying.
        :return: The session key and the proof material.
        :raises ProtocolError: If ``B`` is malformed or is a multiple of ``N``, which
            would collapse the shared secret.
        """
        try:
            server_public = int(server_public_hex, 16)
        except ValueError as exc:
            raise ProtocolError(f'server public key B is not hex: {server_public_hex!r}') from exc
        group = self._group
        if server_public % group.n == 0:
            raise ProtocolError('server public key B is a multiple of N; refusing to continue')

        x = int_from_bytes(sha256_bytes((salt + password).encode('utf-8')))
        u = int_from_bytes(sha256_bytes((self.public_key_hex + server_public_hex).encode('utf-8')))
        base = (server_public - (group.k * pow(group.g, x, group.n))) % group.n
        shared = pow(base, self._private_key + u * x, group.n)
        shared_hex = to_hex(shared)
        # M = H(A || B || S). Note B is the server's hex as sent, not a re-rendering of the
        # parsed integer: the server does not reduce B modulo N (`SRP.cs` Setup), so the two
        # spellings can differ and only the one on the wire hashes to the value it expects.
        return SrpSecrets(
            session_key=sha256_bytes(shared_hex.encode('utf-8')),
            client_proof=sha256_hex(self.public_key_hex + server_public_hex + shared_hex),
            shared_secret_hex=shared_hex,
        )

    def verify_server_proof(self, secrets_: SrpSecrets, server_proof: str) -> None:
        """Check ``M2`` and raise if it does not match.

        This is the mutual half of the authentication: it proves the far end really holds
        the shared secret rather than merely having accepted our proof. Skipping it would
        leave the client trusting whatever answered on the port.

        :param secrets_: The result of :meth:`derive`.
        :param server_proof: ``M2`` as sent by the server.
        :raises AuthenticationError: If the proof is absent or does not match.
        """
        expected = sha256_hex(self.public_key_hex + secrets_.client_proof + secrets_.shared_secret_hex)
        if not hmac.compare_digest(expected.lower(), (server_proof or '').lower()):
            raise AuthenticationError('server proof (M2) mismatch; refusing to trust this session')


def new_client_nonce() -> str:
    """Generate ``cc`` for the reconnect, decimal-formatted as the server's ``sc`` is."""
    return str(int_from_bytes(secrets.token_bytes(_PRIVATE_KEY_BYTES)))


def client_challenge_response(key_hex: str, server_nonce: str, client_nonce: str) -> str:
    """Compute ``cr``, the client's answer to the server challenge.

    Mirrors `KeyChallengeResponse2`: ``Hash('1' + key + sc + cc)``.

    :param key_hex: The stored session key as lowercase hex.
    :param server_nonce: ``sc`` as sent.
    :param client_nonce: ``cc`` as generated.
    :return: Lowercase hex.
    """
    return sha256_hex('1' + key_hex + server_nonce + client_nonce)


def expected_server_response(key_hex: str, server_nonce: str, client_nonce: str) -> str:
    """Compute the ``sr`` the server must return: ``Hash('0' + key + sc + cc)``.

    The leading digit is the only thing separating this from the client's own ``cr``,
    which is what stops a reflection of our own answer from passing as the server's.
    """
    return sha256_hex('0' + key_hex + server_nonce + client_nonce)


def verify_server_response(key_hex: str, server_nonce: str, client_nonce: str, server_response: str) -> None:
    """Check ``sr`` and raise if it does not match.

    :raises AuthenticationError: If the response is absent or does not match.
    """
    expected = expected_server_response(key_hex, server_nonce, client_nonce)
    if not hmac.compare_digest(expected.lower(), (server_response or '').lower()):
        raise AuthenticationError('server proof (sr) mismatch; refusing to trust this session')
