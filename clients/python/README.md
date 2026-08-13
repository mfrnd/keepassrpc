# keepassrpc-client

A Python client for the KeePassRPC plugin in this repository: SRP-6a pairing, a
key-challenge reconnect for headless use, and AES-encrypted JSON-RPC on top.

It exists for two reasons: to test the plugin from the outside while the V3 API is built,
and to be consumed by unattended workloads once V3 lands.

## Why it lives here

The protocol is defined by the C# in this repository, so the client that speaks it belongs
next to it. The constants and constructions were read off `SRP.cs`,
`KeyChallengeResponse.cs` and `KeePassRPCClient.cs` rather than off the SRP-6a
specification, because the two differ in ways that silently break interoperability. The
test suite implements the *server* side independently from the same C# and checks the two
agree, which is what makes the port defensible.

## Install

Uses [uv](https://docs.astral.sh/uv/).

```bash
cd clients/python
uv sync
```

## Pairing

Pairing is interactive by design: KeePass shows a code and a human types it. Do it once per
identity, then reconnect headlessly forever after.

```bash
uv run keepassrpc-client --username my-agent pair
```

KeePass raises an authorisation dialog showing a code; enter it at the prompt. The session
key is then stored, DPAPI-protected under your Windows account, at a per-identity path
under `%LOCALAPPDATA%\keepassrpc-client\`.

**One identity per agent.** The plugin keys its stored keys on the identity, so that is the
granularity at which access can be revoked and audited. Sharing one identity across two
agents means neither can be revoked without breaking the other.

Afterwards, everything is headless:

```bash
uv run keepassrpc-client --username my-agent info
uv run keepassrpc-client --username my-agent call GetDatabaseName
```

## Library use

```python
from keepassrpc_client import DpapiKeyStore, KeePassRpcClient, default_key_path

store = DpapiKeyStore(default_key_path('my-agent'))
with KeePassRpcClient.connect(store) as client:
    print(client.get_database_name())
    print(client.call('GetAllDatabases', [False]))
```

`connect()` pops no dialog and verifies the server's proof before returning. Anything
without a convenience wrapper is reachable through `call()`.

## The Origin gotcha

The plugin rejects any connection whose `Origin` is not on its allowlist, and its default
list is browser-extension schemes only
(`KeePassRPCServer.ValidateOrigin`, prefix match). A non-browser client therefore has to
present something starting with one of those prefixes, which is why the default here is
`chrome-extension://keepassrpc-python-client`.

The cleaner alternative is to name your client explicitly in the KeePass config, under
`KeePassRPC.webSocket.permittedOrigins` (comma-separated). Setting it replaces the default
list rather than adding to it, so include the browser prefixes if a browser extension also
uses this KeePass.

## Security posture

- **Fail closed.** Every ambiguity raises. There is no path that returns a partial result
  or continues with an unverified session.
- **Mutual authentication.** Both `M2` (pairing) and `sr` (reconnect) are verified with a
  constant-time comparison. Without that, the client would trust whatever answered on the
  port.
- **No plaintext key store.** A session key on disk in the clear is a bearer token for the
  database. Only DPAPI and in-memory stores ship; implement `KeyStore` yourself if you need
  something else, and own that decision.
- **The CLI prints no secrets by design.** There is no "get password" command. Reading
  secret values belongs in the caller's own code, where handling the value is a deliberate
  choice rather than a side effect of a convenience command.

What this does **not** defend against: anything running as your Windows account. The stored
key is DPAPI user-scoped, so a process with your privileges can use it. That is the same
boundary the plugin itself assumes, and it is worth being clear that the guard rail is
against a confused deputy, not against an attacker who already has your account.

### Session crypto

This client asks for `KPRPC_FEATURE_CRYPTO_V2` and gets, per connection: an ephemeral P-256
key agreement authenticated by the paired key, HMAC-SHA256 instead of a hash-of-
concatenation, separate encryption and MAC subkeys, and a sequence number per direction so a
replayed or reordered message is refused.

The point of the exchange is forward secrecy. Without it the AES key IS the key established
at pairing. One key for every message of every session, for up to a year, sitting in a
DPAPI blob any local process can read. Traffic captured today would stay decryptable by
whoever obtained that key later.

**If the plugin does not complete the agreement, this client fails rather than continuing.**
Silently falling back would leave a caller believing it has forward secrecy when it does not.
Drop `crypto_v2.FEATURE_NAME` from `ClientConfig.features` if you deliberately want the
original suite.

The original suite is still there for clients that do not ask, and is reimplemented
faithfully, warts included: a 512-bit SRP group, and a `SHA1(SHA1(key) || ciphertext || iv)`
construction travelling in a field named `hmac`. Do not "fix" those; a client that does
cannot talk to KeePass. What upstream relies on is that the transport is loopback-only.

## Development

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
```

Tests are offline and need no KeePass: the handshake runs against a fake server that
implements the C# server side independently. The DPAPI tests skip themselves off Windows.

## The V3 API

```python
entry = client.get_entry3('92A41B8F959811F198461C1B0D9E4DD7')   # UUID, or an exact title
listed = client.list_group3('Root/Some Group')                  # titles and UUIDs only
blob = client.get_attachment3(entry['uuid'], 'note.txt')        # bytes
```

V3 returns the entry as KeePass holds it: real custom strings, notes, and attachment names.
Empty values are present rather than dropped, so a deliberately blank placeholder survives.
One string is never returned, `KPRPC JSON`, which is upstream's legacy per-entry config.

Two things will surprise you if nobody says them:

- **Declaring the feature is not permission.** Every V3 call is refused unless this client's
  subject holds a profile granting those methods, and then refused again per entry by the
  ACL. A fresh pairing can reach nothing at all until someone grants it, deliberately.
- **`get_attachment3` can block on a human.** Attachment content raises a confirmation
  dialog in KeePass unless the subject's grant says `unattended`, so the call waits for
  someone to answer. It uses `PROMPT_TIMEOUT` (300s) rather than the session's read timeout;
  at the default ten seconds a working prompt looks like a connection failure. Pass
  `timeout=` explicitly if you would rather fail fast.

### Writing

```python
created = client.add_entry3('Root/Some Group', {'title': 'x', 'password': 'y'})
client.update_entry3(created['uuid'], {'password': 'z'})       # only the password changes
client.set_attachment3(created['uuid'], 'note.txt', b'bytes')
client.remove_entry3(created['uuid'])                          # needs the `delete` verb
```

**Know what "not supplied" means, because there are two of them.** A standard member that is
absent or `None` is left alone, while an empty string sets it empty. `fields` absent or `None`
leaves the custom strings alone, but a list **replaces** them, even an empty one, so any
name not in it is deleted. Read-modify-write is the safe shape: take what `get_entry3`
returned, change what you mean to, send it back. KeePass keeps the previous state in entry
history either way, and deletions go to the Recycle Bin.

## Status

Wraps v1, v2 and the whole of V3, read and write.
