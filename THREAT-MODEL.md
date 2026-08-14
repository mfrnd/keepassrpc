# Threat model

What the V3 API and its access controls actually defend against, what they do not, and which of
those gaps are accepted rather than overlooked.

This is a working document, not a certification. Its purpose is to stop the controls in this fork
being credited with more than they do: several of them are guard rails against a legitimate client
asking for too much, and would not survive an attacker who can run code as the same Windows user.
Where that is the case it is said plainly, because a control described as stronger than it is will
eventually be trusted for something it cannot carry.

Read [`V3-DESIGN.md`](V3-DESIGN.md) first. This document assumes the design and argues about its
edges.

## The one boundary that matters

**Everything in this system lives inside a single trust domain: the Windows user account.**

The plugin runs inside the KeePass process, owned by that account. The database is decrypted in that
process's memory whenever it is unlocked. Every paired client's session key is at rest under DPAPI
CurrentUser, decryptable by anything running as that account. That is upstream's `SecurityLevel`
2, the default, and it is what everything below assumes; see
[Key storage at rest](#key-storage-at-rest-upstreams-security-levels), because level 3 removes that
copy and is more usable here than it first appears. The socket is loopback, reachable by any local
process. The audit log, the grants, the profiles and the configuration are all files or
memory belonging to that account.

So the controls below are not a boundary between an attacker and the database. They are a boundary
**between a client and the parts of the database that client should not reach**, enforced by code
that the attacker could bypass entirely if they were executing as the user. That is not a flaw to be
fixed by adding more checks in this repository; it is the shape of the problem. Real separation would
need the agent to run as a different Windows user, or the key held somewhere the agent cannot reach.

Everything that follows should be read against that.

## What is being protected

Ranked by what losing it costs, which is not the same as ranking by how secret it looks.

| Asset | Why it ranks where it does |
| --- | --- |
| **Attachment content** | Typically private keys or whole certificate bundles. A leaked key is usable elsewhere, silently, and rotating it is a project rather than a click. This is why attachment content is a separate right from `read`. |
| **Passwords and custom strings** | The obvious asset. Rotatable, which is exactly why they rank below key material. |
| **The set of entry titles and the group layout** | An inventory. It tells an agent, or whoever is steering it, where the interesting things are. This is why `list` is a rung of its own and why the audit log records UUIDs rather than titles. |
| **Paired session keys** | A key is a bearer token for whatever its subject may reach. Compromising one is compromising that subject. |
| **The grants and profiles themselves** | Rewriting these grants everything else. Their integrity matters more than their confidentiality. |
| **The audit log** | Worth little day to day; the only evidence there is after something goes wrong. |
| **KeePass availability** | Not confidentiality at all, but the plugin runs inside the author's password manager, so a hang or crash here locks them out of everything. |

## Actors

Deliberately concrete rather than abstract, because the interesting threats differ sharply between
them.

1. **The human at the keyboard.** Trusted. Can do anything; the controls exist to serve them.
2. **A browser extension**, paired long ago, speaking v1/v2. Trusted to the extent it always was.
   Not an agent, not scriptable by a third party except through the browser's own compromise.
3. **A non-interactive deploy client.** Resolves secrets over v1, runs unattended. Its behaviour
   is fixed by code that a human reviews.
4. **An AI agent.** The reason this fork exists, and the actor the design is really about. Speaks
   V3, runs unattended or semi-attended, and **its instructions are partly attacker-controlled**:
   anything it reads can attempt to steer it: a web page, an issue, a file, a tool result.
5. **A malicious local process** running as the same Windows account.
6. **A remote attacker** with no local code execution.
7. **Upstream**, as a supply of future code this fork merges.

## Threats, by actor

### 4. The prompt-injected agent, the dominant risk

This is the threat the whole design is aimed at, and the only one where the controls are genuinely
load-bearing rather than incidental.

The agent is authenticated, authorised, and doing exactly what the protocol permits. Nothing is
"exploited". It has simply been persuaded to ask for the wrong thing, and the interesting question is
only ever **how much a single well-formed request can be worth**.

| What it tries | What stops it |
| --- | --- |
| Read every entry in the database | The ACL: default deny, and a grant only reaches the entries beneath it |
| Sidestep V3 by calling v1 `GetAllLogins` | The method gate: the `v3` profile contains no v1 or v2 method at all |
| Sidestep the gate by re-casing the method name | The gate resolves the canonical name through Jayrock's own lookup before deciding |
| Enumerate what exists, to choose a target | `list` is a separate rung; a client whose profiles hold `read` on one entry cannot list its neighbours |
| Pull a private key out of an attachment | `attachments` is a separate flag, and content prompts unless the grant says `unattended` |
| Widen its own access by writing a grant | Grants live in `CustomData`, which no API generation exposes. Verified: no v1, v2 or V3 code path reads or writes it, and V3's field API works on `Strings` and `Binaries` only |
| Widen its access by joining a wider profile | The profile registry lives in the same root-group `CustomData`, behind the same structural boundary: no API generation can read or write it |
| Widen its access by rewriting the entry config | `KPRPC JSON` is refused on read and stripped on write |
| Escalate by moving an entry to a permissive group | V3 has no move; `UpdateEntry3` ignores the DTO's `group` |
| Quietly destroy data instead of stealing it | `CreateBackup` before every mutation, deletion to the Recycle Bin, `delete` a separate rung above `write` |

**What does not stop it:** anything it is legitimately granted. An agent granted `read` on a group
can read every entry in that group, forever, and no amount of prompting design changes that. The
control that matters is therefore the size of the grant, and the design's real advice is to keep
grants narrow rather than to trust the ladder to compensate for a broad one.

**Prompt fatigue is a real weakening.** Confirmation dialogs are only worth something while they are
rare enough to be read. A workflow that triggers one every few minutes trains the human to approve
reflexively, at which point the prompt is worse than nothing because it is credited as a control.
`unattended` exists so that a frequent, low-risk grant can skip the prompt deliberately rather than
eroding it by attrition.

### 5. The malicious local process, mostly undefended by construction

Running as the same Windows account, it can:

- read any paired client's session key from DPAPI and present itself as that subject, unless the
  installation runs at `SecurityLevel` 3, where there is no stored key to read;
- connect to the loopback socket and pass the `Origin` check, which is a header the client chooses
  (this fork's own test client presents an invented `chrome-extension://` value and is accepted --
  the Origin allowlist keeps a stray *browser page* out, and is not an authentication control);
- read, rewrite or delete the audit log;
- edit `KeePass.config.xml` while KeePass is closed, granting itself any profile;
- read the decrypted database out of KeePass's memory, bypassing all of this entirely.

Only the last of those needs any sophistication. **The correct summary is that this fork does not
defend against local code execution as the user, and nothing in it should be described as if it
does.** The method gate and the ACL still have value in that world, but only as a record and a
speed bump, not as a boundary.

### 6. The remote attacker

Largely out of reach. The server binds `127.0.0.1` only (`bindOnlyToLoopback`, default true, verified
on a live instance), so there is no listening surface off-host. The residual paths are the ordinary
ones, meaning a browser or agent that can be induced to make loopback requests on the attacker's behalf,
which lands back on actor 4.

**Since 2026-08-12 the plugin nevertheless treats an off-host connection differently**, in
preparation for an exposure that has not happened. `RemoteAccess` marks a connection remote from a
non-loopback peer address or a marker segment in the request path, and a remote connection must use
`KPRPC_FEATURE_CRYPTO_V2`, must use the 2048-bit SRP group if it is pairing, and is recorded as
remote in the audit log. **None of that makes exposure supported**, and none of it is reachable
today: it removes prerequisites from a list in
[`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md) that still has infrastructure items on it. It is
described here so the controls are not mistaken for evidence that the question is settled.

Worth being explicit about one thing these controls do NOT cover, because the wording invites the
assumption: there is no per-subject notion of remote capability. Any subject whose paired key an
attacker holds can be used from anywhere the transport allows. That was proposed and rejected; see
[`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md). What bounds a remote subject is its method profile and
its ACL scope, the same things that bound a local one.

One item from that analysis belonged here even while the port stays local, because it was a defect
rather than a design limit: an unauthenticated client could raise a KeePass dialog whose text it
controlled. `SRPIdentifyToServer` shows the authorisation prompt before any authentication, and the
client's own description was concatenated into that dialog's RTF without escaping. (The name was
never injectable; upstream allowlists it, which the first write-up of this missed.) **Fixed
2026-08-12** by `RtfText.Escape`. What remains is upstream's design rather than a defect: any client
may ask to pair, and asking raises a prompt, which is a nuisance locally and would be a denial of
service remotely. Barring remote pairing was considered as an answer to that and rejected, because it
would not have held, and a rate limit at the proxy is the control that fits. Note that asking is as
far as an unauthenticated caller gets: the code it would have to quote back is only ever rendered on
this machine's screen.

The ORIGINAL wire crypto would not withstand a capable attacker on the path, and there is no path.
Were there one, a connection over it would be refused unless it negotiated the newer suite, so the
weak crypto and the network are mutually exclusive by construction rather than by deployment
discipline. See [Inherited weaknesses](#inherited-weaknesses).

### 2 and 3. Existing clients

Their risk is not malice but **breadth**: both hold `legacy`, which is every v1 and v2 method, which
is the whole database.

Since 2026-08-12 that breadth can be narrowed. The ACL covers v1 and v2 for any subject whose
`KeePassRPC.AclScope` is `all`, so a legacy subject can be constrained to the same entries as a V3
one. It is opt-in and defaults to off, because a filtered v1 read returns a list rather than an
error, so a mistake here looks like an empty database and v1 resolves secrets in production.

**So the residual risk is now configuration, not architecture.** A subject left on the default is
authorised wholesale exactly as before, and nothing in the product will tell you that except the
Authorised clients tab, which shows the access each client holds. Moving every subject to `all` is the intended
end state.

### 7. Upstream

A merge can add a JSON-RPC method. If profiles were data, such a method might land inside an existing
profile silently. They are code, so it lands in none, is denied, and `MethodProfilesTest` fails until
someone decides where it belongs. This is the one place where "fail closed" is enforced by the build
rather than at runtime.

## Key storage at rest: upstream's security levels

Inherited, unmodified, and not mentioned anywhere else in this fork's documents until now, which was
an omission: it is the one upstream control that acts on the same asset the ACL protects, and its
strongest setting partly answers this model's central concession.

`KeePassRPC.SecurityLevel` decides where a paired client's key is kept between sessions. Despite
sitting on a tab called "Connection security", it says nothing about the connection.

| Level | Where the key lives | What that costs, and buys |
| --- | --- | --- |
| 1 | Plain text in `KeePass.config.xml` | A bearer credential in a file that gets backed up, synced and roamed. Worse than level 2 in a way that has nothing to do with local processes: a DPAPI blob is inert on another machine, a plaintext key is not. No reason to choose it. |
| 2 | DPAPI, CurrentUser scope, in the config | The default, and the assumption everything else here is written against. Readable by anything running as that account, which is the concession this whole document is built around. |
| 3 | Nowhere. Not persisted | No key on disk to steal. Against the local process it closes the path that needs no sophistication at all, leaving only reading KeePass's memory. |

`KeePassRPC.SecurityLevelClientMinimum` refuses a client that declares a level below the configured
minimum. It is a claim the client makes about its own storage, unverifiable, in the same category as
the `Origin` allowlist: useful as a nudge, not as a control.

### Why level 3 is more plausible here than it sounds, and what actually rules it out

The obvious objection is that re-pairing needs a human to read a code off the KeePass screen, and
unattended agents have no human. That objection is weaker than it looks, because **nothing
unattended can happen until a human unlocks the database anyway**. If a person is already present at
every KeePass start, one authorisation dialog per agent at that same moment is a small addition to
something they were doing regardless.

What rules it out is not the human, it is the granularity. **Measured 2026-08-12: at level 3 the
key does not survive the connection, not merely the KeePass session.** The plugin keeps it on the
connection object and caches it nowhere else, so pairing, closing the socket and reconnecting with
the same key is refused with `AUTH_FAILED` and "Stored key not found", and no dialog is raised, so the
client simply fails rather than waiting for anybody.

That makes level 3's usability a property of the client, not of the plugin:

- **A client holding one connection for the life of the KeePass session** pairs once per start,
  which does coincide with the human unlock. Level 3 is genuinely available to it. The Kee extension
  works this way.
- **A client that connects per call** pairs per call. Every secret resolution raises a dialog. No
  unattended workload survives that, and a connect-per-call consumer is the shape this fork was
  written for.

Two further caveats before anyone reaches for it. The premise fails if the database is opened
without a human, by a key file alone or a password on the command line, because then there is
nobody to answer the dialog and the agent is simply dead. And any reconnect at all, after a network
blip or a client restart, needs a person; an agent that must be re-paired to recover is not
unattended in the sense that matters.

**So level 3 is a real option for a persistent-connection client and not a general answer**, and the
concession in "the one boundary that matters" stands for the setting this fork is deployed into.
It is worth revisiting if the consumer is ever changed to hold its connection open, because it would
retire the easiest attack in the model at a cost of one dialog per agent per KeePass start.

## What each control is actually worth

| Control | Worth | Not worth |
| --- | --- | --- |
| SRP pairing + key challenge | Real mutual authentication; the client proves it holds the key and the server proves it too | Nothing, once the key is readable by anything running as the user |
| Key storage at rest (upstream `SecurityLevel`) | At level 3 there is no stored key at all, which removes the cheapest way to impersonate a subject | At the default level 2 it stops nothing that runs as the user; at level 1 it also exposes the key to backups. Level 3 costs a pairing per connection, not per session |
| Origin allowlist | Keeps a random web page from reaching the socket | Not an authentication control; a local client picks its own Origin |
| Session crypto (original) | Obscures traffic on loopback | One key for the life of the pairing, no replay protection, and a MAC that is not an HMAC |
| Session crypto (negotiated) | Forward secrecy per connection, HMAC-SHA256, replay and reorder refused | Still not an AEAD, because .NET Framework 4.5 has none; and it protects the channel, not the caller |
| **Method gate** | The outer boundary. Without it the ACL is decorative, because a client can decline to use V3 | Cannot help a subject that legitimately holds `legacy` |
| **ACL** | Per-entry, narrow-only, deny by default unless a database opts into allow by default. Rules name profiles; clients are mapped through the database's registry. The control that makes a narrow agent possible | Guards only the generations a subject's scope covers; defaults to V3 alone. A client in several profiles holds the WIDEST of what they grant, so a `none` in one does not revoke what another gives |
| Confirmation prompts | A human in the loop for the irreversible and the high-value | Erodes under frequency; skippable by grant |
| Audit log | The only after-the-fact evidence that exists; records whether each call crossed the network | Not tamper-proof against the account that writes it |
| Remote connection detection | Lets the plugin hold off-host connections to a stronger standard than local ones. Two signals: a non-loopback peer address, which is definitive, and a marker in the request path, which a proxy sets and a client cannot | Blind to anyone who reaches the port without going through the proxy, which is what loopback binding is for. Errs towards "remote", so its mistakes cost access rather than safety |
| Crypto required of remote connections | A remote connection cannot use the original session suite, and cannot pair in the 512-bit group. The two weakest inherited things are unreachable from a network by construction, not by configuration | Says nothing about a key that was paired weakly before: the plugin does not record which group a key came from, and a key from an old 512-bit pairing still reconnects remotely. Those pairings were over loopback, where the exchange could not be watched |
| `CustomData` for grants | Structural: no API path reaches it, so a grant cannot be written through the API by any client | Does not protect against a process editing the `.kdbx` with KeePass closed |

## Inherited weaknesses

Upstream's, reimplemented faithfully because a client that "fixes" them cannot talk to KeePass.
Listed so that nobody rediscovers them and assumes they are this fork's choices.

**Since 2026-08-12 a client can negotiate away from most of this.** `KPRPC_FEATURE_CRYPTO_V2` gets
an ephemeral P-256 key agreement per connection, HMAC-SHA256, and a sequence number per direction.
Everything below therefore describes the ORIGINAL suite, which is what a client gets when it does
not ask. Notably the Kee browser extension, which is the only legacy client that matters here.

- **One key for the life of the pairing.** The worst of these, and not obvious from reading the
  cipher: the AES key IS the key established at pairing. The key challenge proves possession and
  derives nothing, so every message of every session shares one key for up to a year. Combined with
  that key sitting in a DPAPI blob any local process can read, it means **traffic captured today is
  decryptable by anyone who obtains the key later**. The negotiated suite fixes exactly this; a
  legacy client still has it.
- **512-bit SRP group.** Weak for a modern key exchange, and not addressed by the newer session
  suite, which authenticates its exchange with the paired key rather than replacing pairing. Its
  practical importance already dropped for a negotiating client, because breaking the group yields
  the paired key and that no longer decrypts recorded sessions on its own. **Answered 2026-08-12**
  for clients that ask: `KPRPC_FEATURE_SRP_2048` pairs in the RFC 5054 2048-bit group instead.
  Inherited rather than fixed, because the group is negotiated and not universally required: a
  LOCAL client that does not declare the feature still pairs in the 512-bit group, which is what
  keeps Kee working and is therefore what keeps this entry on the list. A REMOTE pairing has no
  such latitude and is refused unless it asks for the strong group, since a remote pairing is the
  only case where the exchange could plausibly be observed.
- **The session MAC is `SHA1(SHA1(key) || ciphertext || iv)`**, a hash of a concatenation rather than
  an HMAC, travelling in a field named `hmac`, using SHA-1 while the rest of the protocol uses
  SHA-256. Upstream's own source carries a TODO about strengthening it.
- **Nothing detects replay** in the original suite. Nothing binds a message to a session or an
  ordinal.
- **Jayrock resolves method names case-insensitively.** Not a weakness in itself, but it invalidates
  the obvious way to write a name-based gate, and did so here before it was caught. Any future check
  keyed on a method name must resolve it the way the dispatcher will.
- **The plugin shares the KeePass UI process.** A deadlock or unhandled exception in this code takes
  the password manager with it. This is why refusals return errors rather than throwing, and why the
  confirmation prompt is the only place that blocks the UI thread.

## Accepted risks

Decisions, not oversights. Each could be revisited; none is being.

1. **Local code execution as the user defeats everything.** Accepted because the alternative is a
   different architecture, and because the same account already holds the master password in a
   running KeePass. Partly avoidable, and not taken: `SecurityLevel` 3 would remove the stored key
   that makes impersonating a subject trivial, but it forces a fresh pairing on every connection
   rather than every session, which the connect-per-call consumer cannot survive. See
   [Key storage at rest](#key-storage-at-rest-upstreams-security-levels).
2. **An audit write failure does not refuse the call.** Refusing would let a full disk revoke every
   agent's access. The recording failure is reported instead.
3. **The audit log is not tamper-proof.** Append-only describes this code, not the filesystem.
4. **Clients paired before this build are granted `legacy API, unrestricted` without anybody asking.**
   A default-deny gate arriving on a working installation would otherwise break every one of them,
   so `LegacyClients.Migrate` gives each the access it already had. It runs once, marked by
   `KeePassRPC.MethodGate.LegacyClientsMigrated`, and covers only clients that were paired before
   it first ran, so it widens nothing that was not already wide. It replaced a configurable
   fallback that did the same job and then stayed on the options dialog, where it could hand the
   whole database to every future client; a one-off migration cannot be left switched on by
   accident, and what it grants is visible per client and can be narrowed.
5. **No rate limiting.** An agent can call as fast as it likes, and can raise as many prompts as it
   likes, because any client may ask to pair and asking raises a modal dialog. Denial of service
   against the human's attention is possible, and against KeePass itself, since the plugin shares
   its UI process. Accepted on loopback, where anything that can reach the socket can do worse. It
   would not be acceptable under exposure, and there is no plugin-side answer planned: barring
   remote pairing was considered and rejected, so a rate limit in front of the plugin is the whole
   of the mitigation. That makes it a hard prerequisite for exposure rather than a nicety.
6. **v1 and v2 are unguarded by the ACL until a subject is moved to `AclScope = all`.** The
   capability exists; the default does not use it, so this is an accepted risk about defaults rather
   than about what is possible.
7. **A database can be set to allow by default**, which inverts the entry-access posture: every
   client the method gate lets through then holds delete, attachment content and no confirmation
   prompt on every entry that no rule speaks about. It exists because an operator may genuinely want
   a database whose rules read as exclusions, and it does not weaken anything structurally: the
   method gate still decides who gets to V3 at all, groups and entries still only narrow, and the
   fail-closed readings are untouched, since an unreadable document and an unrecognised `default`
   both still deny. What it does change is the cost of an omission. Under deny by default a
   forgotten rule grants nothing; under allow by default a forgotten rule grants everything, which
   is why switching to it asks for confirmation and why the tab keeps saying so afterwards. Do not
   describe a database in that mode as least-privilege.
8. **Entry history retains superseded values.** `CreateBackup` is what makes a bad write recoverable,
   and the same mechanism means a password that leaked is still in the file after being changed.
   Revoking a leaked credential means rotating it at the far end, not editing KeePass.
9. **Two of the four shipped dependencies are prebuilt binaries with no source in this repository,
   and nothing scans them.** `Fleck2.dll` (2.0.0.0) terminates the WebSocket connection, and
   `DomainPublicSuffix.dll` (2.0.1.0) parses URLs; both are committed binaries, both are copied
   into the `.plgx`, and both are therefore code this fork ships and cannot read. Fleck2 is the
   worse of the two by position: it handles the handshake and the frame decoding, so it sees
   attacker-controlled bytes before anything in this repository does, including the `Origin`
   allowlist and the method gate.

   Upstream chose these and the fork keeps them, because replacing either means rewriting the
   socket layer, and a client that cannot connect is not a safer client. The other two are better
   off: `Jayrock.dll` and `Jayrock.Json.dll` are also committed prebuilt, but their source is in
   `Jayrock/src`, it builds to the same assembly version, and CodeQL analyses it, which is why no
   path filter excludes it. The parser reachable from the socket is at least readable.

   What this costs is specific and worth naming: for Fleck2 and DomainPublicSuffix there is no
   version to watch, no advisory feed that names them, and no scan that would find a flaw in them,
   so a vulnerability in either would arrive here silently. Dependabot covers the Python client and
   the workflow actions; it has nothing to say about a committed DLL. Treat a WebSocket-layer flaw
   as unmitigated rather than assume the controls in this document apply above it.

## Operational hazards

Ways the model quietly weakens without anybody changing code. These are the ones worth re-reading
before granting anything.

- **A grant on the database root reaches the Recycle Bin.** Deleted entries stay in the file, under a
  group that inherits from the root like any other. Grant at group level, not at the root, unless
  reaching deleted entries is intended.
- **Moving an entry silently changes its access.** Effective rights come from where an entry sits, so
  dragging one into a granted group grants it. Nothing warns about this, because it is KeePass's own
  UI doing the moving.
- **An omitted flag narrows.** A child grant that does not repeat `attachments` removes it. Safe by
  default, and surprising the first time.
- **`"*": "none"` at the root denies everyone everywhere** and cannot be reopened lower down.
- **A pairing made in a development KeePass does not exist for the installed one**, and vice versa,
  because a KeePass run outside its install directory keeps its own configuration.
- **A profile cannot be removed, only set to `none`.** Configuration exposes no delete.

## What would change this model

Triggers for rewriting rather than amending:

- **Running an agent as a different Windows user.** This is the change that would turn the guard
  rails into a boundary, and most of the "accepted risks" above would stop being acceptable because
  they would stop being necessary.
- **Exposing the socket beyond loopback**, for any reason. This document assumes a single trust
  domain and a transport nobody else can reach; exposure changes the first assumption's
  consequences and removes the second. Analysed in
  [`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md), which concludes that the plugin should stay bound to
  loopback behind a mesh VPN, with a reverse proxy whose only job is rate limiting. Client
  certificates were considered and dropped: a VPN peer key is already a per-agent credential, and
  the plugin's payloads are encrypted between client and plugin, so the proxy is not in the
  confidentiality boundary.

  The plugin-side prerequisites from that document are built as of 2026-08-12, namely remoteness
  detection, the crypto requirements and the audit field, **and that is not the same as exposure
  being supported.** What remains is infrastructure, and one control with no plugin-side answer at
  all: rate limiting. The interesting consequence if it ever happens is in that document rather than
  this one, and it is not the obvious one: a remote attacker cannot run code as the user, so the
  method gate and the ACL would become a real boundary against them rather than the guard rails they
  are here.
- ~~Bringing v1 and v2 under the ACL.~~ Done 2026-08-12. What remains is moving each subject onto
  it, which is configuration and is tracked per client in the options dialog.
- **A second human using the same database**, which would make the audit log's attribution matter in
  a way it currently does not.
