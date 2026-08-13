# Exposing KeePassRPC beyond loopback

An analysis of what it would take to reach this plugin from the LAN or the internet, what breaks,
and what to build instead. Read [`THREAT-MODEL.md`](THREAT-MODEL.md) first; this document argues
about what changes when its central assumption is removed.

## The short answer

**Do not bind the plugin to anything but loopback, and do not put a reverse proxy on the internet in
front of it.** Both are achievable, and neither is the right shape of answer.

The recommendation is a mesh VPN so the port has no public existence at all, a plain reverse proxy on
the KeePass host whose only jobs are rate limiting and binding the tunnel interface, and the plugin
changes listed below, which are built.

**Revised 2026-08-12: no mTLS.** An earlier version of this document put client certificates from a
private CA in front of the plugin. That was redundant and is dropped; see
[Should there be a reverse proxy](#should-there-be-a-reverse-proxy).

And before any of it, a question worth asking, because this repository's own design already answers
it: V3 is scoped to "bootstrap secrets, human-facing storage, and seeding". A remote unattended
agent is the opposite of that scope, and serving one from here puts a desktop application, in a UI
process, on the network, to do the job of a hardened runtime secret store. Which store is the
consumer's architecture, not this repository's; what belongs here is only that KeePass is not it.
See [Is this the right question](#is-this-the-right-question).

## The blocker, fixed 2026-08-12

**An unauthenticated client could make KeePass display a dialog whose text it controlled.**

One correction to the first version of this section, which overstated the defect: the client NAME
was never injectable. Upstream filters it through an allowlist of letters, digits, spaces and
hyphens. The **description** was the unescaped field, and it was not filtered at all.

`SRPIdentifyToServer` runs before any authentication: connect, send `identifyToServer`, and the
plugin generates a code and calls `ShowAuthDialog` on the UI thread. The dialog's body was built by
concatenating the client's own `clientDisplayDescription` into an RTF document with no escaping:

```csharp
richTextBoxClientID.Rtf = @"{\rtf1\ansi{\fonttbl\f0\fArial;}\f0A program claiming to be ""{\b "
    + ClientName + @"}"" is asking you to confirm ..."
```

Three consequences, in ascending order of seriousness:

1. **Denial of service.** Every connection raises a modal dialog. A loop makes the password manager
   unusable.
2. **Text of the user's own security prompt is attacker-controlled.** The dialog asking "do you want
   to allow this to access your passwords" says whatever the caller wants it to say.
3. **RTF injection.** A description containing `}` or `\` escaped the bold group and injected control
   words into a document the application renders. At minimum that means arbitrary formatting and content;
   RTF also supports embedded objects, and I have not tested how this control handles those, so the
   ceiling is not established.

On loopback this was bounded by the threat model's existing concession: a local process able to reach
the socket can already read the DPAPI key or the decrypted database, so a fake dialog buys it
nothing. **On a network that reasoning evaporates.** It would be a pre-authentication, remotely
triggerable phishing surface inside a password manager, reachable by anyone who can open a socket.

**Fixed.** `RtfText.Escape` escapes the three characters that carry meaning in RTF, turns control
characters into spaces so a caller cannot add paragraphs and scroll the real text out of a
fixed-size dialog, encodes non-ASCII as a numeric escape (which also fixes a display bug that
predated this, since the document declares ANSI), and caps the length. Applied to the
description and, belt and braces, to the already-filtered name. URL auto-detection is switched off
on that box too, so caller-supplied text cannot even look clickable. Verified live: an injection
attempt renders as literal text with the rest of the dialog intact.

The unauthenticated dialog TRIGGER remains, because it is upstream's pairing design rather than a
defect: any client may ask to pair, and asking raises a prompt. That is a nuisance locally and a
denial of service remotely, which the proxy's rate limit is the answer to; barring remote pairing
was considered for this and rejected, for the reasons under plugin change 1 below.

Still open, and yours rather than mine: **reporting the original defect upstream.** This repo is a
public fork of `kee-org/keepassrpc`, so the description above is effectively published, and the
shipped plugin still has it.

## What loopback was holding up

Every control in the fork was designed against a local adversary. Four of them lean on the transport
in ways that are easy to miss.

| What | Why loopback was carrying it |
| --- | --- |
| **512-bit SRP group** | Was fine when nobody could observe the pairing exchange. A 512-bit discrete log is within reach of a determined attacker, and solving one recovers the paired key, which authenticates everything afterwards, including the newer suite's key agreement. **Answered 2026-08-12**: a client declaring `KPRPC_FEATURE_SRP_2048` pairs in the RFC 5054 2048-bit group. Clients that do not, notably Kee, are unchanged and still carry this. |
| **The original session suite** | One static key for the life of the pairing, a MAC that is not an HMAC, no replay protection. Unusable on a network. |
| **The `Origin` allowlist** | Not an authentication control anywhere, and on a network it is worse than useless because it looks like one. |
| **Fleck2's frame parser** | A small, old WebSocket library, currently fed only by local processes. Any exposure feeds it hostile bytes. |

There is also no rate limiting anywhere, and the plugin shares the KeePass UI process, so
**availability becomes a security property**: a remote attacker who can hang or crash the process
locks the operator out of every credential they own.

## Should there be a reverse proxy?

Yes, but for one job, and not the job the first draft of this document gave it.

**Two corrections to that draft**, because the case for mTLS rested on both of them.

*It said the proxy "terminates TLS, so it sees every request in clear: it becomes a fully trusted
component".* **That is wrong for this protocol.** Every JSON-RPC payload is encrypted before it
reaches the socket (`KeePassRPCClient.cs`, `data2client.jsonrpc = Encrypt(output)`), under a key
derived between the client and the plugin, and a remote connection is required to use
`KPRPC_FEATURE_CRYPTO_V2`, so that key is ephemeral and the proxy never sees it. What a proxy can
read is the envelope: protocol, version, the declared feature list, the subject name in the SRP and
key blocks, and the client's display name. Metadata worth something for traffic analysis, and not
one credential. The proxy is not a trusted component and does not need to be treated as one.

*It offered client certificates as "a second, independent authentication factor".* Independent of
the plugin's SRP, yes, but not independent of the VPN underneath it. **A WireGuard peer key and a
client certificate are the same primitive doing the same job**: prove you hold a private key, and
receive an identity. Running both is the same check twice, not defence in depth. Under a mesh VPN
there are already two genuinely independent layers: the peer key, and the plugin's own SRP pairing
plus key challenge, with the method gate and the ACL behind that.

So **no mTLS, and no private CA.** That is a security improvement rather than a mere simplification:
this document previously and correctly noted that a CA key "becomes an asset ranking near the paired
session keys", since whoever holds it can mint a client. Not creating it removes the asset, along
with the certificate rotation, distribution and revocation that come with it.

**What the proxy is still for**, and it is enough to keep it:

- **Rate limiting and connection caps.** The real reason. Availability is a security property here:
  the plugin lives in the KeePass UI process, any client may ask to pair, and asking raises a modal
  dialog. Refusing remote pairing was considered as an answer to that and rejected, so this is where
  the answer lives. Nothing in a VPN rate-limits at the application layer.
- **Binding the tunnel interface only.** `bindOnlyToLoopback` is all or nothing --
  `WebSocketServerConfig` has no bind-address field, so turning it off would also put the plugin on
  the LAN. A forwarder bound to the VPN interface is how the port reaches VPN peers and nobody else.
- **Read and idle timeouts**, and logging that survives the plugin being unhappy.

**What it is not for.** It cannot apply policy inside a WebSocket conversation: once the upgrade
completes it is forwarding frames, so "this connection may not pair" is not enforceable by
inspection and has to be a plugin rule. It does not shield Fleck2's frame parser either, which the
first draft implied. nginx and friends proxy WebSockets at the TCP level after the upgrade and do
not validate frames. Only a proxy that terminated and re-originated the WebSocket would, and that is
not what is being proposed.

**It must run on the KeePass host.** If it runs anywhere else the hop from proxy to KeePass crosses
a network in the clear, which defeats the exercise.

**Who may reach the port** is now the VPN's question rather than the proxy's. Tailscale ACLs express
it as peer-to-port rules, which is the same granularity per-agent certificates would have given.
Plain WireGuard needs firewall rules keyed on tunnel addresses.

## Proposed architecture

Four layers. Each is independently useful, and the first is the one that matters most.

### 1. Network: a mesh VPN, not an open port

WireGuard, or Tailscale/Headscale if you want the NAT traversal and key distribution handled.

This is the highest-value single decision, and the reasoning is not subtle: the internet scans every
port continuously, an exposed service is found within hours, and the thing behind this one is every
credential you have. A mesh VPN gives modern authenticated key exchange, peer identity by public key,
and, with Tailscale-style NAT traversal, **no inbound port on the public internet at all**.

For LAN-only exposure a VPN is still worth it, because "the LAN" includes IoT devices, guest
networks, and whatever laptop was plugged in last week.

**Do not skip this layer.** Since the proxy no longer authenticates anybody, the VPN is the only
thing deciding who may reach the port at all. This layer is not one of two, it is the one. Even
when the proxy did hold client certificates the argument ran the same way: a proxy on a public
address is a respectable design for a web service, and for a password database it means an
unauthenticated stranger reaches your TLS stack and your validation logic, with only that code being
perfect between them and the plugin.

### 2. Transport: a plain reverse proxy on the KeePass host

Caddy, nginx or Traefik, bound to the VPN interface, forwarding to `127.0.0.1:12546`. No TLS: the
tunnel already encrypts, and terminating a second time would add keys to protect without protecting
anything that is not already protected twice over.

- **Rate limits and connection caps.** The reason this layer exists.
- **Read and idle timeouts**, remembering that a legitimate call can block for minutes on a
  confirmation dialog. Set the timeouts around that, not under it.
- **Forward to the remote path**, `proxy_pass ... /remote` or the equivalent, so the plugin knows
  the connection came from off-host. The path is fixed in the proxy configuration, so the client has
  no say in it; see `RemoteAccess`.

Authentication is deliberately not this layer's job. The VPN identifies the peer and the plugin
authenticates the subject.

**If you would rather not run a proxy at all**, the honest trade is: bind the plugin beyond loopback
and accept both that it appears on every interface rather than just the tunnel, and that nothing
rate-limits the pairing dialog. In that shape remoteness detection still works without any
configuration, because `RemoteAccess` treats a non-loopback peer address as remote on its own. It is
a worse deployment for the availability reason, not for a confidentiality one.

### 3. Plugin: six changes, four built and two rejected

None are large. All are additive and negotiated the same way everything else in this fork is. The
two rejected entries are kept rather than deleted, because the reasoning is the useful part and
both are the kind of control that looks obviously worth adding until it is examined.

0. **Know which connections are remote.** A prerequisite every other item here shares, and the only
   interesting part of it, because everything arrives from the proxy on loopback and the plugin
   therefore cannot tell by looking at the socket. `RemoteAccess` takes two signals. A peer address
   that is not loopback, which is definitive but only ever happens if `bindOnlyToLoopback` has been
   turned off. And **a marker segment in the request path**, the fixed segment `remote`, which is
   what the proxy deployment relies on: `proxy_pass` is given that upstream path, so the marker
   is set by the operator's own infrastructure and the client has no say in it. A local caller can
   mark itself remote, which only ever costs it access. What none of this can catch is a remote
   party who bypasses the proxy and reaches the port directly, and that is what `bindOnlyToLoopback`
   is for. Matching is deliberately generous, accepting any segment in either case after unescaping, because
   every mistake it can make is in the restrictive direction. **Done.**
1. ~~**Refuse pairing on remote connections.**~~ **Rejected 2026-08-12: local and remote pair
   equally.** An earlier draft proposed barring it, on the grounds that pairing is the pre-auth
   dialog trigger and the only user of the 512-bit group. Both are true and neither survives
   contact with the deployment.

   The 512-bit group is only worth attacking by someone who can observe the exchange, and in this
   architecture the exchange runs inside the VPN tunnel. A passive network observer sees nothing of
   it. The parties who do see it, namely the proxy on the KeePass host and any authenticated VPN peer,
   are inside the trust boundary already. Since 2026-08-12 the question is settled at the
   plugin rather than left to the deployment: a remote pairing that has not asked for the
   2048-bit group is refused outright. See item 5.

   And barring it buys less than it looks. **Pairing cannot be completed remotely in any case**,
   because the code is generated server-side and rendered only on the KeePass host's screen
   (`KeePassRPCClient.cs:770`, passed to `ShowAuthDialog` and never sent to the client). An
   attacker who reaches the socket can raise a dialog; it cannot get past one. Meanwhile the bar
   is not enforceable in the way it appears to be: an SSH tunnel to the host presents as loopback
   on `/`, so anyone with shell access pairs regardless. A control that stops the honest operator
   and not the attacker is worse than no control, because it is mistaken for a boundary.

   What actually remains is dialog-spam denial of service, and that is the proxy's rate limit to
   carry, not the plugin's. Verified 2026-08-12 that pairing over the marked path works exactly as
   it does locally, and still gets the negotiated crypto suite.
2. ~~**Require `KPRPC_FEATURE_CRYPTO_V2` on remote connections.**~~ **Done.** The original suite has
   one static key for the life of the pairing, a MAC that is not an HMAC, and no replay protection.
   A remote connection that has not declared the feature is refused at its first message with
   `AUTH_CRYPTO_TOO_WEAK`. Checked twice, because a claim and a fact are different things: the
   declared feature is all there is to go on during the handshake, but once real calls start the
   session key is the evidence, so a client that declared it and then did not complete the key
   agreement cannot fall through to the legacy path. Kee is local and unaffected, which is the whole
   reason the negotiated suite exists.
3. ~~**A per-subject "may connect remotely" permission**, default deny.~~ **Rejected 2026-08-12:
   operationally not worth it.** The idea was that a stolen credential for the transport, meaning a
   client certificate when this document still proposed mTLS and a VPN peer key now, would then reach only
   the subjects deliberately marked remote-capable.

   It guards a narrower case than it appears to. Reaching the port authenticates nothing here: an
   attacker also needs a subject's paired key, and the realistic way to get one is to compromise the
   host holding it, which is exactly the host that would have been marked remote-capable. The flag
   only bites when someone holds transport access plus a key belonging to a subject that lives
   somewhere else, and if that somewhere else is the KeePass host then everything is lost anyway.

   Against that, it would be the third per-subject key an operator has to set correctly, after
   `KeePassRPC.Profile.<subject>` and `KeePassRPC.AclScope.<subject>`, default deny like the others
   and with a failure that looks the same as theirs: the agent simply does not work. Three gates
   that fail identically is a real cost paid every time an agent is provisioned.

   What carries the weight instead is what already exists: the method profile and the ACL scope
   decide what any subject can do at all, and the audit log's `remote` field means a subject used
   from somewhere it should not have been is visible afterwards. If the enforcement is ever wanted,
   it is a small change, since the plugin already knows which connections are remote.
4. ~~**Record remoteness in the audit log**~~, so "what did it read" can distinguish a local call
   from one that crossed the network. **Done.** Every record carries a `remote` field, written even
   when false: a field that appeared only sometimes could not answer the question, because a missing
   one would mean "local" and "written by an older build" at once. Verified by reading the same two
   entries down each path and finding the log lines identical but for that field.

5. ~~**Require the 2048-bit SRP group on remote pairings.**~~ **Done 2026-08-12.** Follows from
   deciding that pairing may happen remotely: a remote pairing is the one case where the exchange
   could plausibly be observed, and the 512-bit group is only safe when it cannot be. A remote
   connection attempting to pair without declaring `KPRPC_FEATURE_SRP_2048` is refused with
   `AUTH_CRYPTO_TOO_WEAK`, naming the feature.

   Scoped to pairing, not to every remote connection. A key challenge proves possession of a key
   agreed earlier and never touches N, so refusing a reconnect over a group it does not use would
   be a rule about the wrong thing. One consequence, recorded rather than papered over: the plugin
   does not remember which group a key was paired in, so a key from an older 512-bit pairing still
   reconnects remotely. Those pairings happened over loopback where the exchange could not be
   watched, so the group did not weaken the key they produced. No remote pairing can produce
   such a key from here on.

### 4. Application: unchanged

Method gate, ACL, confirmation prompts, audit. All of it already applies and none of it needs to
change.

## What this does to the threat model

### A genuinely new actor, and an interesting one

**A compromised device on the trusted network** is new: it can reach the API, but it cannot read the
DPAPI session key, cannot read KeePass's memory, and cannot edit `KeePass.config.xml`.

That makes it the **first actor against which the method gate and the ACL are a real boundary rather
than a guard rail.** The threat model is careful to say those controls do not survive local code
execution. True, and it is why they are described as guard rails. A remote attacker has no such
capability. Exposure therefore *increases* the security value of the work already done here, which is
an argument in favour of the layered design rather than against exposure as such.

### A new component, but not a trusted one

The proxy is new surface and its correctness matters for availability, since it is the thing holding
the rate limit. It is not, however, in the confidentiality boundary: it forwards frames whose
payloads are encrypted between the client and the plugin, so compromising it yields metadata and the
ability to deny service, not credentials. Dropping mTLS is what keeps this true, and removes the
certificate authority key that would otherwise have become an asset ranking near the paired session
keys.

The VPN's key material replaces it in that ranking, which is a better place for it: a WireGuard
private key is a well-understood thing to protect and rotate, and losing one still leaves an
attacker facing the plugin's own authentication.

### Human presence weakens, and prompts get worse

The design's argument for talking to an unlocked KeePass is that a human is present. A remote agent
calling at 03:00 still triggers confirmation dialogs, and nobody sees them, so either the call
hangs until the timeout, or the operator wakes to a queue of prompts they will approve without
reading. Prompt fatigue is already listed as a real weakening; remote access makes it worse.

The honest resolution is uncomfortable: **for remote unattended subjects the human gate does not
work, so grant `unattended` and compensate with narrowness.** A prompt nobody can see is not a
control. Which leads to:

**Do not grant `attachments` to remote subjects.** Attachment content is the highest-value asset in
the model, and the confirmation prompt is its main guard. If the prompt is not meaningful remotely,
the flag should not be set remotely.

### Availability becomes a security property

It was not one before. A remote party who can hang the KeePass UI thread denies the operator every
credential they own, and any client may raise a modal dialog by asking to pair. **Rate limits at the
proxy are the mitigation, and since barring remote pairing was rejected they are the only one.**
That is the whole reason the proxy survives the removal of mTLS: it does no authentication and it is
not in the confidentiality boundary, but it is the only place this particular failure can be
bounded.

## Is this the right question?

Worth putting plainly, because the answer may make most of the above unnecessary.

This repository's design scopes V3 to bootstrap secrets, human-facing storage and seeding. A
runtime secret store for unattended consumers, whatever a consumer chooses to run, is a different
job with different machinery: policies, leases, revocation, unattended unsealing. Remote unattended
agents are that job, by definition.

So the layering the design already chose is: **KeePass is the human-facing store; the local machine
seeds whatever runtime store a consumer runs; remote agents talk to that store.** Exposing KeePass
to remote agents inverts it, and puts a desktop application in a UI process on the network to do a
job purpose-built daemons do better, with leases and revocation this plugin does not have and must
not grow.

Two cases where exposure is still the right call:

- **A trusted LAN host that needs bootstrap secrets** and cannot reach its own runtime store yet,
  the chicken and egg case that V3 exists for. Narrow, occasional, and a good fit.
- **A human at another machine** wanting their own password manager, where the alternative is
  syncing the `.kdbx` and the human presence assumption still holds.

For general remote agent access, seeding a runtime store locally is very likely the better answer,
and it needs nothing in this document.

## What I would not do

- **Bind the plugin itself to a non-loopback interface**, unless you have accepted the trade set out
  under layer 2. The flag is all or nothing, so it means every interface, not just the tunnel.
- **Expose to the internet without a VPN**, proxy or not. This is the one that matters; a proxy on a
  public address is a respectable design for a web service and not for a password database.
- **Expose the pairing exchange outside the tunnel.** Pairing over the network is fine and is the
  decision taken. A remote pairing is required to use the 2048-bit group, so the tunnel is no longer
  the only thing standing behind it, but it is still what keeps the exchange private.
- **Rely on the `Origin` allowlist** for anything.
- **Grant remote subjects attachment content.**
- **Do any of it before the dialog defect is fixed.**

## If you proceed, in order

1. ~~Fix the RTF injection.~~ Done 2026-08-12. The dialog trigger is upstream's design and is
   addressed by plugin change 1. Upstream disclosure still to decide.
2. ~~Add the plugin changes.~~ **Done 2026-08-12.** Remoteness detection, the CRYPTO_V2
   requirement, the audit field and the 2048-bit group requirement are built; refusing pairing
   remotely and the per-subject remote permission were both considered and rejected, for the
   reasons above. Nothing plugin-side is outstanding: what remains below is infrastructure.
3. Stand up WireGuard or Tailscale. Confirm the plugin is still loopback-only.
4. Add the reverse proxy on the KeePass host, bound to the VPN interface, forwarding to the remote
   path. Rate limits and timeouts are the whole of its configuration; there is no CA to run.
5. Pair each remote agent, over the VPN or on the host, whichever is convenient, and grant it
   narrowly. Someone has to read the code off the KeePass host's screen either way, which is the
   real constraint and is not one the transport can remove. Narrowly means the method profile and
   the ACL scope, which are now the only per-subject limits there are; the guidance further up
   about not granting `attachments` to a subject that runs off-host is advice an operator follows,
   not something the plugin will enforce.
6. ~~Raise the SRP group to 2048-bit, negotiated per client.~~ **Done 2026-08-12.** Declaring
   `KPRPC_FEATURE_SRP_2048` pairs in the RFC 5054 2048-bit group; everything else is untouched.
   A remote agent does not have to be checked for this by hand, because plugin change 5 refuses a
   remote pairing that has not asked for it. A LOCAL client that does not declare it still pairs
   in the old group in silence, which is the whole point of the negotiation and is what keeps Kee
   working.
