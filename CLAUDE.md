# CLAUDE.md

This file provides guidance for anyone, human or AI assistant, working in this repository.

## What this is

**This repository is a fork of the KeePassRPC KeePass 2.x plugin.** The work in it is **V3**: a new
API generation giving full access to a KeePass entry (real custom strings, attachments, notes, not
just a password) behind a **subject-aware ACL**, so that automation and AI agents can each be given a
narrow, revocable, audited slice of the database.

**There is no separate product name for this, deliberately.** It is V3 of KeePassRPC, named the way
upstream names things: DTOs take a bare numeric suffix (`Entry3`, beside upstream's `Entry2`), the
service partial keeps the `DTOV<n>` form (`KeePassRPCService.DTOV3.cs`), methods reuse upstream's
`Add`/`Update`/`Remove` verbs, feature flags keep the `KPRPC` prefix, and the ACL's `CustomData` key
follows upstream's dotted convention for its own keys (`KeePassRPC.ACL`, beside `KeePassRPC.Config`).
A second vocabulary for the same plugin would only make the fork harder to merge and harder to read.

The fork branched at `v2.0.2-1-gdc0a59b`, the exact tip the design was verified against, so file and
line references in the design documents are valid against this working tree. Upstream code is
changed only where the work needs it, and `README.md` carries a short fork notice prepended above
upstream's text. It is prepended rather than woven in, so that merging upstream's own README changes
stays trivial.

[`V3-DESIGN.md`](V3-DESIGN.md) is the contract. Read it in full before writing code or proposing
changes. It records not just what to build but which alternatives were surveyed and rejected and why,
so that ground does not get re-covered.

[`THREAT-MODEL.md`](THREAT-MODEL.md) says what the controls are actually worth, and what they are
not. Read it before describing anything here as secure, and before adding a control: several of the
obvious additions defend against an attacker this design has already conceded.

[`CONTRIBUTION.md`](CONTRIBUTION.md) is the short version, for a reader rather than a builder: what
the fork adds, screenshots of the two UI additions, and diagrams of the local and remote call paths.
Keep it in step with the others, because it is the one somebody actually reads first.

**Most of it is now built**, which an earlier version of this file denied. The V3 API, the method
gate, the ACL and its editor, the audit log, the negotiated session crypto, the 2048-bit SRP group
and remoteness detection all exist and are verified against a live KeePass.
[`CONTRIBUTION.md`](CONTRIBUTION.md) summarises what that amounts to;
[`TODO.md`](TODO.md) carries only what is left, deliberately, so there is one account of each
decision rather than two that drift apart.

## This repo is PUBLIC, which constrains what may be written in it

GitHub forks inherit the parent's visibility and cannot be made private. So treat every file here as
world-readable:

- **Nothing about the actual database.** No credentials, and also no host names, no entry titles, no
  group layout, no subject or agent identities, no examples lifted from a real `.kdbx`. The ACL
  design is safe to publish and benefits from being reviewable; an inventory of what is stored behind
  it is not.
- Examples and tests use invented names, obviously invented.
- Upstream is **GPLv2**, so anything added here is distributed under GPLv2 once pushed.

## The Python client

| where | what |
| --- | --- |
| **here** | the plugin: the V3 API, the ACL, the KeePass-side work |
| **`clients/python/`** | `keepassrpc-client`, the protocol client: pairing, session crypto, JSON-RPC |

The protocol core is a clean-room client of this plugin's own SRP pairing and session crypto,
proven against a live KeePass, which is the reason forking KeePassRPC beat every alternative: a
working authentication path already existed. The protocol belongs beside the C# that defines it, and
the client is defensible because its test suite implements the **server** side independently from
the same C# and checks the two agree.

**This repository is self-contained.** A consumer is responsible for its own compatibility with it; a
client declares `KPRPC_FEATURE_DTO_V3` and gains the V3 calls. It depends on no consumer, and
nothing about a consumer's own data or configuration belongs in this public repository.

## Building, which is done and works

The build spike passed on 2026-08-11: the unmodified upstream builds against .NET Framework 4.5 and
the resulting `.plgx` loads into the installed KeePass 2.61.1. Every plugin-based option stays open.

**A toolchain is already installed, so do not propose adding one.** Visual Studio 2019 Community (and
a 2017 Enterprise), with .NET Framework targeting packs through v4.7.2 including **v4.5**, which is
what this project targets. `msbuild` is not on `PATH`; locate it rather than hardcoding a path:

```powershell
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe"
& $msbuild KeeFox-KPRPC.sln /p:Configuration=Debug
```

Four things about this build are not obvious and cost time if rediscovered:

- **`%USERPROFILE%\KeePassDEV\` must exist and contain `KeePass.exe`.** Both projects reference
  KeePass through that path, and `ReleasePLGX` invokes that same exe to package the `.plgx`. It is
  not in the repo and nothing creates it; populate it by copying an installed KeePass. (The plugin
  builds against `KeePass.exe` itself, not a `KeePass2.dll`.)
- **Do not build `Configuration=Release`.** It compiles, then fails: the post-build batch only
  handles `Debug` and `ReleasePLGX` and falls through to `exit 1` for anything else. Use `Debug`,
  which also copies the DLLs into `%USERPROFILE%\KeePassDEV\plugins\`.
- **`ReleasePLGX` must be built on the project, not the solution.** The solution maps
  `ReleasePLGX|Any CPU` for `KeePassRPC` to a stray `teast` configuration, so a solution-level build
  produces the wrong config and then fails the same post-build check. Build
  `KeePassRPC\KeePassRPC.csproj /p:Configuration=ReleasePLGX` directly.
- **`KeePassRPCTest` needs a NuGet restore first** (NUnit 3.6.1, `packages.config` style, so
  `msbuild /t:Restore /p:RestorePackagesConfig=true`). Without it the test project fails to compile
  with a wall of `ExpectedResult` errors that look like a code problem and are not.

`KeePassRPCTest` gives a build target to check against; it compiles and is worth keeping green.

## Testing against a live plugin

Never against the author's real database. Build a throwaway KDBX4 with `pykeepass` (ephemerally, via
`uv run --no-project --with pykeepass`), open it with `KeePass.exe <db> -pw:<password>`, and pair a
test identity against that. Keep the database and any driver scripts in the session scratchpad; a
`.kdbx` must never be committed, and `-pw:` puts the password in the process list, so it is only ever
acceptable for a dummy.

**Testing the grant editor means pressing OK, not just looking.** A KeePass dialog with a "Plugin
Data" tab keeps its own copy of the object's `CustomData` and writes that copy back when it is
accepted, so a grant written to the live object is destroyed by OK and kept by Cancel, exactly
backwards and with nothing on screen to say so. That is how group grants behaved until 2026-08-13.
So the check is: make a grant, press OK, reopen the dialog, and only then believe it. Do the same
after saving and reloading the file, because those are two different failures.

**A KeePass launched from `%USERPROFILE%\KeePassDEV\` writes its own `KeePass.config.xml` next to the
exe.** It seeds that from the user config on first run, so existing pairings are visible to it, and
everything it writes afterwards stays local. That is why testing there cannot damage the real
configuration, and equally why a pairing made there does not exist for the installed KeePass.

The plugin rejects any `Origin` outside its allowlist, which by default is browser-extension schemes
only, so a non-browser client must present one of those prefixes or be named in
`KeePassRPC.webSocket.permittedOrigins`. This bites before anything else does, because it surfaces as
a dropped connection rather than an error.

**Since the method gate exists, a test subject also needs a profile or every call is refused.**
Pairing now asks for one: a client that completes SRP and has no profile of its own raises a prompt
offering the five `AccessChoice` settings, defaulting to `refused`. Dismissing it leaves the client
refused. The same choice lives on the "Authorised clients" tab of the KeePassRPC options, and
it writes both `KeePassRPC.Profile.<subject>` and `KeePassRPC.AclScope.<subject>` together. For a scripted
test that never sees the prompt, set it in the config of whichever KeePass is under test, then
restart it, because KeePass rewrites that file on exit and an edit under a running instance is
lost:

```text
KeePassRPC.Profile.<subject>            "none" | "legacy" | "v3", comma-separated to combine
KeePassRPC.AclScope.<subject>           "v3" (the ACL guards V3 only) | "all"
```

`KeePassRPC.Profile.` here is the METHOD profile, which API generations the gate lets a client
call. It predates and is unrelated to the ACL's profiles, which live in the kdbx and are what
access rules name. Prose in this repo always qualifies this one as "method profile".

There is no key that answers for every subject at once, deliberately. **Installing this build into a
KeePass that already has paired clients would otherwise deny all of them**, including the v1 path
that resolves secrets today, so `LegacyClients.Migrate` runs once at start-up and gives each client
already paired the access it had before: `legacy` with the ACL standing aside. It remembers itself
with `KeePassRPC.MethodGate.LegacyClientsMigrated`, so it cannot re-grant a client whose access has
since been taken away, and a client paired afterwards is asked at pairing time as usual. Clearing
that key in a test config makes the migration run again on the next start.

**Connecting on a path that carries the remote marker makes the plugin treat the connection as
off-host**, which is how the remote behaviour is exercised without a proxy or a network: connect to
`ws://127.0.0.1:12546/remote` instead of `ws://127.0.0.1:12546` and the connection must then use
`KPRPC_FEATURE_CRYPTO_V2` or be refused, and a connection that tries to PAIR there must also
declare `KPRPC_FEATURE_SRP_2048`. A reconnect need not: the group only matters while pairing. The
marker is the fixed path segment `remote`, not a setting. Nothing about this binds a port off
loopback; see [`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md).

Run the C# tests with the runner restored alongside NUnit:

```powershell
& packages\NUnit.ConsoleRunner.3.6.1\tools\nunit3-console.exe KeePassRPCTest\bin\Debug\KeePassRPCTest.dll --noresult
```

## Reference clone

Only one is still needed; upstream's source is this repo. Blobless clone into the gitignored
`.tmp/repos/`:

```bash
git clone --filter=blob:none https://github.com/MircoBabin/KeePassCommander .tmp/repos/github.com__MircoBabin__KeePassCommander
```

**MircoBabin/KeePassCommander** at `v4.7` was the main alternative, rejected because it is entirely
read-only and its named pipe is unauthenticated. It stays useful as a reference: it is MIT, much
smaller, and its read commands show how to reach attachments, notes and real custom strings through
the KeePass API. It also vendors a portable KeePass 2.44 under `assets/`.

Never commit clones.

## Things that are already decided

These came out of a long design discussion. Treat them as settled unless you have new evidence, and
if you do, say so explicitly rather than quietly designing around them.

- **Follow upstream naming**, everywhere, including internals. No parallel product name, no parallel
  field prefix.
- **Fork KeePassRPC**, not KeePassCommander, not a `pykeepass` daemon, not a WASM-hosted plugin.
  Authentication and a working client already exist here; the alternatives meant building both.
- **V3 is feature-gated**, following the upstream pattern (`KPRPC_FEATURE_DTO_V2`). v1 and v2 keep
  working untouched. **v1 and v2 must not break**: the Kee browser extension speaks them and cannot
  be updated in step with this plugin.
- **V3 reads `pwe.Strings` and `pwe.Binaries` directly**, deliberately bypassing the `conf.Fields`
  entry-config machinery that v1 and v2 filter through. That is the point of V3, and it is also a
  comprehension trap, so document it at the top of `DTOV3.cs`.
- **V3 writes must not route through the v1 `MergeEntries` path**, which replaces the entry's field
  set wholesale.
- **The ACL is `(profile, verb, object)`**, and a profile is NOT a client. Profiles are defined per
  database on the database settings dialog, clients are assigned to one or more of them there, and
  every rule on a group or entry names a profile. A client with no assignment, or whose profiles
  were all deleted, is in `default`, which every database has and none can delete: a client is never
  without a profile. A client in several holds the WIDEST of what they grant, so a `none` in one
  profile does not revoke what another gives. Inheritance is still top-down and narrow-only: rights
  narrow within a profile as the chain descends, and widen across a client's profiles at the end.
- **Grants live in their own `CustomData` key, `KeePassRPC.ACL`**, on **groups and entries**, NOT in
  custom string fields and NOT as a property on upstream's `EntryConfigv2`. `CustomData` is a
  different dictionary from `pwe.Strings`, and V3's field API has no code path to it, so a client
  cannot reach a grant by writing a cleverly named field. That is a structural boundary; the
  reserved-name filter an earlier draft used was a blocklist by name, which loses to case folding and
  whitespace. Keeping it in a separate key also means the ACL never edits an upstream model class.
  Requires KDBX 4, **which the target database is** (confirmed), and a plugin-side grant UI, since
  `CustomData` is not editable in the stock KeePass dialog. Both are detailed in the design.
- **There is no database-level grant**, removed 2026-08-13. The root group is the one group every
  entry is inside, so it says everything a database rule could say, and two places meaning
  "everything" is one more to forget to look in. A document found on a database is refused, not
  read: everything stays denied while one is there, and the database settings dialog offers to
  discard it. The migration that moved them was removed once the databases had been converted. Do
  not re-propose a database level.
- **The database settings dialog carries the starting point and nothing else**: deny by default or
  allow by default, stored on the root group's document as `default`, read from that document only.
  Deny by default is a WEAK deny, a starting value the first group can lift; `"*": "none"` on the
  root group is the strong one, a floor nothing below can raise. Allow by default does not change
  how rights combine, only what they narrow from, and switching to it asks first because every rule
  already written flips from a permission to a restriction.
- **Minimum KDBX 4.0 and minimum KeePass 2.48.** Group and entry `CustomData` came with KDBX 4
  (KeePass 2.35), and `KdbxVersionTest` pins that by asking KeePass's own `GetMinKdbxVersion` rather
  than asserting it. 2.48 is what the packaged `.plgx` already demands (`--plgx-prereq-kp:2.48`), so
  `MinimumKeePass` makes the same demand at start-up for a plain DLL install, which KeePass does not
  check by itself. Grants on a KDBX 3.1 file are not lost, the file is rewritten as KDBX 4, which the
  tab warns about because KeePass 2.34 and older then cannot open it.
- **The ACL is NOT the outer boundary.** v1 and v2 are unguarded, so a client that simply does not
  call V3 reads and writes every entry in every open database. The boundary is a **per-subject method
  allowlist, default deny**, enforced in `KprpcJsonRpcDispatcher.Invoke` before `base.Invoke`.
  Allowlist and not blocklist, so a method added by a future upstream merge is denied until a human
  decides. **Built 2026-08-11**, before the V3 write path as planned; see `MethodProfiles.cs` and the
  "As built" notes in the design. Two rules for anyone touching it: gate on the method name resolved
  through Jayrock's own `FindMethodByName`, never on the name as sent, because Jayrock falls back to
  a case-insensitive lookup and a case-sensitive gate is bypassable by re-casing; and refuse by
  returning a JSON-RPC error, never by throwing, because nothing catches between `Process` and the
  socket handler.
- **Subject separation is a guard rail, not a boundary, on one Windows account.** The client session
  key is DPAPI user-scope, so anything running as that user can present itself as a subject holding
  v1 access. The gate answers the confused deputy, which is the dominant agent risk; it does not
  answer an attacker with filesystem access to the account. Do not oversell it in docs or comments.
- **Local and remote connections pair equally.** Barring pairing on remote connections was proposed
  in an earlier draft of [`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md) and **rejected 2026-08-12**.
  Pairing cannot be completed remotely regardless, because the code is generated server-side and
  rendered only on the KeePass host's screen, so an attacker who reaches the socket can raise a
  dialog but never get past one; and the bar would not have held anyway, since an SSH tunnel
  presents as a loopback connection. What remains is dialog-spam denial of service, which belongs
  to the proxy's rate limit. Do not re-propose this.
- **No per-subject "may connect remotely" permission.** Proposed in
  [`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md) and **rejected 2026-08-12** as operationally not
  worth it: it would be a third default-deny per-subject key alongside `KeePassRPC.Profile.` and
  `KeePassRPC.AclScope.`, failing the same indistinguishable way, to guard an attacker who holds
  both transport access (a VPN peer key) and a paired key belonging to a subject hosted elsewhere.
  The method gate, the ACL scope and the audit log's `remote` field carry it. Do not re-propose
  this.
- **Scope**: bootstrap secrets, human-facing storage, and seeding. Do not grow this into a general
  secret daemon.

## Conventions

- **No dashes as punctuation, anywhere.** Not em-dashes, not en-dashes, and not the ASCII
  substitutes `--` and ` - `. This covers prose, code comments, commit messages, docs and UI
  strings. When a dash feels wanted, rewrite the sentence: a full stop, a colon, a comma pair or
  parentheses will all read better, and dash-joined clauses are what screen readers and plain-text
  renderers handle worst. Hyphenated compounds (`fail-closed`, `top-down`) and command-line flags
  (`--noresult`) are unaffected. ASCII punctuation only otherwise.
- **British English**, because upstream is: `_authorised` and the public `Authorised` property are
  upstream's own identifiers, and `behaviour` runs through its comments. Every American spelling in
  the inherited code is either .NET API surface (`XmlSerializer`, `InitializeComponent`) or the
  vendored `BigInteger.cs`. So: `authorise`, `behaviour`, `recognise`, `analyse`, `licence` as the
  noun. This applies to identifiers and user-visible strings as much as to prose. The plugin's own
  dialog is titled "Authorise a new connection", and a client that calls it an "authorization
  dialog" is wrong twice over. Names belonging to someone else keep their own spelling: .NET
  properties, GitHub's `codeql-action/analyze`, and a quoted KeePass button such as "Synchronize".
- **Commits:** one commit per logical unit, imperative mood, subject starts with a capital letter, no
  `component:` prefix. The author reads history as if it were a PR, so each commit must stand alone
  and say why, not just what.
- **Backtick code references** in commit messages and PR descriptions: file paths, identifiers and
  literals, but not product names (KeePass, Windows, .NET).
- **Docs stay with code.** Behaviour or architecture changes update the design doc in the same pass.

### Fork hygiene, which matters more than usual here

- **Follow upstream's existing C# style rather than importing a new one.** A diff that mixes a
  reformat with a change is unreviewable and makes every future upstream merge worse.
- **Keep changes additive where possible.** V3 lands beside v1 and v2; it does not refactor them.
- **Never push to `upstream`.** Its push URL is set to `DISABLED` to make that a mechanical error
  rather than a matter of care.

## Security posture

This plugin guards every secret the author has. Two consequences:

- **Fail closed, always.** A malformed marker, an unknown subject, an unparseable grant, a missing
  chain: all deny. There is no permissive default anywhere in the ACL.
- **The threat model includes the caller.** AI agents are intended consumers and can be
  prompt-injected, so the ACL is not defending against a hostile network, it is defending against a
  legitimate client asking for more than it should. That is why enumeration (`list`) is separate from
  `read`, why attachment content is separate again, and why writes and attachment reads prompt by
  default.

The plugin runs inside the KeePass UI process, so a bug here can hang or crash the author's password
manager. Prefer keeping upstream's threading and server structure over rewriting it.
