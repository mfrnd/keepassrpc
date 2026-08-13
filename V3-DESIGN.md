# KeePassRPC V3: a full-entry API with a profile-based ACL

How this plugin gets full access to a KeePass entry (custom fields, attachments, notes, not just a
password) and how access is constrained per calling client, so that AI agents can be given a narrow,
revocable, audited slice of the database.

This is a design, not a description: nothing below is built yet. The build spike in
[First step](#first-step) has to succeed before any of it is worth writing.

## Why

**The protocol the client speaks today cannot carry what is needed, and no other plugin can
either.** Verified against `kee-org/keepassrpc` at `v2.0.2`:

- **Attachments do not exist in the wire model.** Neither `Entry`, `Entry2` nor `LightEntry` has a
  binary field, and no method exposes one. A repo-wide search for `binar|attachment|ProtectedBinary`
  hits only the vendored Jayrock library and `BigInteger.cs`.
- **Notes does not exist either.** Zero occurrences across `Models/`.
- **Custom fields are readable but not writable.** The read loop iterates `conf.Fields`, the entry's
  `KPRPC JSON` config, NOT `pwe.Strings` (`KeePassRPCService.DTOV1.cs:60`), so a custom string added
  in the KeePass UI is invisible until registered in that entry's Kee tab. On the write side the only
  `Strings.Set` calls in either DTO path are `Password`, `UserName`, `URL` and `Title`; anything else
  is stored inside the `KPRPC JSON` blob (`ValuePath = "."`), invisible to every other reader of the
  `.kdbx`. In v2 a value aimed at a named string is silently discarded outright
  (`Value = incomingField.ValuePath == "." ? incomingField.Value : null`, `DTOV2.cs:202`).

The alternatives were surveyed and rejected. KeePassCommander reads attachments, notes and real
custom strings, which is more than we have, but its dispatcher handles five commands and **all of
them are reads**; it would delete `store`/`create`/`ensure`/`delete`, and its named pipe is created
with no ACL and an anonymous ECDH, so any process running as the user can read every open database.
The browser-integration family as a whole (`KeePassRPC`, `KeePassHttp`, `KeePassNatMsg`) skips
attachments by design, because a form filler never needs them. KPScript's only attachment command is
`DetachBins`, which removes them as it exports. A `pykeepass` daemon does deliver the whole matrix,
but it opens the `.kdbx` itself, which means an unattended master key (removing the human-presence
gate that is the point of talking to an unlocked KeePass) and a genuine data-loss hazard: KeePass
offers "Overwrite" or "Synchronize" when the file changed underneath it, and "Overwrite" silently
discards everything written since it loaded.

**Being in-process dissolves both of those hazards.** One writer, so no merge and no dialog; an
already-unlocked database, so no master credential stored anywhere.

**And a fork of this plugin is much cheaper than a fork of any other**, because two of the expensive
parts already exist:

- **Authentication.** SRP-6a pairing plus a per-session key challenge, already proven against a
  live KeePass. Forking KeePassCommander would have meant building auth AND a new client. Since
  2026-08-11 that protocol core also exists in this repo as
  [`clients/python/`](clients/python/README.md), so the plugin can be exercised from the outside
  with the client kept beside it.
- **A first-class extension point.** API generations are gated per client by a feature string
  (`ClientMetadata.Features.Contains("KPRPC_FEATURE_DTO_V2")`), so v1, v2 and V3 coexist and each
  client sees only what it declares. v1 keeps serving today's config resolution unchanged while V3
  lands beside it: no flag day, no dual-plugin period, no re-pairing.

Do NOT take the upstream v2 commit (102 files, +5880/-3552) as the effort estimate. That was a
semantic redesign of the entry-config and matcher model. V3 is the opposite in character: it
deliberately bypasses `conf.Fields` and reads `pwe.Strings` and `pwe.Binaries` directly.

## The V3 API

Gated on `KPRPC_FEATURE_DTO_V3`, which a consuming client declares in its handshake.
[`clients/python/`](clients/python/README.md) is the client this repository maintains; anything else
that speaks the protocol declares the same flag and is responsible for its own compatibility.

### Naming

This work has no product name of its own and introduces no parallel vocabulary: it is V3 of
KeePassRPC, named the way upstream names things. DTOs take a bare numeric suffix (upstream `Entry2`,
so `Entry3`); the service partial keeps the `DTOV<n>` form (`KeePassRPCService.DTOV3.cs`, beside
`DTOV1`/`DTOV2`); methods reuse upstream's `Add`/`Update`/`Remove` verbs with the same bare numeral;
feature flags and reserved fields keep the `KPRPC` prefix. Inventing a second name for the same
plugin would only make the fork harder to merge and harder to read.

`Entry3` carries what an automation client actually wants, and nothing it should pay for on every
read:

```text
uuid          stable id; the primary address
group         full group path
title         standard field
username      standard field
password      standard field
notes         standard field
fields        real custom strings from pwe.Strings (non-standard keys only)
attachments   NAMES and sizes only, never content
```

Methods, each enforcing the ACL below before touching anything:

```text
GetEntry3(uuid|title)               read one entry
ListGroup3(uuid|path)               titles + uuids of a group's entries
AddEntry3(group, Entry3)            new entry
UpdateEntry3(uuid, Entry3)          modify in place
RemoveEntry3(uuid)                  remove
GetAttachment3(uuid, name)          attachment CONTENT
SetAttachment3(uuid, name, bytes)   add or replace
RemoveAttachment3(uuid, name)       remove
```

**Address by UUID first**, title as fallback. UUIDs are preferred because they survive a rename
or a move, and v1's title lookup matches case-sensitively across every open database.

### The read half, as built 2026-08-11

`GetEntry3`, `ListGroup3` and `GetAttachment3` are implemented in `KeePassRPCService.DTOV3.cs`, and
they are where the ACL stops being a stored intention and starts being enforced. Four notes.

**`Entry3` also carries `url` and `db`.** The field list above omits both. A URL is a standard field
a human sees on the entry, so leaving it out would make V3 lossy for no benefit; `db` is the file
path of the database that answered, which a client needs because a UUID lookup spans every open
database.

**Lookup searches the true root of every open database, not the Kee home group.** Upstream's
`GetRootPwGroup` honours a "location" setting belonging to the browser extension. Scoping V3 by that
would make an agent's reach depend on a display preference; the ACL decides reach instead. An
ambiguous title matches nothing rather than picking one, and an absent database prompts nobody:
`EnsureDBisOpen` is deliberately not called, because an unattended agent must not be able to raise a
dialog on someone's screen.

**Listing omits what it may not show, rather than reporting it as forbidden.** An entry carved out
with `none` inside a listable group simply is not in the result. "There is something here you may
not see" is itself disclosure, and enumeration is the rung of the ladder that exists to control
exactly that.

**A prompted call waits on a human, which broke the client.** Attachment content asks for
confirmation unless the grant says `unattended`, and the plugin blocks on that dialog. The Python
client's ten second read timeout turned a correctly working prompt into a connection failure. Any
client for this API needs a much longer timeout on calls that can prompt, which now means attachment
reads and will later mean writes and deletes.

### The write half, as built 2026-08-11

`AddEntry3`, `UpdateEntry3`, `RemoveEntry3`, `SetAttachment3` and `RemoveAttachment3`, to the rules
already stated: `CreateBackup` before, `Touch(true)` after, saved through `BeginInvoke`, never via
`MergeEntries`. Three things the design did not pin down, decided here.

**Null means "leave alone", an empty string means "set empty", and a supplied `fields` list
REPLACES.** The same absent-versus-empty distinction the read path preserves, now load-bearing on
the way in: it is what lets a caller send a partial update without blanking everything it did not
mention, and what makes deleting a custom field possible at all. The cost is that a careless partial
`fields` list destroys the fields it omits, which is exactly why the backup is not optional.

**Creating checks `write` on the GROUP.** A new entry has no grant of its own, so the thing being
authorised is the container, which is also the grant the entry will inherit once it exists.
Attachment writes need `write` plus the `attachments` flag, because a subject trusted to change a
password is not thereby trusted to plant a key file; removing an attachment is a `write` rather than
a `delete`, since it modifies an entry rather than removing one and the backup keeps the content
recoverable.

**A second client bug, worse than the timeout.** The plugin pushes `Signal` messages such as
`DATABASE_SAVING` and `DATABASE_SAVED` down the same socket, framed as jsonrpc
**requests**, not responses (`KeePassRPCClient.Signal`). Every save emits two. A client that treats
the next frame as its answer therefore sees the write succeed and the NEXT call return null, which is
a horrible failure to diagnose because the damage appears one call away from its cause. Any client
for this protocol must read past server-initiated messages; the discriminator is the `method` member,
which a response never carries.

Three implementation notes that are corrections of what the existing code does, not preferences:

- **V3 writes must NOT go through the v1 `MergeEntries` path.** It assigns
  `destConfig.Fields = sourceConfig.Fields` wholesale (`KeePassRPCService.cs:542`), so a V3 write
  routed through it would clobber field state. Write a V3 path that calls `CreateBackup(db)`, mutates
  `Strings`/`Binaries` directly, then `Touch(true)`.
- **`CreateBackup` and `Touch` are not optional.** The backup is what puts a change into entry
  history and makes it recoverable; the timestamp is what lets KeePass's own synchronisation resolve
  correctly afterwards if the file is ever merged.
- **Save via `BeginInvoke`.** KeePass steals window focus while saving, which the existing code
  already works around.

Empty values are worth knowing about because v1 drops them: `if (!string.IsNullOrEmpty(ffValue))`
(`DTOV1.cs:126`) removes an empty field from the response entirely. V3 reads `pwe.Strings` directly
and MUST distinguish "absent" from "present and empty", because a deliberately blank placeholder is a
legitimate state in a secret-management workflow.

## The ACL

The model is `(profile, object, verb)`. An earlier sketch had only `(object, capability)`, which
gives every authenticated client identical rights; that is tolerable for one deploy identity and
untenable once agents are consumers, because the whole point is that a docs agent and the deploy
pipeline differ, and that one can be revoked without touching the other.

### Who a rule is about, and who a request is from

Two identities meet at enforcement time and they are deliberately not the same thing.

A REQUEST is from a client: the paired identity the plugin assigns at SRP pairing, one per agent,
because revocation and audit are only useful at the granularity you paired at. The method gate, the
ACL scope and the audit log all speak about clients, and their per-client keys in
`KeePass.config.xml` are unchanged by any of this.

A RULE is about a profile: a name the database defines, which its clients are assigned to. The
resolver joins the two: it looks the client up in the database's registry, resolves the chain once
per profile the client is in, and the client holds the widest result. Inside a grant document the
code keeps `subject` as the neutral term for "who this rule names", because the resolver does not
care; since the move to profiles that name is always a profile or the wildcard, never a client.

One near-collision to keep straight when reading config keys: `KeePassRPC.Profile.<subject>` stores
the client's METHOD profile (`none`/`legacy`/`v3`, which API generations the gate lets it call),
which predates and is unrelated to the database's access profiles. Prose here always qualifies the
former as "method profile".

### Grants live in their own `CustomData` key, not in fields and not in upstream's config

**A grant names a profile, not a client.** A client is a paired identity, a fact about a machine
somewhere; a profile is a job, which is what the rules are actually about. The database defines the
profiles and says which clients are in them, both on the root group's document, and every rule
elsewhere names one of those profiles. Three things follow, and all three are why it is worth the
indirection:

- A second agent doing the same work is one assignment, not a sweep through every group and entry
  that mentions the first.
- A rule needs ONE column to say who it is for. It used to need two, a client name and the identity
  it paired under, because a browser extension pairs as a GUID nobody can read and neither half fits
  a column on the group dialog.
- The same client can be an auditor in one database and hold nothing in another, because a profile
  means nothing outside the database that defines it.

**A client is never without a profile.** An assignment naming profiles that have since been deleted,
or no profiles at all, reads as `default`, which every database has and none can delete. The floor
is deliberate: "in no profile" would have to mean either everything or nothing, and both are traps.
Nothing makes deleting a profile a silent revocation of access somebody depends on; everything needs
no explanation.

**A client in several profiles holds the widest of what they grant.** Roles add up, which is what
makes a profile something that can be reasoned about on its own, and the cost is the one every
additive role model has: a `none` in one profile does not take away what another profile gives.
Taking access away means taking it out of every profile the client is in, or taking the client out
of the profile. The alternative, narrowest-wins, would mean adding a profile to a client could cut
access it already had, and then no profile could be read without reading all the others.

The order is the model in one line: **narrowing happens within a profile as the chain descends, and
widening happens across a client's profiles at the end.**

Grants are a JSON object under the `CustomData` key **`KeePassRPC.ACL`**, carried at two levels:

```text
group.CustomData["KeePassRPC.ACL"]    per group, the root group being the widest
entry.CustomData["KeePassRPC.ACL"]    per entry
```

The root group's document carries three things no other document does, all read from it and nowhere
else: the database's `default` (see below), the `profiles` it defines, and the `clients` map that
says who is in them. A group document carrying any of them is ignored, which is what stops a group
re-opening what its parents closed.

**There was a third, `db.CustomData`, removed 2026-08-13.** A KDBX has exactly one root group and
every entry is inside it, so a rule on the root group reaches precisely what a database rule
reached, under the same inheritance. Two places that both mean "everything" is one more place to
forget to look, and the database one was in a dialog most people never open. The root group is also
the better of the two mechanically: its dialog hands out a working copy of its custom data, so OK
keeps a grant and Cancel discards one, where the database settings dialog keeps no copy and the
editor had to write the live database and undo it by hand. And it asks less of the file format: see
below.

A document found on a database is refused rather than read: `AclResolver` denies everything while
one is there, because ignoring a rule that used to deny is the one direction this must never fail
in. There was a migration that moved such documents onto the root group; it was **removed
2026-08-13** once the databases that needed it had been converted, since a migration outliving its
job is a code path nobody exercises that runs against every database anyway. The access control
page on the database settings dialog reports a leftover document and offers to discard it.

### Where the chain starts: deny by default or allow by default

The root group's document carries a `default`, and it is the only document whose `default` is read:

```text
"default": "deny"     nothing is granted until a rule grants it (absent means this)
"default": "allow"    every subject starts holding everything, and rules take it away
```

**Deny by default is a weak deny, and the distinction is the whole point.** It is the value the
chain starts from, so the first group that grants something lifts it for that group and everything
inside it. Writing `"*": "none"` on the root group is a different rule: a floor, which nothing
below can raise. Both read as "denied" on a database with no other rules, and confusing them is how
somebody ends up unable to grant anything anywhere.

**Allow by default does not change how rights combine.** Groups and entries still only narrow. The
setting decides what they narrow FROM: `AclGrant.Everything` instead of nothing. That is one line in
the resolver, and keeping it to one line is deliberate, because a second set of combination rules
for the other mode would be a model nobody could reason about.

It is edited on the database settings dialog, since it is a statement about the whole file, and
stored on the root group, since that is where the chain starts. The split is on purpose: it keeps
every piece of ACL state inside group and entry custom data, so nothing here raises the file to
KDBX 4.1. The editor shows an allow-by-default database as an inherited wildcard row granting
everything, which nobody typed, because a tab that showed an empty inherited list on such a database
would invite an operator to grant what is already granted.

Switching to allow asks first, and the question says what it costs: every rule already written was
written as a permission and now reads as a restriction, so all of them need reviewing. Switching
back does not ask, because narrowing is the safe direction and a confirmation on both would train
the reader to dismiss the one that matters.

**One representation, two vocabularies.** A rule is stored as an allowance in both modes: the verb
in a document is the most a profile may do, and nothing in the resolver knows any other form. One
representation means one set of combination rules, which is what keeps the model reasonable.

What the table calls it follows the database. On a deny-by-default database a rule is a permission
and the column is headed "Allow"; on an allow-by-default one the same rule is a restriction and the
column is headed "Deny", showing the same fact from the other side. A column headed "Allow" on a
database where every rule takes access away tells the reader the opposite of what is happening.

The two readings are exact opposites, because an allowance names the strongest verb permitted and
carries everything weaker, while a denial names the weakest verb forbidden and carries everything
stronger:

```text
allow none    =  deny list       (nothing is permitted)
allow list    =  deny read
allow read    =  deny write
allow write   =  deny delete
allow delete  =  deny nothing    (everything is permitted)
```

So a denial is the allowance one rung below it, and the ladder needs one extra word at the top of
the deny vocabulary for "nothing is denied". `AclVerbView` is that translation and nothing else,
and `AclVerbViewTest` pins both directions: an off-by-one rung here would hand out or withhold a
whole level of access without changing a single stored document.

```json
{
  "version": 1,
  "grants": {
    "deploy":     { "verb": "write" },
    "agent-docs": { "verb": "read", "attachments": false, "unattended": true },
    "*":          { "verb": "none" }
  }
}
```

The name follows upstream's existing dotted convention for its own database keys (`KeePassRPC.Config`,
`KeePassRPC.KeeFox.rootUUID`).

**The security property is that `CustomData` is a different dictionary from `pwe.Strings`.** V3's
field API reads and writes `Strings` and `Binaries` and has no code path to `CustomData`, so a client
cannot reach a grant by writing a cleverly named field: there is no field to write. An earlier draft
reserved every `KPRPC`-prefixed field name instead, which is a blocklist by name, and name filters
lose to case folding, trailing whitespace and homoglyphs. Structural separation has none of that
surface.

v1 and v2 cannot set it either, and by construction rather than by rule: `Entry` and `Entry2` have no
member that maps to `CustomData`, and `setPwEntryFromEntry` builds only the Kee config from the DTO.
Subject names are JSON keys, so they may contain `:` or `.` freely, which is why the grant carries
`unattended` as a property instead of needing a second field to dodge parse ambiguity.

**A separate key rather than a property on upstream's `EntryConfigv2`**, which an earlier draft
proposed. Three reasons, and each removes a hazard that draft carried:

- **No coupling to an upstream model class.** `EntryConfigv2` is upstream's; adding a property to it
  puts our diff in the path of every upstream change to that class. A separate key means the ACL code
  never edits upstream's model at all, which is the fork-hygiene rule applied rather than stated.
- **No silent grant loss.** A stock, unforked KeePassRPC deserialises `KPRPC JSON` into its own
  `EntryConfigv2`, would drop an unknown `Acl` property and re-serialise without it. It never touches
  `KeePassRPC.ACL`, so grants survive a stock build.
- **No migration coupling, which was the sharpest edge.** `KPRPC JSON` also exists as a legacy custom
  STRING, and `GetKPRPCConfigNormalised` prefers `CustomData` once it exists. Embedding the ACL there
  meant granting on a legacy entry had to migrate its Kee config from v1 to v2 in the same operation,
  silently changing how v1 and v2 clients see that entry. A separate key does not touch the Kee config
  at all, so that entire rule disappears.

There is also no upstream group config to extend even if we wanted to: upstream writes `KPRPC JSON`
on **entries only** and no group `CustomData` whatsoever. Embedding group grants would have meant
inventing an upstream-shaped object where upstream has none.

### What storing grants there costs

- **The database must be KDBX 4, and the target database is** (confirmed 2026-08-11), so this is
  settled rather than pending. Group and entry `CustomData` arrived with KDBX 4 in KeePass 2.35.
  **KDBX 4.0 is the floor, not 4.1**, and that is checked rather than asserted: `KdbxVersionTest`
  calls KeePass's own `KdbxFile.GetMinKdbxVersion` and pins that a database carrying group or entry
  grants comes out as `0x00040000`. A grant on the database itself came out as `0x00040001`, because
  a database custom data item carries a modification time and timestamped custom data is what 4.1
  added, so removing that level lowered the format floor by a version.

  **An older file is upgraded, not damaged.** An earlier version of this document said KeePass
  accepts a `CustomData` write on a KDBX 3.1 file and then fails to persist it. That is wrong:
  KeePass does not keep the version a file was read as, it asks `GetMinKdbxVersion` what the data
  needs and writes that. A grant made on a 3.1 database is kept and the file is rewritten as KDBX 4.
  Worth warning about all the same, because it changes the format of somebody's password database
  and KeePass 2.34 and older cannot open KDBX 4 at all. The tab says so, reading the file header:
  after the signatures (`9AA2D903`, `B54BFB67`) the major version is the 16-bit value at offset 10.

- **The plugin needs KeePass 2.48 or newer**, which is what the packaged `.plgx` already asks for
  (`--plgx-prereq-kp:2.48` in `KeePassRPC.csproj`) and is upstream's floor rather than the ACL's.
  KeePass performs that check only for a `.plgx`, so `MinimumKeePass` makes the same demand at
  start-up and refuses to load a plain DLL install into anything older. The ACL alone would run on
  2.35, where KDBX 4 and group and entry custom data arrived; there is no reason to be more
  permissive than the rest of the plugin.
- **The plugin must provide the grant UI.** `CustomData` is not editable in the stock KeePass entry
  dialog, so unlike a custom string a human cannot simply type a grant. Upstream ships entry UI
  (`Forms/KeeEntryUserControl.cs`, `Forms/KeeFieldForm.cs`) to extend, and a real dialog is better
  than free text anyway because it can validate and list known subjects. But it is work, and it
  changes ordering: **until that UI exists, no grant can be made at all**, so it belongs with the ACL
  step rather than after it.

  **Built 2026-08-11, as a separate tab rather than by extending `KeeEntryUserControl`.** That is a
  deliberate departure from the sentence above. `KeeEntryUserControl` is 750 lines of upstream's, and
  threading a second concern through it would put this fork's diff in the path of every upstream
  change to that file, which is the one thing fork hygiene here is meant to prevent. `AclUserControl`
  is the fork's own file, attached by `AclTabs` as an "Access control" page inside upstream's own "Kee" tab on
  the entry and group dialogs. Inside rather than beside it, so the plugin owns one tab on
  a dialog rather than two; where upstream already nests a strip there the page joins it, and where
  it does not, one is created and upstream's content moved onto its first page. Upstream's control
  is untouched either way.

  Two behaviours in it are security decisions rather than interface ones. Grants that cannot be
  parsed disable editing and offer an explicit discard, rather than being silently replaced by
  whatever the user does next: overwriting a rule nobody can read is destroying a rule that may be
  doing real work. And a database that is not KDBX4 is called out in the tab, because KeePass accepts
  a `CustomData` write on an older file and then does not persist it, so the grant would look made
  and be gone after the next save.

  **Which dictionary the tab writes into is not a detail, and getting it wrong cost every group
  grant made in the UI until 2026-08-13.** A KeePass dialog that offers a "Plugin Data" tab keeps
  its own copy of the object's `CustomData` while it is open and writes that copy back over the
  object when it is accepted. `GroupForm` and `PwEntryForm` both do; `DatabaseSettingsForm` does
  not. So a grant written straight to `group.CustomData` survived Cancel and was destroyed by OK,
  silently and completely, which is the worst way an access control editor can fail: the rule is on
  screen as the dialog closes and absent from the database afterwards. Entry grants were never
  affected, because upstream already reaches `PwEntryForm.m_sdCustomData` for its own entry config
  and the Access control tab rides along with it.

  The tab now edits `GroupForm.m_sdCustomData` for a group, the same working copy, so OK keeps a
  grant and Cancel discards one, which is what the rest of the dialog does. The database settings
  page writes the live root group's custom data, correctly, because that dialog has no copy to
  write back, and `DismissalRevert` puts the old value back if it is dismissed. These are
  private fields of somebody else's dialogs, so `DialogCustomDataTest` pins all three, including the
  absence on `DatabaseSettingsForm`: if a KeePass update adds a copy there, database grants would
  start disappearing on OK the same way, and the test is the warning.

  **The profile is chosen, not typed.** A mistyped name is the worst kind of mistake this UI can
  produce, because it writes a rule that matches no profile and reports nothing: the outcome is
  indistinguishable from having granted nothing, and it fails silently in the safe direction only
  by luck. The pick list offers the profiles the database defines, plus the wildcard as itself. The
  cell stays typeable, because writing the rules before the profile exists is a legitimate order,
  and a rule naming an undefined profile grants nobody anything until a profile of that name
  exists. This used to be two columns, a client name and the GUID it paired under, and the move to
  profiles is what collapsed them: one short chosen name fits where a GUID never did.

  **Who a row is about is settled once the row exists.** The profile cell locks as soon as the row
  names one. Retyping it would move a rule from one profile to another, which reads as an edit and
  is really a revoke plus a grant; removing the row and adding another makes both halves of that
  visible. A row started and not finished stays completable, or a stray click would strand a row
  nobody can fill in.

  **The grants are edited in the table itself**, not through a second set of fields below it. The
  first version had a profile box, a verb box, two checkboxes and "Add or Update" / "Remove"
  buttons, which was a second copy of the table kept in step by hand and cost a third of a short
  tab's height to say nothing the table was not already saying. The rows are now the document: the
  blank row at the bottom adds, right-click or Delete on a selected row removes, and every cell is
  edited where it is shown.

  **What a level inherits is shown alongside what it stores.** A tab listing only an entry's own
  grants reports an empty table for an entry that a group grant already opens wide, and an operator
  reading that empty table is being invited to grant more. So the table merges the two, and says
  which is which by weight: italic for a rule inherited and left alone, bold for one inherited and
  narrowed here, upright for one that exists only here. `AclResolver.Effective` computes the
  inherited view with the same top-down narrow-only rule the resolver applies at call time, so the
  tab and the enforcement cannot disagree; an unreadable document anywhere above yields null rather
  than a partial answer, and the tab says so, because a chain with an unintelligible link grants
  nothing and showing its readable half would describe rights that are not in force.

  Three rules follow from that and are all enforced. **Inherited rows are never written to this
  level**, or a rule meant to follow its group would be frozen at whatever it said the first time
  somebody opened the dialog. **An override may only narrow**: a wider one is refused and marked,
  because the resolver would ignore it and the tab would then be showing more than the client can
  ever get. And **taking an override back restores the inherited values in place** rather than
  removing the row, since the rule is not this level's to delete. Delete and the right-click menu
  are the same gesture, and on a purely inherited row they do nothing at all.

  That makes what the table refuses part of the security surface rather than a matter of polish. A
  row with no profile and a row naming a profile that already appears above are both refused and
  marked, never guessed at: picking one of two rows for the same profile would decide an access
  question on the reader's behalf, and either answer could be the wide one. A new row starts at the
  tightest value its column offers, so naming a profile and stopping there produces a rule that is
  valid and is the safe one.
  Nothing is written while the control is being disposed, because disposing clears the table and
  clearing the table is how a row is removed. Without that guard, closing the dialog would read as
  the user having deleted every grant.

**Opening a dialog is not an edit.** The grant editor lives on dialogs a person opens to look at
something, so it must leave the database exactly as it found it. Two separate writes broke that, and
both are fixed:

- The editor rebuilds its document and saves whenever the grid commits, and the grid commits for
  reasons that are not edits: entering the blank row fills in its defaults, leaving a row validates
  it. `StringDictionaryEx.Set` stamps a new modification time even for an identical value, so this
  had to become a comparison rather than a write. No grants is the absent key and never an empty
  document, which is also what makes a purged ACL indistinguishable from one that never existed.
- `KeeEntryUserControl` is upstream's, and filling in its controls during `Load` raised their change
  handlers, each of which wrote the whole entry config back. Opening any entry that had no
  `KPRPC JSON` gave it one, plus a history record and a new modification time. It now waits until
  the controls are populated before treating a change handler as a person. This is a change to an
  upstream file, justified because the ACL editor shares that dialog: reviewing who may reach an
  entry would otherwise modify the database every time. Nothing depends on the config being
  materialised early, since every reader normalises for itself through `GetKPRPCConfigNormalised`.

Verified by opening an entry twice, the database settings and a group dialog, pressing OK on each,
saving, and diffing the `.kdbx` against a copy taken beforehand: no difference at all.

### Verbs

A ladder, each implying the ones below:

| verb | grants |
| --- | --- |
| `none` | nothing, and blocks inheritance |
| `list` | title and UUID only |
| `read` | standard fields, custom strings, notes, attachment NAMES |
| `write` | create and update; implies `read` |
| `delete` | remove entries; implies `write` |
| `+attachments` | modifier: attachment CONTENT, at the level of the verb it modifies |

Two splits are deliberate:

- **`list` is separate from `read`**, because enumeration is itself disclosure. A list of titles tells
  an agent what exists and where the interesting things are, which is exactly the reconnaissance step
  you do not want to hand out with a password read.
- **Attachment content is separate from `read`** (`read+attachments`). Attachments are the highest
  risk payload in the database, typically private keys or whole certificate bundles, and an agent
  allowed to read a service password should not get the key file beside it for free.

### Inheritance

Top-down, and **narrow-only**: effective rights are the minimum along the chain from root to entry,
evaluated per subject. Narrow-only is what stops an entry marked `write` inside a `read` group from
being a silent escalation authored in a text field.

The corollary is easy to miss: because a child that says nothing inherits its parent's grant,
**revoking one entry inside a granted group requires an explicit `none`**. That is why `none` is a
real value and not merely the absence of a key.

Default is deny: no key anywhere in the chain means no access, including no `list`.

**And the trap on the other side, found while building this: `"*": "none"` on the root group is not
a default-deny you can then grant beneath.** Narrow-only means the root's `none` is the minimum for
every profile on every chain below it, so the whole database goes dark and no group or entry rule
can reopen it. Default deny is already what an absent document does, so the root should simply
carry no rule for a profile that is meant to be granted further down. The wildcard earns its keep
at the level where the exceptions are named, denying every profile not listed in the same
document.

The omission rule for the flags is worth stating too, because it is the fail-closed reading rather
than the intuitive one. `attachments` and `unattended` are ANDed along the chain and an absent flag
counts as false, so a child grant that omits `attachments` REMOVES an attachment right held above it.
A child meant to keep a flag has to repeat it.

### The one exception the structure does not cover

Storing grants in `CustomData` removes the need for a reserved namespace, but not quite all of it,
and the remainder must be handled deliberately.

**`KPRPC JSON` also exists as a custom STRING.** Upstream has two overloads:
`SetKPRPCConfig(EntryConfigv2)` writes `entry.CustomData`, while `SetKPRPCConfig(EntryConfigv1)`
writes `entry.Strings` under that same name. Entries whose config was never migrated still keep it
there, and `GetKPRPCConfigNormalised` falls back to it when `CustomData` has none.

So V3's string surface excludes exactly one name, `KPRPC JSON`:

- The V3 API refuses to read or write it, for every subject, unconditionally.
- `AddEntry3` and `UpdateEntry3` strip it from an incoming payload rather than rejecting the whole
  call, so a client that echoes back an entry it read cannot accidentally fail.

That is one exact name with a migration path, rather than a namespace policy. Much easier to defend
and to test.

That blob decides which fields v1 and v2 expose, so a client able to rewrite it could change what
other clients see, or what a form-filling client submits. The exclusion stands on its own merit and
no longer has anything to do with protecting the ACL, which now lives elsewhere entirely.

Grants are made by a human, through the plugin, and by nothing else.

### Session crypto, as built 2026-08-12

The wire crypto was upstream's and weak, and the reason to leave it alone was compatibility. With
the Kee browser extension established as the only legacy client that matters, that reason no longer
covers the whole surface, so `KPRPC_FEATURE_CRYPTO_V2` adds a stronger suite the same way `DTO_V2`
and `DTO_V3` added APIs: negotiated per client, with the old path untouched for anyone who does not
ask.

**The problem worth fixing was not the one that looks worst.** The 512-bit SRP group is the alarming
number, but it only protects pairing. The real weakness is that the AES key IS the paired key: the
key challenge proves possession and derives nothing, so one key covers every message of every
session for up to a year. Since that key is also a DPAPI blob any local process can read, and the
threat model already concedes local code execution, **traffic captured today could be decrypted by
anyone who obtained the key months later**. Forward secrecy is what removes that, and nothing else
does.

So: an ephemeral P-256 agreement per connection, authenticated by the paired key (the session key
derives from both, so it is secure if either is), HMAC-SHA256 in place of
`SHA1(SHA1(key) || ciphertext || iv)`, separate encryption and MAC subkeys, and a per-direction
counter that makes a replayed or reordered message an error.

Three constraints shaped it:

- **No AEAD.** .NET Framework 4.5 has no `AesGcm`; it arrived in .NET Core 3.0. So AES-256-CBC with
  explicit encrypt-then-MAC, which is at least the ordering upstream already had right.
- **No spare round trip.** The server refuses setup messages once authorised, and before that there
  is no shared key to authenticate an exchange with. The agreement therefore rides on the message
  that completes authentication, in both the pairing and the reconnect paths.
- **The wire container could not change shape.** The counter travels inside the ciphertext rather
  than beside it, so the three-member `{iv, message, hmac}` container is byte-identical in form for
  both suites and nothing a legacy client parses moves.

**A client that asks and is refused is not downgraded.** It fails instead. A client that believes it
has forward secrecy and silently does not is worse off than one that knows it does not.

### The SRP group, as built 2026-08-12

Upstream pairs in a hardcoded 512-bit group. That was defensible while pairing could only happen
over loopback, where nobody can observe the exchange, and it stopped being defensible once pairing
could happen across a network: a 512-bit discrete log is within reach of a determined attacker, and
solving one yields the paired key, which authenticates everything afterwards including the newer
suite's own key agreement.

`KPRPC_FEATURE_SRP_2048` selects the RFC 5054 Appendix A 2048-bit group. Negotiated like everything
else, so a client that declares nothing gets exactly what it always got. That is not politeness,
it is the Kee extension, which cannot be updated in step with this plugin.

**A published group rather than a generated one**, so a reviewer can check the constant against the
RFC instead of trusting whoever generated it. Verified before it was embedded: 2048 bits, N prime,
(N-1)/2 prime, and 2 a generator of the prime-order subgroup.

**`k` follows this codebase rather than the RFC.** It is SHA-256 over the hex spelling of N then g,
because this SRP hashes hex strings throughout, its salt is decimal and its B is not reduced modulo
N. Following the RFC's byte-oriented `k = H(N | PAD(g))` for that one value would have put it on a
different footing from every other. It is a literal, and a test in each language recomputes it so
the constant cannot drift from the derivation it claims.

**N and g are never sent**, so the feature flag is the whole negotiation. A client that asks for the
strong group against a server that does not offer it computes A in a different group and fails the
proof, which is the right failure: pairing stops, and neither side quietly settles for the weaker
group.

**A remote pairing has no choice.** Offering the group is not the same as getting it. A client that
simply does not declare the feature pairs in the 512-bit group in silence, which is correct for a
local client and wrong for one whose exchange might be observed. A remote connection that tries to
pair without asking for the strong group is refused. Scoped to pairing: a key challenge never
touches N.

The cost is a wider `BigInteger`. Upstream's is fixed-width at 70 words, and a 2048-bit modulus needs
more than that for its intermediates. The binding constraint is inside `BarrettReduction`, not the
obvious multiply. It is 140 words now. A 2048-bit exchange measures 236ms against 64ms for the
512-bit one, once, on the socket thread rather than the UI thread.

### Remote connections, as built 2026-08-12

The plugin can tell a connection that came from off this machine from a local one, and holds it to
stricter requirements: the negotiated session suite always, the 2048-bit group when pairing, and a
`remote` field on every audit record. **None of this binds a port off loopback**, and none of it
makes exposure supported. It exists because the alternative, deciding these things at deployment
time, puts the weakest crypto one misconfiguration away from a network.

The detection, the two controls that were proposed and deliberately rejected, and what would still
have to be true before any of it were used, are in [`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md).

### The limit worth writing down

On a single Windows account this is a guard rail, not a boundary. A legacy client's session key is
DPAPI user-scope, so anything running as that user, an agent included, can read it and present itself
as a subject holding v1 access. Real separation needs the agent to run as a different Windows user,
or the key held somewhere it cannot reach.

That does not make the gate pointless: the dominant risk with an agent is the confused deputy, an
injected or mistaken client using the API as designed, and the gate answers that squarely. But it
answers misuse of the interface, not an attacker with filesystem access to the same account, and the
design should not pretend otherwise.

[`THREAT-MODEL.md`](THREAT-MODEL.md) works this through properly: what each control is worth against
each actor, which weaknesses are inherited from upstream rather than chosen here, which risks are
accepted rather than overlooked, and the operational hazards that weaken the model without anyone
changing code.

(On expiry: authorisation already expires, and the decision is to keep the stock behaviour.
`KeePassRPC.AuthorisationExpiryTime` defaults to 31536000 seconds, one year. Per-subject TTLs remain
an existing knob if that ever needs tightening, so there is nothing to build for it now.)

### Confirmation

The plugin runs inside the KeePass UI process, so it can prompt. A headless daemon cannot, and this is
the strongest single argument for the in-process design.

**`write`, `delete` and attachment-content reads prompt by default.** A path that has been
deliberately automated opts out with `"unattended": true` on the profile's rule.
This is the best available mitigation against a prompt-injected agent asking for something it should
not, and it costs nothing on the paths where the answer is always yes.

### Audit

Append-only, on the Windows host, outside the `.kdbx` (logging into the database would generate write
traffic and history churn): timestamp, subject, entry UUID, verb, allow or deny. **Never values.**
The subject recorded is the CLIENT identity, not a profile: rules are written about profiles, but
what acted was a client, and "which profile allowed this" is recoverable from the database while
"which client did this" is recoverable from nowhere else.

With a single human-driven client an audit log is a nicety. With agents it is the only way to answer
"what did it actually touch", and the first time something behaves oddly it is the only evidence
there is.

**Built 2026-08-12** as `Audit.cs`, JSON Lines at `%LOCALAPPDATA%\KeePassRPC\audit.jsonl`, rotating
at 8 MB with one previous file kept. Four notes on how it turned out.

**The target is a UUID and stays one.** No title, no field name, no value. Not only because titles
can be sensitive: a log of titles is an inventory of the database, sitting in a plain file that
anything able to read the log can read, and it would quietly become the easiest place in the whole
system to learn what exists. Resolving a UUID back to an entry is the reader's job, in KeePass.

**Allows are recorded, not just denials.** A log of refusals answers "what was blocked", which is the
question you already know the answer to. "What did it read" is the one that matters after the fact,
and a read leaves no other trace anywhere: not in the `.kdbx`, not in entry history.

**A write failure does not refuse the call.** The strict reading of fail-closed would, so that
nothing happens unobserved. But that rule governs ambiguous access decisions, and this is not one:
the decision has already been made correctly and only the recording failed. Refusing would mean a
full disk or a locked file silently revokes every agent's access, trading a logging outage for an
outage of the thing being logged. Failures go to the plugin's debug log instead, because an audit log
that has quietly stopped recording looks exactly like one with nothing to record.

**"Append-only" describes this code, not the filesystem.** Nothing prevents a process running as the
same Windows account from rewriting the file, just as nothing prevents it reading the DPAPI session
key. It is the same boundary as everything else here and should not be described as more.

## Scope

V3 is for **bootstrap secrets, human-facing storage, and seeding**. It is not a general secret
daemon and must not grow into one: no leases, no dynamic credentials, no policy engine beyond the
ACL this document describes.

**The client is the boundary.** This repository ends at the protocol it serves: a client declares
its features, authenticates, and gets whatever the method gate and the ACL allow it, and everything
past that point is the consumer's own architecture. What a consumer feeds, seeds or builds with the
secrets it fetches is its business and is deliberately not described here, in either direction:
nothing in this repo depends on any consumer, and no consumer's infrastructure is named in it.

## Licence, and what that means for a PUBLIC fork

KeePassRPC is **GPLv2** (KeePassCommander, the other candidate, is MIT), and this fork is **public**:
GitHub forks inherit the parent's visibility and cannot be made private. A private copy would have to
be a mirror into a new repository, which is a different thing and loses the fork relationship.

So the GPL is a live constraint rather than the deferred one an earlier draft assumed. Everything
added here is distributed under GPLv2 the moment it is pushed, and that includes these design
documents.

The consequence that matters day to day is not the licence, it is the visibility:

- **Nothing about the actual database goes in this repo.** Credentials obviously not, but also no
  host names, no entry titles, no group layout, no subject/agent identities, no examples drawn from a
  real `.kdbx`. The ACL *design* is safe to publish and benefits from review; an inventory of what is
  stored behind it is not.
- Use invented names in examples and tests, and keep them obviously invented.

## First step

Build the **unmodified** KeePassRPC against .NET Framework 4.5 and load it into KeePass with existing
pairing intact. The upstream `KeePassRPCTest` project gives a build target to check against.

If a drop-in rebuild is not achievable on this workstation, every option that involves a plugin
collapses and what remains all lives outside KeePass. That is an hour's work and it gates everything
above, so it comes first.
