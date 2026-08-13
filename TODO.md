# TODO

What is left to do. **Finished work is described where it was designed, not here.** This file used
to carry a section per completed step, which meant every decision had two accounts that had to be
kept in step with each other, and they drifted: the ACL section still said "enforcement still to
come" months after enforcement shipped. One account is enough, and it should be the one next to the
reasoning.

Read [`V3-DESIGN.md`](V3-DESIGN.md) before starting any of these.
[`CONTRIBUTION.md`](CONTRIBUTION.md) is the short version of what exists.

## What exists

Built and verified against a live KeePass. 469 C# tests, 137 Python tests.

| Piece | Described in |
| --- | --- |
| Build and load path, and its four non-obvious traps | [`CLAUDE.md`](CLAUDE.md) |
| V3 API, read and write halves | [`V3-DESIGN.md`](V3-DESIGN.md) |
| Method gate, and the v1/v2 bypass it closes | [`V3-DESIGN.md`](V3-DESIGN.md) |
| ACL: grant storage, resolver, editor, enforcement | [`V3-DESIGN.md`](V3-DESIGN.md) |
| Profiles, and the deny/allow starting point per database | [`V3-DESIGN.md`](V3-DESIGN.md) |
| Access choice, and the prompt raised when a client pairs | [`V3-DESIGN.md`](V3-DESIGN.md) |
| Audit log | [`V3-DESIGN.md`](V3-DESIGN.md) |
| Session crypto, `KPRPC_FEATURE_CRYPTO_V2` | [`V3-DESIGN.md`](V3-DESIGN.md) |
| 2048-bit SRP group, `KPRPC_FEATURE_SRP_2048` | [`V3-DESIGN.md`](V3-DESIGN.md) |
| Remote connection handling, and two controls rejected | [`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md) |
| What each control is worth, and what it is not | [`THREAT-MODEL.md`](THREAT-MODEL.md) |
| Python protocol client | [`clients/python/README.md`](clients/python/README.md) |

## 1. After this build replaces the installed plugin

The method gate is default deny, and the installed KeePass has paired clients with no
`KeePassRPC.Profile.<subject>` entries. That used to be a prerequisite: without one of two keys set
by hand, installing this build denied every one of them, including whatever resolves secrets over
v1 today.

It is a follow-up now. `LegacyClients.Migrate` runs once on the first start and gives every client
already paired the access it had before, `legacy API, unrestricted`, so nothing breaks on the way
in. What is left is the narrowing, which is the point of the exercise:

- Work down the Authorised clients tab and give each one the narrowest setting it can do its job
  with. A client that never needed the whole database should not keep it because a migration was
  cautious.
- A client paired from now on is asked at the moment it pairs, and is refused until answered.

## 2. Consumers

Nothing, here. A consumer declares `KPRPC_FEATURE_DTO_V3` and gains the V3 calls, and keeping up
with this plugin is its own responsibility. This repository does not track or depend on any of
them. What it owes them is the feature negotiation it already has, so that a client which declares
nothing new keeps working.

## 3. Optional, and none of it blocking

- **The infrastructure in [`NETWORK-EXPOSURE.md`](NETWORK-EXPOSURE.md)**, if the plugin is ever to be
  reached from off-host: a mesh VPN, then a reverse proxy for rate limiting. The plugin side is
  done; nothing there is code.

## Decided

- **Fork structure and hosting**: resolved 2026-08-11. This repo IS the fork
  (`mfrnd/keepassrpc`, forked from `kee-org/keepassrpc`), work happens on `feature/v3-api`, and
  `upstream` exists as a remote with its push URL disabled.
- **Naming**: resolved 2026-08-11. Follow upstream throughout, internals included. There is no
  separate product name; this is V3 of KeePassRPC. An earlier working title has been removed.
- **Where grants live**: resolved 2026-08-11, refined the same day. In their own `CustomData` key,
  `KeePassRPC.ACL`, not in custom string fields and NOT as a property on upstream's config object --
  an earlier version of this line said the latter and was wrong. Structural separation from the V3
  field API beats a reserved-name filter.
- **Pairing granularity**: resolved 2026-08-11. **One identity per agent.** Revocation and audit are
  only useful at the granularity you paired at.
- **Database format**: confirmed 2026-08-11. The target database is **KDBX 4**, so `CustomData` grant
  storage is available and the ACL design stands as written.
- **Grant TTL**: resolved 2026-08-11. **Keep the stock default**,
  `KeePassRPC.AuthorisationExpiryTime` = 31536000 seconds (one year). Nothing to build; per-subject
  values remain available if it ever needs tightening.
- **Pushing**: resolved 2026-08-11. **Do not push until the author says otherwise.** Standing
  instruction, not a pending question.

## Open questions for the author

None. The last one, whether to fold `AclScope` into the method profile, was answered on 2026-08-13
by answering the question behind it. The two keys stay separate on disk, because the method profile
is about methods and the scope is about entries and merging them would make one value mean two
things, but they are no longer separately editable: `AccessChoice` offers the five pairs that are real and writes
both together. The complaint was never the second key, it was being asked two questions to make one
decision.
