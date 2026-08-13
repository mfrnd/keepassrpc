> ### This is a fork
>
> It adds a third API generation to KeePassRPC: full access to an entry, meaning real custom
> strings, notes and attachments rather than just a password, behind a per-client method allowlist and a
> per-entry access control list, so that automation and AI agents can each be given a narrow,
> revocable, audited slice of the database. Existing clients are unaffected; everything new is
> negotiated by feature flag.
>
> **[`CONTRIBUTION.md`](CONTRIBUTION.md) is the place to start**: what the fork adds and why, with
> screenshots of the new UI and diagrams of the local and remote call paths. The design is in
> [`V3-DESIGN.md`](V3-DESIGN.md), what the controls are worth in
> [`THREAT-MODEL.md`](THREAT-MODEL.md).
>
> #### Installing this fork
>
> The plugin ships as `KeePassRPC.plgx`, the same filename upstream uses, so KeePass loads whichever
> one is present. Install this fork **or** upstream's plugin, never both.
>
> With [Scoop](https://scoop.sh), this repository doubles as a bucket:
>
> ```powershell
> scoop bucket add keepassrpc-v3 https://github.com/mfrnd/keepassrpc
> scoop install keepassrpc-v3/keepass-plugin-keepassrpc-v3
> ```
>
> That targets a Scoop-managed KeePass (it declares `extras/keepass` as a dependency) and copies the
> plugin into its `Plugins` folder. For a KeePass installed any other way, download `KeePassRPC.plgx`
> from the [releases page](https://github.com/mfrnd/keepassrpc/releases) and drop it into that
> KeePass's `Plugins` folder by hand. Either way, restart KeePass afterwards so it compiles and loads
> the plugin.
>
> Everything below this note is upstream's README, unchanged. Its own download and install
> instructions refer to the official plugin at
> [kee-org/keepassrpc](https://github.com/kee-org/keepassrpc), not to this fork.

# Simple and secure password management

## Kee adds free, secure and easy to use password management features to your web browser which save you time and keep your private data more secure.

**Login automatically, never forget another password, stay in control of your passwords and improve their security. Powered by the world-renowned KeePass Password Safe.**

[Kee](https://github.com/kee-org/browser-addon) is a Firefox and Chrome add-on for linking browsers to KeePass, using the KeePassRPC KeePass plugin contained within this repository.

Official website with download instructions: https://www.kee.pm

Community support forum: https://forum.kee.pm

Download KeePassRPC from the [releases page](https://github.com/kee-org/keepassrpc/releases).

KeePass will notify you when updates are available but it does not support automatic updates so you will need to perform the update manually. You can find [instructions on the forum](https://forum.kee.pm/t/upgrading-keepassrpc/22).

KeePassRPC supports multiple clients, although the Kee web browser add-on is the most widely used. Other known uses include Thunderbird integration and integration with old web browsers such as Firefox before version 57 was released in 2017.

Please feel free to fork and submit pull requests for any changes or improvements you would like to see incorporated to the official KeePassRPC plugin. However, in most cases, it would be best if you discuss your ideas on the Kee [community forum](https://forum.kee.pm) first since the need to support multiple clients with backwards compatible changes can require some careful planning and the most obvious implementation approach is not always the best one.

If your change relates to Thunderbird or older web browsers (those that KeeFox version 1.7 supports but Kee 2.x does not) you can [find appropriate categories](https://forum.kee.pm/categories) in which to start the discussion.