using System;
using System.Collections.Generic;
using KeePass.Plugins;
using KeePassRPC.Acl;

namespace KeePassRPC
{
    /// <summary>
    /// What happens to the clients that were already paired when this build arrived.
    ///
    /// The method gate is default deny, so installing this over a KeePass with paired clients
    /// refuses every one of them at once, including whatever resolves secrets over v1 today.
    /// That was handled by a fallback setting on the options dialog: set it wide, work down
    /// the list, set it back. It is gone, because it was a footgun left lying about long after
    /// the migration it existed for. A control that can hand every future client the whole
    /// database, sitting on a tab somebody visits to tighten things, is not worth keeping for
    /// a job that runs once.
    ///
    /// So the job runs itself, once, and writes a real setting for each client it finds. Every
    /// migrated client then has a row on the Authorised clients tab saying "legacy API,
    /// unrestricted", which is exactly what it had before this build and is visible, auditable
    /// and narrowable. An invisible fallback was none of those.
    ///
    /// A client that pairs after this has run is not covered: it is asked at pairing time, and
    /// dismissing that prompt leaves it refused. Default deny survives for everything new,
    /// which is the whole point of the gate.
    ///
    /// Nothing here can widen access beyond what a client already had, which is what makes an
    /// automatic grant defensible at all. It writes only for a subject that holds a pairing key,
    /// and what it writes is the access every paired client had before the gate existed. Where
    /// the subject list comes back short, the clients it missed are refused rather than granted,
    /// and the Authorised clients tab is where that is both visible and fixable.
    /// </summary>
    public static class LegacyClients
    {
        /// <summary>
        /// Set once the migration has run. Its presence, not its value, is what matters: a
        /// second run must not re-grant a client whose access somebody has since taken away.
        /// </summary>
        public const string MigratedKey = "KeePassRPC.MethodGate.LegacyClientsMigrated";

        /// <summary>
        /// Give every client that predates this build the access it used to have.
        ///
        /// Never throws. This runs during plugin start-up, and a failure to migrate must not
        /// stop KeePass loading the plugin: the consequence of skipping it is that clients are
        /// refused until somebody sets them by hand, which is safe, loud and recoverable.
        /// </summary>
        /// <returns>The subjects that were migrated, for the log.</returns>
        public static IList<string> Migrate(IPluginHost host)
        {
            List<string> migrated = new List<string>();
            if (host == null)
                return migrated;

            try
            {
                if (host.CustomConfig.GetBool(MigratedKey, false))
                    return migrated;

                foreach (string subject in SubjectRegistry.Known(host))
                {
                    if (string.IsNullOrEmpty(subject))
                        continue;

                    // Only where a pairing key actually exists. The list of subjects comes
                    // partly from reflecting into KeePass's config, and a name is not
                    // authority to grant anything; the key is. Checking it means the worst a
                    // wrong name can do is nothing, and it holds the rule that this grants
                    // only what the client already had: no key, nothing had, nothing given.
                    string key = host.CustomConfig.GetString(
                        SubjectRegistry.KeyPrefix + subject, null);
                    if (string.IsNullOrEmpty(key))
                        continue;

                    // Only a client with no answer of its own. One that already holds a
                    // profile has been decided about, and this must not overrule that.
                    string stored = host.CustomConfig.GetString(
                        SubjectRegistry.ProfilePrefix + subject, null);
                    if (!string.IsNullOrEmpty(stored))
                        continue;

                    host.CustomConfig.SetString(
                        SubjectRegistry.ProfilePrefix + subject, AccessChoice.LegacyUnrestricted.Profile);
                    host.CustomConfig.SetString(
                        AclScope.SubjectPrefix + subject, AccessChoice.LegacyUnrestricted.Scope);
                    migrated.Add(subject);
                }

                host.CustomConfig.SetBool(MigratedKey, true);
            }
            catch (Exception)
            {
                // See the summary: refused-until-set is the safe failure, so it is preferred
                // to an exception on the start-up path.
            }

            return migrated;
        }
    }
}
