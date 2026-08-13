// Extending the ACL over v1 and v2.
//
// This is the riskiest change in the fork, and the design deferred it for that reason: v1
// resolves secrets in production, and a v1 read returns a LIST, so a filtered list looks
// like an empty database rather than an error. Getting this wrong does not throw; it
// quietly returns nothing, and the caller reports that the entry does not exist.
//
// Hence two properties, both load-bearing:
//
//   Opt-in per subject. A subject stays on the old behaviour until someone moves it, so
//   installing this build changes nothing for anybody until a deliberate act.
//
//   Filtering happens at the single point where a PwEntry becomes a wire object. Every v1
//   and v2 read funnels through GetEntryFromPwEntry / GetEntry2FromPwEntry, including the
//   recursive whole-database dumps, which reach entries through the same conversion. Doing
//   it there rather than at twenty method sites is what makes the coverage checkable: there
//   is one place to read, and a new upstream read method inherits the filter for free.
//
// Upstream's own `abortIfHidden` path already returns null from that conversion for hidden
// entries, and every caller either checks for null or returns it straight to the client, so
// the shape was already supported. That was verified call site by call site before this was
// written, not assumed.

using System;
using KeePassLib;
using KeePassLib.Utility;
using KeePassRPC.Acl;

namespace KeePassRPC
{
    public partial class KeePassRPCService
    {
        /// <summary>
        /// The subject of the request in progress, or null when there is no request.
        ///
        /// Null means this is not an RPC at all. The method gate refuses any call it cannot
        /// attribute to a subject, so a request that reaches the conversion always has one.
        /// </summary>
        private string CurrentSubject
        {
            get
            {
                if (ClientMetadata == null)
                    return null;
                return string.IsNullOrEmpty(ClientMetadata.Subject) ? null : ClientMetadata.Subject;
            }
        }

        /// <summary>
        /// Whether the ACL governs v1 and v2 for the subject of this request.
        ///
        /// Read per subject and nowhere else. There was a database-wide fallback key beside
        /// this one, and it went with the fallback profile it partnered: both belonged to the
        /// same one-off migration, which <see cref="LegacyClients"/> now performs on its own.
        /// </summary>
        private bool AclCoversLegacy(string subject)
        {
            if (string.IsNullOrEmpty(subject))
                return false;

            string scope = _host.CustomConfig.GetString(
                AclScope.SubjectPrefix + subject, AclScope.V3Only);
            return AclScope.CoversLegacy(scope);
        }

        /// <summary>
        /// Whether the entry may be returned to the current client through v1 or v2.
        ///
        /// Returns true, and audits nothing, whenever the subject is not governed for legacy
        /// access; that is the untouched path and it must stay as cheap as it was.
        /// </summary>
        /// <param name="db">The database the entry belongs to.</param>
        /// <param name="pwe">The entry about to be converted.</param>
        /// <param name="method">
        /// The method being served, for the log. The conversion does not know it, so this is
        /// the generation rather than the method name; a v1 read is a v1 read.
        /// </param>
        private bool LegacyReadPermitted(PwDatabase db, PwEntry pwe, string method)
        {
            string subject = CurrentSubject;
            if (subject == null || !AclCoversLegacy(subject))
                return true;

            // read, not list, even for the "light" DTO. A v1 LightEntry carries the username
            // and the URLs, which is already more than list is defined to disclose, so there
            // is no honest way to serve one on a list grant.
            AclGrant grant = AclResolver.Resolve(db, pwe, subject);
            if (!grant.Permits(AclVerb.Read))
                return false;

            // Allows are recorded and the withheld entries are not, which is the opposite of
            // the usual instinct and is deliberate. A bulk read over a database where the
            // subject is granted two entries would otherwise write a denial line for every
            // other entry, on every poll, burying the few lines that say what was actually
            // disclosed. "What did it read" is the question worth being able to answer, and
            // silence means everything else was withheld.
            Audit.Record(_host, subject, RequestIsRemote(), method, MemUtil.ByteArrayToHexString(pwe.Uuid.UuidBytes),
                AclVerbs.ToJsonValue(AclVerb.Read), true, "granted " + grant);
            return true;
        }

        /// <summary>
        /// Refuse a v1 or v2 mutation the ACL does not permit.
        ///
        /// Writes get an explicit check rather than riding on the conversion, because the
        /// conversion happens AFTER the mutation: filtering there would create or delete the
        /// entry and then decline to describe it, which is the worst of both.
        /// </summary>
        /// <exception cref="Exception">If the subject is governed and not permitted.</exception>
        private void RequireLegacyWrite(PwDatabase db, PwEntry pwe, AclVerb required, string method)
        {
            string subject = CurrentSubject;
            if (subject == null || !AclCoversLegacy(subject))
                return;

            AclGrant grant = AclResolver.Resolve(db, pwe, subject);
            bool allowed = grant.Permits(required);

            Audit.Record(_host, subject, RequestIsRemote(), method, MemUtil.ByteArrayToHexString(pwe.Uuid.UuidBytes),
                AclVerbs.ToJsonValue(required), allowed,
                allowed ? "granted " + grant : "no grant permits it");

            if (!allowed)
                throw new Exception("Not permitted.");
        }

        /// <summary>Refuse a v1 or v2 mutation aimed at a group.</summary>
        /// <exception cref="Exception">If the subject is governed and not permitted.</exception>
        private void RequireLegacyWrite(PwDatabase db, PwGroup group, AclVerb required, string method)
        {
            string subject = CurrentSubject;
            if (subject == null || !AclCoversLegacy(subject))
                return;

            AclGrant grant = AclResolver.Resolve(db, group, subject);
            bool allowed = grant.Permits(required);

            Audit.Record(_host, subject, RequestIsRemote(), method, MemUtil.ByteArrayToHexString(group.Uuid.UuidBytes),
                AclVerbs.ToJsonValue(required), allowed,
                allowed ? "granted " + grant : "no grant permits it");

            if (!allowed)
                throw new Exception("Not permitted.");
        }
    }
}
