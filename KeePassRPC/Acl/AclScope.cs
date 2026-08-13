using System;

namespace KeePassRPC.Acl
{
    /// <summary>
    /// How far the ACL reaches for one subject.
    ///
    /// The ACL began by guarding V3 only, because v1 and v2 resolve secrets in production and
    /// a default-deny arriving on a working installation would break them silently. v1 reads
    /// return lists, so a filtered list looks like an empty database rather than an error.
    /// Extending it therefore has to be opt-in per subject, which is why this is a setting at
    /// all rather than something the ACL simply does.
    ///
    /// The intended end state is every subject on <see cref="All"/>. <see cref="V3Only"/> is
    /// where a subject starts, not where it should stay.
    /// </summary>
    public static class AclScope
    {
        /// <summary>The ACL guards V3 only. v1 and v2 are authorised wholesale, as before.</summary>
        public const string V3Only = "v3";

        /// <summary>The ACL guards v1 and v2 entry access as well as V3.</summary>
        public const string All = "all";

        /// <summary>
        /// Per-subject setting: <c>KeePassRPC.AclScope.&lt;subject&gt;</c>. The only place a
        /// scope is read from. A subject with none stored gets <see cref="V3Only"/>, and there
        /// is deliberately no key that changes that for everyone at once.
        /// </summary>
        public const string SubjectPrefix = "KeePassRPC.AclScope.";

        /// <summary>
        /// Whether this scope extends the ACL over v1 and v2.
        /// </summary>
        /// <param name="scope">A stored scope value, possibly absent or misspelled.</param>
        /// <returns>
        /// True for <see cref="All"/>, false for <see cref="V3Only"/> and for an absent value,
        /// and TRUE for anything unrecognised.
        ///
        /// That last case looks inconsistent with treating an absent value as "not covered",
        /// so it is worth saying why. An absent value is the documented default and means the
        /// subject has never been considered. A value that is present but unreadable means
        /// somebody tried to configure something and got it wrong, and the two possible
        /// mistakes are not symmetric: guarding a subject that should not have been guarded
        /// breaks its access loudly and gets fixed, while failing to guard one that should
        /// have been leaves a control switched off that its author believes is on.
        /// </returns>
        public static bool CoversLegacy(string scope)
        {
            if (string.IsNullOrEmpty(scope))
                return false;

            string trimmed = scope.Trim();
            if (trimmed.Length == 0)
                return false;

            if (string.Equals(trimmed, V3Only, StringComparison.OrdinalIgnoreCase))
                return false;

            return true;
        }
    }
}
