using System;
using System.Collections.Generic;
using KeePassRPC.Acl;

namespace KeePassRPC
{
    /// <summary>
    /// One thing a human can decide about a client, spelling out a profile and an ACL scope
    /// together.
    ///
    /// Those two settings were separately editable, as a profile dropdown and a tickbox, and
    /// nobody could say what the pair of them meant. They are not independent in practice:
    /// the tickbox only ever spoke about the older API, so it said nothing at all for a
    /// client on V3, and the combination it implied there could not happen. Offering the
    /// handful of pairs that are real, under names that say what the client gets, is both
    /// shorter to read and impossible to set to something meaningless.
    ///
    /// The list is deliberately not every combination. There is no "all APIs, unrestricted":
    /// unrestricted already means the whole of every open database, so adding V3 to it grants
    /// nothing further and would only offer a second way to spell the widest setting.
    /// </summary>
    public sealed class AccessChoice
    {
        /// <summary>What the dropdown shows.</summary>
        public readonly string Label;

        /// <summary>Stored under <c>KeePassRPC.Profile.&lt;subject&gt;</c>.</summary>
        public readonly string Profile;

        /// <summary>Stored under <c>KeePassRPC.AclScope.&lt;subject&gt;</c>.</summary>
        public readonly string Scope;

        /// <summary>The longer explanation, for a tooltip.</summary>
        public readonly string Detail;

        private AccessChoice(string label, string profile, string scope, string detail)
        {
            Label = label;
            Profile = profile;
            Scope = scope;
            Detail = detail;
        }

        public override string ToString()
        {
            return Label;
        }

        /// <summary>Nothing at all. This is what every client holds until someone says otherwise.</summary>
        public static readonly AccessChoice Refused = new AccessChoice(
            "refused",
            MethodProfiles.None,
            AclScope.V3Only,
            "Every call is refused. This is where a client starts, and setting it back here is "
                + "how access is taken away, because a setting can be changed but not removed.");

        /// <summary>
        /// The older API with the ACL standing aside. The widest setting there is, and what
        /// the Kee browser extension needs.
        /// </summary>
        public static readonly AccessChoice LegacyUnrestricted = new AccessChoice(
            "legacy API, unrestricted",
            MethodProfiles.Legacy,
            AclScope.V3Only,
            "The v1 and v2 API, with the ACL standing aside. This reaches every entry in every "
                + "open database and no grant constrains it. It is what the Kee browser "
                + "extension expects, and it is the widest setting here.");

        /// <summary>The older API, held to the same grants as V3.</summary>
        public static readonly AccessChoice LegacyWithAcl = new AccessChoice(
            "legacy API, with ACL",
            MethodProfiles.Legacy,
            AclScope.All,
            "The v1 and v2 API, held to the rules on the Access control tabs. A client that speaks "
                + "only the older API but should still be confined to a few entries belongs here.");

        /// <summary>The V3 API, which the ACL always governs.</summary>
        public static readonly AccessChoice V3WithAcl = new AccessChoice(
            "V3 API, with ACL",
            MethodProfiles.V3,
            AclScope.V3Only,
            "The V3 API only. What it may actually reach is decided by the profiles it is in "
                + "and the Access control rules of each database, and it can call none of the "
                + "older API.");

        /// <summary>Both APIs, both held to the grants. The transition setting.</summary>
        public static readonly AccessChoice AllWithAcl = new AccessChoice(
            "all APIs, with ACL",
            MethodProfiles.Legacy + "," + MethodProfiles.V3,
            AclScope.All,
            "Both APIs, both held to the Access control rules. This is for a client moving "
                + "from the older API to V3, which needs both while it changes over.");

        /// <summary>
        /// Every choice, widest last but for the transition case, so the list does not lead
        /// with the answer that grants the most.
        /// </summary>
        public static IList<AccessChoice> All
        {
            get
            {
                return new List<AccessChoice>
                {
                    Refused,
                    LegacyUnrestricted,
                    LegacyWithAcl,
                    V3WithAcl,
                    AllWithAcl
                };
            }
        }

        /// <summary>
        /// The choice a stored profile and scope amount to, or null if they amount to none of
        /// them.
        ///
        /// Null rather than a nearest match. A configuration this list cannot express is one
        /// somebody wrote by hand, and showing it as the closest option would misreport what
        /// the gate is enforcing.
        /// </summary>
        public static AccessChoice For(string profile, string scope)
        {
            bool coversLegacy = AclScope.CoversLegacy(scope);

            foreach (AccessChoice choice in All)
            {
                if (SameProfile(choice.Profile, profile)
                    && AclScope.CoversLegacy(choice.Scope) == coversLegacy)
                {
                    return choice;
                }
            }

            // "refused" means the same whatever the scope says, because a client that may call
            // nothing is not constrained by how far the ACL reaches.
            if (SameProfile(MethodProfiles.None, profile))
                return Refused;

            return null;
        }

        /// <summary>
        /// How a stored setting reads, whether or not this list can express it.
        /// </summary>
        public static string Describe(string profile, string scope)
        {
            AccessChoice choice = For(profile, scope);
            if (choice != null)
                return choice.Label;

            return (string.IsNullOrEmpty(profile) ? MethodProfiles.None : profile.Trim())
                + (AclScope.CoversLegacy(scope) ? ", with ACL" : ", unrestricted");
        }

        /// <summary>
        /// Whether two profile specs name the same set of profiles.
        ///
        /// Order and spacing do not matter and case does not either, matching how
        /// <see cref="MethodProfiles.IsAllowed"/> reads a spec. A stored "v3,legacy" has to
        /// select the same entry in the list as the "legacy,v3" this code writes, or the tab
        /// would report a hand-edited config as something the gate is not doing.
        /// </summary>
        private static bool SameProfile(string one, string other)
        {
            List<string> a = Names(one);
            List<string> b = Names(other);
            if (a.Count != b.Count)
                return false;

            foreach (string name in a)
            {
                if (!b.Contains(name))
                    return false;
            }

            return true;
        }

        private static List<string> Names(string spec)
        {
            List<string> names = new List<string>();
            if (!string.IsNullOrEmpty(spec))
            {
                foreach (string raw in spec.Split(','))
                {
                    string name = raw.Trim().ToLowerInvariant();
                    if (name.Length > 0 && !names.Contains(name))
                        names.Add(name);
                }
            }

            // An empty spec names no profile and so allows no method, which is what "none"
            // says. Reading the two as the same thing keeps a config with the key missing and
            // a config with the key set to "none" reporting identically, because the gate
            // cannot tell them apart either.
            if (names.Count == 0)
                names.Add(MethodProfiles.None);

            return names;
        }
    }
}
