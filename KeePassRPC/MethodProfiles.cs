using System;

namespace KeePassRPC
{
    /// <summary>
    /// Named sets of JSON-RPC methods that a paired subject may call.
    ///
    /// The sets live here in code, never in configuration. Configuration records only WHICH
    /// profiles a subject holds; it cannot describe a profile's contents. That is what makes
    /// this an allowlist in the useful sense: a method arriving in a future upstream merge
    /// falls outside every profile and is refused until someone adds it here deliberately.
    ///
    /// Everything about this class fails closed. An empty spec, an unrecognised profile name,
    /// an unknown method: all deny. There is no spelling of a profile that means "everything".
    /// </summary>
    public static class MethodProfiles
    {
        /// <summary>Holds nothing. The default for any subject without an explicit profile.</summary>
        public const string None = "none";

        /// <summary>
        /// Everything the v1 and v2 APIs expose today. This is what preserves existing
        /// behaviour for a browser extension or for the client that resolves secrets over v1,
        /// and it is deliberately wide: it is the profile you grant to say "as before".
        /// </summary>
        public const string Legacy = "legacy";

        /// <summary>
        /// The narrow profile intended for automation and agents. It holds only
        /// <c>GetApplicationMetadata</c> until the V3 API exists, at which point the V3
        /// methods are added here and nowhere else.
        /// </summary>
        public const string V3 = "v3";

        /// <summary>
        /// The complete v1 and v2 surface, verified against every method carrying
        /// <c>[JsonRpcMethod]</c> in <c>KeePassRPCService</c> at fork point v2.0.2.
        /// <c>MethodProfilesTest</c> fails if the service and this list ever disagree.
        /// </summary>
        private static readonly string[] LegacyMethods = new string[]
        {
            "AddEntry",
            "AddGroup",
            "AddLogin",
            "AllDatabases",
            "AllDatabasesAndIcons",
            "AllIcons",
            "ChangeDatabase",
            "ChangeLocation",
            "FindEntries",
            "FindGroups",
            "FindLogins",
            "GeneratePassword",
            "GetAllChildEntries",
            "GetAllDatabases",
            "GetAllEntries",
            "GetAllLogins",
            "GetApplicationMetadata",
            "GetChildEntries",
            "GetChildGroups",
            "GetCurrentKFConfig",
            "GetDatabaseFileName",
            "GetDatabaseName",
            "GetEntries",
            "GetParent",
            "GetPasswordProfiles",
            "GetRoot",
            "LaunchGroupEditor",
            "LaunchLoginEditor",
            "OpenAndFocusDatabase",
            "RemoveEntry",
            "RemoveGroup",
            "UpdateEntry",
            "UpdateLogin"
        };

        /// <summary>
        /// The V3 API, plus <c>GetApplicationMetadata</c>: a client has to be able to ask what
        /// it is talking to before it can decide anything, and the reply carries version
        /// strings rather than database content.
        ///
        /// Note what is absent. Holding <c>v3</c> grants no v1 or v2 method at all, so an agent
        /// on this profile cannot reach <c>GetAllLogins</c> and read the whole database around
        /// the ACL. That is the entire point of the profile, and the reason the method gate had
        /// to exist before this API did.
        ///
        /// Being listed here only means the method may be CALLED. Which entries it may touch is
        /// then decided per entry by the ACL, which these methods enforce themselves.
        /// </summary>
        private static readonly string[] V3Methods = new string[]
        {
            "AddEntry3",
            "GetApplicationMetadata",
            "GetAttachment3",
            "GetEntry3",
            "ListGroup3",
            "RemoveAttachment3",
            "RemoveEntry3",
            "SetAttachment3",
            "UpdateEntry3"
        };

        private static readonly string[] EmptyMethods = new string[0];

        /// <summary>
        /// Every profile name that may appear in a spec. Anything else is a typo, and a typo
        /// denies rather than falling back to something.
        /// </summary>
        public static string[] KnownProfileNames
        {
            get { return new string[] { None, Legacy, V3 }; }
        }

        /// <summary>
        /// Whether a subject holding <paramref name="profileSpec"/> may call
        /// <paramref name="methodName"/>.
        /// </summary>
        /// <param name="profileSpec">
        /// One or more profile names separated by commas, as recorded in configuration under
        /// <c>KeePassRPC.Profile.&lt;subject&gt;</c>. Several names union their methods, which
        /// is how a subject holds both <c>legacy</c> and <c>v3</c> during a transition.
        /// </param>
        /// <param name="methodName">
        /// The method's canonical name as declared by the service. Callers MUST resolve the
        /// name the dispatcher will actually invoke rather than passing the name as sent; see
        /// the note in <c>KprpcJsonRpcDispatcher</c> about case-insensitive lookup.
        /// </param>
        /// <returns>True only if some named profile contains the method.</returns>
        public static bool IsAllowed(string profileSpec, string methodName)
        {
            if (string.IsNullOrEmpty(methodName) || methodName.Trim().Length == 0)
                return false;

            if (string.IsNullOrEmpty(profileSpec))
                return false;

            string[] requested = profileSpec.Split(',');

            // Validate every name before honouring any of them, so that "legacy,v33" denies
            // outright instead of quietly granting whatever "legacy" happens to cover. A
            // misspelled profile is far more likely to be a mistake than an intention.
            foreach (string raw in requested)
            {
                string name = raw.Trim();
                if (name.Length == 0)
                    continue;
                if (MethodsIn(name) == null)
                    return false;
            }

            foreach (string raw in requested)
            {
                string name = raw.Trim();
                if (name.Length == 0)
                    continue;
                if (Contains(MethodsIn(name), methodName))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// The methods a single profile grants, or null if the name is not a known profile.
        /// </summary>
        /// <param name="profileName">One profile name, untrimmed input is not accepted.</param>
        public static string[] MethodsIn(string profileName)
        {
            if (string.IsNullOrEmpty(profileName))
                return null;

            // Profile names are matched without regard to case so that a hand-edited config
            // saying "Legacy" behaves as its author plainly intended. Method names are a
            // different matter and are compared separately, below.
            if (string.Equals(profileName, None, StringComparison.OrdinalIgnoreCase))
                return EmptyMethods;
            if (string.Equals(profileName, Legacy, StringComparison.OrdinalIgnoreCase))
                return LegacyMethods;
            if (string.Equals(profileName, V3, StringComparison.OrdinalIgnoreCase))
                return V3Methods;

            return null;
        }

        private static bool Contains(string[] methods, string methodName)
        {
            if (methods == null)
                return false;

            foreach (string candidate in methods)
            {
                // Ordinal and case-insensitive, matching how the dispatcher resolves a method
                // name. A case-sensitive comparison here would be a hole rather than a
                // tightening, because Jayrock would still route "getdatabasename" to
                // GetDatabaseName after this check had failed to recognise it.
                if (string.Equals(candidate, methodName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}
