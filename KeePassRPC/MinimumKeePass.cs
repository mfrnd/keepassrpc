using KeePassLib;

namespace KeePassRPC
{
    /// <summary>
    /// The oldest KeePass this build will run on, and why that number.
    ///
    /// **2.48**, which is the version that introduced KDBX 4.1. It is also what the packaged
    /// plugin already asks for: <c>KeePassRPC.csproj</c> passes
    /// <c>--plgx-prereq-kp:2.48</c> when it builds the <c>.plgx</c>, so KeePass refuses to
    /// load that form of the plugin on anything older. A plugin installed as a plain DLL gets
    /// no such check from KeePass, which is what this class is for: the two ways of installing
    /// should not disagree about what they need.
    ///
    /// What the ACL itself needs is older than that. Grants live in group and entry
    /// <c>CustomData</c>, which arrived with KDBX 4 in KeePass 2.35, and KeePass's own
    /// <c>GetMinKdbxVersion</c> confirms that a database carrying only group and entry grants
    /// is a 4.0 file (<c>KdbxVersionTest</c> pins this). The floor is 2.48 because the plugin
    /// as a whole is built against it, not because a grant needs it.
    ///
    /// Version numbers are KeePass's own 64-bit form: major in the top 16 bits, then minor,
    /// build and revision, so 2.48 is 0x0002003000000000 and 2.61.1 is 0x0002003D00010000.
    /// </summary>
    public static class MinimumKeePass
    {
        /// <summary>2.48, in <see cref="PwDefs.FileVersion64"/> form.</summary>
        public const ulong Required = 0x0002003000000000UL;

        /// <summary>Human-readable, for the log and for a refusal message.</summary>
        public const string RequiredText = "2.48";

        /// <summary>Whether <paramref name="running"/> is new enough.</summary>
        public static bool Satisfied(ulong running)
        {
            return running >= Required;
        }

        /// <summary>Whether the KeePass this plugin is loaded into is new enough.</summary>
        public static bool SatisfiedHere
        {
            get { return Satisfied(PwDefs.FileVersion64); }
        }
    }
}
