using System;

namespace KeePassRPC.Acl
{
    /// <summary>
    /// The verb ladder. Each verb implies the ones below it, and the numeric order IS the
    /// ladder: narrowing along an inheritance chain is a numeric minimum, so do not reorder
    /// or renumber these.
    /// </summary>
    public enum AclVerb
    {
        /// <summary>Nothing at all, and blocks inheritance from above.</summary>
        None = 0,

        /// <summary>
        /// Title and UUID only. Deliberately separate from <see cref="Read"/>, because
        /// enumeration is itself disclosure: a list of titles tells an agent what exists and
        /// where the interesting things are.
        /// </summary>
        List = 1,

        /// <summary>Standard fields, custom strings, notes, and attachment NAMES.</summary>
        Read = 2,

        /// <summary>Create and update. Implies <see cref="Read"/>.</summary>
        Write = 3,

        /// <summary>Remove entries. Implies <see cref="Write"/>.</summary>
        Delete = 4
    }

    /// <summary>
    /// Parsing and formatting for <see cref="AclVerb"/>, strict in both directions.
    /// </summary>
    public static class AclVerbs
    {
        /// <summary>
        /// Parse a verb from its JSON spelling.
        ///
        /// Deliberately does not use <c>Enum.Parse</c>, which accepts numeric strings and
        /// comma-separated combinations. A grant reading <c>"verb": "3"</c> or
        /// <c>"verb": "Read,Write"</c> is not something to interpret generously; it is
        /// something to refuse.
        /// </summary>
        /// <returns>True only for one of the five exact names.</returns>
        public static bool TryParse(string text, out AclVerb verb)
        {
            verb = AclVerb.None;

            if (string.IsNullOrEmpty(text))
                return false;

            string candidate = text.Trim();

            // Case-insensitive because a grant is written by a human, and "Read" plainly
            // means read. The set of accepted spellings is still closed.
            if (string.Equals(candidate, "none", StringComparison.OrdinalIgnoreCase))
            {
                verb = AclVerb.None;
                return true;
            }
            if (string.Equals(candidate, "list", StringComparison.OrdinalIgnoreCase))
            {
                verb = AclVerb.List;
                return true;
            }
            if (string.Equals(candidate, "read", StringComparison.OrdinalIgnoreCase))
            {
                verb = AclVerb.Read;
                return true;
            }
            if (string.Equals(candidate, "write", StringComparison.OrdinalIgnoreCase))
            {
                verb = AclVerb.Write;
                return true;
            }
            if (string.Equals(candidate, "delete", StringComparison.OrdinalIgnoreCase))
            {
                verb = AclVerb.Delete;
                return true;
            }

            return false;
        }

        /// <summary>The JSON spelling of a verb, always lowercase.</summary>
        public static string ToJsonValue(AclVerb verb)
        {
            switch (verb)
            {
                case AclVerb.None: return "none";
                case AclVerb.List: return "list";
                case AclVerb.Read: return "read";
                case AclVerb.Write: return "write";
                case AclVerb.Delete: return "delete";
                default:
                    // Unreachable unless someone adds a verb without extending this switch,
                    // which must not silently serialise as something else.
                    throw new ArgumentOutOfRangeException("verb");
            }
        }

        /// <summary>
        /// Whether <paramref name="held"/> is at least <paramref name="required"/> on the
        /// ladder. This is the only place the ladder's "implies" property is expressed.
        /// </summary>
        public static bool Permits(AclVerb held, AclVerb required)
        {
            if (held == AclVerb.None)
                return false;

            return held >= required;
        }
    }
}
