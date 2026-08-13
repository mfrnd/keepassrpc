namespace KeePassRPC.Models.DataExchange.V3
{
    /// <summary>
    /// One real custom string from <c>pwe.Strings</c>.
    ///
    /// Not a v1 or v2 form field: there is no matcher, no placeholder handling and no value
    /// path, because a V3 field is simply a named string on the entry as the KeePass UI shows
    /// it. That is the whole point of the generation.
    /// </summary>
    public class Field3
    {
        /// <summary>The string's name, exactly as stored.</summary>
        public string Name;

        /// <summary>
        /// The value, which may legitimately be an empty string. V3 never drops an empty
        /// value: "present and empty" is a deliberate state and has to survive the wire.
        /// </summary>
        public string Value;

        /// <summary>Whether KeePass has this string marked for in-memory protection.</summary>
        public bool Protected;

        public Field3()
        {
        }

        public Field3(string name, string value, bool isProtected)
        {
            Name = name;
            Value = value;
            Protected = isProtected;
        }
    }
}
