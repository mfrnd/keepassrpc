namespace KeePassRPC.Models.DataExchange.V3
{
    /// <summary>
    /// A whole entry as an automation client actually wants it: the standard fields, the real
    /// custom strings, the notes, and the names of the attachments.
    ///
    /// Compare <c>Entry</c> and <c>Entry2</c>, which carry matchers, placeholder handling, URL
    /// match accuracy, icons and automation behaviour, because they exist to fill in a login
    /// form in a browser. None of that is useful to a script, and all of it costs something to
    /// build on every read.
    /// </summary>
    public class Entry3 : LightEntry3
    {
        /// <summary>The full group path, slash separated, from the database root.</summary>
        public string Group;

        /// <summary>The standard username string.</summary>
        public string UserName;

        /// <summary>The standard password string.</summary>
        public string Password;

        /// <summary>
        /// The standard URL string. Not in the design's original list, and added because its
        /// absence would be strange in a full-entry API: it is a standard KeePass field that a
        /// human sees on the entry, and omitting it would make V3 lossy for no benefit.
        /// </summary>
        public string Url;

        /// <summary>The standard notes string, which no earlier generation exposed at all.</summary>
        public string Notes;

        /// <summary>
        /// Every other string on the entry, read straight from <c>pwe.Strings</c>. Empty values
        /// are included; only <c>KPRPC JSON</c> is withheld.
        /// </summary>
        public Field3[] Fields;

        /// <summary>Attachment names and sizes. Never content.</summary>
        public Attachment3[] Attachments;

        public Entry3()
        {
        }
    }
}
