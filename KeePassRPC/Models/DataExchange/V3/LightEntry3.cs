namespace KeePassRPC.Models.DataExchange.V3
{
    /// <summary>
    /// What the <c>list</c> verb discloses: an entry exists, it is called this, and it is
    /// addressed by this UUID.
    ///
    /// Deliberately nothing else. Enumeration is its own rung on the ladder because a list of
    /// titles is a map of where the interesting things are, which is exactly the step you do
    /// not want to hand out along with a password read.
    /// </summary>
    public class LightEntry3
    {
        /// <summary>The primary address. Survives a rename or a move, unlike a title.</summary>
        public string Uuid;

        /// <summary>The entry's title.</summary>
        public string Title;

        /// <summary>
        /// The file path of the database holding this entry. Included because a UUID lookup
        /// spans every open database, so a client needs to know which one answered.
        /// </summary>
        public string Db;

        public LightEntry3()
        {
        }

        public LightEntry3(string uuid, string title, string db)
        {
            Uuid = uuid;
            Title = title;
            Db = db;
        }
    }
}
