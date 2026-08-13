namespace KeePassRPC.Models.DataExchange.V3
{
    /// <summary>
    /// An attachment's existence, never its content.
    ///
    /// Listing a name is a different disclosure from handing over the bytes, and the ACL
    /// treats them separately: content needs the <c>attachments</c> flag and comes back only
    /// from <c>GetAttachment3</c>. Names travel with the entry so a client can decide what to
    /// ask for without being given everything first.
    /// </summary>
    public class Attachment3
    {
        /// <summary>The attachment's name, as KeePass stores it.</summary>
        public string Name;

        /// <summary>Size in bytes, so a client can refuse something enormous before asking.</summary>
        public int Size;

        public Attachment3()
        {
        }

        public Attachment3(string name, int size)
        {
            Name = name;
            Size = size;
        }
    }
}
