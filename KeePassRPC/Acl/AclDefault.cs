namespace KeePassRPC.Acl
{
    /// <summary>
    /// What a database grants before any rule is read: the top of the inheritance chain.
    ///
    /// Kept on the root group's document, because that is where the chain starts, and edited
    /// on the database settings dialog, because it is a decision about the whole file rather
    /// than about one group. Storing it there rather than on the database itself also keeps
    /// every piece of ACL state inside group and entry custom data, which is a KDBX 4.0
    /// feature; a custom data item on the database would raise the file to 4.1.
    /// </summary>
    public enum AclDefault
    {
        /// <summary>
        /// Nothing is granted until something grants it. The default, and the safe reading of
        /// a database that has never been configured.
        ///
        /// This is a WEAK deny, and the distinction matters: it is the starting value of the
        /// chain, so the first group that grants something lifts it for everything inside that
        /// group. It is not the same as writing <c>"*": "none"</c> on the root group, which is
        /// a floor rather than a starting point and cannot be raised anywhere below.
        /// </summary>
        Deny = 0,

        /// <summary>
        /// Every subject starts holding everything, and groups and entries can only take away.
        ///
        /// The inversion is total: with this set, a group that says nothing about a subject
        /// leaves that subject holding delete, attachment content and no confirmation prompt,
        /// for every entry in it. Every rule in the database then reads as a restriction, so
        /// none of them mean what they meant before the switch. The dialog says so and asks
        /// before making the change.
        /// </summary>
        Allow = 1
    }
}
