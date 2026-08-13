namespace KeePassRPC.JsonRpc
{
    public class ClientMetadata
    {
        public string[] Features;

        /// <summary>
        /// The authenticated client identity, as established at SRP pairing. Empty until the
        /// connection is authorised, which is what lets the V3 service refuse anything it
        /// cannot attribute to a subject.
        /// </summary>
        public string Subject;

        /// <summary>
        /// Whether the connection carrying this request reached the plugin from beyond this
        /// machine. Carried here so that the service can record it against every decision;
        /// see <see cref="KeePassRPC.RemoteAccess"/>.
        /// </summary>
        public bool IsRemote;
    }
}
