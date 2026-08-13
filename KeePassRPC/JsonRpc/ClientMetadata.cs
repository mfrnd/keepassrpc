namespace KeePassRPC.JsonRpc
{
    public class ClientMetadata
    {
        public string[] Features;

        /// <summary>
        /// The authenticated client identity, as established at SRP pairing. Empty until the
        /// connection is authorised, which is what lets the method gate refuse anything it
        /// cannot attribute to a subject.
        /// </summary>
        public string Subject;

        /// <summary>
        /// The profile spec recorded for <see cref="Subject"/>, read from configuration at the
        /// start of the request. Null or empty denies everything.
        /// </summary>
        public string MethodProfile;

        /// <summary>
        /// Whether the connection carrying this request reached the plugin from beyond this
        /// machine. Carried here so that the service can record it against every decision;
        /// see <see cref="KeePassRPC.RemoteAccess"/>.
        /// </summary>
        public bool IsRemote;
    }
}
