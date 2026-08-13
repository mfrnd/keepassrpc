namespace KeePassRPC.JsonRpc
{
    public class ClientMetadata
    {
        public string[] Features;

        /// <summary>
        /// Whether the connection carrying this request reached the plugin from beyond this
        /// machine. Carried here so that the service can record it against every decision;
        /// see <see cref="KeePassRPC.RemoteAccess"/>.
        /// </summary>
        public bool IsRemote;
    }
}
