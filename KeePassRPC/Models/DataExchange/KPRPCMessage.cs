namespace KeePassRPC.Models.DataExchange
{
    public class KPRPCMessage
    {
        public string protocol;
        public JSONRPCContainer jsonrpc;
        public SRPParams srp;
        public KeyParams key;

        /// <summary>
        /// The ephemeral key agreement for the newer session crypto, when negotiated. Null
        /// for every legacy client, and the exporter omits null members, so their traffic is
        /// unchanged.
        /// </summary>
        public CryptoParams crypto;
        public int version;
        public string clientDisplayName;
        public string clientDisplayDescription;
        public string clientTypeId;
        public Error error;
        public string[] features;
    }
}