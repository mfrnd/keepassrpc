namespace KeePassRPC.Models.DataExchange
{
    /// <summary>
    /// The ephemeral key agreement, carried on the message that completes authentication.
    ///
    /// It rides along rather than taking a round of its own because the server refuses any
    /// setup message once the connection is authorised, and doing the exchange before
    /// authentication would leave nothing to authenticate it with. So the client's final proof
    /// carries <see cref="cpub"/> and the server's reply carries <see cref="spub"/>.
    ///
    /// Legacy clients never send this and never see it: the JSON exporter omits null members,
    /// so a connection that does not negotiate the newer suite produces byte-identical
    /// messages to before.
    /// </summary>
    public class CryptoParams
    {
        /// <summary>The client's ephemeral P-256 public key, raw X||Y, base64.</summary>
        public string cpub;

        /// <summary>The server's ephemeral P-256 public key, raw X||Y, base64.</summary>
        public string spub;

        /// <summary>
        /// The server's proof that it derived the same session key, base64. Lets the client
        /// fail immediately and clearly rather than at the first unreadable message.
        /// </summary>
        public string proof;
    }
}
