using KeePassLib.Utility;
using KeePassRPC;

namespace KeePassRPCTest
{
    /// <summary>
    /// The client half of an SRP exchange, so a test can run a complete one.
    ///
    /// The plugin only implements the server side, and a server on its own cannot be tested
    /// for the thing that matters here: that both ends arrive at the same key. This is a
    /// deliberately literal transcription of what a client has to do, taken from the
    /// protocol as the server implements it rather than from the RFC, because this SRP is
    /// not the RFC's. It hashes hex strings, its salt is decimal, and its B is not reduced
    /// modulo N.
    ///
    /// It shares this plugin's BigInteger and hash, so agreement here is not independent
    /// evidence that the protocol is right. It is evidence that the arithmetic completes and
    /// that the two groups behave as intended. The independent check lives in the Python
    /// client's test suite, which implements this same server side from scratch.
    /// </summary>
    internal static class SrpExchange
    {
        internal sealed class Result
        {
            public bool ServerAuthenticated;
            public string ServerKey;
            public string ClientKey;
        }

        public static Result Run(SrpGroup group, string username, string password)
        {
            return Run(group, username, password, password);
        }

        /// <summary>
        /// Run an exchange where the client may be using a different password from the one
        /// the server issued, which is how a failed pairing is simulated.
        /// </summary>
        public static Result Run(SrpGroup group, string username, string serverPassword, string clientPassword)
        {
            return Run(group, group, username, serverPassword, clientPassword);
        }

        /// <summary>An exchange where the client and server disagree about the group.</summary>
        public static Result RunMismatched(string username, string password)
        {
            return Run(SrpGroup.Legacy512, SrpGroup.Rfc5054_2048, username, password, password);
        }

        private static Result Run(SrpGroup serverGroup, SrpGroup clientGroup, string username,
            string serverPassword, string clientPassword)
        {
            SRP server = new SRP(serverGroup);
            server.CalculatePasswordHash(serverPassword);

            BigInteger n = new BigInteger(clientGroup.NHex, 16);
            BigInteger g = new BigInteger(clientGroup.G);
            BigInteger k = new BigInteger(clientGroup.KHex, 16);

            BigInteger a = new BigInteger(Utils.GetRandomBytes(32));
            BigInteger bigA = g.modPow(a, n);
            string aHex = bigA.ToString(16);

            server.Setup();
            server.Handshake(username, aHex);

            string bHex = server.Bstr;
            BigInteger bigB = new BigInteger(bHex, 16);

            BigInteger x = new BigInteger(Utils.Hash(server.s + clientPassword));
            BigInteger u = new BigInteger(Utils.Hash(aHex + bHex));

            // base = (B - k * g^x) mod N, forced non-negative. The server's B is not reduced
            // modulo N, and this BigInteger's % keeps the sign of its left operand, so both
            // corrections are needed; Python's % would have hidden the second one.
            BigInteger kgx = (k * g.modPow(x, n)) % n;
            BigInteger baseValue = ((bigB % n) - kgx) % n;
            if (baseValue < 0)
                baseValue = baseValue + n;

            BigInteger s = baseValue.modPow(a + (u * x), n);
            string sHex = s.ToString(16);

            string clientProof = MemUtil.ByteArrayToHexString(Utils.Hash(aHex + bHex + sHex));
            server.Authenticate(clientProof);

            Result result = new Result();
            result.ServerAuthenticated = server.Authenticated;
            result.ClientKey = MemUtil.ByteArrayToHexString(Utils.Hash(sHex)).ToLower();
            result.ServerKey = server.Authenticated ? server.Key : null;
            return result;
        }
    }
}
