using KeePassLib.Utility;

namespace KeePassRPC
{
    /// <summary>
    /// The discrete log group an SRP exchange runs in.
    ///
    /// Upstream has exactly one, hardcoded, of 512 bits. That was defensible while pairing
    /// could only happen over loopback, where nobody can watch the exchange. It stops being
    /// defensible the moment pairing can happen across a network, because a 512-bit discrete
    /// log is within reach of a determined attacker and solving one recovers the paired key
    /// which authenticates everything afterwards, including the newer suite's key
    /// agreement. It is the last of the inherited weaknesses whose only mitigation lives in a
    /// layer above it.
    ///
    /// So the group is negotiated. A client that declares
    /// <see cref="StrongGroupFeatureName"/> gets <see cref="Rfc5054_2048"/>; every other
    /// client gets <see cref="Legacy512"/> and sees no change whatsoever. That matters
    /// because the Kee browser extension cannot be updated in step with this plugin and is
    /// the one legacy client that has to keep working.
    ///
    /// **N and g are never sent.** Both sides hold them as constants and the feature flag is
    /// the whole of the negotiation. The consequence worth knowing: a client that asks for
    /// the strong group against a server that does not offer it computes its public value in
    /// a different group, and the proof fails. Pairing then stops with an authentication
    /// error. That is the right failure: loud, and with neither side quietly settling for
    /// the weaker group.
    /// </summary>
    public sealed class SrpGroup
    {
        /// <summary>
        /// Declared by a client that wants the 2048-bit group. Named like every other
        /// negotiated capability in this plugin.
        /// </summary>
        public const string StrongGroupFeatureName = "KPRPC_FEATURE_SRP_2048";

        /// <summary>The modulus, hex, spelled as <c>BigInteger.ToString(16)</c> renders it.</summary>
        public readonly string NHex;

        /// <summary>The generator.</summary>
        public readonly int G;

        /// <summary>The SRP-6a multiplier, hex.</summary>
        public readonly string KHex;

        private SrpGroup(string nHex, int g, string kHex)
        {
            NHex = nHex;
            G = g;
            KHex = kHex;
        }

        /// <summary>
        /// Upstream's group, unchanged and still the default. Every value here is copied
        /// verbatim from the original <c>SRP</c> constructor, spelling included, because the
        /// Kee extension is on the other side of it.
        ///
        /// Its <c>k</c> is a 160-bit constant inherited from the JavaScript implementation
        /// this protocol was written against. It is not SHA-256 of anything, and is not
        /// recomputed here; it is what the other side uses.
        /// </summary>
        public static readonly SrpGroup Legacy512 = new SrpGroup(
            "d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea"
            + "2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43",
            2,
            "b7867f1299da8cc24ab93e08986ebc4d6a478ad0");

        /// <summary>
        /// The 2048-bit group from RFC 5054 Appendix A, with g = 2.
        ///
        /// A published group rather than a freshly generated one, deliberately: it has been
        /// examined by more people than this fork ever will be, and using it means a reviewer
        /// can check the constant against the RFC instead of trusting that whoever generated
        /// it did so honestly. Verified before it was embedded here: 2048 bits, N prime,
        /// (N-1)/2 prime, and 2 a generator of the prime-order subgroup.
        ///
        /// <c>k</c> is SHA-256 over the hex spelling of N followed by the hex spelling of g,
        /// which is this codebase's idiom, because everything in this SRP implementation hashes hex
        /// strings rather than bytes, so the RFC's byte-oriented <c>k = H(N | PAD(g))</c>
        /// would be the odd one out here and would have to be special-cased on both sides.
        /// The value is a literal so that nothing has to be derived at runtime, and
        /// <c>SrpGroupTest</c> recomputes it to prove the literal is what it claims to be.
        /// </summary>
        public static readonly SrpGroup Rfc5054_2048 = new SrpGroup(
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
            + "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
            + "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
            + "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
            + "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
            + "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
            + "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
            + "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
            2,
            "2ab2340a74f7464acf31c2a60a5cd67d5cd640bba595902523bbd05aa24934c5");

        /// <summary>
        /// Recompute <see cref="KHex"/> from N and g, for the test that keeps the literal
        /// honest. Not used at runtime: a constant that has to be derived on every pairing
        /// buys nothing.
        /// </summary>
        public string DeriveKHex()
        {
            return MemUtil.ByteArrayToHexString(Utils.Hash(NHex + G.ToString())).ToLower();
        }

        /// <summary>Pick the group this client's declared features ask for.</summary>
        public static SrpGroup ForFeatures(string[] clientFeatures)
        {
            if (clientFeatures != null)
            {
                for (int i = 0; i < clientFeatures.Length; i++)
                {
                    if (clientFeatures[i] == StrongGroupFeatureName)
                        return Rfc5054_2048;
                }
            }

            // Default deny does not apply here, and it is worth saying why, because every
            // other decision in this fork defaults to the safe answer. There is no safe
            // answer available: refusing an old client is not "safe", it is an outage for
            // the Kee extension, and there is no third option because the group has to be
            // agreed before either side can compute anything.
            return Legacy512;
        }
    }
}
