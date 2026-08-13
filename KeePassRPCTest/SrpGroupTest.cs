using System;
using System.Diagnostics;
using KeePassRPC;
using NUnit.Framework;

namespace KeePassRPCTest
{
    [TestFixture]
    public class SrpGroupTest
    {
        // --- the constants themselves ----------------------------------------------------

        [Test]
        public void TheStrongGroupIsTwoThousandAndFortyEightBits()
        {
            Assert.AreEqual(512, SrpGroup.Rfc5054_2048.NHex.Length);
            Assert.AreEqual(2048, new BigInteger(SrpGroup.Rfc5054_2048.NHex, 16).bitCount());
        }

        [Test]
        public void TheStrongGroupsHexIsSpeltTheWayEverythingElseSpellsIt()
        {
            // The protocol hashes hex strings, so the spelling is part of the wire format.
            // If N round-trips through BigInteger unchanged, both ends agree on it.
            BigInteger n = new BigInteger(SrpGroup.Rfc5054_2048.NHex, 16);
            Assert.AreEqual(SrpGroup.Rfc5054_2048.NHex, n.ToString(16));
        }

        [Test]
        public void TheMultiplierIsWhatItClaimsToBe()
        {
            // The literal exists so nothing is derived at runtime; this proves the literal
            // is SHA-256 over N and g and not a number somebody pasted in.
            Assert.AreEqual(SrpGroup.Rfc5054_2048.KHex, SrpGroup.Rfc5054_2048.DeriveKHex());
        }

        [Test]
        public void TheLegacyMultiplierIsNotDerivedAndIsNotClaimedToBe()
        {
            // Inherited from the JavaScript implementation on the other side of this
            // protocol. Asserted so that nobody "fixes" it into consistency with the other
            // group and silently breaks every existing pairing.
            Assert.AreEqual("b7867f1299da8cc24ab93e08986ebc4d6a478ad0", SrpGroup.Legacy512.KHex);
            Assert.AreNotEqual(SrpGroup.Legacy512.KHex, SrpGroup.Legacy512.DeriveKHex());
        }

        [Test]
        public void TheTwoGroupsAreDifferent()
        {
            Assert.AreNotEqual(SrpGroup.Legacy512.NHex, SrpGroup.Rfc5054_2048.NHex);
            Assert.AreEqual(2, SrpGroup.Legacy512.G);
            Assert.AreEqual(2, SrpGroup.Rfc5054_2048.G);
        }

        // --- negotiation -------------------------------------------------------------------

        [Test]
        public void AClientThatAsksForTheStrongGroupGetsIt()
        {
            Assert.AreSame(SrpGroup.Rfc5054_2048,
                SrpGroup.ForFeatures(new[] { "KPRPC_FEATURE_VERSION_1_6", SrpGroup.StrongGroupFeatureName }));
        }

        [Test]
        public void EveryOtherClientGetsTheGroupItAlwaysGot()
        {
            Assert.AreSame(SrpGroup.Legacy512, SrpGroup.ForFeatures(new string[0]));
            Assert.AreSame(SrpGroup.Legacy512,
                SrpGroup.ForFeatures(new[] { "KPRPC_FEATURE_VERSION_1_6", "KPRPC_FEATURE_DTO_V2" }));

            // Including the lower-cased spelling: feature names are compared exactly
            // everywhere else in this protocol, and a client that cannot spell the flag has
            // not implemented the group either.
            Assert.AreSame(SrpGroup.Legacy512, SrpGroup.ForFeatures(new[] { "kprpc_feature_srp_2048" }));
        }

        [Test]
        public void AClientThatSendsNoFeaturesAtAllStillPairs()
        {
            // Upstream tolerates a client that never sends a feature list. Refusing one here
            // would be a new way to break Kee rather than a safety improvement.
            Assert.AreSame(SrpGroup.Legacy512, SrpGroup.ForFeatures(null));
        }

        // --- a full exchange, which is what proves the BigInteger bound ------------------

        [TestCase("legacy")]
        [TestCase("strong")]
        public void AFullExchangeAgreesOnAKey(string which)
        {
            // The real point of this test is the 2048-bit case. Raising BigInteger.maxLength
            // was necessary for it, and a bound that is too small throws part way through a
            // modPow, so an exchange that completes and agrees is the proof that 140 words
            // is enough for every intermediate the protocol actually produces.
            SrpGroup group = which == "strong" ? SrpGroup.Rfc5054_2048 : SrpGroup.Legacy512;

            Stopwatch clock = Stopwatch.StartNew();
            SrpExchange.Result exchange = SrpExchange.Run(group, "test-subject", "abc123");
            clock.Stop();

            Assert.IsTrue(exchange.ServerAuthenticated, "server did not accept the client proof");
            Assert.AreEqual(exchange.ServerKey, exchange.ClientKey, "the two sides derived different keys");
            Assert.AreEqual(64, exchange.ServerKey.Length, "the session key should be SHA-256, hex");

            // Pairing is interactive and happens once, so this is a generous ceiling meant
            // only to catch an accidental quadratic blow-up, not to police milliseconds.
            Assert.Less(clock.ElapsedMilliseconds, 20000, "the exchange took " + clock.ElapsedMilliseconds + "ms");
            Console.WriteLine(which + " exchange: " + clock.ElapsedMilliseconds + "ms");
        }

        [Test]
        public void AWrongPasswordDoesNotAuthenticate()
        {
            SrpExchange.Result exchange = SrpExchange.Run(SrpGroup.Rfc5054_2048, "test-subject", "abc123", "wrong1");
            Assert.IsFalse(exchange.ServerAuthenticated);
        }

        // --- what a remote connection is required to bring ------------------------------

        [Test]
        public void ARemotePairingIsRequiredToUseTheStrongGroup()
        {
            // The connection-level rule lives in KeePassRPCClientConnection, which needs a
            // socket and a plugin host to construct. What is checkable here is the decision
            // it is built on, which is the part that could be got wrong: whether a given
            // feature list would put a pairing in the weak group.
            Assert.AreNotSame(SrpGroup.Rfc5054_2048,
                SrpGroup.ForFeatures(new[] { "KPRPC_FEATURE_CRYPTO_V2" }),
                "a client declaring only the session suite would pair in the 512-bit group, "
                + "which is exactly what a remote connection has to be refused for");

            Assert.AreSame(SrpGroup.Rfc5054_2048,
                SrpGroup.ForFeatures(new[] { "KPRPC_FEATURE_CRYPTO_V2", SrpGroup.StrongGroupFeatureName }));
        }

        [Test]
        public void TheTwoRemoteRequirementsAreSeparateFeatures()
        {
            // Declaring one says nothing about the other: the session suite protects the
            // channel afterwards, the group protects the pairing exchange itself. A client
            // has to ask for both, and the refusal names whichever is missing.
            Assert.AreNotEqual(SrpGroup.StrongGroupFeatureName, CryptoV2.FeatureName);
        }

        [Test]
        public void TheTwoGroupsDoNotInteroperate()
        {
            // The failure mode when a client asks for a group the server does not offer: the
            // proof does not match and pairing stops. Asserted because the alternative
            // anyone would fear, one side silently continuing in the weaker group, would
            // look identical from the outside if it ever happened.
            Assert.IsFalse(SrpExchange.RunMismatched("test-subject", "abc123").ServerAuthenticated);
        }
    }
}
