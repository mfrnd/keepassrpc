using KeePassRPC;
using NUnit.Framework;

namespace KeePassRPCTest
{
    [TestFixture]
    public class RemoteAccessTest
    {
        // --- the ordinary local case, which must not regress -----------------------------

        [TestCase("/")]
        [TestCase("")]
        [TestCase("/kprpc")]
        [TestCase("/remotely")]
        [TestCase("/not-remote")]
        public void ALocalClientOnAnUnmarkedPathIsLocal(string path)
        {
            // Kee connects to "/" from 127.0.0.1 and must stay on the path it has always used.
            // "/remotely" and "/not-remote" are here because matching whole segments rather
            // than substrings is the difference between a marker and a guess.
            Assert.IsFalse(RemoteAccess.IsRemote("127.0.0.1", path));
        }

        // --- the marker ------------------------------------------------------------------

        [TestCase("/remote")]
        [TestCase("/remote/")]
        [TestCase("/remote/jsonrpc")]
        [TestCase("/proxy/remote")]
        [TestCase("/REMOTE")]
        [TestCase("/Remote")]
        [TestCase("/remote?client=one")]
        [TestCase("/remote#fragment")]
        public void TheMarkerIsRecognised(string path)
        {
            Assert.IsTrue(RemoteAccess.IsRemote("127.0.0.1", path));
        }

        [Test]
        public void AnEscapedMarkerIsStillTheMarker()
        {
            // Otherwise the check is defeated by spelling: %72 is 'r'. Only relevant if a
            // proxy forwards a client-chosen path, which is a misconfiguration, but the
            // whole point of erring towards "remote" is that misconfigurations land safely.
            Assert.IsTrue(RemoteAccess.IsRemote("127.0.0.1", "/%72emote"));
        }

        // --- the peer address, which is definitive when it says anything at all -----------

        [TestCase("127.0.0.1")]
        [TestCase("127.5.6.7")]
        [TestCase("::1")]
        [TestCase("::ffff:127.0.0.1")]
        [TestCase(" 127.0.0.1 ")]
        public void LoopbackPeersAreLocal(string address)
        {
            Assert.IsTrue(RemoteAccess.IsLoopbackAddress(address));
            Assert.IsFalse(RemoteAccess.IsRemote(address, "/"));
        }

        [TestCase("10.0.0.4")]
        [TestCase("192.168.1.20")]
        [TestCase("100.64.0.1")]
        [TestCase("2001:db8::1")]
        [TestCase("::ffff:10.0.0.4")]
        public void NonLoopbackPeersAreRemoteWhateverThePathSays(string address)
        {
            // Reachable only with bindOnlyToLoopback off, which is not a supported
            // deployment. If it ever happens the plugin should still know where it is.
            Assert.IsFalse(RemoteAccess.IsLoopbackAddress(address));
            Assert.IsTrue(RemoteAccess.IsRemote(address, "/"));
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("not-an-address")]
        [TestCase("999.999.999.999")]
        public void AnUnreadablePeerAddressCountsAsRemote(string address)
        {
            // Fail closed: "we cannot tell where this came from" is not a reason to relax.
            Assert.IsFalse(RemoteAccess.IsLoopbackAddress(address));
            Assert.IsTrue(RemoteAccess.IsRemote(address, "/"));
        }

        // --- degenerate input --------------------------------------------------------------

        [Test]
        public void ANullPathFromALoopbackPeerIsLocal()
        {
            Assert.IsFalse(RemoteAccess.IsRemote("127.0.0.1", null));
        }
    }
}
