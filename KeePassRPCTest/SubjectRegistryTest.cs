using System.Collections.Generic;
using KeePassRPC;
using NUnit.Framework;

namespace KeePassRPCTest
{
    [TestFixture]
    public class SubjectRegistryTest
    {
        [Test]
        public void RoundTripsASubject()
        {
            List<string> parsed = SubjectRegistry.ParseIndex(
                SubjectRegistry.FormatIndex(new[] { "agent-one" }));

            CollectionAssert.AreEqual(new[] { "agent-one" }, parsed);
        }

        [Test]
        public void RoundTripsSubjectsWithAwkwardCharacters()
        {
            // A subject is whatever identity was chosen at pairing, so the index cannot be a
            // comma or space separated list. This is why it is JSON.
            string[] awkward =
            {
                "host.example:agent/one",
                "agent with spaces",
                "comma,separated,looking",
                "quote\"inside",
                "backslash\\inside",
                "unicode-éè"
            };

            CollectionAssert.AreEqual(awkward,
                SubjectRegistry.ParseIndex(SubjectRegistry.FormatIndex(awkward)));
        }

        [Test]
        public void AnEmptyIndexParsesToNothing()
        {
            CollectionAssert.IsEmpty(SubjectRegistry.ParseIndex(null));
            CollectionAssert.IsEmpty(SubjectRegistry.ParseIndex(""));
            CollectionAssert.IsEmpty(SubjectRegistry.ParseIndex(SubjectRegistry.FormatIndex(new string[0])));
        }

        [TestCase("not json")]
        [TestCase("{\"not\":\"an array\"}")]
        [TestCase("[")]
        [TestCase("42")]
        public void ACorruptIndexParsesToNothingRatherThanThrowing(string stored)
        {
            // The index is a convenience that rebuilds itself as subjects reconnect, so there
            // is nothing to gain from guessing at a damaged one, and a dialog must not fail to
            // open because of it.
            CollectionAssert.IsEmpty(SubjectRegistry.ParseIndex(stored));
        }

        [Test]
        public void NonStringMembersAreSkipped()
        {
            CollectionAssert.AreEqual(new[] { "keeper" },
                SubjectRegistry.ParseIndex("[\"keeper\", 42, null, {\"a\":1}]"));
        }

        [Test]
        public void EmptyMembersAreSkipped()
        {
            CollectionAssert.AreEqual(new[] { "keeper" }, SubjectRegistry.ParseIndex("[\"\", \"keeper\"]"));
        }

        [Test]
        public void ThePrefixesMatchWhatIsActuallyStored()
        {
            // Pinned because the reflected lookup slices names on this exact prefix, and the
            // method gate reads the other one. A change to either in KeePassRPCClient without
            // a change here would silently stop finding subjects.
            Assert.AreEqual("KeePassRPC.Key.", SubjectRegistry.KeyPrefix);
            Assert.AreEqual("KeePassRPC.Profile.", SubjectRegistry.ProfilePrefix);
        }

        [Test]
        public void KnownIsEmptyRatherThanNullWithoutAHost()
        {
            // Every caller is a dialog being helpful. None of them should have to null check.
            CollectionAssert.IsEmpty(SubjectRegistry.Known(null));
        }

        [Test]
        public void RememberingWithoutAHostIsHarmless()
        {
            Assert.DoesNotThrow(delegate { SubjectRegistry.Remember(null, "agent"); });
        }
    }
}
