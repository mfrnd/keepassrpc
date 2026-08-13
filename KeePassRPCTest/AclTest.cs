using System.Collections.Generic;
using System.IO;
using System.Text;
using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    [TestFixture]
    public class AclVerbTest
    {
        [TestCase("none", AclVerb.None)]
        [TestCase("list", AclVerb.List)]
        [TestCase("read", AclVerb.Read)]
        [TestCase("write", AclVerb.Write)]
        [TestCase("delete", AclVerb.Delete)]
        [TestCase("Read", AclVerb.Read)]
        [TestCase("  read  ", AclVerb.Read)]
        public void KnownSpellingsParse(string text, AclVerb expected)
        {
            AclVerb verb;
            Assert.IsTrue(AclVerbs.TryParse(text, out verb));
            Assert.AreEqual(expected, verb);
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("  ")]
        [TestCase("banana")]
        [TestCase("readwrite")]
        [TestCase("read,write")]
        [TestCase("admin")]
        [TestCase("*")]
        public void UnknownSpellingsAreRefused(string text)
        {
            AclVerb verb;
            Assert.IsFalse(AclVerbs.TryParse(text, out verb));
        }

        [TestCase("2")]
        [TestCase("4")]
        [TestCase("0")]
        public void NumericStringsAreRefused(string text)
        {
            // Enum.Parse would accept these and hand back a verb nobody wrote down.
            AclVerb verb;
            Assert.IsFalse(AclVerbs.TryParse(text, out verb));
        }

        [Test]
        public void TheLadderImpliesDownwards()
        {
            Assert.IsTrue(AclVerbs.Permits(AclVerb.Delete, AclVerb.Write));
            Assert.IsTrue(AclVerbs.Permits(AclVerb.Delete, AclVerb.Read));
            Assert.IsTrue(AclVerbs.Permits(AclVerb.Write, AclVerb.Read));
            Assert.IsTrue(AclVerbs.Permits(AclVerb.Read, AclVerb.List));
            Assert.IsTrue(AclVerbs.Permits(AclVerb.Read, AclVerb.Read));
        }

        [Test]
        public void TheLadderDoesNotImplyUpwards()
        {
            Assert.IsFalse(AclVerbs.Permits(AclVerb.List, AclVerb.Read));
            Assert.IsFalse(AclVerbs.Permits(AclVerb.Read, AclVerb.Write));
            Assert.IsFalse(AclVerbs.Permits(AclVerb.Write, AclVerb.Delete));
        }

        [Test]
        public void NonePermitsNothingIncludingItself()
        {
            Assert.IsFalse(AclVerbs.Permits(AclVerb.None, AclVerb.None));
            Assert.IsFalse(AclVerbs.Permits(AclVerb.None, AclVerb.List));
        }

        [Test]
        public void ListDoesNotImplyRead()
        {
            // Enumeration is disclosure, and is deliberately its own rung.
            Assert.IsTrue(AclVerbs.Permits(AclVerb.List, AclVerb.List));
            Assert.IsFalse(AclVerbs.Permits(AclVerb.List, AclVerb.Read));
        }
    }

    [TestFixture]
    public class AclGrantTest
    {
        [Test]
        public void NarrowingTakesTheLowerVerb()
        {
            AclGrant parent = new AclGrant(AclVerb.Read, false, false);
            AclGrant child = new AclGrant(AclVerb.Write, false, false);

            // The escalation case the design calls out by name: write inside read stays read.
            Assert.AreEqual(AclVerb.Read, parent.NarrowedBy(child).Verb);
            Assert.AreEqual(AclVerb.Read, child.NarrowedBy(parent).Verb);
        }

        [Test]
        public void NarrowingAndsTheFlags()
        {
            AclGrant withFlags = new AclGrant(AclVerb.Read, true, true);
            AclGrant without = new AclGrant(AclVerb.Read, false, false);

            Assert.IsFalse(withFlags.NarrowedBy(without).Attachments);
            Assert.IsFalse(withFlags.NarrowedBy(without).Unattended);
            Assert.IsTrue(withFlags.NarrowedBy(withFlags).Attachments);
            Assert.IsTrue(withFlags.NarrowedBy(withFlags).Unattended);
        }

        [Test]
        public void DenyPermitsNothing()
        {
            Assert.IsFalse(AclGrant.Deny.Permits(AclVerb.List));
            Assert.IsFalse(AclGrant.Deny.Permits(AclVerb.Read));
        }
    }

    [TestFixture]
    public class AclDocumentTest
    {
        private const string Valid =
            "{\"version\":1,\"grants\":{\"deploy\":{\"verb\":\"write\"}," +
            "\"agent-docs\":{\"verb\":\"read\",\"attachments\":false,\"unattended\":true}," +
            "\"*\":{\"verb\":\"none\"}}}";

        [Test]
        public void ParsesTheDocumentedExample()
        {
            AclDocument document = AclDocument.Parse(Valid);

            Assert.IsNotNull(document);
            Assert.AreEqual(AclVerb.Write, document.GrantFor("deploy").Verb);
            Assert.AreEqual(AclVerb.Read, document.GrantFor("agent-docs").Verb);
            Assert.IsTrue(document.GrantFor("agent-docs").Unattended);
            Assert.IsFalse(document.GrantFor("agent-docs").Attachments);
        }

        [Test]
        public void AnUnnamedSubjectFallsBackToTheWildcard()
        {
            Assert.AreEqual(AclVerb.None, AclDocument.Parse(Valid).GrantFor("somebody-else").Verb);
        }

        [Test]
        public void AnExplicitGrantBeatsTheWildcard()
        {
            Assert.AreEqual(AclVerb.Write, AclDocument.Parse(Valid).GrantFor("deploy").Verb);
        }

        [Test]
        public void WithoutAWildcardAnUnnamedSubjectGetsNothingToInherit()
        {
            AclDocument document = AclDocument.Parse("{\"version\":1,\"grants\":{\"deploy\":{\"verb\":\"read\"}}}");

            // Null means "this level says nothing", which the resolver treats as inherit.
            Assert.IsNull(document.GrantFor("other"));
        }

        [Test]
        public void SubjectMatchingIsCaseSensitive()
        {
            // Two identities differing only in case are two identities. Matching loosely could
            // hand one subject's rights to another; failing to match merely denies.
            AclDocument document = AclDocument.Parse("{\"version\":1,\"grants\":{\"Deploy\":{\"verb\":\"read\"}}}");
            Assert.IsNull(document.GrantFor("deploy"));
            Assert.IsNotNull(document.GrantFor("Deploy"));
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("   ")]
        [TestCase("not json")]
        [TestCase("[]")]
        [TestCase("\"a string\"")]
        [TestCase("42")]
        [TestCase("{")]
        public void GarbageIsRefused(string json)
        {
            Assert.IsNull(AclDocument.Parse(json));
        }

        [TestCase("{\"grants\":{}}")]
        [TestCase("{\"version\":2,\"grants\":{}}")]
        [TestCase("{\"version\":0,\"grants\":{}}")]
        [TestCase("{\"version\":\"1\",\"grants\":{}}")]
        public void TheWrongVersionIsRefused(string json)
        {
            // A version bump exists because the meaning changed, so reading it optimistically
            // is exactly the mistake to avoid. A quoted version is refused too.
            Assert.IsNull(AclDocument.Parse(json));
        }

        [TestCase("{\"version\":1}")]
        [TestCase("{\"version\":1,\"grants\":[]}")]
        [TestCase("{\"version\":1,\"grants\":\"deploy\"}")]
        public void AMissingOrMisshapenGrantsMemberIsRefused(string json)
        {
            Assert.IsNull(AclDocument.Parse(json));
        }

        [Test]
        public void AnUnknownTopLevelPropertyIsRefused()
        {
            // If a later version adds a restriction, ignoring what we do not understand would
            // apply the grant WITHOUT it.
            Assert.IsNull(AclDocument.Parse("{\"version\":1,\"grants\":{},\"expires\":\"2030-01-01\"}"));
        }

        [Test]
        public void AnUnknownGrantPropertyIsRefused()
        {
            Assert.IsNull(AclDocument.Parse(
                "{\"version\":1,\"grants\":{\"deploy\":{\"verb\":\"read\",\"onlyOnTuesdays\":true}}}"));
        }

        [TestCase("{\"version\":1,\"grants\":{\"deploy\":{\"verb\":\"banana\"}}}")]
        [TestCase("{\"version\":1,\"grants\":{\"deploy\":{\"verb\":2}}}")]
        [TestCase("{\"version\":1,\"grants\":{\"deploy\":{}}}")]
        [TestCase("{\"version\":1,\"grants\":{\"deploy\":\"read\"}}")]
        [TestCase("{\"version\":1,\"grants\":{\"\":{\"verb\":\"read\"}}}")]
        public void AMalformedGrantRefusesTheWholeDocument(string json)
        {
            // One bad grant invalidates the document rather than being skipped: a partially
            // applied ACL is not something to guess at.
            Assert.IsNull(AclDocument.Parse(json));
        }

        [TestCase("{\"version\":1,\"grants\":{\"deploy\":{\"verb\":\"read\",\"attachments\":\"true\"}}}")]
        [TestCase("{\"version\":1,\"grants\":{\"deploy\":{\"verb\":\"read\",\"attachments\":1}}}")]
        [TestCase("{\"version\":1,\"grants\":{\"deploy\":{\"verb\":\"read\",\"unattended\":\"yes\"}}}")]
        public void ACoercedFlagIsRefused(string json)
        {
            // Whether an agent can pull a private key out of an attachment must not depend on
            // string-to-bool coercion rules.
            Assert.IsNull(AclDocument.Parse(json));
        }

        [Test]
        public void AnAbsentFlagIsFalse()
        {
            AclGrant grant = AclDocument.Parse("{\"version\":1,\"grants\":{\"d\":{\"verb\":\"read\"}}}").GrantFor("d");
            Assert.IsFalse(grant.Attachments);
            Assert.IsFalse(grant.Unattended);
        }

        [Test]
        public void RoundTripsThroughJson()
        {
            AclDocument document = new AclDocument();
            document.Set("deploy", new AclGrant(AclVerb.Write, false, false));
            document.Set("agent", new AclGrant(AclVerb.Read, true, true));
            document.Set(AclDocument.WildcardSubject, new AclGrant(AclVerb.None, false, false));

            AclDocument reparsed = AclDocument.Parse(document.ToJson());

            Assert.IsNotNull(reparsed);
            Assert.AreEqual(3, reparsed.Count);
            Assert.AreEqual(AclVerb.Write, reparsed.GrantFor("deploy").Verb);
            Assert.IsTrue(reparsed.GrantFor("agent").Attachments);
            Assert.IsTrue(reparsed.GrantFor("agent").Unattended);
            Assert.AreEqual(AclVerb.None, reparsed.GrantFor("nobody").Verb);
        }

        [Test]
        public void SubjectsMayContainAwkwardCharacters()
        {
            // Subject names are JSON keys, which is why the design put unattended inside the
            // grant rather than encoding it into a composite key.
            AclDocument document = new AclDocument();
            document.Set("host.example:agent/one", new AclGrant(AclVerb.Read, false, false));

            AclDocument reparsed = AclDocument.Parse(document.ToJson());
            Assert.AreEqual(AclVerb.Read, reparsed.GrantFor("host.example:agent/one").Verb);
        }

        [Test]
        public void RemoveDropsASubject()
        {
            AclDocument document = new AclDocument();
            document.Set("deploy", new AclGrant(AclVerb.Read, false, false));

            Assert.IsTrue(document.Remove("deploy"));
            Assert.IsNull(document.GrantFor("deploy"));
            Assert.IsFalse(document.Remove("deploy"));
        }
    }

    [TestFixture]
    public class AclResolverTest
    {
        private const string Subject = "agent-one";

        private static string Doc(string subject, string verb)
        {
            return "{\"version\":1,\"grants\":{\"" + subject + "\":{\"verb\":\"" + verb + "\"}}}";
        }

        private static string Doc(string subject, string verb, bool attachments)
        {
            return "{\"version\":1,\"grants\":{\"" + subject + "\":{\"verb\":\"" + verb
                + "\",\"attachments\":" + (attachments ? "true" : "false") + "}}}";
        }

        private static AclGrant Resolve(params string[] chain)
        {
            return AclResolver.Resolve(new List<string>(chain), Subject);
        }

        // --- the default ----------------------------------------------------------

        [Test]
        public void NoGrantAnywhereIsDeny()
        {
            Assert.AreEqual(AclVerb.None, Resolve(null, null, null).Verb);
        }

        [Test]
        public void AnEmptyChainIsDeny()
        {
            Assert.AreEqual(AclVerb.None, AclResolver.Resolve(new List<string>(), Subject).Verb);
        }

        [Test]
        public void ANullChainIsDeny()
        {
            Assert.AreEqual(AclVerb.None, AclResolver.Resolve(null, Subject).Verb);
        }

        [TestCase(null)]
        [TestCase("")]
        public void AnUnidentifiedSubjectIsDeny(string subject)
        {
            Assert.AreEqual(AclVerb.None,
                AclResolver.Resolve(new List<string> { Doc("*", "delete") }, subject).Verb);
        }

        [Test]
        public void TheWildcardIsNotAnIdentity()
        {
            // A client must never be able to authenticate as "*" and collect the fallback rule.
            Assert.AreEqual(AclVerb.None,
                AclResolver.Resolve(new List<string> { Doc("*", "delete") }, "*").Verb);
        }

        // --- inheritance ----------------------------------------------------------

        [Test]
        public void AGrantOnTheDatabaseReachesTheEntry()
        {
            Assert.AreEqual(AclVerb.Read, Resolve(Doc(Subject, "read"), null, null).Verb);
        }

        [Test]
        public void ASilentLevelInheritsFromAbove()
        {
            Assert.AreEqual(AclVerb.Read, Resolve(Doc(Subject, "read"), null, Doc("someone-else", "delete")).Verb);
        }

        [Test]
        public void AnEntryAloneCanBeGranted()
        {
            // Granting one entry must not require granting the database it lives in.
            Assert.AreEqual(AclVerb.Write, Resolve(null, null, Doc(Subject, "write")).Verb);
        }

        [Test]
        public void AChildMayNarrow()
        {
            Assert.AreEqual(AclVerb.List, Resolve(Doc(Subject, "write"), Doc(Subject, "list"), null).Verb);
        }

        [Test]
        public void AChildMayNotWiden()
        {
            // The headline rule: write inside read is not an escalation.
            Assert.AreEqual(AclVerb.Read, Resolve(Doc(Subject, "read"), null, Doc(Subject, "delete")).Verb);
        }

        [Test]
        public void NarrowingIsTheMinimumAcrossTheWholeChain()
        {
            Assert.AreEqual(AclVerb.List,
                Resolve(Doc(Subject, "delete"), Doc(Subject, "list"), Doc(Subject, "write")).Verb);
        }

        [Test]
        public void AnExplicitNoneRevokesInsideAGrantedGroup()
        {
            // The corollary of silence-inherits: revoking one entry needs an explicit none.
            Assert.AreEqual(AclVerb.None, Resolve(Doc(Subject, "delete"), null, Doc(Subject, "none")).Verb);
        }

        [Test]
        public void AnExplicitNoneHigherUpBlocksEverythingBelow()
        {
            Assert.AreEqual(AclVerb.None, Resolve(Doc(Subject, "none"), Doc(Subject, "delete"), null).Verb);
        }

        [Test]
        public void TheWildcardDeniesSubjectsNotNamedAtTheSameLevel()
        {
            // Both rules in one document: the named subject reads, everybody else gets nothing.
            const string mixed = "{\"version\":1,\"grants\":{\"" + Subject
                + "\":{\"verb\":\"read\"},\"*\":{\"verb\":\"none\"}}}";

            Assert.AreEqual(AclVerb.Read, AclResolver.Resolve(new List<string> { mixed }, Subject).Verb);
            Assert.AreEqual(AclVerb.None, AclResolver.Resolve(new List<string> { mixed }, "stranger").Verb);
        }

        [Test]
        public void AWildcardDenyHighUpCannotBeReopenedLowerDown()
        {
            // Worth pinning because it is the obvious way to get this wrong: "*": "none" at the
            // database root is NOT a default-deny that you then grant beneath. Narrow-only means
            // the root's none wins over every grant below it, so the whole database goes dark.
            // Default deny is already what an absent document does; the root should simply carry
            // no grant for a subject you intend to grant further down.
            Assert.AreEqual(AclVerb.None,
                AclResolver.Resolve(new List<string> { Doc("*", "none"), Doc(Subject, "read") }, Subject).Verb);
        }

        // --- flags ----------------------------------------------------------------

        [Test]
        public void AttachmentsSurviveWhenEveryLevelGrantsThem()
        {
            Assert.IsTrue(Resolve(Doc(Subject, "read", true), null, Doc(Subject, "read", true)).Attachments);
        }

        [Test]
        public void AttachmentsAreLostWhenAnyLevelOmitsThem()
        {
            // Documented consequence: an omission reads as false and removes the right.
            Assert.IsFalse(Resolve(Doc(Subject, "read", true), null, Doc(Subject, "read")).Attachments);
        }

        [Test]
        public void AttachmentsCannotBeAddedByAChild()
        {
            Assert.IsFalse(Resolve(Doc(Subject, "read"), null, Doc(Subject, "read", true)).Attachments);
        }

        // --- failure handling -----------------------------------------------------

        [Test]
        public void AMalformedDocumentDeniesRatherThanInherits()
        {
            // The dangerous alternative would be to skip the broken level and keep the parent's
            // more generous grant.
            Assert.AreEqual(AclVerb.None, Resolve(Doc(Subject, "delete"), "{ this is broken", null).Verb);
        }

        [Test]
        public void AMalformedDocumentAtTheLeafDenies()
        {
            Assert.AreEqual(AclVerb.None, Resolve(Doc(Subject, "delete"), null, "not json at all").Verb);
        }

        [Test]
        public void AnEmptyValueIsMalformedNotAbsent()
        {
            // Something wrote that key. An unintelligible grant is refused, not ignored.
            Assert.AreEqual(AclVerb.None, Resolve(Doc(Subject, "delete"), "", null).Verb);
        }

        [Test]
        public void AWrongVersionAnywhereDenies()
        {
            Assert.AreEqual(AclVerb.None,
                Resolve(Doc(Subject, "delete"), "{\"version\":9,\"grants\":{}}", null).Verb);
        }
    }

    [TestFixture]
    public class KdbxFormatTest
    {
        private static Stream Header(uint signature1, uint signature2, ushort minor, ushort major)
        {
            MemoryStream stream = new MemoryStream();
            stream.Write(System.BitConverter.GetBytes(signature1), 0, 4);
            stream.Write(System.BitConverter.GetBytes(signature2), 0, 4);
            stream.Write(System.BitConverter.GetBytes(minor), 0, 2);
            stream.Write(System.BitConverter.GetBytes(major), 0, 2);
            stream.Position = 0;
            return stream;
        }

        [Test]
        public void ReadsTheMajorVersionOfAKdbx4Header()
        {
            Assert.AreEqual(4, KdbxFormat.ReadMajorVersion(Header(0x9AA2D903, 0xB54BFB67, 1, 4)));
        }

        [Test]
        public void ReadsTheMajorVersionOfAKdbx3Header()
        {
            Assert.AreEqual(3, KdbxFormat.ReadMajorVersion(Header(0x9AA2D903, 0xB54BFB67, 1, 3)));
        }

        [Test]
        public void RejectsAFileThatIsNotAKdbx()
        {
            Assert.AreEqual(KdbxFormat.Unknown, KdbxFormat.ReadMajorVersion(Header(0xDEADBEEF, 0xB54BFB67, 1, 4)));
            Assert.AreEqual(KdbxFormat.Unknown, KdbxFormat.ReadMajorVersion(Header(0x9AA2D903, 0xDEADBEEF, 1, 4)));
        }

        [Test]
        public void RejectsATruncatedFile()
        {
            Assert.AreEqual(KdbxFormat.Unknown,
                KdbxFormat.ReadMajorVersion(new MemoryStream(Encoding.ASCII.GetBytes("short"))));
        }

        [Test]
        public void RejectsAMissingFileWithoutThrowing()
        {
            Assert.AreEqual(KdbxFormat.Unknown, KdbxFormat.ReadMajorVersion(@"Z:\no\such\file.kdbx"));
            Assert.IsFalse(KdbxFormat.SupportsCustomData(@"Z:\no\such\file.kdbx"));
        }

        [TestCase(null)]
        [TestCase("")]
        public void RejectsAnEmptyPath(string path)
        {
            Assert.AreEqual(KdbxFormat.Unknown, KdbxFormat.ReadMajorVersion(path));
        }
    }
}
