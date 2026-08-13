using System.Collections.Generic;
using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// Where the chain starts: deny by default, or allow by default.
    ///
    /// The setting decides what rights narrow FROM. Everything else about resolution is
    /// unchanged, and that is the property most worth pinning: with allow by default a group
    /// still cannot hand out more than it was given, it can only take away. A database whose
    /// default was flipped and whose groups quietly became able to widen would be an access
    /// control model with two different sets of rules, which nobody could reason about.
    ///
    /// The other half is the difference between the weak deny and a written one. Deny by
    /// default is a starting point, so the first group that grants something lifts it.
    /// <c>"*": "none"</c> is a floor, and nothing below can raise it. Both read as "denied" on
    /// an empty database and they are not the same rule.
    /// </summary>
    [TestFixture]
    public class AclDefaultTest
    {
        private static string Root(AclDefault mode, params object[] subjectsAndGrants)
        {
            AclDocument document = new AclDocument();
            document.Default = mode;
            for (int i = 0; i < subjectsAndGrants.Length; i += 2)
                document.Set((string)subjectsAndGrants[i], (AclGrant)subjectsAndGrants[i + 1]);
            return document.ToJson();
        }

        private static string Level(params object[] subjectsAndGrants)
        {
            AclDocument document = new AclDocument();
            for (int i = 0; i < subjectsAndGrants.Length; i += 2)
                document.Set((string)subjectsAndGrants[i], (AclGrant)subjectsAndGrants[i + 1]);
            return document.ToJson();
        }

        private static AclGrant Grant(AclVerb verb)
        {
            return new AclGrant(verb, false, false);
        }

        private static AclGrant Resolve(string subject, params string[] chain)
        {
            return AclResolver.Resolve(new List<string>(chain), subject);
        }

        // --- deny by default, which is where a database starts ------------------------------

        [Test]
        public void NothingIsGrantedWhenNothingSaysSo()
        {
            Assert.AreEqual(AclVerb.None,
                Resolve("docs-agent", Root(AclDefault.Deny)).Verb);
        }

        [Test]
        public void TheWeakDenyIsLiftedByTheFirstGroupThatGrants()
        {
            // The distinction the setting exists to make: this is a starting point, not a
            // floor, so a group below can open what the database has not granted.
            Assert.AreEqual(AclVerb.Read,
                Resolve("docs-agent",
                    Root(AclDefault.Deny),
                    Level("docs-agent", Grant(AclVerb.Read))).Verb);
        }

        [Test]
        public void AWrittenDenyIsAFloorThatNoGroupCanLift()
        {
            // Same visible outcome on an empty database, entirely different rule.
            Assert.AreEqual(AclVerb.None,
                Resolve("docs-agent",
                    Root(AclDefault.Deny, AclDocument.WildcardSubject, Grant(AclVerb.None)),
                    Level("docs-agent", Grant(AclVerb.Delete))).Verb);
        }

        // --- allow by default ---------------------------------------------------------------

        [Test]
        public void EverythingIsGrantedWhenNothingSaysOtherwise()
        {
            AclGrant grant = Resolve("docs-agent", Root(AclDefault.Allow));

            Assert.AreEqual(AclVerb.Delete, grant.Verb);
            Assert.IsTrue(grant.Attachments);
            Assert.IsTrue(grant.Unattended);
        }

        [Test]
        public void ItReachesAnEntryNestedSeveralGroupsDeep()
        {
            Assert.AreEqual(AclVerb.Delete,
                Resolve("docs-agent", Root(AclDefault.Allow), null, null, null).Verb);
        }

        [Test]
        public void AGroupCanStillOnlyTakeAway()
        {
            Assert.AreEqual(AclVerb.List,
                Resolve("docs-agent",
                    Root(AclDefault.Allow),
                    Level("docs-agent", Grant(AclVerb.List))).Verb);
        }

        [Test]
        public void AGroupCannotWidenWhatAnotherGroupNarrowed()
        {
            // The rule that has to survive the flip: narrow-only is not conditional on the
            // default. A deeper group asking for more than it inherits gets what it inherits.
            Assert.AreEqual(AclVerb.List,
                Resolve("docs-agent",
                    Root(AclDefault.Allow),
                    Level("docs-agent", Grant(AclVerb.List)),
                    Level("docs-agent", Grant(AclVerb.Delete))).Verb);
        }

        [Test]
        public void AnEntryCanBeCarvedOutCompletely()
        {
            Assert.AreEqual(AclVerb.None,
                Resolve("docs-agent",
                    Root(AclDefault.Allow),
                    null,
                    Level("docs-agent", Grant(AclVerb.None))).Verb);
        }

        [Test]
        public void TheFlagsAreGrantedTooAndCanBeTakenAway()
        {
            AclGrant grant = Resolve("docs-agent",
                Root(AclDefault.Allow),
                Level("docs-agent", new AclGrant(AclVerb.Read, true, false)));

            Assert.IsTrue(grant.Attachments);
            Assert.IsFalse(grant.Unattended, "the prompt was skipped by inheritance");
        }

        [Test]
        public void TheWildcardStillCannotAuthenticate()
        {
            Assert.AreEqual(AclVerb.None,
                Resolve(AclDocument.WildcardSubject, Root(AclDefault.Allow)).Verb);
        }

        // --- where the setting is read from --------------------------------------------------

        [Test]
        public void OnlyTheRootDocumentDecidesIt()
        {
            // A group saying "allow" would be a group re-opening what its parents closed, which
            // is the one thing this model does not permit. The parser accepts the property
            // anywhere; the resolver reads it in one place.
            Assert.AreEqual(AclVerb.None,
                Resolve("docs-agent", Level(), Root(AclDefault.Allow)).Verb);
        }

        [Test]
        public void AnUnreadableRootStillRefusesEverything()
        {
            Assert.AreEqual(AclVerb.None, Resolve("docs-agent", "{ not a document").Verb);
        }

        [Test]
        public void AnAbsentRootDocumentMeansDeny()
        {
            Assert.AreEqual(AclVerb.None, Resolve("docs-agent", null, Level()).Verb);
        }

        // --- what the editor is told it inherits ---------------------------------------------

        [Test]
        public void TheEditorShowsAllowByDefaultAsAWildcardItDidNotType()
        {
            IDictionary<string, AclGrant> effective =
                AclResolver.Effective(new List<string> { Root(AclDefault.Allow) });

            Assert.IsTrue(effective.ContainsKey(AclDocument.WildcardSubject),
                "a tab on an allow-by-default database showed nothing inherited, which would "
                + "invite an operator to grant what is already granted");
            Assert.AreEqual(AclVerb.Delete, effective[AclDocument.WildcardSubject].Verb);
        }

        [Test]
        public void ANamedSubjectInheritsFromTheDefaultToo()
        {
            IDictionary<string, AclGrant> effective = AclResolver.Effective(new List<string>
            {
                Root(AclDefault.Allow),
                Level("docs-agent", Grant(AclVerb.Read))
            });

            Assert.AreEqual(AclVerb.Read, effective["docs-agent"].Verb);
        }

        // --- storage ---------------------------------------------------------------------------

        [Test]
        public void TheSettingSurvivesARoundTrip()
        {
            AclDocument document = AclDocument.Parse(Root(AclDefault.Allow));
            Assert.AreEqual(AclDefault.Allow, document.Default);

            AclDocument again = AclDocument.Parse(document.ToJson());
            Assert.AreEqual(AclDefault.Allow, again.Default);
        }

        [Test]
        public void ADocumentWithoutTheSettingDenies()
        {
            AclDocument document = AclDocument.Parse("{\"version\":1,\"grants\":{}}");
            Assert.AreEqual(AclDefault.Deny, document.Default);
        }

        [Test]
        public void AnUnrecognisedSettingIsRefusedRatherThanGuessedAt()
        {
            Assert.IsNull(AclDocument.Parse("{\"version\":1,\"default\":\"maybe\",\"grants\":{}}"));
            Assert.IsNull(AclDocument.Parse("{\"version\":1,\"default\":true,\"grants\":{}}"));
            Assert.IsNull(AclDocument.Parse("{\"version\":1,\"default\":\"Allow\",\"grants\":{}}"));
        }

        [Test]
        public void DenyIsNotWrittenOutBecauseAbsenceAlreadyMeansIt()
        {
            AclDocument document = new AclDocument();
            document.Set("docs-agent", Grant(AclVerb.Read));

            Assert.IsFalse(document.ToJson().Contains("default"));
        }

        [Test]
        public void ADocumentThatOnlyCarriesTheSettingIsNotEmpty()
        {
            // Otherwise deleting the last grant on the root group would remove the key and
            // silently put an allow-by-default database back to denying everything.
            AclDocument document = new AclDocument();
            document.Default = AclDefault.Allow;

            Assert.AreEqual(0, document.Count);
            Assert.IsFalse(document.IsEmpty);

            document.Default = AclDefault.Deny;
            Assert.IsTrue(document.IsEmpty);
        }
    }
}
