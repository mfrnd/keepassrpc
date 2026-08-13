using System.Collections.Generic;
using KeePassLib;
using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// Profiles: what a database defines, who is in them, and what a client ends up holding.
    ///
    /// Rules name a profile rather than a client, which puts a lookup between the identity a
    /// client authenticates as and the rules that decide what it may reach. Two properties of
    /// that lookup carry the whole model, and both are here.
    ///
    /// A client is never without a profile. Deleting a profile, or clearing an assignment,
    /// leaves a client in <c>default</c> rather than in nothing, because "in nothing" would
    /// have to mean either everything or nothing and both readings are traps: one makes
    /// deleting a profile a silent revocation of access somebody depends on, and the other
    /// needs no explanation.
    ///
    /// A client in several profiles holds the WIDEST of what they grant. Roles add up; that is
    /// what makes a profile something you can reason about on its own, and the cost, said out
    /// loud here so nobody discovers it in production, is that a <c>none</c> in one profile
    /// does not take away what another profile gives.
    /// </summary>
    [TestFixture]
    public class AclProfilesTest
    {
        private static AclGrant Grant(AclVerb verb)
        {
            return new AclGrant(verb, false, false);
        }

        // --- the registry --------------------------------------------------------------------

        [Test]
        public void ADatabaseAlwaysHasTheDefaultProfile()
        {
            AclProfiles profiles = new AclProfiles();

            Assert.AreEqual(1, profiles.Names.Count);
            Assert.AreEqual(AclProfiles.DefaultProfile, profiles.Names[0]);
        }

        [Test]
        public void TheDefaultProfileCannotBeRemoved()
        {
            AclProfiles profiles = new AclProfiles();

            Assert.IsFalse(profiles.Remove(AclProfiles.DefaultProfile));
            Assert.IsTrue(profiles.Defines(AclProfiles.DefaultProfile));
        }

        [Test]
        public void TwoNamesDifferingOnlyInCaseAreRefused()
        {
            // A rule naming the wrong one of them looks right and grants nobody anything.
            AclProfiles profiles = new AclProfiles();
            Assert.IsTrue(profiles.Add("release"));
            Assert.IsFalse(profiles.Add("Release"));
            Assert.IsFalse(profiles.Add("RELEASE"));
        }

        [Test]
        public void TheWildcardIsNotAProfileName()
        {
            // It already means "every profile not named here" in a rule.
            AclProfiles profiles = new AclProfiles();
            Assert.IsFalse(profiles.Add(AclDocument.WildcardSubject));
        }

        [Test]
        public void ANameIsRefusedIfItIsBlankOrPadded()
        {
            AclProfiles profiles = new AclProfiles();

            Assert.IsFalse(profiles.Add(""));
            Assert.IsFalse(profiles.Add("   "));
            Assert.IsFalse(profiles.Add(" release"), "a name with an edge nobody can see");
        }

        // --- who is in them ------------------------------------------------------------------

        [Test]
        public void AClientNobodyHasAssignedIsInTheDefault()
        {
            AclProfiles profiles = new AclProfiles();

            IList<string> held = profiles.For("docs-agent");
            Assert.AreEqual(1, held.Count);
            Assert.AreEqual(AclProfiles.DefaultProfile, held[0]);
        }

        [Test]
        public void AClientHoldsWhatItWasAssigned()
        {
            AclProfiles profiles = new AclProfiles();
            profiles.Add("docs");
            profiles.Assign("docs-agent", new List<string> { "docs" });

            CollectionAssert.AreEqual(new[] { "docs" }, profiles.For("docs-agent"));
        }

        [Test]
        public void ClearingEveryAssignmentFallsBackToTheDefault()
        {
            AclProfiles profiles = new AclProfiles();
            profiles.Add("docs");
            profiles.Assign("docs-agent", new List<string> { "docs" });
            profiles.Assign("docs-agent", new List<string>());

            CollectionAssert.AreEqual(new[] { AclProfiles.DefaultProfile },
                profiles.For("docs-agent"));
        }

        [Test]
        public void DeletingAClientsOnlyProfileFallsBackToTheDefault()
        {
            AclProfiles profiles = new AclProfiles();
            profiles.Add("docs");
            profiles.Assign("docs-agent", new List<string> { "docs" });
            profiles.Remove("docs");

            CollectionAssert.AreEqual(new[] { AclProfiles.DefaultProfile },
                profiles.For("docs-agent"));
        }

        [Test]
        public void DeletingOneOfSeveralLeavesTheRest()
        {
            AclProfiles profiles = new AclProfiles();
            profiles.Add("docs");
            profiles.Add("release");
            profiles.Assign("agent", new List<string> { "docs", "release" });
            profiles.Remove("docs");

            CollectionAssert.AreEqual(new[] { "release" }, profiles.For("agent"));
        }

        [Test]
        public void AnAssignmentToSomethingUndefinedIsIgnored()
        {
            AclProfiles profiles = new AclProfiles();
            profiles.Assign("agent", new List<string> { "never-existed" });

            CollectionAssert.AreEqual(new[] { AclProfiles.DefaultProfile }, profiles.For("agent"));
        }

        // --- what that means at resolution time ------------------------------------------------

        private static PwDatabase Database(AclDocument root)
        {
            PwDatabase database = new PwDatabase();
            database.RootGroup = new PwGroup(true, true);
            if (root != null)
                database.RootGroup.CustomData.Set(AclDocument.CustomDataKey, root.ToJson());

            return database;
        }

        private static PwEntry EntryIn(PwDatabase database)
        {
            PwEntry entry = new PwEntry(true, true);
            database.RootGroup.AddEntry(entry, true);
            return entry;
        }

        [Test]
        public void AClientIsResolvedThroughItsProfileAndNotItsIdentity()
        {
            AclDocument root = new AclDocument();
            root.Profiles.Add("docs");
            root.Profiles.Assign("docs-agent", new List<string> { "docs" });
            root.Set("docs", Grant(AclVerb.Read));

            PwDatabase database = Database(root);
            PwEntry entry = EntryIn(database);

            Assert.AreEqual(AclVerb.Read, AclResolver.Resolve(database, entry, "docs-agent").Verb);
        }

        [Test]
        public void ARuleNamingTheClientItselfGrantsNothing()
        {
            // The change that this whole model rests on: identities are not what rules are
            // about any more, so a rule naming one matches no profile and grants nobody
            // anything. It fails closed, which is the only acceptable direction.
            AclDocument root = new AclDocument();
            root.Set("docs-agent", Grant(AclVerb.Delete));

            PwDatabase database = Database(root);
            PwEntry entry = EntryIn(database);

            Assert.AreEqual(AclVerb.None, AclResolver.Resolve(database, entry, "docs-agent").Verb);
        }

        [Test]
        public void AnUnassignedClientGetsWhatTheDefaultProfileGets()
        {
            AclDocument root = new AclDocument();
            root.Set(AclProfiles.DefaultProfile, Grant(AclVerb.List));

            PwDatabase database = Database(root);
            PwEntry entry = EntryIn(database);

            Assert.AreEqual(AclVerb.List,
                AclResolver.Resolve(database, entry, "never-heard-of-it").Verb);
        }

        [Test]
        public void TwoProfilesAddUpToTheWiderOfThem()
        {
            AclDocument root = new AclDocument();
            root.Profiles.Add("readers");
            root.Profiles.Add("writers");
            root.Profiles.Assign("agent", new List<string> { "readers", "writers" });
            root.Set("readers", new AclGrant(AclVerb.Read, true, false));
            root.Set("writers", new AclGrant(AclVerb.Write, false, true));

            PwDatabase database = Database(root);
            PwEntry entry = EntryIn(database);

            AclGrant held = AclResolver.Resolve(database, entry, "agent");
            Assert.AreEqual(AclVerb.Write, held.Verb);
            Assert.IsTrue(held.Attachments, "the attachment right from the other profile was lost");
            Assert.IsTrue(held.Unattended);
        }

        [Test]
        public void ADenialInOneProfileDoesNotTakeAwayWhatAnotherGives()
        {
            // Stated as a test because it is the trap in every additive role model, and
            // somebody will meet it. Taking access away means taking it out of every profile
            // the client is in, or taking the client out of the profile.
            AclDocument root = new AclDocument();
            root.Profiles.Add("readers");
            root.Profiles.Add("barred");
            root.Profiles.Assign("agent", new List<string> { "readers", "barred" });
            root.Set("readers", Grant(AclVerb.Read));
            root.Set("barred", Grant(AclVerb.None));

            PwDatabase database = Database(root);
            PwEntry entry = EntryIn(database);

            Assert.AreEqual(AclVerb.Read, AclResolver.Resolve(database, entry, "agent").Verb);
        }

        [Test]
        public void AGroupStillOnlyNarrowsWithinAProfile()
        {
            AclDocument root = new AclDocument();
            root.Profiles.Add("docs");
            root.Profiles.Assign("agent", new List<string> { "docs" });
            root.Set("docs", Grant(AclVerb.Read));

            PwDatabase database = Database(root);
            PwGroup inner = new PwGroup(true, true);
            database.RootGroup.AddGroup(inner, true);

            AclDocument narrower = new AclDocument();
            narrower.Set("docs", Grant(AclVerb.List));
            inner.CustomData.Set(AclDocument.CustomDataKey, narrower.ToJson());

            PwEntry entry = new PwEntry(true, true);
            inner.AddEntry(entry, true);

            Assert.AreEqual(AclVerb.List, AclResolver.Resolve(database, entry, "agent").Verb);
        }

        [Test]
        public void AnUnreadableRootRegistryRefusesEverything()
        {
            PwDatabase database = new PwDatabase();
            database.RootGroup = new PwGroup(true, true);
            database.RootGroup.CustomData.Set(AclDocument.CustomDataKey, "{ not a document");

            PwEntry entry = EntryIn(database);

            Assert.IsNull(AclResolver.RegistryOf(database));
            Assert.AreEqual(AclVerb.None, AclResolver.Resolve(database, entry, "agent").Verb);
        }

        // --- storage ---------------------------------------------------------------------------

        [Test]
        public void TheRegistrySurvivesARoundTrip()
        {
            AclDocument document = new AclDocument();
            document.Profiles.Add("docs");
            document.Profiles.Add("release");
            document.Profiles.Assign("docs-agent", new List<string> { "docs", "release" });
            document.Set("docs", Grant(AclVerb.Read));

            AclDocument again = AclDocument.Parse(document.ToJson());

            Assert.IsNotNull(again);
            CollectionAssert.AreEquivalent(new[] { "default", "docs", "release" },
                again.Profiles.Names);
            CollectionAssert.AreEquivalent(new[] { "docs", "release" },
                again.Profiles.For("docs-agent"));
        }

        [Test]
        public void ADatabaseThatDefinesNothingWritesNoRegistry()
        {
            AclDocument document = new AclDocument();
            document.Set("default", Grant(AclVerb.Read));

            string json = document.ToJson();
            Assert.IsFalse(json.Contains("profiles"), json);
            Assert.IsFalse(json.Contains("clients"), json);
        }

        [Test]
        public void ADocumentThatOnlyDefinesProfilesIsNotEmpty()
        {
            // Otherwise deleting the last rule on the root group would take the database's
            // profiles with it.
            AclDocument document = new AclDocument();
            document.Profiles.Add("docs");

            Assert.AreEqual(0, document.Count);
            Assert.IsFalse(document.IsEmpty);
        }

        [Test]
        public void AMalformedRegistryIsRefusedRatherThanGuessedAt()
        {
            Assert.IsNull(AclDocument.Parse("{\"version\":1,\"profiles\":\"docs\",\"grants\":{}}"));
            Assert.IsNull(AclDocument.Parse("{\"version\":1,\"profiles\":[7],\"grants\":{}}"));
            Assert.IsNull(AclDocument.Parse(
                "{\"version\":1,\"clients\":{\"agent\":\"docs\"},\"grants\":{}}"));
        }
    }
}
