using KeePassRPC;
using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// The five things a human can say about a client, and the two config values each one
    /// amounts to.
    ///
    /// This list is the whole vocabulary of the access decision, so it has to agree with the
    /// two things that enforce it: <see cref="MethodProfiles"/> reads the profile spec and
    /// <see cref="AclScope"/> reads the scope. If a label ever described a pair that the gate
    /// reads differently, the tab would be reporting access nobody has and hiding access
    /// somebody does.
    /// </summary>
    [TestFixture]
    public class AccessChoiceTest
    {
        [Test]
        public void EveryChoiceRoundTripsThroughWhatIsStored()
        {
            foreach (AccessChoice choice in AccessChoice.All)
            {
                Assert.AreSame(choice, AccessChoice.For(choice.Profile, choice.Scope),
                    choice.Label + " does not come back from what it stores");
            }
        }

        [Test]
        public void EveryChoiceNamesProfilesTheGateRecognises()
        {
            // A label promising something the gate refuses to parse would deny everything
            // while reading as a grant. MethodProfiles refuses a whole spec if any name in it
            // is unknown, so this checks the spec as a whole.
            foreach (AccessChoice choice in AccessChoice.All)
            {
                bool anyAllowed = MethodProfiles.IsAllowed(choice.Profile, "GetApplicationMetadata");
                if (choice == AccessChoice.Refused)
                    Assert.IsFalse(anyAllowed, "'refused' allows a method");
                else
                    Assert.IsTrue(anyAllowed, choice.Label + " names a profile the gate rejects");
            }
        }

        [Test]
        public void OnlyOneChoiceLeavesTheOlderApiUnconstrained()
        {
            // The widest setting there is. If a second one ever appeared it would be a second
            // way to spell "the whole database", and one of the two would go unnoticed.
            int unconstrained = 0;
            foreach (AccessChoice choice in AccessChoice.All)
            {
                bool reachesLegacy = MethodProfiles.IsAllowed(choice.Profile, "GetAllLogins");
                if (reachesLegacy && !AclScope.CoversLegacy(choice.Scope))
                    unconstrained++;
            }

            Assert.AreEqual(1, unconstrained);
        }

        [Test]
        public void TheOrderOfNamesInAStoredProfileDoesNotMatter()
        {
            // A hand-edited config may say either, and MethodProfiles treats them the same.
            Assert.AreSame(AccessChoice.AllWithAcl, AccessChoice.For("v3,legacy", AclScope.All));
            Assert.AreSame(AccessChoice.AllWithAcl, AccessChoice.For(" legacy , v3 ", AclScope.All));
            Assert.AreSame(AccessChoice.AllWithAcl, AccessChoice.For("Legacy,V3", AclScope.All));
        }

        [Test]
        public void AnAbsentSettingReadsAsRefused()
        {
            Assert.AreSame(AccessChoice.Refused, AccessChoice.For(null, null));
            Assert.AreSame(AccessChoice.Refused, AccessChoice.For("", ""));
            Assert.AreSame(AccessChoice.Refused, AccessChoice.For("none", AclScope.All));
        }

        [Test]
        public void ACombinationTheListCannotOfferIsReportedRatherThanRounded()
        {
            // Rounding to the nearest option would misreport what the gate is enforcing, and
            // would invite somebody to press Apply and change it without meaning to.
            Assert.IsNull(AccessChoice.For("legacy,v3", AclScope.V3Only),
                "an unoffered combination was matched to something");

            string described = AccessChoice.Describe("legacy,v3", AclScope.V3Only);
            StringAssert.Contains("legacy,v3", described);
            StringAssert.Contains("unrestricted", described);
        }

        [Test]
        public void ATyposProfileIsNotQuietlyTreatedAsSomethingKnown()
        {
            Assert.IsNull(AccessChoice.For("legacyy", AclScope.All));
            StringAssert.Contains("legacyy", AccessChoice.Describe("legacyy", AclScope.All));
        }

        [Test]
        public void TheListLeadsWithRefusedAndNeverRepeatsALabel()
        {
            Assert.AreSame(AccessChoice.Refused, AccessChoice.All[0],
                "the list does not lead with the answer that grants nothing");

            for (int i = 0; i < AccessChoice.All.Count; i++)
            {
                for (int j = i + 1; j < AccessChoice.All.Count; j++)
                {
                    Assert.AreNotEqual(AccessChoice.All[i].Label, AccessChoice.All[j].Label);
                    Assert.IsNotEmpty(AccessChoice.All[i].Detail);
                }
            }
        }
    }
}
