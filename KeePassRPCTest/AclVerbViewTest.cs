using System.Collections.Generic;
using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// Showing a stored allowance as the denial it amounts to.
    ///
    /// A rule is stored one way, always: the verb is the most a profile may do. What the table
    /// calls it depends on which way round the database reads, because on a database that
    /// allows by default every rule is a restriction, and a column headed "Allow" there tells
    /// the reader the opposite of what is happening.
    ///
    /// The translation is exact, and an off-by-one rung would silently hand out or withhold a
    /// whole level of access, so both directions are pinned here rather than eyeballed. An
    /// allowance names the strongest verb permitted and carries everything weaker with it; a
    /// denial names the weakest verb forbidden and carries everything stronger. A denial is
    /// therefore the allowance one rung below it.
    /// </summary>
    [TestFixture]
    public class AclVerbViewTest
    {
        [Test]
        public void TheColumnIsCalledWhatItDoes()
        {
            Assert.AreEqual("Allow", AclVerbView.Header(AclDefault.Deny));
            Assert.AreEqual("Deny", AclVerbView.Header(AclDefault.Allow));
        }

        [Test]
        public void ADenyByDefaultDatabaseShowsRulesAsTheyAreStored()
        {
            Assert.AreEqual("read", AclVerbView.Text(AclVerb.Read, AclDefault.Deny));
            Assert.AreEqual("none", AclVerbView.Text(AclVerb.None, AclDefault.Deny));
            Assert.AreEqual("delete", AclVerbView.Text(AclVerb.Delete, AclDefault.Deny));
        }

        [Test]
        [TestCase(AclVerb.None, "list")]
        [TestCase(AclVerb.List, "read")]
        [TestCase(AclVerb.Read, "write")]
        [TestCase(AclVerb.Write, "delete")]
        [TestCase(AclVerb.Delete, AclVerbView.DeniesNothing)]
        public void AnAllowanceIsShownAsTheDenialItAmountsTo(AclVerb allowed, string shown)
        {
            // The examples the model was specified with: allow list reads as deny read, and
            // deny delete means allow write.
            Assert.AreEqual(shown, AclVerbView.Text(allowed, AclDefault.Allow));
        }

        [Test]
        [TestCase("list", AclVerb.None)]
        [TestCase("read", AclVerb.List)]
        [TestCase("write", AclVerb.Read)]
        [TestCase("delete", AclVerb.Write)]
        [TestCase(AclVerbView.DeniesNothing, AclVerb.Delete)]
        public void ADenialIsReadBackAsTheAllowanceItStandsFor(string shown, AclVerb allowed)
        {
            AclVerb parsed;
            Assert.IsTrue(AclVerbView.TryParse(shown, AclDefault.Allow, out parsed));
            Assert.AreEqual(allowed, parsed);
        }

        [Test]
        public void EveryValueSurvivesTheRoundTripInBothDirections()
        {
            // The property that matters: a rule shown and then read back is the same rule.
            // Everything else here is an example of it.
            foreach (AclDefault mode in new[] { AclDefault.Deny, AclDefault.Allow })
            {
                foreach (AclVerb verb in new[] { AclVerb.None, AclVerb.List, AclVerb.Read,
                    AclVerb.Write, AclVerb.Delete })
                {
                    AclVerb parsed;
                    Assert.IsTrue(AclVerbView.TryParse(AclVerbView.Text(verb, mode), mode, out parsed),
                        verb + " could not be read back in " + mode + " mode");
                    Assert.AreEqual(verb, parsed, "the round trip changed the rule in " + mode + " mode");
                }
            }
        }

        [Test]
        public void TheListOffersOneValuePerRungAndNoMore()
        {
            IList<string> denying = AclVerbView.Items(AclDefault.Allow);
            IList<string> allowing = AclVerbView.Items(AclDefault.Deny);

            Assert.AreEqual(5, allowing.Count);
            Assert.AreEqual(5, denying.Count);

            CollectionAssert.AreEqual(
                new[] { "none", "list", "read", "write", "delete" }, allowing);
            CollectionAssert.AreEqual(
                new[] { "list", "read", "write", "delete", AclVerbView.DeniesNothing }, denying);
        }

        [Test]
        public void DenyingNoneIsNotAThing()
        {
            // There is no rung below "none" to allow, so a denial cannot name it. The list
            // never offers it; this is about a document somebody typed by hand.
            AclVerb parsed;
            Assert.IsFalse(AclVerbView.TryParse("none", AclDefault.Allow, out parsed));
        }

        [Test]
        public void NothingIsNotAValueInTheOtherDirection()
        {
            AclVerb parsed;
            Assert.IsFalse(AclVerbView.TryParse(AclVerbView.DeniesNothing, AclDefault.Deny, out parsed));
        }

        [Test]
        public void AnUnrecognisedValueIsRefusedRatherThanGuessedAt()
        {
            AclVerb parsed;
            Assert.IsFalse(AclVerbView.TryParse("maybe", AclDefault.Deny, out parsed));
            Assert.IsFalse(AclVerbView.TryParse("maybe", AclDefault.Allow, out parsed));
            Assert.IsFalse(AclVerbView.TryParse(null, AclDefault.Allow, out parsed));
            Assert.IsFalse(AclVerbView.TryParse("", AclDefault.Allow, out parsed));
        }

        [Test]
        public void AGrantIsDescribedInTheSameDirectionAsTheColumn()
        {
            AclGrant grant = new AclGrant(AclVerb.List, true, false);

            Assert.AreEqual("list+attachments", AclVerbView.Describe(grant, AclDefault.Deny));
            Assert.AreEqual("read+attachments", AclVerbView.Describe(grant, AclDefault.Allow));
        }

        [Test]
        public void WhatIsStoredIsTheAllowanceWhicheverWayItIsShown()
        {
            // The point of the whole class: one representation in the file, two vocabularies on
            // screen. A document written on an allow-by-default database has to mean the same
            // thing when that database is switched back.
            AclDocument document = new AclDocument();
            document.Set("docs", new AclGrant(AclVerb.Read, false, false));

            Assert.IsTrue(document.ToJson().Contains("\"verb\":\"read\""), document.ToJson());
        }
    }
}
