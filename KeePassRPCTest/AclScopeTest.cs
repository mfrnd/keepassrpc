using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    [TestFixture]
    public class AclScopeTest
    {
        [Test]
        public void AbsentMeansV3Only()
        {
            // The default has to be the old behaviour. Installing this build must not start
            // filtering v1 for anybody, because a filtered v1 read looks like an empty
            // database rather than an error, and v1 resolves secrets in production.
            Assert.IsFalse(AclScope.CoversLegacy(null));
            Assert.IsFalse(AclScope.CoversLegacy(""));
            Assert.IsFalse(AclScope.CoversLegacy("   "));
        }

        [TestCase("v3")]
        [TestCase("V3")]
        [TestCase("  v3  ")]
        public void V3OnlyLeavesLegacyUnguarded(string scope)
        {
            Assert.IsFalse(AclScope.CoversLegacy(scope));
        }

        [TestCase("all")]
        [TestCase("ALL")]
        [TestCase("  all  ")]
        public void AllExtendsTheAclOverLegacy(string scope)
        {
            Assert.IsTrue(AclScope.CoversLegacy(scope));
        }

        [TestCase("alll")]
        [TestCase("everything")]
        [TestCase("v33")]
        [TestCase("none")]
        public void AnUnrecognisedValueGuards(string scope)
        {
            // Deliberately NOT symmetric with the absent case, and the asymmetry is the point.
            //
            // Absent means nobody has considered this subject yet, so the documented default
            // applies. A value that is present but unreadable means somebody tried to
            // configure something and got it wrong, and the two mistakes cost different
            // amounts: guarding a subject that should not have been guarded breaks its access
            // loudly and gets fixed within minutes, while failing to guard one that should
            // have been leaves a control switched off that its author believes is on, silently
            // and indefinitely.
            Assert.IsTrue(AclScope.CoversLegacy(scope));
        }

        [Test]
        public void TheConfigKeysAreWhatTheCodeReads()
        {
            // Pinned because these strings are duplicated in the guard and in the options
            // dialog; a rename in one place without the others would silently stop governing
            // anybody, which is the failure mode with no symptom.
            Assert.AreEqual("KeePassRPC.AclScope.", AclScope.SubjectPrefix);
            Assert.AreEqual("v3", AclScope.V3Only);
            Assert.AreEqual("all", AclScope.All);
        }
    }
}
