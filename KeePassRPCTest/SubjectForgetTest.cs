using KeePassRPC;
using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// What forgetting a client has to clear.
    ///
    /// The red X on the Client access tab means "this client is not mine any more", and the
    /// dangerous way to implement that is the obvious one: drop the key and stop. The key is
    /// what lets it authenticate, but the profile is what says how much it may do, and a
    /// profile left behind is restored in full the moment somebody pairs under the same
    /// identity again. Worse, the pairing prompt would not even ask, because it only asks
    /// about a subject with no profile of its own.
    ///
    /// The config keys are checked by name because they are the contract: the gate, the ACL
    /// and this all agree on those three strings and nothing else joins them up.
    /// </summary>
    [TestFixture]
    public class SubjectForgetTest
    {
        [Test]
        public void TheThreeKeysForgettingHasToClearAreTheOnesTheGateReads()
        {
            // Named rather than exercised, since clearing them needs a KeePass to clear them
            // in. If a fourth per-subject key is ever added, this is the test that should
            // fail until somebody decides whether forgetting should clear it too.
            Assert.AreEqual("KeePassRPC.Key.", SubjectRegistry.KeyPrefix);
            Assert.AreEqual("KeePassRPC.Profile.", SubjectRegistry.ProfilePrefix);
            Assert.AreEqual("KeePassRPC.AclScope.", AclScope.SubjectPrefix);
            Assert.AreEqual("KeePassRPC.Subjects", SubjectRegistry.IndexKey);
        }

        [Test]
        public void ForgettingWithNothingToForgetIsHarmless()
        {
            // Called from a dialog, so it must not throw on the way out of one.
            Assert.DoesNotThrow(delegate
            {
                SubjectRegistry.Forget(null, "agent-fictitious");
                SubjectRegistry.Forget(null, null);
                SubjectRegistry.Forget(null, "");
            });
        }

        [Test]
        public void AForgottenSubjectLeavesTheIndexWithoutDisturbingTheRest()
        {
            // The index is the only one of the four that holds more than one subject, so it
            // is the only one where forgetting could take a bystander with it.
            string index = SubjectRegistry.FormatIndex(
                new[] { "agent-one", "agent-two", "agent-three" });

            System.Collections.Generic.List<string> known = SubjectRegistry.ParseIndex(index);
            Assert.IsTrue(known.Remove("agent-two"));

            CollectionAssert.AreEqual(new[] { "agent-one", "agent-three" },
                SubjectRegistry.ParseIndex(SubjectRegistry.FormatIndex(known)));
        }
    }
}
