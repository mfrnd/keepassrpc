using System;
using System.Collections.Generic;
using System.Reflection;
using Jayrock.JsonRpc;
using KeePassRPC;
using NUnit.Framework;

namespace KeePassRPCTest
{
    [TestFixture]
    public class MethodProfilesTest
    {
        // --- the allowlist itself -------------------------------------------------

        [Test]
        public void LegacyGrantsAKnownMethod()
        {
            Assert.IsTrue(MethodProfiles.IsAllowed(MethodProfiles.Legacy, "GetDatabaseName"));
        }

        [Test]
        public void NoneGrantsNothing()
        {
            Assert.IsFalse(MethodProfiles.IsAllowed(MethodProfiles.None, "GetDatabaseName"));
        }

        [Test]
        public void V3DoesNotGrantTheLegacySurface()
        {
            // The whole point of the narrow profile: an agent holding v3 must not reach the
            // methods that read or write entries through v1 and v2.
            Assert.IsFalse(MethodProfiles.IsAllowed(MethodProfiles.V3, "GetAllLogins"));
            Assert.IsFalse(MethodProfiles.IsAllowed(MethodProfiles.V3, "UpdateLogin"));
            Assert.IsFalse(MethodProfiles.IsAllowed(MethodProfiles.V3, "RemoveEntry"));
        }

        [Test]
        public void V3GrantsTheV3ApiAndMetadataAndNothingElse()
        {
            // Pinned as an exact set rather than a count, so that widening the narrow profile
            // has to be written down here before it can happen.
            CollectionAssert.AreEquivalent(
                new[]
                {
                    "AddEntry3", "GetApplicationMetadata", "GetAttachment3", "GetEntry3", "ListGroup3",
                    "RemoveAttachment3", "RemoveEntry3", "SetAttachment3", "UpdateEntry3"
                },
                MethodProfiles.MethodsIn(MethodProfiles.V3));
        }

        // --- fail-closed behaviour ------------------------------------------------

        [TestCase(null)]
        [TestCase("")]
        [TestCase(" ")]
        [TestCase(",")]
        [TestCase(" , ")]
        public void AnEmptySpecGrantsNothing(string spec)
        {
            Assert.IsFalse(MethodProfiles.IsAllowed(spec, "GetDatabaseName"));
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("   ")]
        public void AnEmptyMethodNameIsRefused(string methodName)
        {
            Assert.IsFalse(MethodProfiles.IsAllowed(MethodProfiles.Legacy, methodName));
        }

        [Test]
        public void AnUnknownProfileGrantsNothing()
        {
            Assert.IsFalse(MethodProfiles.IsAllowed("everything", "GetDatabaseName"));
            Assert.IsFalse(MethodProfiles.IsAllowed("*", "GetDatabaseName"));
            Assert.IsFalse(MethodProfiles.IsAllowed("admin", "GetDatabaseName"));
        }

        [Test]
        public void AMisspelledProfileDeniesTheWholeSpec()
        {
            // "legacy,v33" must not quietly degrade to "legacy". A typo in a security control
            // should stop the thing working, loudly, rather than grant a subset by accident.
            Assert.IsFalse(MethodProfiles.IsAllowed("legacy,v33", "GetDatabaseName"));
            Assert.IsFalse(MethodProfiles.IsAllowed("v33,legacy", "GetDatabaseName"));
        }

        [Test]
        public void AnUnknownMethodIsRefusedByEveryProfile()
        {
            foreach (string profile in MethodProfiles.KnownProfileNames)
            {
                Assert.IsFalse(MethodProfiles.IsAllowed(profile, "DropAllTables"),
                    "profile " + profile + " must not grant an unknown method");
            }
        }

        // --- composition ----------------------------------------------------------

        [Test]
        public void ProfilesUnion()
        {
            // The transition case: a subject keeps v1 while gaining V3.
            const string both = MethodProfiles.Legacy + "," + MethodProfiles.V3;
            Assert.IsTrue(MethodProfiles.IsAllowed(both, "GetAllLogins"));
            Assert.IsTrue(MethodProfiles.IsAllowed(both, "GetApplicationMetadata"));
            Assert.IsFalse(MethodProfiles.IsAllowed(both, "DropAllTables"));
        }

        [Test]
        public void WhitespaceAroundNamesIsTolerated()
        {
            Assert.IsTrue(MethodProfiles.IsAllowed(" legacy , v3 ", "GetAllLogins"));
        }

        [Test]
        public void NoneAlongsideAnotherProfileDoesNotSubtract()
        {
            // "none" holds nothing; it does not veto. Revoking means removing the profile that
            // grants, not adding one that denies.
            Assert.IsTrue(MethodProfiles.IsAllowed("none,legacy", "GetDatabaseName"));
        }

        // --- case handling, which is a bypass if it is wrong ----------------------

        [Test]
        public void ProfileNamesAreCaseInsensitive()
        {
            Assert.IsTrue(MethodProfiles.IsAllowed("LEGACY", "GetDatabaseName"));
            Assert.IsTrue(MethodProfiles.IsAllowed("Legacy", "GetDatabaseName"));
        }

        [Test]
        public void MethodNamesAreMatchedCaseInsensitively()
        {
            // Jayrock's ServiceClass.FindMethodByName falls back to a case-insensitive lookup,
            // so it will happily route "getdatabasename" to GetDatabaseName. If this check
            // were case-sensitive it would fail to recognise the method and deny it, which
            // sounds safe until you invert it: the same laxity means a DENIED method could be
            // re-cased to slip past a case-sensitive comparison while still resolving. The
            // gate must match the dispatcher's own semantics exactly.
            Assert.IsTrue(MethodProfiles.IsAllowed(MethodProfiles.Legacy, "getdatabasename"));
            Assert.IsTrue(MethodProfiles.IsAllowed(MethodProfiles.Legacy, "GETDATABASENAME"));
            Assert.IsFalse(MethodProfiles.IsAllowed(MethodProfiles.V3, "getallLOGINS"));
        }

        // --- the profile list versus the service's actual surface ------------------

        [Test]
        public void EveryServiceMethodIsAccountedForInSomeProfile()
        {
            // An upstream merge that adds a JSON-RPC method must not silently land outside
            // every profile: default deny would refuse it in production and the reason would
            // be a mystery. Failing here instead makes it a decision, and the decision is
            // which profile the method belongs to.
            List<string> missing = new List<string>();
            foreach (string name in ServiceMethodNames())
            {
                if (!MethodProfiles.IsAllowed(MethodProfiles.Legacy, name)
                    && !MethodProfiles.IsAllowed(MethodProfiles.V3, name))
                    missing.Add(name);
            }

            Assert.IsEmpty(missing,
                "these [JsonRpcMethod] methods are in no profile, so nobody can call them: "
                + string.Join(", ", missing.ToArray()));
        }

        [Test]
        public void TheV3MethodsAreNotInTheLegacyProfile()
        {
            // A subject kept on legacy through a transition must not silently acquire the new
            // API, and the guarded generation must not become reachable by the profile that
            // exists to mean "as before".
            foreach (string name in new[]
                     {
                         "GetEntry3", "ListGroup3", "GetAttachment3",
                         "AddEntry3", "UpdateEntry3", "RemoveEntry3", "SetAttachment3", "RemoveAttachment3"
                     })
            {
                Assert.IsFalse(MethodProfiles.IsAllowed(MethodProfiles.Legacy, name),
                    name + " must not be in the legacy profile");
                Assert.IsTrue(MethodProfiles.IsAllowed(MethodProfiles.V3, name),
                    name + " must be in the v3 profile");
            }
        }

        [Test]
        public void NoProfileNamesAMethodTheServiceDoesNotExpose()
        {
            // The other direction: a method removed upstream should not linger here, where it
            // would suggest a grant that does nothing.
            List<string> actual = new List<string>(ServiceMethodNames());
            List<string> stale = new List<string>();
            foreach (string profile in new[] { MethodProfiles.Legacy, MethodProfiles.V3 })
            {
                foreach (string name in MethodProfiles.MethodsIn(profile))
                {
                    if (!actual.Contains(name) && !stale.Contains(name))
                        stale.Add(name);
                }
            }

            Assert.IsEmpty(stale,
                "these profile entries name methods the service no longer exposes: "
                + string.Join(", ", stale.ToArray()));
        }

        [Test]
        public void TheServiceSurfaceIsTheSizeWeThinkItIs()
        {
            // A blunt canary: 33 inherited from upstream, plus three V3 reads and five V3
            // writes. If this number moves, the tests above explain why.
            Assert.AreEqual(41, new List<string>(ServiceMethodNames()).Count);
        }

        private static IEnumerable<string> ServiceMethodNames()
        {
            List<string> names = new List<string>();
            MethodInfo[] methods = typeof(KeePassRPCService).GetMethods(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

            foreach (MethodInfo method in methods)
            {
                object[] attributes = method.GetCustomAttributes(typeof(JsonRpcMethodAttribute), true);
                if (attributes.Length > 0 && !names.Contains(method.Name))
                    names.Add(method.Name);
            }

            return names;
        }
    }
}
