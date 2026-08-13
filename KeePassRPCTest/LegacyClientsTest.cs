using KeePassRPC;
using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// The one-time grant given to clients that predate this build.
    ///
    /// This is the only code in the plugin that grants access without a human saying so, which
    /// is reason enough to pin what it does. It exists because the method gate is default deny,
    /// so arriving on a KeePass with paired clients would otherwise refuse every one of them at
    /// once, including whatever resolves secrets over v1 today. It replaces a fallback setting
    /// that could do the same thing but stayed on the options dialog long after the migration
    /// it existed for, where it could hand every future client the whole database.
    ///
    /// A migration cannot be exercised without a KeePass to migrate, so what is checked here is
    /// the shape of what it writes and the promise that it is not the gate's own default.
    /// </summary>
    [TestFixture]
    public class LegacyClientsTest
    {
        [Test]
        public void ItGrantsExactlyWhatThoseClientsAlreadyHad()
        {
            // The whole of the older API with the ACL standing aside, which is what every
            // client had before this fork existed. Anything narrower would break them, which
            // is the breakage the migration is for; anything wider does not exist.
            Assert.AreEqual(MethodProfiles.Legacy, AccessChoice.LegacyUnrestricted.Profile);
            Assert.AreEqual(AclScope.V3Only, AccessChoice.LegacyUnrestricted.Scope);
        }

        [Test]
        public void ItIsRememberedByItsOwnKeySoItCannotRunTwice()
        {
            // Running again would re-grant a client whose access somebody has since taken
            // away, which is the one thing a migration must never do.
            Assert.AreEqual("KeePassRPC.MethodGate.LegacyClientsMigrated",
                LegacyClients.MigratedKey);
        }

        [Test]
        public void MigratingNothingIsHarmless()
        {
            // It runs during plugin start-up, where an exception would stop KeePass loading
            // the plugin at all. Being refused until somebody sets things by hand is safe and
            // recoverable; failing to load is neither.
            Assert.DoesNotThrow(delegate { LegacyClients.Migrate(null); });
            CollectionAssert.IsEmpty(LegacyClients.Migrate(null));
        }

        [Test]
        public void WhatItGrantsIsSomethingTheTabCanShowAndNarrow()
        {
            // A migrated client has to appear as an ordinary row that can be read and tightened,
            // not as a state the list cannot express. That is the advantage it has over the
            // invisible fallback it replaces.
            Assert.AreSame(AccessChoice.LegacyUnrestricted,
                AccessChoice.For(AccessChoice.LegacyUnrestricted.Profile,
                    AccessChoice.LegacyUnrestricted.Scope));
        }

        [Test]
        public void SilenceStillMeansRefused()
        {
            // Everything the migration does is write real settings. A client it does not cover,
            // which is every client paired since, is left with nothing stored, and nothing
            // stored has to keep meaning no.
            Assert.AreSame(AccessChoice.Refused, AccessChoice.For(null, null));
            Assert.IsFalse(MethodProfiles.IsAllowed(null, "GetAllLogins"));
            Assert.IsFalse(MethodProfiles.IsAllowed("", "GetAllLogins"));
        }
    }
}
