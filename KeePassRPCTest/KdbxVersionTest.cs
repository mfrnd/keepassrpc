using System.Reflection;
using KeePassLib;
using KeePassLib.Serialization;
using KeePassRPC;
using KeePassRPC.Acl;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// What file format a database carrying grants has to be written as, asked of KeePass
    /// rather than assumed.
    ///
    /// KeePass does not keep the version a file was read as. When it saves, it calls
    /// <c>KdbxFile.GetMinKdbxVersion</c> and writes whatever that says the data needs, which
    /// is why a grant cannot be silently dropped for being too new for the file: the file
    /// follows the data. Calling that same function here turns "the minimum KDBX version" from
    /// a claim in a document into something the build checks.
    ///
    /// It also records the reason the database level was removed rather than kept: grants on
    /// groups and entries need KDBX 4.0, while a custom data item on the database carries a
    /// modification time, which is a 4.1 feature. Dropping that level lowered the floor.
    /// </summary>
    [TestFixture]
    public class KdbxVersionTest
    {
        private const uint Kdbx4 = 0x00040000;
        private const uint Kdbx4_1 = 0x00040001;

        private const string Document = "{\"version\":1,\"grants\":{\"docs-agent\":{\"verb\":\"read\"}}}";

        private static uint MinimumVersionFor(PwDatabase database)
        {
            KdbxFile file = new KdbxFile(database);
            MethodInfo method = typeof(KdbxFile).GetMethod("GetMinKdbxVersion",
                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance);
            Assert.IsNotNull(method, "KeePass no longer exposes GetMinKdbxVersion, so this "
                + "test can no longer answer what format grants require.");

            return (uint)method.Invoke(file, null);
        }

        private static PwDatabase Database()
        {
            PwDatabase database = new PwDatabase();
            database.RootGroup = new PwGroup(true, true);
            return database;
        }

        [Test]
        public void AGroupGrantNeedsKdbx4()
        {
            PwDatabase database = Database();
            database.RootGroup.CustomData.Set(AclDocument.CustomDataKey, Document);

            Assert.AreEqual(Kdbx4, MinimumVersionFor(database));
        }

        [Test]
        public void AnEntryGrantNeedsKdbx4()
        {
            PwDatabase database = Database();
            PwEntry entry = new PwEntry(true, true);
            database.RootGroup.AddEntry(entry, true);
            entry.CustomData.Set(AclDocument.CustomDataKey, Document);

            Assert.AreEqual(Kdbx4, MinimumVersionFor(database));
        }

        [Test]
        public void AGrantOnTheDatabaseItselfWouldHaveNeeded4Point1()
        {
            // Why the level was worth removing rather than keeping beside the root group: a
            // database custom data item is written with a modification time, and timestamped
            // custom data is what KDBX 4.1 added. Storing the same rule on the root group asks
            // one format version less of the file.
            PwDatabase database = Database();
            database.CustomData.Set(AclDocument.CustomDataKey, Document);

            Assert.AreEqual(Kdbx4_1, MinimumVersionFor(database));
        }

        [Test]
        public void TheMinimumKeePassIsTheOneThePackagedPluginAsksFor()
        {
            // 2.48, matching --plgx-prereq-kp:2.48 in KeePassRPC.csproj. A plain DLL install
            // gets no check from KeePass, so the plugin makes the same demand itself.
            Assert.AreEqual(0x0002003000000000UL, MinimumKeePass.Required);
            Assert.AreEqual("2.48", MinimumKeePass.RequiredText);
        }

        [Test]
        public void AnOlderKeePassIsRefusedAndANewerOneIsNot()
        {
            Assert.IsFalse(MinimumKeePass.Satisfied(0x0002002F00000000UL), "2.47 was accepted");
            Assert.IsTrue(MinimumKeePass.Satisfied(0x0002003000000000UL), "2.48 was refused");
            Assert.IsTrue(MinimumKeePass.Satisfied(0x0002003D00010000UL), "2.61.1 was refused");
            Assert.IsFalse(MinimumKeePass.Satisfied(0x0001003D00000000UL), "KeePass 1.x was accepted");
        }

        [Test]
        public void TheKeePassBeingBuiltAgainstSatisfiesIt()
        {
            Assert.IsTrue(MinimumKeePass.SatisfiedHere,
                "this build is compiled against a KeePass it would refuse to load into: "
                + PwDefs.VersionString);
        }
    }
}
