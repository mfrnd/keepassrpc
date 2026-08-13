using System;
using System.Collections.Generic;
using System.Threading;
using System.Windows.Forms;
using KeePassLib.Collections;
using KeePassRPC;
using KeePassRPC.Acl;
using KeePassRPC.Forms;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// What the grant editor must not write.
    ///
    /// The editor rebuilds its whole document and saves whenever the grid commits, and the
    /// grid commits for reasons that are not edits: entering the blank row fills in its
    /// defaults, leaving a row validates it. `StringDictionaryEx.Set` stamps a new
    /// modification time even for an identical value, so an unconditional write turned
    /// "open the entry, look at the ACL tab, press OK" into an unsaved change on a database
    /// the user had not touched. A password manager that reports changes nobody made is a
    /// password manager whose change indicator stops being read.
    ///
    /// The same guard keeps a purged ACL indistinguishable from one that never existed.
    /// </summary>
    [TestFixture]
    public class AclNoSpuriousWriteTest
    {
        private const int Profile = 0;
        private const int Verb = 1;

        private static AclUserControl Editor(StringDictionaryEx customData, params string[] above)
        {
            return new AclUserControl(customData, "scope", "the longer explanation", null,
                new List<string>(), new List<string>(above));
        }

        private static StringDictionaryEx Holding(string subject, AclVerb verb)
        {
            AclDocument document = new AclDocument();
            document.Set(subject, new AclGrant(verb, false, false));

            StringDictionaryEx customData = new StringDictionaryEx();
            customData.Set(AclDocument.CustomDataKey, document.ToJson());
            return customData;
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void OpeningATabWithGrantsOnItWritesNothing()
        {
            StringDictionaryEx customData = Holding("agent-fictitious", AclVerb.Read);
            using (AclUserControl editor = Editor(customData))
                Assert.AreEqual(0, editor.Writes, "merely showing the grants rewrote them");
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void CommittingWithoutChangingAnythingWritesNothing()
        {
            StringDictionaryEx customData = Holding("agent-fictitious", AclVerb.Read);
            using (AclUserControl editor = Editor(customData))
            {
                editor.CommitNow();
                editor.CommitNow();

                Assert.AreEqual(0, editor.Writes, "an unchanged document was written back");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void OpeningATabWithNoGrantsAtAllWritesNothing()
        {
            // The empty case is the one that used to call Remove on a key that was not there.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData))
            {
                editor.CommitNow();

                Assert.AreEqual(0, editor.Writes);
                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey));
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void OpeningATabThatOnlyInheritsWritesNothing()
        {
            // Inherited rows are shown but not owned, so a level that adds nothing of its own
            // has nothing to store, and storing it would freeze the parent's rule here.
            AclDocument above = new AclDocument();
            above.Set("agent-fictitious", new AclGrant(AclVerb.Read, false, false));

            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData, above.ToJson()))
            {
                editor.CommitNow();

                Assert.AreEqual(0, editor.Writes);
                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey),
                    "an inherited grant was copied down and marked the database modified");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ARealChangeIsStillWrittenExactlyOnce()
        {
            StringDictionaryEx customData = Holding("agent-fictitious", AclVerb.Read);
            using (AclUserControl editor = Editor(customData))
            {
                editor.Grants.Rows[0].Cells[Verb].Value = "list";

                Assert.AreEqual(1, editor.Writes, "the change was not written, or written twice");
                Assert.AreEqual(AclVerb.List,
                    AclDocument.Parse(customData.Get(AclDocument.CustomDataKey))
                        .GrantFor("agent-fictitious").Verb);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void PurgingTheLastGrantLeavesNoTraceThatOneWasEverThere()
        {
            StringDictionaryEx customData = Holding("agent-fictitious", AclVerb.Read);
            using (AclUserControl editor = Editor(customData))
            {
                editor.DiscardRow(editor.Grants.Rows[0]);

                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey),
                    "an empty document was left where the grants had been");
            }

            // And reopening it is then the same as opening a scope that never had one: no
            // rows, and nothing written.
            using (AclUserControl reopened = Editor(customData))
            {
                reopened.CommitNow();

                Assert.AreEqual(0, reopened.Writes);
                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey));
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnEmptyDocumentLeftByAnOlderBuildIsTidiedAway()
        {
            // Storing "no grants" as a document rather than as an absent key was the old
            // behaviour in one path. Reading it should clear it, because the two have to mean
            // the same thing and only one of them can be the spelling.
            StringDictionaryEx customData = new StringDictionaryEx();
            customData.Set(AclDocument.CustomDataKey, new AclDocument().ToJson());

            using (AclUserControl editor = Editor(customData))
            {
                editor.CommitNow();

                Assert.AreEqual(1, editor.Writes);
                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey));
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void GrantsThatCannotBeReadAreLeftExactlyAsFound()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            customData.Set(AclDocument.CustomDataKey, "{ this is not the document we wrote");

            using (AclUserControl editor = Editor(customData))
            {
                editor.CommitNow();

                Assert.AreEqual(0, editor.Writes);
                Assert.AreEqual("{ this is not the document we wrote",
                    customData.Get(AclDocument.CustomDataKey));
            }
        }
    }
}
