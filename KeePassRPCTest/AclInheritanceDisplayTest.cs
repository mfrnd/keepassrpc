using System;
using System.Collections.Generic;
using System.Drawing;
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
    /// What the grant table shows about rules it does not own, and what happens when one of
    /// them is overridden.
    ///
    /// The reason this is in the editor at all is that a tab showing only an entry's own
    /// grants reports an empty list for an entry a group grant already opens wide, and an
    /// operator reading that empty list is being invited to grant more. Once inherited rules
    /// are on screen, three things have to hold or the display is worse than none: they must
    /// not be written to this level, an override must only ever narrow, and taking an
    /// override back must restore the inherited rule rather than appear to delete it.
    /// </summary>
    [TestFixture]
    public class AclInheritanceDisplayTest
    {
        // The table's columns: client name, identity, verb, attachments, unattended.
        private const int Profile = 0;
        private const int Verb = 1;
        private const int Attachments = 2;
        private const int Unattended = 3;

        private static string DocumentWith(string subject, AclVerb verb, bool attachments,
            bool unattended)
        {
            AclDocument document = new AclDocument();
            document.Set(subject, new AclGrant(verb, attachments, unattended));
            return document.ToJson();
        }

        private static AclUserControl Editor(StringDictionaryEx customData, params string[] above)
        {
            return new AclUserControl(customData, "scope", "the longer explanation", null,
                new List<string>(), new List<string>(above));
        }

        private static DataGridViewRow RowFor(AclUserControl editor, string subject)
        {
            foreach (DataGridViewRow row in editor.Grants.Rows)
            {
                if (!row.IsNewRow && Convert.ToString(row.Cells[Profile].Value) == subject)
                    return row;
            }

            return null;
        }

        private static FontStyle StyleOf(DataGridViewRow row)
        {
            Font font = row.Cells[Profile].Style.Font;
            return font == null ? FontStyle.Regular : font.Style;
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnInheritedGrantIsShownInItalicAndIsNotWrittenToThisLevel()
        {
            // Writing it here would freeze a rule that is supposed to follow its group: change
            // the group afterwards and every entry ever opened would keep the old answer.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData,
                DocumentWith("agent-fictitious", AclVerb.Read, true, false)))
            {
                DataGridViewRow row = RowFor(editor, "agent-fictitious");
                Assert.IsNotNull(row, "the inherited grant is not shown at all");
                Assert.AreEqual("read", row.Cells[Verb].Value);
                Assert.AreEqual(FontStyle.Italic, StyleOf(row));

                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey),
                    "an inherited grant was copied into this level");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void NarrowingAnInheritedGrantStoresItHereAndTurnsItBold()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData,
                DocumentWith("agent-fictitious", AclVerb.Write, true, true)))
            {
                RowFor(editor, "agent-fictitious").Cells[Verb].Value = "list";

                AclGrant stored = AclDocument.Parse(customData.Get(AclDocument.CustomDataKey))
                    .GrantFor("agent-fictitious");
                Assert.IsNotNull(stored, "the override was not written");
                Assert.AreEqual(AclVerb.List, stored.Verb);
                Assert.AreEqual(FontStyle.Bold, StyleOf(RowFor(editor, "agent-fictitious")));
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AWideningOverrideIsRefusedRatherThanStored()
        {
            // Rights only narrow as they descend, so the resolver would ignore this anyway.
            // Storing it would leave something on screen saying more than the client can get.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData,
                DocumentWith("agent-fictitious", AclVerb.List, false, false)))
            {
                DataGridViewRow row = RowFor(editor, "agent-fictitious");
                row.Cells[Verb].Value = "write";

                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey),
                    "an override wider than the inherited grant was stored");
                Assert.IsNotEmpty(row.ErrorText, "the widening was dropped without saying so");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void TickingAFlagTheParentDoesNotHoldIsAlsoAWidening()
        {
            // The flags narrow by AND, so a tick the parent does not hold buys nothing either.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData,
                DocumentWith("agent-fictitious", AclVerb.Read, false, false)))
            {
                DataGridViewRow row = RowFor(editor, "agent-fictitious");
                row.Cells[Attachments].Value = true;

                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey));
                Assert.IsNotEmpty(row.ErrorText);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void DeletingAnOverrideRestoresTheInheritedGrantRatherThanRemovingTheRow()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData,
                DocumentWith("agent-fictitious", AclVerb.Read, true, false)))
            {
                DataGridViewRow row = RowFor(editor, "agent-fictitious");
                row.Cells[Verb].Value = "none";
                Assert.IsTrue(customData.Exists(AclDocument.CustomDataKey));

                editor.DiscardRow(row);

                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey),
                    "the override was not taken back");
                row = RowFor(editor, "agent-fictitious");
                Assert.IsNotNull(row, "the inherited rule disappeared with the override");
                Assert.AreEqual("read", row.Cells[Verb].Value,
                    "the inherited values were not restored");
                Assert.AreEqual(FontStyle.Italic, StyleOf(row));
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AGrantThatOnlyExistsHereIsUprightAndIsRemovedOutright()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData))
            {
                DataGridViewRow row = editor.Grants.Rows[editor.Grants.Rows.Add()];
                editor.ApplyNewRowDefaults(row);
                row.Cells[Profile].Value = "agent-fictitious";

                Assert.AreEqual(FontStyle.Regular, StyleOf(RowFor(editor, "agent-fictitious")));

                editor.DiscardRow(RowFor(editor, "agent-fictitious"));

                Assert.IsNull(RowFor(editor, "agent-fictitious"), "the row outlived its grant");
                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey));
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AWildcardHereDoesNotHideWhatIsInherited()
        {
            // The membership test used to be "GrantFor returns something", and GrantFor
            // answers with the wildcard grant for a subject that has no entry of its own.
            // So a level holding any * rule looked as though it named every client, and every
            // inherited row disappeared from a table whose whole job is to show them.
            AclDocument above = new AclDocument();
            above.Set("agent-fictitious", new AclGrant(AclVerb.Read, false, false));

            AclDocument here = new AclDocument();
            here.Set(AclDocument.WildcardSubject, new AclGrant(AclVerb.List, false, false));

            StringDictionaryEx customData = new StringDictionaryEx();
            customData.Set(AclDocument.CustomDataKey, here.ToJson());

            using (AclUserControl editor = Editor(customData, above.ToJson()))
            {
                Assert.IsNotNull(RowFor(editor, "agent-fictitious"),
                    "the inherited grant was hidden by the wildcard rule beside it");
                Assert.IsNotNull(RowFor(editor, AclDocument.WildcardSubject));
                Assert.AreEqual(FontStyle.Italic, StyleOf(RowFor(editor, "agent-fictitious")),
                    "the inherited row was reported as belonging to this level");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void TheWildcardSortsAboveEverythingElse()
        {
            // It is the rule about everyone that the others are exceptions to, so it reads as
            // the default the rest of the list then qualifies.
            AclDocument above = new AclDocument();
            above.Set("zebra-agent", new AclGrant(AclVerb.Read, false, false));
            above.Set(AclDocument.WildcardSubject, new AclGrant(AclVerb.List, false, false));
            above.Set("alpha-agent", new AclGrant(AclVerb.Read, false, false));

            using (AclUserControl editor = Editor(new StringDictionaryEx(), above.ToJson()))
            {
                Assert.AreEqual(AclDocument.WildcardSubject,
                    editor.Grants.Rows[0].Cells[Profile].Value);
                Assert.AreEqual("alpha-agent", editor.Grants.Rows[1].Cells[Profile].Value);
                Assert.AreEqual("zebra-agent", editor.Grants.Rows[2].Cells[Profile].Value);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void RowsSortByProfileNameRegardlessOfCase()
        {
            // Sorting is what a reader scans down, so it follows the name as written rather
            // than its bytes: "Release" belongs beside "release", not before every lowercase
            // name in the table.
            List<string> known = new List<string>();
            known.Add("Zulu");
            known.Add("alpha");

            AclDocument above = new AclDocument();
            above.Set("Zulu", new AclGrant(AclVerb.Read, false, false));
            above.Set("alpha", new AclGrant(AclVerb.Read, false, false));

            using (AclUserControl editor = new AclUserControl(new StringDictionaryEx(), "scope",
                "the longer explanation", null, known, new List<string>(new[] { above.ToJson() })))
            {
                Assert.AreEqual("alpha", editor.Grants.Rows[0].Cells[Profile].Value);
                Assert.AreEqual("Zulu", editor.Grants.Rows[1].Cells[Profile].Value);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ANarrowerRuleFurtherUpTheChainIsTheOneShown()
        {
            // Two levels above, and the tighter of them wins, which is the same rule the
            // resolver applies at call time. Showing the looser one would overstate the right.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData,
                DocumentWith("agent-fictitious", AclVerb.Write, true, true),
                DocumentWith("agent-fictitious", AclVerb.Read, false, true)))
            {
                DataGridViewRow row = RowFor(editor, "agent-fictitious");
                Assert.AreEqual("read", row.Cells[Verb].Value);
                Assert.AreEqual(false, row.Cells[Attachments].Value);
                Assert.AreEqual(true, row.Cells[Unattended].Value);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnUnreadableRuleAboveIsSaidRatherThanIgnored()
        {
            // A chain with an unintelligible link grants nothing at all, so a tab that quietly
            // showed the readable half would describe rights that are not in force.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = Editor(customData,
                "{ this is not the document we wrote",
                DocumentWith("agent-fictitious", AclVerb.Read, false, false)))
            {
                Assert.IsNull(RowFor(editor, "agent-fictitious"),
                    "a grant was shown as inherited through an unreadable level");
                Assert.IsTrue(editor.WarningShown, "nothing was said about the unreadable level");
            }
        }
    }
}
