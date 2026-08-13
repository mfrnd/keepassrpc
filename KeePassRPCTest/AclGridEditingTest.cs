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
    /// What the grant table will and will not turn into a grant.
    ///
    /// The editor used to have a subject box, a verb box, two checkboxes and an "Add or
    /// update" button, so nothing was written until somebody pressed it. Editing in the table
    /// itself means the rows are the document, and every one of them has to be answered for:
    /// a row half typed is not a grant, and a client named twice is not resolved by picking
    /// one. Both of those are access decisions, so they are checked here rather than looked
    /// at once in a running KeePass.
    /// </summary>
    [TestFixture]
    public class AclGridEditingTest
    {
        // The table's columns: client name, identity, verb, attachments, unattended, forget.
        private const int Profile = 0;
        private const int Verb = 1;
        private const int Attachments = 2;
        private const int Unattended = 3;

        private static AclUserControl NewEditor(StringDictionaryEx customData)
        {
            return NewEditor(customData, new List<string>());
        }

        /// <summary>An editor over a level that inherits the given chain of grants.</summary>
        private static AclUserControl NewEditor(StringDictionaryEx customData,
            IList<string> inheritedChainRootFirst)
        {
            return new AclUserControl(customData, "scope", "the longer explanation", null,
                new List<string>(), inheritedChainRootFirst);
        }

        /// <summary>Type a row the way the grid's own editing does, cell by cell.</summary>
        private static DataGridViewRow TypeRow(AclUserControl editor, string subject, string verb,
            bool attachments, bool unattended)
        {
            DataGridViewRow row = editor.Grants.Rows[editor.Grants.Rows.Add()];
            row.Cells[Profile].Value = subject;
            row.Cells[Verb].Value = verb;
            row.Cells[Attachments].Value = attachments;
            row.Cells[Unattended].Value = unattended;
            return row;
        }

        private static AclDocument Stored(StringDictionaryEx customData)
        {
            return AclDocument.Parse(customData.Get(AclDocument.CustomDataKey));
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ARowTypedIntoTheTableIsStoredWithoutPressingAnything()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                TypeRow(editor, "agent-fictitious", "read", true, false);

                AclGrant grant = Stored(customData).GrantFor("agent-fictitious");
                Assert.IsNotNull(grant, "the row was never written back");
                Assert.AreEqual(AclVerb.Read, grant.Verb);
                Assert.IsTrue(grant.Attachments);
                Assert.IsFalse(grant.Unattended);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnExistingGrantIsShownAndCanBeNarrowedInPlace()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl seed = NewEditor(customData))
                TypeRow(seed, "agent-fictitious", "write", true, true);

            using (AclUserControl editor = NewEditor(customData))
            {
                Assert.AreEqual(1, RealRows(editor), "the stored grant did not appear");

                editor.Grants.Rows[0].Cells[Verb].Value = "list";
                editor.Grants.Rows[0].Cells[Attachments].Value = false;

                AclGrant grant = Stored(customData).GrantFor("agent-fictitious");
                Assert.AreEqual(AclVerb.List, grant.Verb);
                Assert.IsFalse(grant.Attachments);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ARowWithNoIdentityIsRefusedRatherThanGuessedAt()
        {
            // Half a row is somebody who has started and not finished. Storing it under an
            // empty subject would be a grant nobody asked for and nobody can see the owner of.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                DataGridViewRow row = TypeRow(editor, "   ", "write", false, false);

                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey),
                    "an unnamed row was written back as a grant");
                Assert.IsNotEmpty(row.ErrorText, "the row was dropped without saying so");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnIdentityNamedTwiceIsRefusedRatherThanResolved()
        {
            // Two rows for one client is ambiguous. Every possible answer, whether first
            // wins, last wins or widest wins, decides an access question on the reader's behalf.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                TypeRow(editor, "agent-fictitious", "list", false, false);
                DataGridViewRow second = TypeRow(editor, "agent-fictitious", "write", true, true);

                AclDocument stored = Stored(customData);
                Assert.AreEqual(1, stored.Count);
                Assert.AreEqual(AclVerb.List, stored.GrantFor("agent-fictitious").Verb,
                    "the duplicate silently widened the grant");
                Assert.IsNotEmpty(second.ErrorText, "the duplicate was dropped without saying so");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void DeletingTheLastRowRemovesTheKeyRatherThanStoringAnEmptyDocument()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                TypeRow(editor, "agent-fictitious", "read", false, false);
                Assert.IsTrue(customData.Exists(AclDocument.CustomDataKey));

                editor.Grants.Rows.RemoveAt(0);

                Assert.IsFalse(customData.Exists(AclDocument.CustomDataKey),
                    "an empty document was left behind, which reads as a deliberate rule");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ClosingTheEditorDoesNotLookLikeDeletingEveryGrant()
        {
            // Disposing the control clears the table, and clearing the table is how a row is
            // removed. Getting this wrong would wipe the grants of every dialog ever opened.
            StringDictionaryEx customData = new StringDictionaryEx();
            AclUserControl editor = NewEditor(customData);
            TypeRow(editor, "agent-fictitious", "read", false, false);
            editor.Dispose();

            Assert.IsTrue(customData.Exists(AclDocument.CustomDataKey),
                "closing the dialog removed the grants");
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void GrantsThatCannotBeReadAreNotEditable()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            customData.Set(AclDocument.CustomDataKey, "{ this is not the document we wrote");

            using (AclUserControl editor = NewEditor(customData))
            {
                Assert.IsTrue(editor.Unreadable);
                Assert.IsFalse(editor.Grants.Enabled, "an unreadable ACL was left editable");
                Assert.IsFalse(editor.Grants.AllowUserToAddRows);
                Assert.AreEqual("{ this is not the document we wrote",
                    customData.Get(AclDocument.CustomDataKey),
                    "an unreadable ACL was overwritten rather than refused");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void EveryColumnFitsInTheNarrowestDialogTheEditorIsAddedTo()
        {
            // The flags are the whole point of the table, and a horizontal scrollbar is where
            // they would go to be missed. The group dialog offers about 350px, which is not
            // enough for four honest columns, so the headers give way rather than the columns.
            using (AclUserControl editor = NewEditor(new StringDictionaryEx()))
            {
                editor.Size = new Size(350, 260);

                // RowHeadersWidth keeps its value while the headers are hidden, so it is
                // only counted when they are actually drawn.
                int total = editor.Grants.RowHeadersVisible ? editor.Grants.RowHeadersWidth : 0;
                foreach (DataGridViewColumn column in editor.Grants.Columns)
                    total += column.Width;


                // Measured against the width left once the vertical scrollbar has taken its
                // share, because that scrollbar arrives on the fourth grant and the columns
                // are not resized again when it does.
                Assert.LessOrEqual(total,
                    editor.Grants.ClientSize.Width - SystemInformation.VerticalScrollBarWidth,
                    "the grant table needs a horizontal scrollbar on the group dialog");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ARuleIsKeyedOnTheProfileNameItShows()
        {
            // What replaced picking a client by name and having the identity filled in beside
            // it. A rule names one thing now, and the thing it names is what it is stored
            // under: keying it on anything else would produce a rule matching no profile,
            // which denies silently.
            List<string> profiles = new List<string>();
            profiles.Add("release");

            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = new AclUserControl(customData, "scope",
                "the longer explanation", null, profiles, new List<string>()))
            {
                DataGridViewRow row = editor.Grants.Rows[editor.Grants.Rows.Add()];
                editor.ApplyNewRowDefaults(row);
                row.Cells[Profile].Value = "release";
                row.Cells[Verb].Value = "read";

                AclDocument stored = Stored(customData);
                Assert.AreEqual(1, stored.Count);
                Assert.IsNotNull(stored.GrantFor("release"),
                    "the rule was not stored under the profile it names");
            }

            using (AclUserControl reopened = new AclUserControl(customData, "scope",
                "the longer explanation", null, profiles, new List<string>()))
            {
                Assert.AreEqual("release", reopened.Grants.Rows[0].Cells[Profile].Value);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void TheWildcardIsOfferedAndGrantsToTheWildcard()
        {
            // Offered as itself. With one column of short names there is room for a literal
            // "*", where the two-column version had to spell it out in the name beside it.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                DataGridViewComboBoxColumn profiles =
                    (DataGridViewComboBoxColumn)editor.Grants.Columns[Profile];

                Assert.Contains(AclDocument.WildcardSubject, profiles.Items,
                    "the wildcard is not on the profile pick list");

                DataGridViewRow row = editor.Grants.Rows[editor.Grants.Rows.Add()];
                editor.ApplyNewRowDefaults(row);
                row.Cells[Profile].Value = AclDocument.WildcardSubject;

                Assert.IsNotNull(Stored(customData).GrantFor(AclDocument.WildcardSubject));
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnIdentityThatHasNeverPairedCanStillBeGranted()
        {
            // Deciding an agent's access before the agent exists is the normal order, so the
            // pick list has to stay typeable.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                TypeRow(editor, "agent-that-has-not-paired", "list", false, false);

                Assert.IsNotNull(Stored(customData).GrantFor("agent-that-has-not-paired"));
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ANewRowStartsAtTheVerbThatDenies()
        {
            // Naming a client and stopping there has to produce the safe rule, not the wide
            // one and not a row that is quietly thrown away.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                DataGridViewRow row = editor.Grants.Rows[editor.Grants.Rows.Add()];
                editor.ApplyNewRowDefaults(row);
                row.Cells[Profile].Value = "agent-fictitious";

                Assert.AreEqual(AclVerb.None,
                    Stored(customData).GrantFor("agent-fictitious").Verb);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void TheFlagTickboxesStayClickableAndTheIdentityGetsTheRest()
        {
            // The flag headers are one letter each so that these columns stop competing with
            // the identity for width. What they must not lose is the tickbox itself, which is
            // the only part of them a user actually operates.
            using (AclUserControl editor = NewEditor(new StringDictionaryEx()))
            {
                editor.Size = new Size(350, 260);

                int flags = 0;
                foreach (DataGridViewColumn column in editor.Grants.Columns)
                {
                    if (!(column is DataGridViewCheckBoxColumn))
                        continue;

                    flags++;
                    Assert.GreaterOrEqual(column.Width, 24,
                        column.HeaderText + " has no room left for its tickbox");
                    Assert.LessOrEqual(column.Width, 40,
                        column.HeaderText + " is taking width the identity needs");
                }

                Assert.AreEqual(2, flags);

                foreach (DataGridViewColumn column in editor.Grants.Columns)
                {
                    if (!(column is DataGridViewCheckBoxColumn))
                        continue;

                    Assert.AreEqual(DataGridViewContentAlignment.MiddleCenter,
                        column.HeaderCell.Style.Alignment,
                        column.HeaderText + " sits off to one side of the tickbox it labels");
                }

                Assert.Greater(editor.Grants.Columns[Profile].Width,
                    editor.Grants.Columns[Verb].Width,
                    "the profile is not the column with the most room");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void WhoARowIsAboutIsSettledOnceTheRowExists()
        {
            // Retyping the identity would move a grant from one client to another, which
            // reads as an edit and is really a revoke plus a grant. Removing the row and
            // adding another makes both halves of that visible.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                DataGridViewRow row = TypeRow(editor, "agent-fictitious", "read", false, false);

                Assert.IsTrue(row.Cells[Profile].ReadOnly, "the profile can still be retyped");
                Assert.IsFalse(row.Cells[Verb].ReadOnly, "the grant itself can no longer be changed");
                Assert.IsFalse(row.Cells[Attachments].ReadOnly);
                Assert.IsFalse(row.Cells[Unattended].ReadOnly);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ASettledRowShowsNoDropDownArrow()
        {
            // The arrow is an offer to pick, and on a settled row there is nothing to pick:
            // the cells are read-only. Most rows on a table are settled, so leaving the
            // arrows there put a control that does nothing on nearly every row.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                DataGridViewRow row = TypeRow(editor, "agent-fictitious", "read", false, false);

                Assert.AreEqual(DataGridViewComboBoxDisplayStyle.Nothing,
                    ((DataGridViewComboBoxCell)row.Cells[Profile]).DisplayStyle);

                // The verb and the flags stay editable, so they keep theirs.
                Assert.AreEqual(DataGridViewComboBoxDisplayStyle.DropDownButton,
                    ((DataGridViewComboBoxCell)row.Cells[Verb]).DisplayStyle);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void TheRowBeingFilledInKeepsItsArrow()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                DataGridViewRow row = editor.Grants.Rows[editor.Grants.Rows.Add()];
                editor.ApplyNewRowDefaults(row);

                Assert.AreEqual(DataGridViewComboBoxDisplayStyle.DropDownButton,
                    ((DataGridViewComboBoxCell)row.Cells[Profile]).DisplayStyle,
                    "a row with nobody named yet cannot be picked into");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnUnfinishedRowCanStillBeGivenAnIdentity()
        {
            // Only a row that names somebody is settled. One started and not finished has to
            // stay completable, or a stray click would strand a row nobody can fill in.
            StringDictionaryEx customData = new StringDictionaryEx();
            using (AclUserControl editor = NewEditor(customData))
            {
                DataGridViewRow row = editor.Grants.Rows[editor.Grants.Rows.Add()];
                editor.ApplyNewRowDefaults(row);

                Assert.IsFalse(row.Cells[Profile].ReadOnly);

                row.Cells[Profile].Value = "agent-fictitious";
                Assert.IsTrue(row.Cells[Profile].ReadOnly);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void TheIdentityListsDropDownWiderThanTheCellsTheyBelongTo()
        {
            // Profile names are short, but nothing stops one being long, and a list of
            // truncated names is one nobody can pick from with any confidence.
            string longest = "release-signing-and-deployment";
            List<string> known = new List<string>();
            known.Add(longest);

            using (AclUserControl editor = new AclUserControl(new StringDictionaryEx(), "scope",
                "the longer explanation", null, known, new List<string>()))
            {
                editor.Size = new Size(350, 260);

                DataGridViewComboBoxColumn profiles =
                    (DataGridViewComboBoxColumn)editor.Grants.Columns[Profile];
                int needed = TextRenderer.MeasureText(longest, editor.Font).Width;

                Assert.GreaterOrEqual(profiles.DropDownWidth, needed,
                    "the longest profile name is cut off in the list");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void TheVerbColumnIsWideEnoughForItsLongestValueAndNoWider()
        {
            // Trimmed on purpose, so the slack goes to the profile. The floor is what the
            // longest verb plus a drop-down button needs; below that a chosen "delete" is
            // clipped, and a clipped verb misreports what a client may do.
            using (AclUserControl editor = NewEditor(new StringDictionaryEx()))
            {
                editor.Size = new Size(491, 300);

                DataGridViewComboBoxColumn verb =
                    (DataGridViewComboBoxColumn)editor.Grants.Columns[Verb];
                int text = TextRenderer.MeasureText("delete", editor.Font, Size.Empty,
                    TextFormatFlags.NoPadding).Width;
                int button = SystemInformation.VerticalScrollBarWidth;

                Assert.GreaterOrEqual(verb.Width, text + button);
                Assert.LessOrEqual(verb.Width, text + button + 10,
                    "the verb column is padded well past what its values need");
            }
        }

        private static int RealRows(AclUserControl editor)
        {
            int count = 0;
            foreach (DataGridViewRow row in editor.Grants.Rows)
            {
                if (!row.IsNewRow)
                    count++;
            }

            return count;
        }
    }
}
