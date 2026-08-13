using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeePassLib.Collections;
using KeePassRPC.Acl;
using KeePassRPC.Properties;

namespace KeePassRPC.Forms
{
    /// <summary>
    /// Edits the grants stored under <c>KeePassRPC.ACL</c> for one database, group or entry.
    ///
    /// This exists because <c>CustomData</c> is not editable in the stock KeePass dialogs, so
    /// without it no grant can be made at all and the whole ACL is inert. It is deliberately a
    /// tab of its own rather than an addition to upstream's <c>KeeEntryUserControl</c>: that
    /// control is 750 lines of upstream's, and threading a second concern through it would put
    /// this fork's diff in the path of every upstream change to it.
    ///
    /// Two behaviours here are security decisions rather than interface choices. An existing
    /// value that cannot be parsed disables editing instead of being silently replaced, because
    /// overwriting a grant nobody can read is destroying a rule that may be doing real work.
    /// And a database that is not KDBX4 is called out, because KeePass accepts a
    /// <c>CustomData</c> write on an older file and then does not persist it, so the grant would
    /// look made and be gone after the next save.
    /// </summary>
    public partial class AclUserControl : UserControl
    {
        private readonly StringDictionaryEx _customData;
        private AclDocument _document;
        private bool _unreadable;

        /// <summary>Puts the grants back if the dialog is dismissed.</summary>
        private readonly DismissalRevert _revert;

        /// <summary>Which way round this database reads. Storage is unaffected by it.</summary>
        private readonly AclDefault _mode;

        /// <summary>
        /// </summary>
        /// <param name="customData">
        /// The dictionary to edit. For an entry and for a group this is the dialog's own
        /// working copy, so the change follows that dialog's OK and Cancel; for a database it
        /// is the live object, because that dialog keeps no copy to write back.
        /// </param>
        /// <param name="scopeSummary">What this tab is editing, in one line.</param>
        /// <param name="scopeDetail">The rest of that explanation, shown on hover.</param>
        /// <param name="databasePath">
        /// Used only to check the storage format. Null or empty skips the check rather than
        /// warning about something unknown.
        /// </param>
        /// <param name="profiles">
        /// The profiles this database defines, for the pick list. A rule may still name one
        /// that is not on the list, which grants nobody anything until a profile by that name
        /// exists.
        /// </param>
        /// <param name="inheritedChainRootFirst">
        /// The raw grant documents above this level, root group first. Shown but not owned:
        /// nothing here writes to them.
        /// </param>
        public AclUserControl(StringDictionaryEx customData, string scopeSummary, string scopeDetail,
            string databasePath, IList<string> profiles,
            IList<string> inheritedChainRootFirst)
            : this(customData, scopeSummary, scopeDetail, databasePath, profiles,
                inheritedChainRootFirst, null, AclDefault.Deny)
        {
        }

        public AclUserControl(StringDictionaryEx customData, string scopeSummary, string scopeDetail,
            string databasePath, IList<string> profiles,
            IList<string> inheritedChainRootFirst, string unsaveableReason)
            : this(customData, scopeSummary, scopeDetail, databasePath, profiles,
                inheritedChainRootFirst, unsaveableReason, AclDefault.Deny)
        {
        }

        /// <param name="unsaveableReason">
        /// Why an edit made here could not be kept, or null when it can. Set, it shows the
        /// reason and locks the table: grants stay readable, which is the point of opening
        /// this tab, and nothing can be typed that would be thrown away on OK.
        /// </param>
        /// <param name="mode">
        /// Which way round the database reads. Rules are stored as allowances either way; this
        /// decides whether the table shows them as what a profile may do or as what it may
        /// not.
        /// </param>
        public AclUserControl(StringDictionaryEx customData, string scopeSummary, string scopeDetail,
            string databasePath, IList<string> profiles,
            IList<string> inheritedChainRootFirst, string unsaveableReason, AclDefault mode)
        {
            if (customData == null)
                throw new ArgumentNullException("customData");

            _mode = mode;

            _customData = customData;
            _revert = new DismissalRevert(customData, AclDocument.CustomDataKey);

            InitializeComponent();

            // The columns are sized to leave room for a scrollbar whether or not there is one
            // yet. This fills that room while there is not.
            RestingScrollBar.AttachTo(gridGrants);

            // What this level already inherits, worked out before anything is drawn, because
            // the table shows inherited rules alongside its own.
            _inherited = AclResolver.Effective(inheritedChainRootFirst);

            labelScope.Text = scopeSummary;

            // One line, with the rest a hover away. The full explanation ran to three or four
            // lines on every dialog, which is a lot of permanent height for something read
            // once; the tab it lives on is short and the grant list is what needs the room.
            _help = new Label();
            _help.AutoSize = true;
            _help.Text = "(?)";
            _help.ForeColor = SystemColors.HotTrack;
            _help.Cursor = Cursors.Help;
            Controls.Add(_help);

            _tips.AutoPopDelay = 32000;
            _tips.InitialDelay = 300;
            _tips.ReshowDelay = 100;
            _tips.SetToolTip(_help, Tooltips.Wrapped(scopeDetail));
            _tips.SetToolTip(labelScope, Tooltips.Wrapped(scopeDetail));

            // Headed and filled for the direction this database reads. The stored value is an
            // allowance whichever it is; only the words change.
            columnVerb.HeaderText = AclVerbView.Header(_mode);
            foreach (string item in AclVerbView.Items(_mode))
                columnVerb.Items.Add(item);

            // The headers are truncated on the narrow dialogs, so what they meant has to be
            // recoverable without widening a window.
            columnProfile.ToolTipText = Tooltips.Wrapped("The profile this rule is for, or * for "
                + "every profile not named here. Profiles are defined per database, on the "
                + "database settings dialog, and clients are put into them there. A client in "
                + "more than one profile holds the widest of what they grant.");
            columnVerb.ToolTipText = Tooltips.Wrapped(AclVerbView.Explanation(_mode));
            columnAttachments.ToolTipText = Tooltips.Wrapped("A (attachments). Attachment CONTENTS may "
                + "be read. Listing an attachment is part of reading the entry. Its contents "
                + "are not, because an attachment is usually the highest risk thing in a "
                + "database.");
            columnUnattended.ToolTipText = Tooltips.Wrapped("U (unattended). No confirmation prompt. "
                + "Without this, a write or an attachment read asks a human first.");
            columnForget.ToolTipText = Tooltips.Wrapped("D (delete). The X removes a rule this "
                + "level stores. On a rule narrowed from an inherited one it puts the "
                + "inherited rule back. A rule that is purely inherited has no X, because "
                + "there is nothing here to remove.");

            // Offer the profiles this database defines. Granting is then a choice rather than
            // a spelling test: a mistyped profile grants to nobody and reports nothing, which
            // is indistinguishable from having granted nothing at all.
            //
            // The wildcard is offered alongside them because it is a legitimate thing to
            // write here, and it is shown as itself: one column of short names has room for a
            // literal "*", where the two-column version needed a phrase.
            Offer(AclDocument.WildcardSubject);
            foreach (string profile in profiles)
                Offer(profile);

            gridGrants.EditingControlShowing += gridGrants_EditingControlShowing;
            gridGrants.CurrentCellDirtyStateChanged += gridGrants_CurrentCellDirtyStateChanged;
            gridGrants.CellValidating += gridGrants_CellValidating;
            gridGrants.CellValueChanged += gridGrants_CellValueChanged;
            gridGrants.RowValidated += delegate { CommitGrid(); };
            gridGrants.RowsRemoved += delegate { CommitGrid(); };
            gridGrants.DataError += gridGrants_DataError;
            gridGrants.DefaultValuesNeeded += gridGrants_DefaultValuesNeeded;
            gridGrants.CellMouseDown += gridGrants_CellMouseDown;
            gridGrants.CellContentClick += gridGrants_CellContentClick;
            gridGrants.UserDeletingRow += gridGrants_UserDeletingRow;

            // Delete already removes a selected row, but selecting one means finding the
            // narrow strip down the left-hand side, because clicking a cell starts editing
            // it. A right-click menu is the obvious place to look, and revoking access should
            // not be the hard half of this editor.
            _rowMenu = new ContextMenuStrip();
            _removeItem = new ToolStripMenuItem("Remove this grant");
            _removeItem.Click += removeItem_Click;
            _rowMenu.Items.Add(_removeItem);

            Load(databasePath, unsaveableReason);
            LayOutRows();
        }

        private void Load(string databasePath, string unsaveableReason)
        {
            if (!_customData.Exists(AclDocument.CustomDataKey))
            {
                _document = new AclDocument();
            }
            else
            {
                _document = AclDocument.Parse(_customData.Get(AclDocument.CustomDataKey));
                if (_document == null)
                {
                    _unreadable = true;
                    ShowWarning("The existing grants here cannot be read, so they are being refused "
                        + "outright and nothing can be edited until they are discarded. Refusing is the "
                        + "safe reading: an unintelligible grant might be doing real work.");
                    SetEditingEnabled(false);
                    buttonDiscard.Visible = true;
                    return;
                }
            }

            if (_inherited == null)
            {
                ShowWarning("Rules above this level cannot be read, so nothing is being inherited "
                    + "and every client is refused here regardless of what this tab says. Fix the "
                    + "rules on the groups above first.");
            }

            if (!string.IsNullOrEmpty(databasePath) && !KdbxFormat.SupportsCustomData(databasePath))
            {
                ShowWarning("This database is an older KDBX than version 4. Grants are stored in "
                    + "CustomData, which KDBX 4 introduced, so saving one rewrites this database as "
                    + "KDBX 4. Nothing is lost, but KeePass 2.34 and older cannot open the file "
                    + "afterwards.");
            }

            // Last of the warnings, and deliberately so: where more than one applies, this is
            // the one that says an edit cannot be kept at all, so it is the one worth reading.
            if (!string.IsNullOrEmpty(unsaveableReason))
            {
                ShowWarning(unsaveableReason);
                SetEditingEnabled(false);
            }

            Populate();
        }

        private void ShowWarning(string text)
        {
            labelWarning.Text = text;
            labelWarning.Visible = true;
        }

        private void SetEditingEnabled(bool enabled)
        {
            gridGrants.Enabled = enabled;
            gridGrants.AllowUserToAddRows = enabled;
            gridGrants.AllowUserToDeleteRows = enabled;
        }

        /// <summary>
        /// Add a profile to the pick list.
        ///
        /// A name that is not in the database's registry can still appear here, because a
        /// stored rule may name a profile that has since been deleted, and a combo cell
        /// refuses a value its list does not hold. Offering it keeps the rule visible and
        /// editable instead of raising a data error over somebody else's dialog. It grants
        /// nobody anything while no profile by that name exists.
        /// </summary>
        private void Offer(string profile)
        {
            if (string.IsNullOrEmpty(profile) || columnProfile.Items.Contains(profile))
                return;

            columnProfile.Items.Add(profile);
        }

        /// <summary>
        /// Fill the table with this level's own grants and with what it inherits.
        ///
        /// Both, in one table, because they are one answer. A tab that showed only the local
        /// grants would report an empty list for an entry that a group grant already opens
        /// wide, and an operator reading that empty list is being invited to grant more.
        /// </summary>
        private void Populate()
        {
            _populating = true;
            try
            {
                gridGrants.Rows.Clear();

                List<string> subjects = new List<string>();
                foreach (string subject in _document.Subjects)
                    subjects.Add(subject);

                if (_inherited != null)
                {
                    foreach (KeyValuePair<string, AclGrant> above in _inherited)
                    {
                        if (!OwnedHere(above.Key))
                            subjects.Add(above.Key);
                    }
                }

                subjects.Sort(CompareForDisplay);

                foreach (string subject in subjects)
                {
                    AclGrant grant;
                    if (OwnedHere(subject))
                        AddRow(subject, _document.GrantFor(subject), true);
                    else if (_inherited != null && _inherited.TryGetValue(subject, out grant))
                        AddRow(subject, grant, false);
                }

                Restyle();
            }
            finally
            {
                _populating = false;
            }
        }

        /// <summary>
        /// Whether this level names the subject itself.
        ///
        /// Not <c>GrantFor(subject) != null</c>, which is what this used to ask.
        /// <see cref="AclDocument.GrantFor"/> answers with the wildcard grant for a subject
        /// that has no entry of its own, quite rightly, since that is what resolution does.
        /// Used as a membership test it meant that a level holding any <c>*</c> rule looked
        /// as though it named every client, and every inherited row vanished from the table.
        /// </summary>
        private bool OwnedHere(string subject)
        {
            return subject != null && _document.Subjects.Contains(subject);
        }

        /// <summary>
        /// The order rows are shown in: the wildcard first, then by profile name.
        ///
        /// The wildcard is pinned because it is the rule about everyone the others are
        /// exceptions to, so it reads as the default the list then qualifies. The rest sort
        /// case-insensitively, with ties broken exactly, so the order cannot wobble.
        /// </summary>
        private int CompareForDisplay(string one, string other)
        {
            bool oneIsWildcard = one == AclDocument.WildcardSubject;
            if (oneIsWildcard != (other == AclDocument.WildcardSubject))
                return oneIsWildcard ? -1 : 1;

            int byName = string.Compare(one, other, StringComparison.OrdinalIgnoreCase);
            return byName != 0 ? byName : string.Compare(one, other, StringComparison.Ordinal);
        }

        /// <summary>One row, remembering whether this level owns it or merely shows it.</summary>
        private void AddRow(string subject, AclGrant grant, bool local)
        {
            Offer(subject);

            int index = gridGrants.Rows.Add(subject,
                AclVerbView.Text(grant.Verb, _mode), grant.Attachments, grant.Unattended);
            gridGrants.Rows[index].Tag = new RowOwnership(local);
        }

        /// <summary>
        /// Whether this level stores the row, as opposed to only displaying it.
        ///
        /// A class rather than a boxed bool so that a row can be marked local when it is
        /// edited without replacing the tag and losing track of which row it was.
        /// </summary>
        private sealed class RowOwnership
        {
            public bool Local;

            public RowOwnership(bool local)
            {
                Local = local;
            }
        }

        private static RowOwnership OwnershipOf(DataGridViewRow row)
        {
            RowOwnership ownership = row.Tag as RowOwnership;
            if (ownership == null)
            {
                // A row the user started typing into. Anything they author is theirs.
                ownership = new RowOwnership(true);
                row.Tag = ownership;
            }

            return ownership;
        }

        /// <summary>
        /// The grant this row would inherit if it stored nothing, or null if it inherits
        /// nothing. Looked up live, because the identity cell can be edited.
        /// </summary>
        private AclGrant InheritedFor(DataGridViewRow row)
        {
            if (_inherited == null)
                return null;

            AclGrant above;
            return _inherited.TryGetValue(SubjectOf(row), out above) ? above : null;
        }

        /// <summary>
        /// Say in the identity cell where each rule comes from: italic for one inherited and
        /// left alone, bold for one inherited and overridden here, upright for one that only
        /// exists here.
        ///
        /// Worth the weight it costs on screen. The three cases behave differently on the way
        /// out as well as the way in: deleting an override restores the inherited rule rather
        /// than removing anything, and an inherited row cannot be deleted from here at all.
        /// </summary>
        private void Restyle()
        {
            foreach (DataGridViewRow row in gridGrants.Rows)
            {
                if (row.IsNewRow)
                    continue;

                bool local = OwnershipOf(row).Local;
                AclGrant above = InheritedFor(row);

                FontStyle style = !local ? FontStyle.Italic
                    : above != null ? FontStyle.Bold : FontStyle.Regular;

                DataGridViewCellStyle cell = row.Cells[ProfileColumn].Style;
                if (cell.Font == null || cell.Font.Style != style)
                    cell.Font = new Font(Font, style);

                // Who a row is about is settled when the row is made. Retyping it would
                // silently move a grant from one profile to another, which reads as an edit
                // and is really a revoke plus a grant; removing the row and adding another
                // makes both halves of that visible.
                bool named = SubjectOf(row).Length > 0;

                // The tooltip is the cell's own text in full, not an explanation of the
                // column. A profile name is shorter than the identity this column used to
                // hold, but the group dialog is narrow enough to truncate one, and the
                // truncated half is what a reader hovers to recover. What the column means is
                // on its header, where a description belongs and is not in the way.
                LockIdentity(row, ProfileColumn, named, SubjectOf(row));

                // The X appears only where there is something to take back. A purely
                // inherited row has nothing here to remove, and offering one would promise a
                // deletion this level cannot make.
                row.Cells[ForgetColumn].Value = local ? ForgetMark : string.Empty;
                row.Cells[ForgetColumn].ToolTipText = local
                    ? Tooltips.Wrapped(above != null
                        ? "Reset this profile to the rule it inherits."
                        : "Remove this rule.")
                    : string.Empty;
            }
        }

        /// <summary>
        /// Rebuild the document from the grid and write it back.
        ///
        /// The grid is the document: rather than tracking which cell changed, the whole thing
        /// is read back whenever anything is committed. There are a handful of rows and this
        /// runs on a keystroke boundary, so the simplicity is worth more than the saving.
        ///
        /// Rows that would not make a grant are skipped and marked rather than guessed at. An
        /// empty identity is a row somebody has started and not finished; a repeated identity
        /// is ambiguous, and choosing one of the two silently would decide an access question
        /// on the reader's behalf.
        ///
        /// Only rows this level owns are written. The inherited ones are on display, and
        /// writing them here would freeze a rule that is supposed to follow its group: change
        /// the group afterwards and every entry ever opened would quietly keep the old answer.
        /// </summary>
        private void CommitGrid()
        {
            // Removing a row commits, and disposing the control removes every row. Without
            // this the dialog closing would look like the user having deleted every grant,
            // and the last thing written would be the key's removal.
            if (_populating || _unreadable || Disposing || IsDisposed)
                return;

            AclDocument rebuilt = new AclDocument();

            // The root group's document carries the database's starting point and its profile
            // registry as well as its grants, and this table knows about none of that. It is
            // carried across rather than rebuilt, because rebuilding the document from a grid
            // that never showed those parts would delete them: the first edit to a rule on
            // the root group would silently put an allow-by-default database back to denying
            // and empty its list of profiles.
            rebuilt.Default = _document.Default;
            rebuilt.Profiles = _document.Profiles;

            List<string> seen = new List<string>();

            foreach (DataGridViewRow row in gridGrants.Rows)
            {
                if (row.IsNewRow)
                    continue;

                Flag(row, null);
                string subject = SubjectOf(row);

                if (subject.Length == 0)
                {
                    if (RowHasAnything(row))
                        Flag(row, "Name the profile this rule is for, or * for every other profile.");
                    continue;
                }

                if (seen.Contains(subject))
                {
                    Flag(row, "This profile already has a rule above. Remove one of them.");
                    continue;
                }

                AclVerb verb;
                if (!AclVerbView.TryParse(Convert.ToString(row.Cells[VerbColumn].Value), _mode, out verb))
                {
                    Flag(row, "Choose what this profile may do.");
                    continue;
                }

                seen.Add(subject);
                if (!OwnershipOf(row).Local)
                    continue;

                AclGrant grant = new AclGrant(verb,
                    IsChecked(row.Cells[AttachmentsColumn]), IsChecked(row.Cells[UnattendedColumn]));
                AclGrant above = InheritedFor(row);
                if (above != null && !IsNarrowerOrEqual(grant, above))
                {
                    // Rights only narrow as they descend, so a wider override is not a rule,
                    // it is a misunderstanding. Storing it would leave something on screen
                    // that says more than the client will ever get.
                    Flag(row, "Wider than this profile inherits, which is "
                        + AclVerbView.Describe(above, _mode)
                        + ". A rule here can only narrow what the groups above already allow.");
                    continue;
                }

                rebuilt.Set(subject, grant);
            }

            _document = rebuilt;
            Save();
            Restyle();
        }

        /// <summary>Whether <paramref name="grant"/> asks for no more than <paramref name="above"/>.</summary>
        private static bool IsNarrowerOrEqual(AclGrant grant, AclGrant above)
        {
            return grant.Verb <= above.Verb
                && (!grant.Attachments || above.Attachments)
                && (!grant.Unattended || above.Unattended);
        }

        /// <summary>
        /// The identity a row grants to: what the pick list shows, resolved back to what the
        /// ACL is keyed on. Anything typed by hand stands for itself.
        /// </summary>
        private string SubjectOf(DataGridViewRow row)
        {
            string subject = Convert.ToString(row.Cells[ProfileColumn].Value);
            return subject == null ? string.Empty : subject.Trim();
        }

        // Column positions, named because five indices in a row read as noise otherwise.
        private const int ProfileColumn = 0;
        private const int VerbColumn = 1;
        private const int AttachmentsColumn = 2;
        private const int UnattendedColumn = 3;
        private const int ForgetColumn = 4;

        /// <summary>What the last column shows on a row this level owns.</summary>
        private const string ForgetMark = "X";

        /// <summary>
        /// Mark a row that is not being turned into a grant, or clear the mark.
        ///
        /// On the identity cell as well as the row header. A row header 24px wide has room
        /// for the current-row arrow and not much else, so its error glyph is easy to miss --
        /// and a row that looks stored and is not is the one failure this editor must never
        /// have.
        /// </summary>
        private static void Flag(DataGridViewRow row, string problem)
        {
            string text = problem == null ? string.Empty : problem;
            row.ErrorText = text;
            row.Cells[ProfileColumn].ErrorText = text;
        }

        private static bool RowHasAnything(DataGridViewRow row)
        {
            for (int i = 0; i < row.Cells.Count; i++)
            {
                if (i != ProfileColumn && row.Cells[i].Value != null)
                    return true;
            }

            return false;
        }

        private static bool IsChecked(DataGridViewCell cell)
        {
            return cell.Value != null && Convert.ToBoolean(cell.Value);
        }

        /// <summary>
        /// Write the document back, or remove the key when nothing is granted.
        ///
        /// An empty document is removed rather than stored, because absence is already the
        /// natural spelling of "no rule here" and leaving an empty one behind would suggest a
        /// deliberate statement that was not made.
        /// </summary>
        private void Save()
        {
            string stored = _customData.Exists(AclDocument.CustomDataKey)
                ? _customData.Get(AclDocument.CustomDataKey)
                : null;

            // No grants is the absent key, never an empty document. An ACL that has been
            // purged from a database, group or entry has to be indistinguishable from one
            // that was never there: an empty document left behind would read as somebody
            // having deliberately said "nothing", and would keep a KDBX4 modification time
            // for a rule that no longer exists.
            // IsEmpty, not "no grants": the root group's document also carries the database's
            // default, and removing the key because the last grant was deleted would silently
            // put an allow-by-default database back to denying everything.
            string wanted = _document.IsEmpty ? null : _document.ToJson();

            if (Unchanged(stored, wanted))
                return;

            if (wanted == null)
                _customData.Remove(AclDocument.CustomDataKey);
            else
                _customData.Set(AclDocument.CustomDataKey, wanted);

            _writes++;
        }

        /// <summary>
        /// Whether storing <paramref name="wanted"/> would change anything.
        ///
        /// This is what stops merely opening a dialog from marking the database as modified.
        /// The editor rebuilds its whole document and saves whenever the grid commits, and
        /// the grid commits for reasons that are not edits: entering the blank row fills in
        /// its defaults, leaving a row validates it. `StringDictionaryEx.Set` stamps a new
        /// modification time even when the value is identical, so an unconditional write
        /// turned "look at the ACL tab and press OK" into an unsaved change, on a database
        /// the user had not touched.
        ///
        /// Compared through the parser as well as literally, so a document written by hand
        /// that differs only in spacing or key order is not rewritten just for being read.
        /// </summary>
        private static bool Unchanged(string stored, string wanted)
        {
            if (stored == null || wanted == null)
                return stored == null && wanted == null;

            if (stored == wanted)
                return true;

            AclDocument parsed = AclDocument.Parse(stored);
            return parsed != null && parsed.ToJson() == wanted;
        }

        /// <summary>How many times this editor has actually written. For the tests.</summary>
        internal int Writes
        {
            get { return _writes; }
        }

        /// <summary>
        /// Commit as though the grid had raised one of the events that commit. For the tests,
        /// which need to exercise a commit that changes nothing.
        /// </summary>
        internal void CommitNow()
        {
            CommitGrid();
        }

        private int _writes;

        /// <summary>
        /// Let the identity cell be typed into as well as picked from.
        ///
        /// A combo box column is a closed list by default, and this one cannot be: a client
        /// that has not paired yet still has to be grantable, and pairing it afterwards is
        /// the normal order for an agent that does not exist at the time its access is
        /// decided.
        /// </summary>
        private void gridGrants_EditingControlShowing(object sender, DataGridViewEditingControlShowingEventArgs e)
        {
            ComboBox box = e.Control as ComboBox;
            if (box == null || gridGrants.CurrentCell == null
                || gridGrants.CurrentCell.ColumnIndex != ProfileColumn)
            {
                return;
            }

            box.DropDownStyle = ComboBoxStyle.DropDown;
            box.AutoCompleteMode = AutoCompleteMode.SuggestAppend;
            box.AutoCompleteSource = AutoCompleteSource.ListItems;
        }

        /// <summary>
        /// A change to an inherited row makes it this level's own.
        ///
        /// That is what "override" means here, and doing it on the first edit rather than
        /// through a separate command keeps the table honest: a row shown in bold is one this
        /// level stores, and it went bold the moment it was touched.
        /// </summary>
        private void gridGrants_CellValueChanged(object sender, DataGridViewCellEventArgs e)
        {
            // The X is drawn by Restyle, not typed by anybody. Without this, redrawing it
            // counted as an edit, which marked the row as belonging to this level and wrote
            // back the very override that had just been taken away.
            if (e.ColumnIndex == ForgetColumn)
                return;

            if (!_populating && e.RowIndex >= 0 && e.RowIndex < gridGrants.Rows.Count)
                OwnershipOf(gridGrants.Rows[e.RowIndex]).Local = true;

            CommitGrid();
        }

        /// <summary>
        /// Right-clicking a row selects it and offers to remove it.
        ///
        /// Selecting first matters: without it the menu would act on whatever happened to be
        /// current, which on this grid is a rule about who may read a password.
        /// </summary>
        /// <summary>The red X, which does what the right-click menu does.</summary>
        private void gridGrants_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.ColumnIndex != ForgetColumn || e.RowIndex < 0
                || e.RowIndex >= gridGrants.Rows.Count)
            {
                return;
            }

            DataGridViewRow row = gridGrants.Rows[e.RowIndex];
            if (row.IsNewRow || !OwnershipOf(row).Local)
                return;

            DiscardRow(row);
        }

        private void gridGrants_CellMouseDown(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.Button != MouseButtons.Right || !gridGrants.Enabled)
                return;

            if (e.RowIndex < 0 || gridGrants.Rows[e.RowIndex].IsNewRow)
                return;

            gridGrants.EndEdit();
            gridGrants.ClearSelection();
            gridGrants.Rows[e.RowIndex].Selected = true;
            gridGrants.CurrentCell = gridGrants.Rows[e.RowIndex].Cells[ProfileColumn];

            DataGridViewRow row = gridGrants.Rows[e.RowIndex];
            string subject = SubjectOf(row);
            bool local = OwnershipOf(row).Local;
            bool inherited = InheritedFor(row) != null;

            _removeItem.Enabled = local;
            _removeItem.Text = !local
                ? "Inherited from above, so it cannot be removed here"
                : inherited
                    ? "Reset " + subject + " to the inherited grant"
                    : "Remove the grant for " + subject;

            _rowMenu.Show(gridGrants, gridGrants.PointToClient(Cursor.Position));
        }

        private void removeItem_Click(object sender, EventArgs e)
        {
            if (gridGrants.CurrentRow == null || gridGrants.CurrentRow.IsNewRow)
                return;

            DiscardRow(gridGrants.CurrentRow);
        }

        /// <summary>
        /// Take back what this level says about a row.
        ///
        /// For a row that only exists here, that removes it. For one that overrides something
        /// inherited, it puts the inherited values back and leaves the row in place, because
        /// the rule itself is not this level's to delete. Both are the same gesture from the
        /// user's side, and both are the safe direction: they can only narrow what is in
        /// force or leave it unchanged.
        /// </summary>
        internal void DiscardRow(DataGridViewRow row)
        {
            AclGrant above = InheritedFor(row);
            if (above == null)
            {
                gridGrants.Rows.Remove(row);
                return;
            }

            _populating = true;
            try
            {
                OwnershipOf(row).Local = false;
                row.Cells[VerbColumn].Value = AclVerbView.Text(above.Verb, _mode);
                row.Cells[AttachmentsColumn].Value = above.Attachments;
                row.Cells[UnattendedColumn].Value = above.Unattended;
                Flag(row, null);
            }
            finally
            {
                _populating = false;
            }

            CommitGrid();
        }

        /// <summary>
        /// Delete does the same as the menu, including on a row that is only inherited, where
        /// it does nothing at all.
        ///
        /// The grid's own handling would remove the row from the table, which for an
        /// inherited rule would show it revoked while it carried on applying. Cancelling and
        /// routing through <see cref="DiscardRow"/> keeps the table and the stored rules in step.
        /// </summary>
        private void gridGrants_UserDeletingRow(object sender, DataGridViewRowCancelEventArgs e)
        {
            e.Cancel = true;
            if (e.Row == null || e.Row.IsNewRow || !OwnershipOf(e.Row).Local)
                return;

            DiscardRow(e.Row);
        }

        /// <summary>
        /// Settle one of the identity cells, unless it is the one being typed in right now.
        ///
        /// Locking a cell mid-edit ends that edit under the user's hands, and this runs on
        /// every committed keystroke, so the cell they are in is left alone and settles as
        /// soon as they leave it.
        /// </summary>
        private void LockIdentity(DataGridViewRow row, int column, bool settled, string tip)
        {
            DataGridViewCell cell = row.Cells[column];
            cell.ToolTipText = tip;

            bool beingEdited = gridGrants.IsCurrentCellInEditMode
                && gridGrants.CurrentCell != null
                && gridGrants.CurrentCell.RowIndex == row.Index
                && gridGrants.CurrentCell.ColumnIndex == column;

            if (beingEdited)
                return;

            if (cell.ReadOnly != settled)
                cell.ReadOnly = settled;

            // And take the drop-down arrow away with the editing. A button that opens nothing
            // is an offer the cell cannot honour, and on a table where most rows are settled
            // it was most of the arrows on screen. The blank row at the bottom keeps its
            // arrow, which is the only row where picking is still a thing you can do.
            DataGridViewComboBoxCell list = cell as DataGridViewComboBoxCell;
            if (list == null)
                return;

            DataGridViewComboBoxDisplayStyle style = settled
                ? DataGridViewComboBoxDisplayStyle.Nothing
                : DataGridViewComboBoxDisplayStyle.DropDownButton;

            if (list.DisplayStyle != style)
                list.DisplayStyle = style;
        }

        /// <summary>
        /// Let the profile list drop down wider than the cell it belongs to, if it needs to.
        ///
        /// It rarely does now that the column holds a profile name rather than an identity
        /// that could be a GUID, but a list of truncated names is one nobody can pick from
        /// with confidence and the cell stays as narrow as the table needs either way.
        /// </summary>
        private void SizeDropDowns()
        {
            columnProfile.DropDownWidth = WidestItem(columnProfile);
        }

        /// <summary>
        /// How wide a list has to be to show its longest entry whole, never narrower than the
        /// column it drops out of and never wider than the screen it opens on.
        /// </summary>
        private int WidestItem(DataGridViewComboBoxColumn column)
        {
            int widest = column.Width;
            foreach (object item in column.Items)
            {
                int needs = TextRenderer.MeasureText(Convert.ToString(item), Font).Width;
                if (needs > widest)
                    widest = needs;
            }

            // Room for the scrollbar the list grows when there are more clients than fit.
            widest += SystemInformation.VerticalScrollBarWidth + 8;

            int ceiling = Screen.GetWorkingArea(this).Width - 40;
            return widest > ceiling ? ceiling : widest;
        }

        /// <summary>
        /// Accept an identity that is not on the list.
        ///
        /// A combo cell refuses a value its list does not hold, and refuses it by throwing a
        /// data error over the host dialog. Adding what was typed to the list first turns
        /// that into an ordinary commit. The entry is only a suggestion, so nothing is granted
        /// by its presence.
        /// </summary>
        private void gridGrants_CellValidating(object sender, DataGridViewCellValidatingEventArgs e)
        {
            string typed = Convert.ToString(e.FormattedValue);
            if (typed == null)
                return;

            typed = typed.Trim();
            if (typed.Length == 0)
                return;

            if (e.ColumnIndex == ProfileColumn)
                Offer(typed);
        }

        /// <summary>
        /// Commit a checkbox or a chosen verb as soon as it changes.
        ///
        /// Without this a tick is only committed when the cell loses focus, so closing the
        /// dialog straight after clicking one would lose it. Silently, and in the permissive
        /// direction if the tick was being cleared.
        /// </summary>
        private void gridGrants_CurrentCellDirtyStateChanged(object sender, EventArgs e)
        {
            if (!gridGrants.IsCurrentCellDirty || gridGrants.CurrentCell == null)
                return;

            if (gridGrants.CurrentCell is DataGridViewCheckBoxCell
                || gridGrants.CurrentCell is DataGridViewComboBoxCell)
            {
                gridGrants.CommitEdit(DataGridViewDataErrorContexts.Commit);
            }
        }

        /// <summary>
        /// Start a new row at "none" rather than at nothing.
        ///
        /// A row is only a grant once a verb has been picked, so an unset one has to be
        /// refused, and a row silently refused for a reason sitting in the row header is a
        /// poor way to say so. Defaulting to the tightest value means naming a profile and
        /// stopping there produces a rule that is both valid and the safe one. It also makes
        /// "shut this profile out here", which is the point of a narrowing ACL, two clicks.
        /// </summary>
        private void gridGrants_DefaultValuesNeeded(object sender, DataGridViewRowEventArgs e)
        {
            ApplyNewRowDefaults(e.Row);
        }

        /// <summary>
        /// What a row holds before anything has been said about it. Its own method because
        /// the grid only raises the event above from a real click, and this is a rule worth
        /// a test.
        /// </summary>
        internal void ApplyNewRowDefaults(DataGridViewRow row)
        {
            row.Cells[VerbColumn].Value = AclVerbView.Text(AclVerb.None, _mode);
            row.Cells[AttachmentsColumn].Value = false;
            row.Cells[UnattendedColumn].Value = false;
        }

        /// <summary>
        /// Never let a cell error reach the user as a dialog.
        ///
        /// This control is inside somebody else's entry dialog; an unhandled data error there
        /// throws a message box over it, and repeatedly.
        /// </summary>
        private void gridGrants_DataError(object sender, DataGridViewDataErrorEventArgs e)
        {
            e.ThrowException = false;
            if (e.RowIndex >= 0 && e.RowIndex < gridGrants.Rows.Count)
                Flag(gridGrants.Rows[e.RowIndex], "That value cannot be used here.");
        }

        private void buttonDiscard_Click(object sender, EventArgs e)
        {
            DialogResult confirmed = MessageBox.Show(
                "Discard the unreadable grants stored here and start from nothing?\n\n"
                + "Whatever they said is currently being refused, so nothing is being granted by them, "
                + "but they may still be a record of an intended rule. This cannot be undone.",
                "Discard grants", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);

            if (confirmed != DialogResult.Yes)
                return;

            _document = new AclDocument();
            _unreadable = false;
            labelWarning.Visible = false;
            buttonDiscard.Visible = false;
            SetEditingEnabled(true);
            Populate();
            Save();
            LayOutRows();
        }

        /// <summary>Whether the tab is telling the user something is wrong. For the tests.</summary>
        internal bool WarningShown
        {
            get { return labelWarning.Visible; }
        }

        /// <summary>Whether the stored grants could not be read.</summary>
        public bool Unreadable
        {
            get { return _unreadable; }
        }

        /// <summary>
        /// The grant table, exposed for the tests.
        ///
        /// What the table refuses to turn into a grant, meaning a row with no identity or an
        /// identity that already appears above, are access decisions rather than interface
        /// polish. They are worth checking without a KeePass to click through.
        /// </summary>
        internal DataGridView Grants
        {
            get { return gridGrants; }
        }

        // Row metrics. Named because the layout below reads as arithmetic otherwise.
        private const int Margin = 8;
        private const int GapAfterText = 6;
        private const int ButtonHeight = 23;
        private const int GridMinimumHeight = 60;

        /// <summary>The group dialog's tab, and so the worst case this editor is laid out for.</summary>
        private const int NarrowestDialogWidth = 350;

        private readonly ToolTip _tips = new ToolTip();

        /// <summary>
        /// What every subject inherits from above this level, or null when that could not be
        /// read. Never written to, only shown and narrowed against.
        /// </summary>
        private readonly IDictionary<string, AclGrant> _inherited;


        private ContextMenuStrip _rowMenu;
        private ToolStripMenuItem _removeItem;
        private Label _help;
        private bool _populating;
        private bool _layingOut;

        /// <summary>
        /// Place the description, the optional warning, the grid, and the optional discard
        /// button, giving the grid everything left over.
        ///
        /// In code rather than with anchors because two of these are hidden most of the time,
        /// namely the "cannot be read" warning and the discard button that goes with it. An
        /// anchored layout keeps their space whether they are shown or not.
        /// </summary>
        private void LayOutRows()
        {
            // Re-entrancy guard. Moving a child nudges its siblings, which raises another
            // resize, which lands back here; unguarded that hung the KeePass UI thread.
            if (_layingOut)
                return;

            _layingOut = true;
            try
            {
                int width = ClientSize.Width;
                int height = ClientSize.Height;
                if (width <= 0 || height <= 0)
                    return;

                int inner = width - (Margin * 2);
                if (inner <= 0)
                    return;

                int helpWidth = _help == null ? 0 : _help.PreferredSize.Width + 6;
                int textWidth = inner - helpWidth;
                labelScope.SetBounds(Margin, Margin, textWidth, HeightOf(labelScope, textWidth));
                if (_help != null)
                    _help.Location = new Point(width - Margin - _help.PreferredSize.Width, Margin);

                int top = labelScope.Bottom + GapAfterText;
                if (labelWarning.Visible)
                {
                    labelWarning.SetBounds(Margin, top, inner, HeightOf(labelWarning, inner));
                    top = labelWarning.Bottom + GapAfterText;
                }

                int bottom = height - Margin;
                if (buttonDiscard.Visible)
                {
                    buttonDiscard.SetBounds(Margin, bottom - ButtonHeight, 160, ButtonHeight);
                    bottom -= ButtonHeight + GapAfterText;
                }

                gridGrants.SetBounds(Margin, top, inner, Math.Max(GridMinimumHeight, bottom - top));
                LayOutColumns();
            }
            finally
            {
                _layingOut = false;
            }
        }

        /// <summary>
        /// Share the grid's width out: fixed widths for the columns whose content is a short
        /// fixed phrase, and the rest to the identity, which has no bound.
        /// </summary>
        private void LayOutColumns()
        {
            // A couple of pixels in hand, or the last column tips the grid into a horizontal
            // scrollbar for the sake of one pixel. Behind that scrollbar are the two flags,
            // which is where they are least likely to be noticed and most likely to matter.
            //
            // The scrollbar is subtracted whether or not it is showing yet. A grid's client
            // area includes the space its own scrollbar draws in, so sizing the columns to the
            // full width works until a fourth grant appears, at which point the scrollbar
            // arrives and pushes the last column half off the edge. Reserving it costs a
            // fixed sliver of the identity column and never moves again.
            int available = gridGrants.ClientSize.Width
                - SystemInformation.VerticalScrollBarWidth - 4;
            if (available <= 0)
                return;

            // Measured from the content, not fixed, because the three right-hand columns hold
            // a short phrase from a closed set and every pixel they do not need belongs to the
            // identity, which has no bound: a GUID today, whatever a future client pairs as
            // next.
            // The verb is measured without TextRenderer's own padding and given only the
            // drop-down button plus a cell border. It holds one word from a closed set, the
            // longest of which is "delete", so anything beyond that is width taken from the
            // identity for nothing.
            int verb = TextRenderer.MeasureText(LongestVerbText(), Font, Size.Empty,
                TextFormatFlags.NoPadding).Width + SystemInformation.VerticalScrollBarWidth + 6;
            // The flag columns are sized by their tickbox, not their header: the headers are
            // one letter each precisely so that these two columns stop taking width the
            // identity needs, and the tickbox is what has to stay clickable.
            int attachments = FlagWidth(columnAttachments);
            int unattended = FlagWidth(columnUnattended);
            // The X and the letter over it are both one character, so whichever is wider
            // decides, and nothing beyond that: this is the narrowest column in the table and
            // every pixel it takes comes out of the identity.
            int forget = Math.Max(
                TextRenderer.MeasureText(ForgetMark, Font).Width,
                TextRenderer.MeasureText(columnForget.HeaderText, Font).Width) + 8;
            columnForget.Width = forget;

            columnVerb.Width = verb;
            columnAttachments.Width = attachments;
            columnUnattended.Width = unattended;

            // Everything else goes to the profile, which is the only column here without a
            // bound. Splitting what was left between two identity columns in proportion to
            // their content used to be the fiddliest part of this method, and a rule naming
            // one short word instead of a name and a GUID is what removed the need for it.
            columnProfile.Width = Math.Max(MinimumSubjectWidth,
                available - verb - attachments - unattended - forget);

            SizeDropDowns();
        }

        /// <summary>
        /// What a column would need to show everything in it without cutting anything off.
        /// More than the table has to give, usually; it is used as a ratio, not a width.
        /// </summary>
        private int ContentWidth(DataGridViewColumn column)
        {
            int widest = TextRenderer.MeasureText(column.HeaderText, Font).Width;

            foreach (DataGridViewRow row in gridGrants.Rows)
            {
                if (row.IsNewRow)
                    continue;

                string text = Convert.ToString(row.Cells[column.Index].Value);
                if (string.IsNullOrEmpty(text))
                    continue;

                int needs = TextRenderer.MeasureText(text, Font).Width;
                if (needs > widest)
                    widest = needs;
            }

            return widest + SystemInformation.VerticalScrollBarWidth + HeaderPadding;
        }

        /// <summary>A tickbox column: its header letter or its tickbox, whichever is wider.</summary>
        private int FlagWidth(DataGridViewColumn column)
        {
            int header = TextRenderer.MeasureText(column.HeaderText, Font).Width + HeaderPadding;
            return Math.Max(header, FlagFloor);
        }

        /// <summary>
        /// The widest thing the rule column has to show, which is its heading as well as its
        /// values: "Allow" and "Deny" are short, but "nothing" only exists in one of the two
        /// vocabularies and the column has to fit whichever it is showing.
        /// </summary>
        private string LongestVerbText()
        {
            string longest = columnVerb.HeaderText == null ? string.Empty : columnVerb.HeaderText;
            foreach (object item in columnVerb.Items)
            {
                string text = Convert.ToString(item);
                if (text != null && text.Length > longest.Length)
                    longest = text;
            }

            return longest;
        }

        /// <summary>Room for a header's own padding, so the text does not touch the divider.</summary>
        private const int HeaderPadding = 10;

        /// <summary>
        /// Below this the identity column shows nothing worth reading. Set low enough that
        /// the group dialog, which is the narrow one, still keeps its full flag headers: a
        /// truncated identity is recoverable by clicking into the cell, whereas two flag
        /// columns squeezed to their tickboxes cannot be told apart at all.
        /// </summary>
        private const int MinimumSubjectWidth = 60;

        /// <summary>Room for a tickbox and enough around it to be an easy target.</summary>
        private const int FlagFloor = 30;

        /// <summary>The height a label needs for its text at a given width.</summary>
        private static int HeightOf(Label label, int width)
        {
            return label.GetPreferredSize(new Size(width, 0)).Height;
        }

        /// <summary>
        /// The shortest this editor can be and still show every row, with the grid at its
        /// smallest useful size. Hosts are grown to this and no further.
        /// </summary>
        internal int MinimumHeight()
        {
            int inner = NarrowestDialogWidth - (Margin * 2);

            int total = Margin + HeightOf(labelScope, inner) + GapAfterText;
            if (labelWarning.Visible)
                total += HeightOf(labelWarning, inner) + GapAfterText;

            total += GridMinimumHeight;
            if (buttonDiscard.Visible)
                total += ButtonHeight + GapAfterText;

            return total + Margin;
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            LayOutRows();
        }

        /// <summary>
        /// A control can have its handle made before it is anywhere near a form, and can be
        /// given a parent before or after that, so the dialog is looked for at both moments as
        /// well as when the tab is attached. Watching is idempotent, and a tab whose Cancel
        /// quietly stopped working would look exactly like one that works.
        /// </summary>
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            _revert.Watch(FindForm());
        }

        protected override void OnParentChanged(EventArgs e)
        {
            base.OnParentChanged(e);
            _revert.Watch(FindForm());
        }

        public static void AttachTo(TabPage keeTabPage, TabControl mainTabControl,
            StringDictionaryEx customData, string scopeSummary, string scopeDetail,
            string databasePath, IList<string> profiles,
            IList<string> inheritedChainRootFirst)
        {
            AttachTo(keeTabPage, mainTabControl, customData, scopeSummary, scopeDetail,
                databasePath, profiles, inheritedChainRootFirst, null, AclDefault.Deny);
        }

        public static void AttachTo(TabPage keeTabPage, TabControl mainTabControl,
            StringDictionaryEx customData, string scopeSummary, string scopeDetail,
            string databasePath, IList<string> profiles,
            IList<string> inheritedChainRootFirst, string unsaveableReason, AclDefault mode)
        {
            if (keeTabPage == null || mainTabControl == null || customData == null)
                return;

            AclUserControl control = new AclUserControl(customData, scopeSummary, scopeDetail,
                databasePath, profiles, inheritedChainRootFirst, unsaveableReason, mode);
            control.Dock = DockStyle.Fill;

            // A floor on the height, set to what the rows need with the grant table at its
            // smallest useful size. Below it the tab scrolls, which is recoverable; a table
            // squeezed to nothing looks like a database with no grants in it, which is not.
            control.MinimumSize = new Size(0, control.MinimumHeight());

            // "Access control", not "ACL". The tab is read by whoever has to decide what an
            // agent may reach, which is not necessarily somebody who knows the acronym, and a
            // screen reader saying "ay see ell" helps nobody.
            TabPage page = new TabPage("Access control");
            page.AutoScroll = true;
            page.Controls.Add(control);

            TabControl inner = InnerTabsOf(keeTabPage);
            inner.TabPages.Add(page);

            control._revert.Watch(mainTabControl.FindForm());

            DialogGrowth.EnsureTabIsReachable(inner);

            // Grow the host only if it cannot show the editor at its smallest, and only in
            // height. Widening would strand upstream's OK and Cancel buttons, which it pins
            // to the right edge, and leave a white band beside its banner bitmap, which is
            // generated at the original width.
            DialogGrowth.EnsureRoomFor(mainTabControl, inner, control.MinimumSize);
        }

        /// <summary>
        /// The tab strip inside the plugin's own "Kee" tab, creating one if there is none.
        ///
        /// The entry and database dialogs already keep their Kee settings in a nested strip,
        /// and the grant editor joins it. The group dialog has a single flat control, which is
        /// wrapped in a strip of its own so that its existing content and the grants become
        /// two pages rather than one crowded one.
        /// </summary>
        internal static TabControl InnerTabsOf(TabPage keeTabPage)
        {
            TabControl existing = FindTabControl(keeTabPage);
            if (existing != null)
            {
                // Upstream sizes these to fit their own pages and anchors nothing, so they
                // would not follow the dialog when it grows to make room for the editor.
                existing.Anchor = AnchorStyles.Top | AnchorStyles.Bottom
                    | AnchorStyles.Left | AnchorStyles.Right;
                return existing;
            }

            TabControl created = new TabControl();
            created.Dock = DockStyle.Fill;

            TabPage general = new TabPage("General");
            while (keeTabPage.Controls.Count > 0)
            {
                Control existingContent = keeTabPage.Controls[0];
                keeTabPage.Controls.Remove(existingContent);
                general.Controls.Add(existingContent);
            }

            created.TabPages.Add(general);
            keeTabPage.Controls.Add(created);
            return created;
        }

        /// <summary>The first tab strip anywhere beneath <paramref name="parent"/>, or null.</summary>
        private static TabControl FindTabControl(Control parent)
        {
            foreach (Control child in parent.Controls)
            {
                TabControl tabs = child as TabControl;
                if (tabs != null)
                    return tabs;

                TabControl deeper = FindTabControl(child);
                if (deeper != null)
                    return deeper;
            }

            return null;
        }
    }
}
