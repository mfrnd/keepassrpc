using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassRPC.Acl;

namespace KeePassRPC.Forms
{
    /// <summary>
    /// What a paired client may reach, on the table that already lists paired clients.
    ///
    /// This began as a tab of its own and should not have been. Upstream's "Authorised
    /// clients" tab already listed every paired client by name and identity, so a second tab
    /// listing the same clients by name and identity meant two places to look, two places to
    /// keep in step, and a revoke gesture on one that said nothing about the access on the
    /// other. There is one table now, and this class is what the fork adds to it.
    ///
    /// It lives here rather than in <c>OptionsForm</c> deliberately. That form is upstream's,
    /// and every line this fork writes into it is a line in the path of the next upstream
    /// merge. The form gains a handful of calls; the behaviour is all here.
    ///
    /// Everything is deferred until the dialog is accepted, which is how the rest of the
    /// dialog behaves and how the tab this replaces behaved. Upstream's revoke was immediate,
    /// so that is a change: pressing Cancel after clicking the X now leaves the client alone,
    /// which is what Cancel means everywhere else on this form.
    /// </summary>
    internal sealed class ClientAccessTable
    {
        private readonly KeePassRPCExt _plugin;
        private readonly IPluginHost _host;
        private readonly DataGridView _grid;

        private readonly Dictionary<string, string> _pendingProfile =
            new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _pendingScope =
            new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly List<string> _forgotten = new List<string>();

        private readonly DataGridViewComboBoxColumn _access = new DataGridViewComboBoxColumn();
        private bool _populating;

        /// <summary>The column the X lives in, which upstream created as a Revoke button.</summary>
        private int _forgetColumn;

        internal ClientAccessTable(KeePassRPCExt plugin, DataGridView grid, TabPage page)
        {
            _plugin = plugin;
            _host = plugin._host;
            _grid = grid;

            RebuildColumns(page);
            AddControlsBelow(page);

            // The columns are sized to leave room for a scrollbar whether or not there is one
            // yet. This fills that room while there is not.
            RestingScrollBar.AttachTo(_grid);

            _grid.CellValueChanged += GridCellValueChanged;
            _grid.CurrentCellDirtyStateChanged += GridCurrentCellDirtyStateChanged;
            _grid.DataError += delegate(object sender, DataGridViewDataErrorEventArgs e)
            {
                // This grid is inside somebody else's dialog; an unhandled data error throws a
                // message box over it, repeatedly.
                e.ThrowException = false;
            };
        }

        /// <summary>
        /// Reshape upstream's columns: add Access, turn Revoke into the red X used elsewhere
        /// in this fork, and drop Connected in favour of a dot beside the name.
        ///
        /// Done here rather than in the designer file so that upstream's own description of
        /// its grid stays as upstream wrote it.
        /// </summary>
        private void RebuildColumns(TabPage page)
        {
            _grid.ReadOnly = false;

            // Clicking a cell selects its row, not the cell on its own. A lone highlighted
            // field says nothing here: every column of a row is about the same client, and
            // there is no operation that applies to one cell rather than to that client.
            _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;

            // The same white the ACL tables use, rather than the grey a DataGridView paints
            // below its last row by default. With the table filling the tab, that grey is
            // most of the tab whenever there are a handful of clients, and it reads as a
            // disabled control rather than as a list with room to grow.
            _grid.BackgroundColor = SystemColors.Window;

            foreach (DataGridViewColumn column in _grid.Columns)
                column.ReadOnly = true;

            _access.HeaderText = "Access";
            _access.Name = "Access";
            _access.ReadOnly = false;
            foreach (AccessChoice choice in AccessChoice.All)
                _access.Items.Add(choice);

            // Before the revoke column, so the destructive one stays last.
            int revoke = _grid.Columns.Count - 1;
            _grid.Columns.Insert(revoke, _access);
            _forgetColumn = _grid.Columns.Count - 1;

            // Upstream's Connected column, kept but narrowed to one letter with the meaning
            // in a tooltip, the same way the ACL table heads its two flag columns. A tickbox
            // needs a header wide enough to say what it ticks, and this table has four other
            // things to fit.
            DataGridViewColumn connected = _grid.Columns["Connected"];
            if (connected != null)
            {
                connected.HeaderText = "C";
                connected.ToolTipText = Tooltips.Wrapped(
                    "C (connected). This client is connected right now.");
                connected.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleCenter;

                // First, because it is the only column that says something about right now
                // rather than about the client's settings, and it is the one a person scans
                // for when they are wondering who is talking to KeePass at this moment.
                connected.DisplayIndex = 0;
            }

            // Upstream's Revoke is a button column, which cannot simply be re-typed, so it is
            // replaced by a text cell painted in the same red the fork uses on the ACL tabs.
            DataGridViewColumn old = _grid.Columns[_forgetColumn];
            DataGridViewTextBoxColumn forget = new DataGridViewTextBoxColumn();

            // One letter, centred over the X, and the meaning in a tooltip. A blank heading
            // left the only destructive control on the tab unlabelled, which is the one column
            // that should say what it is before it is clicked rather than after.
            forget.HeaderText = "D";
            forget.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleCenter;
            forget.ToolTipText = Tooltips.Wrapped(
                "D (delete). The X forgets this client: its key, its access and its name go, "
                + "and it has to pair again from scratch.");
            forget.Name = "Forget";
            forget.ReadOnly = true;
            forget.Width = 26;
            forget.DefaultCellStyle.ForeColor = Color.Firebrick;
            forget.DefaultCellStyle.SelectionForeColor = Color.Firebrick;
            forget.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleCenter;

            _grid.Columns.Remove(old);
            _grid.Columns.Add(forget);
            _forgetColumn = _grid.Columns.Count - 1;

            // "Unique ID" is upstream's word for the same thing the ACL tabs call the
            // identity. One vocabulary across the plugin, and it is the shorter of the two.
            _grid.Columns[1].HeaderText = "Identity";

            // Upstream's "Names are supplied by the client.", which was worth keeping and was
            // costing a line of the tab to say. It belongs on the column it is about, where it
            // is read at the moment somebody is looking at a name they do not recognise.
            _grid.Columns[0].ToolTipText = Tooltips.Wrapped(
                "Names are supplied by the client itself, so treat one you do not recognise "
                + "with suspicion.");

            _grid.CellFormatting += GridCellFormatting;
            _grid.Resize += delegate { LayOutColumns(); };

            // The page is resized by its tab control, which does that on its own schedule
            // after the dialog is widened, so the table is placed again whenever that lands
            // rather than once at a moment that turned out to be too early.
            _grid.Anchor = AnchorStyles.Top | AnchorStyles.Bottom
                | AnchorStyles.Left | AnchorStyles.Right;
            page.Resize += delegate { LayOut(page); };

            // This page arranges itself, so the dialog's own widening must leave it alone.
            page.Tag = DialogGrowth.SelfLaidOut;
        }

        /// <summary>
        /// Clear upstream's notes off the tab, so the table gets the whole of it.
        /// </summary>
        private void AddControlsBelow(TabPage page)
        {
            // Upstream's own notes under this table describe a "Revoke" button that no longer
            // exists. They are hidden rather than deleted, because they live in a generated
            // designer file that a future upstream merge will rewrite. What was still true in
            // them is now a tooltip on the column it is about. The failure label is left
            // alone: it is shown instead of the table when the client list cannot be read at
            // all.
            foreach (Control existing in page.Controls)
            {
                Label label = existing as Label;
                if (label != null && label.Name != "labelAuthorisedClientsFail")
                    label.Visible = false;
            }
        }

        /// <summary>Give the grid the whole page.</summary>
        internal void LayOut(TabPage page)
        {
            const int Margin = 6;
            int width = page.ClientSize.Width - (Margin * 2);
            if (width <= 0)
                return;

            int height = page.ClientSize.Height - (Margin * 2);
            _grid.SetBounds(Margin, Margin, width, Math.Max(80, height));
            LayOutColumns();
        }

        /// <summary>
        /// Decorate a row upstream has just added: its access, whether it is connected, and
        /// the X.
        /// </summary>
        internal void Decorate(DataGridViewRow row, string subject, string clientName,
            bool connected)
        {
            _populating = true;
            try
            {
                row.Tag = subject;

                bool explicitlySet;
                string profile = CurrentProfile(subject, out explicitlySet);
                string scope = CurrentScope(subject);
                AccessChoice access = AccessChoice.For(profile, scope);

                row.Cells[_access.Index].Value = access;
                row.Cells[_forgetColumn].Value = ForgetMark;

                row.Cells[ConnectedColumn].ToolTipText = Tooltips.Wrapped(connected
                    ? "Connected right now."
                    : "Not connected right now.");

                if (access == null)
                {
                    row.Cells[_access.Index].ToolTipText = Tooltips.Wrapped(
                        "Set by hand to '" + AccessChoice.Describe(profile, scope)
                        + "', which this list cannot offer. Choosing here replaces it.");
                }
                else
                {
                    row.Cells[_access.Index].ToolTipText = Tooltips.Wrapped(access.Detail
                        + (explicitlySet
                            ? string.Empty
                            : " Nobody has set this client, so it is refused."));
                }

                if (!explicitlySet)
                {
                    row.Cells[_access.Index].Style.ForeColor = SystemColors.GrayText;
                    row.Cells[_access.Index].Tag = NeverAnswered;
                }

                row.Cells[1].ToolTipText = subject;
                row.Cells[_forgetColumn].ToolTipText = Tooltips.Wrapped(
                    "Forget this client. Its key, its access and its name are removed and it "
                    + "has to pair again from scratch. Nothing happens until this dialog is "
                    + "accepted.");

                row.Cells[2].ToolTipText = Tooltips.Wrapped(
                    "When this client's stored key stops working. It has to pair again after "
                    + "that, which needs somebody at this keyboard.");
            }
            finally
            {
                _populating = false;
            }
        }

        /// <summary>What the last column shows.</summary>
        private const string ForgetMark = "X";

        /// <summary>Upstream's connected tickbox, third from the left.</summary>
        private const int ConnectedColumn = 3;

        /// <summary>Whether the click was on the X, and if so, deal with it.</summary>
        internal bool HandledForgetClick(int columnIndex, int rowIndex)
        {
            if (columnIndex != _forgetColumn || rowIndex < 0 || rowIndex >= _grid.Rows.Count)
                return false;

            DataGridViewRow row = _grid.Rows[rowIndex];
            string subject = row.Tag as string;
            if (string.IsNullOrEmpty(subject))
                return true;

            string name = Convert.ToString(row.Cells[0].Value);
            string called = string.IsNullOrEmpty(name) ? subject : name + " (" + subject + ")";

            DialogResult confirmed = MessageBox.Show(
                "Forget " + called + "?\n\n"
                + "Its key, its access and its name are removed, and it has to pair again from "
                + "scratch, which needs somebody at this keyboard. Any connection it currently "
                + "holds is closed.\n\n"
                + "Nothing is written until this dialog is accepted.",
                "Forget this client", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (confirmed != DialogResult.Yes)
                return true;

            _forgotten.Add(subject);
            _pendingProfile.Remove(subject);
            _pendingScope.Remove(subject);
            _grid.Rows.RemoveAt(rowIndex);
            return true;
        }

        /// <summary>
        /// Say in the cell, not just in its colour, that nobody has answered for this client.
        ///
        /// It reads "refused" either way, and the two are worth telling apart: one is a
        /// decision somebody made and the other is a client still waiting for one. It used to
        /// say "(default)", which pointed at a fallback setting that no longer exists and
        /// would now send a reader looking for a control that is not there.
        ///
        /// Done at paint time because the cell's value is the chosen access itself, and
        /// appending to that would mean storing something the list does not offer.
        /// </summary>
        private void GridCellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.ColumnIndex != _access.Index || e.RowIndex < 0
                || e.RowIndex >= _grid.Rows.Count)
            {
                return;
            }

            if (!NeverAnswered.Equals(_grid.Rows[e.RowIndex].Cells[_access.Index].Tag))
                return;

            e.Value = Convert.ToString(e.Value) + "  (not set)";
            e.FormattingApplied = true;
        }

        /// <summary>Marks a row nobody has answered for. Any non-null token would do.</summary>
        private static readonly object NeverAnswered = new object();

        private void GridCurrentCellDirtyStateChanged(object sender, EventArgs e)
        {
            if (_grid.IsCurrentCellDirty && _grid.CurrentCell is DataGridViewComboBoxCell)
                _grid.CommitEdit(DataGridViewDataErrorContexts.Commit);
        }

        private void GridCellValueChanged(object sender, DataGridViewCellEventArgs e)
        {
            if (_populating || e.RowIndex < 0 || e.ColumnIndex != _access.Index)
                return;

            DataGridViewRow row = _grid.Rows[e.RowIndex];
            AccessChoice chosen = row.Cells[_access.Index].Value as AccessChoice;
            string subject = row.Tag as string;
            if (chosen == null || string.IsNullOrEmpty(subject))
                return;

            _pendingProfile[subject] = chosen.Profile;
            _pendingScope[subject] = chosen.Scope;

            // It is this client's own answer now, so it stops reading as inherited.
            row.Cells[_access.Index].Tag = null;
            row.Cells[_access.Index].Style.ForeColor = _grid.DefaultCellStyle.ForeColor;
            row.Cells[_access.Index].ToolTipText = Tooltips.Wrapped(chosen.Detail);

            LayOutColumns();
        }

        private string CurrentProfile(string subject, out bool explicitlySet)
        {
            string pending;
            if (_pendingProfile.TryGetValue(subject, out pending))
            {
                explicitlySet = true;
                return pending;
            }

            string stored = _host.CustomConfig.GetString(
                SubjectRegistry.ProfilePrefix + subject, null);
            explicitlySet = !string.IsNullOrEmpty(stored);

            // Nothing stored means refused. That used to be a configurable fallback, which is
            // gone: clients that predate this build are migrated once at start-up, and every
            // client paired since has been asked. What is left over is a client nobody
            // answered for, and the safe reading of silence is no.
            return string.IsNullOrEmpty(stored) ? MethodProfiles.None : stored;
        }

        private string CurrentScope(string subject)
        {
            string pending;
            if (_pendingScope.TryGetValue(subject, out pending))
                return pending;

            return _host.CustomConfig.GetString(AclScope.SubjectPrefix + subject,
                AclScope.V3Only);
        }

        /// <summary>Whether this subject is on its way out, so upstream can skip drawing it.</summary>
        internal bool IsForgotten(string subject)
        {
            return _forgotten.Contains(subject);
        }

        /// <summary>Write everything this tab has been told, on the dialog being accepted.</summary>
        internal void Save()
        {
            foreach (KeyValuePair<string, string> assignment in _pendingProfile)
            {
                _host.CustomConfig.SetString(
                    SubjectRegistry.ProfilePrefix + assignment.Key, assignment.Value);
            }

            foreach (KeyValuePair<string, string> scope in _pendingScope)
                _host.CustomConfig.SetString(AclScope.SubjectPrefix + scope.Key, scope.Value);

            foreach (string subject in _forgotten)
            {
                SubjectRegistry.Forget(_host, subject);
                HangUpOn(subject);
            }

            _pendingProfile.Clear();
            _pendingScope.Clear();
            _forgotten.Clear();
        }

        /// <summary>
        /// Close any connection a forgotten client still holds.
        ///
        /// Clearing its key stops it authenticating again and says nothing about a session
        /// already established. That session would fall back to whatever the setting below
        /// allows, which is exactly the client the user has just said they want rid of.
        /// </summary>
        private void HangUpOn(string subject)
        {
            if (_plugin == null)
                return;

            foreach (KeePassRPCClientConnection client in _plugin.GetConnectedRPCClients())
            {
                if (!string.IsNullOrEmpty(client.UserName) && client.UserName == subject)
                {
                    client.WebSocketConnection.Close();
                    break;
                }
            }
        }

        private bool _sizingColumns;

        /// <summary>
        /// Share the width out: fixed for the columns whose content is a phrase from a closed
        /// set, and the rest to the name and the identity, in proportion to what they hold.
        /// </summary>
        private void LayOutColumns()
        {
            if (_sizingColumns)
                return;

            _sizingColumns = true;
            try
            {
                int available = _grid.ClientSize.Width
                    - SystemInformation.VerticalScrollBarWidth - 4;
                if (available <= 0 || _grid.Columns.Count < 4)
                    return;

                // Asked of the grid rather than measured here. A combo cell spends width on
                // its drop-down button, its padding and its borders as well as its text, and
                // an approximation of that clipped the longest setting by a few pixels.
                int access = PreferredWidth(_access.Index);
                int expires = PreferredWidth(2);

                // The X and its heading each need room for one letter and a little air, and
                // no more: it is the narrowest thing on the row and every pixel it takes is
                // one the identity does not get.
                int forget = Math.Max(
                    TextRenderer.MeasureText(ForgetMark, _grid.Font).Width + 8,
                    TextRenderer.MeasureText(_grid.Columns[_forgetColumn].HeaderText,
                        _grid.Font).Width + 8);
                int flag = PreferredWidth(ConnectedColumn);
                _grid.Columns[ConnectedColumn].Width = flag;

                _grid.Columns[_access.Index].Width = access;
                _grid.Columns[_forgetColumn].Width = forget;
                _grid.Columns[2].Width = expires;

                int rest = Math.Max(MinimumNameWidth * 2,
                    available - access - forget - expires - flag);
                int wantsName = ContentWidth(0);
                int wantsIdentity = ContentWidth(1);
                int name = wantsName + wantsIdentity <= 0
                    ? rest / 2
                    : rest * wantsName / (wantsName + wantsIdentity);

                _grid.Columns[0].Width = Math.Min(rest - MinimumNameWidth,
                    Math.Max(MinimumNameWidth, name));
                _grid.Columns[1].Width = rest - _grid.Columns[0].Width;
            }
            finally
            {
                _sizingColumns = false;
            }
        }

        /// <summary>
        /// What a column needs for the values actually in it, according to the grid itself.
        ///
        /// Sized to the content because most of these tables hold two or three clients and
        /// none of the longest setting, and every pixel a column does not need belongs to the
        /// identity, which never has enough. Re-measured whenever a value changes, so choosing
        /// a longer one widens the column rather than clipping it.
        /// </summary>
        private int PreferredWidth(int column)
        {
            return _grid.Columns[column].GetPreferredWidth(
                DataGridViewAutoSizeColumnMode.AllCells, true);
        }

        private int ContentWidth(int column)
        {
            int widest = TextRenderer.MeasureText(
                _grid.Columns[column].HeaderText, _grid.Font).Width;

            foreach (DataGridViewRow row in _grid.Rows)
            {
                if (row == null || row.Cells.Count <= column)
                    continue;

                string text = Convert.ToString(row.Cells[column].Value);
                if (string.IsNullOrEmpty(text))
                    continue;

                int needs = TextRenderer.MeasureText(text, _grid.Font).Width;
                if (needs > widest)
                    widest = needs;
            }

            return widest + Padding;
        }

        private const int Padding = 12;
        private const int MinimumNameWidth = 80;
    }
}
