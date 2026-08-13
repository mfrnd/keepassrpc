using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Collections;
using KeePassRPC.Acl;

namespace KeePassRPC.Forms
{
    /// <summary>
    /// The database-wide starting point for access control: deny by default, or allow by
    /// default.
    ///
    /// A page on the database settings dialog, because it is a decision about the whole file
    /// rather than about one group. What it edits lives on the ROOT GROUP's grant document,
    /// which is where the chain starts: that keeps every piece of ACL state in group and entry
    /// custom data, a KDBX 4.0 feature, where a custom data item on the database itself would
    /// raise the file to KDBX 4.1 for nothing.
    ///
    /// It also holds the database's profiles and which clients are in them, because both are
    /// statements about the whole file too, and because a rule elsewhere is useless until the
    /// profile it names exists.
    ///
    /// The grants themselves are not edited here. They are edited on the root group, on any
    /// other group, and on entries, all through the same table; giving this dialog a second
    /// grant table would put the widest rules in the database in two places at once, which is
    /// the mistake that had the database level removed in the first place.
    /// </summary>
    public class AclDefaultUserControl : UserControl
    {
        private readonly StringDictionaryEx _rootData;
        private readonly DismissalRevert _revert;
        private readonly ToolTip _tips = new ToolTip();

        private readonly Label _intro = new Label();
        private readonly RadioButton _deny = new RadioButton();
        private readonly RadioButton _allow = new RadioButton();
        private readonly Label _detail = new Label();
        private readonly Label _warning = new Label();
        private readonly Button _discardLeftover = new Button();

        private readonly Label _profilesLabel = new Label();
        private readonly DataGridView _profileGrid = new DataGridView();
        private readonly DataGridViewTextBoxColumn _profileColumn = new DataGridViewTextBoxColumn();
        private readonly DataGridViewTextBoxColumn _profileForget = new DataGridViewTextBoxColumn();

        private readonly Label _clientsLabel = new Label();
        private readonly ListBox _clients = new ListBox();
        private readonly CheckedListBox _memberships = new CheckedListBox();

        private readonly IPluginHost _host;
        private bool _assigning;

        /// <summary>The red X, the same one the grant tables use.</summary>
        private const string ForgetMark = "X";

        private AclDocument _document;
        private bool _populating;
        private bool _readOnly;

        /// <param name="database">
        /// The open database. Its root group is what carries the setting, and it is written
        /// live, so the dialog's Cancel is honoured by <see cref="DismissalRevert"/>.
        /// </param>
        public AclDefaultUserControl(PwDatabase database)
            : this(database, null)
        {
        }

        /// <param name="host">
        /// Supplies the paired clients for the assignment list. Null leaves that list empty,
        /// which is what a caller without a host can honestly show.
        /// </param>
        public AclDefaultUserControl(PwDatabase database, IPluginHost host)
        {
            _host = host;
            _rootData = database == null || database.RootGroup == null
                ? null : database.RootGroup.CustomData;

            _revert = new DismissalRevert(_rootData, AclDocument.CustomDataKey);

            Build();
            Load(database);
        }

        private void Build()
        {
            _intro.AutoSize = false;
            _intro.Text = "Where access control starts for this database, before any group or "
                + "entry rule is read. Groups and entries can only take access away from this, "
                + "never add to it.";

            _deny.Text = "Deny by default, allow explicitly";
            _deny.AutoSize = false;
            _tips.SetToolTip(_deny, Tooltips.Wrapped(
                "Nothing is reachable until a group or an entry grants it. This is a weak "
                + "deny: it is only a starting point, so the first group that grants something "
                + "lifts it for everything in that group. It is not the same as a rule of "
                + "'none' for '*' on the root group, which is a floor that nothing below can "
                + "raise."));

            _allow.Text = "Allow by default, deny explicitly";
            _allow.AutoSize = false;
            _tips.SetToolTip(_allow, Tooltips.Wrapped(
                "Every client starts holding everything, and groups and entries can only take "
                + "it away. A group that says nothing about a client leaves that client able "
                + "to delete its entries, read attachment contents and do it without a "
                + "confirmation prompt."));

            _detail.AutoSize = false;
            _detail.ForeColor = SystemColors.GrayText;

            _warning.AutoSize = false;
            _warning.ForeColor = Color.Firebrick;
            _warning.Visible = false;

            _discardLeftover.Text = "Discard it";
            _discardLeftover.Visible = false;
            _discardLeftover.Click += DiscardLeftover;

            _deny.CheckedChanged += ChoiceChanged;
            _allow.CheckedChanged += ChoiceChanged;

            BuildProfiles();

            Controls.Add(_intro);
            Controls.Add(_deny);
            Controls.Add(_allow);
            Controls.Add(_detail);
            Controls.Add(_warning);
            Controls.Add(_discardLeftover);
            Controls.Add(_profilesLabel);
            Controls.Add(_profileGrid);
            Controls.Add(_clientsLabel);
            Controls.Add(_clients);
            Controls.Add(_memberships);
        }

        /// <summary>
        /// The two lists: what profiles exist, and who is in them.
        ///
        /// A grid for the profiles, matching the grant tables so that adding and removing work
        /// the way they do everywhere else in this plugin. A client list beside a tick list
        /// for the membership, because a client can be in several profiles and a grid cell
        /// that holds a set is a control nobody can use.
        /// </summary>
        private void BuildProfiles()
        {
            _profilesLabel.AutoSize = false;
            _profilesLabel.Text = "Profiles. Rules on groups and entries are written about these.";

            _profileColumn.HeaderText = "Profile";
            _profileColumn.Name = "Profile";

            _profileForget.HeaderText = "D";
            _profileForget.Name = "Forget";
            _profileForget.ReadOnly = true;
            _profileForget.Width = 26;
            _profileForget.DefaultCellStyle.ForeColor = Color.Firebrick;
            _profileForget.DefaultCellStyle.SelectionForeColor = Color.Firebrick;
            _profileForget.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleCenter;
            _profileForget.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleCenter;
            _profileForget.ToolTipText = Tooltips.Wrapped(
                "D (delete). Removes a profile and every client's membership of it. A client "
                + "left in nothing falls back to the default profile, which is why the default "
                + "cannot be removed.");

            _profileGrid.Columns.AddRange(new DataGridViewColumn[] { _profileColumn, _profileForget });
            _profileGrid.AllowUserToAddRows = true;
            _profileGrid.AllowUserToDeleteRows = false;
            _profileGrid.AllowUserToResizeRows = false;
            _profileGrid.RowHeadersVisible = false;
            _profileGrid.MultiSelect = false;
            _profileGrid.BackgroundColor = SystemColors.Window;
            _profileGrid.BorderStyle = BorderStyle.FixedSingle;
            _profileGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _profileGrid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            _profileGrid.CellValidating += ProfileValidating;
            _profileGrid.CellValueChanged += ProfileChanged;
            _profileGrid.CellContentClick += ProfileClicked;
            _profileGrid.DataError += delegate(object sender, DataGridViewDataErrorEventArgs e)
            {
                e.ThrowException = false;
            };
            RestingScrollBar.AttachTo(_profileGrid);

            _clientsLabel.AutoSize = false;
            _clientsLabel.Text = "Which profiles each paired client is in.";

            _clients.IntegralHeight = false;
            _clients.SelectedIndexChanged += ClientPicked;

            _memberships.IntegralHeight = false;
            _memberships.CheckOnClick = true;
            _memberships.ItemCheck += MembershipChanged;
        }

        private void Load(PwDatabase database)
        {
            _populating = true;
            try
            {
                if (_rootData == null)
                {
                    Refuse("This database has no root group to store access control on.");
                    return;
                }

                // A document left on the database itself is refused by the resolver, so
                // nothing is reachable until it is dealt with. There is no automatic move any
                // more, which makes this the one place it can be dealt with at all.
                if (database != null && AclResolver.UnmigratedDatabaseGrant(database))
                {
                    Refuse("This database carries grants on the database itself, which this "
                        + "version does not use and cannot read as rules. Every client is "
                        + "refused everything until they are removed. The grants that count "
                        + "are the ones on the root group.");
                    _discardLeftover.Visible = true;
                    _discardLeftover.Tag = database;
                    return;
                }

                _document = _rootData.Exists(AclDocument.CustomDataKey)
                    ? AclDocument.Parse(_rootData.Get(AclDocument.CustomDataKey))
                    : new AclDocument();

                if (_document == null)
                {
                    Refuse("The root group's access control rules cannot be read, so every "
                        + "client is refused everything. Fix or discard them on the root "
                        + "group's own Access control tab before setting this.");
                    return;
                }

                _deny.Checked = _document.Default == AclDefault.Deny;
                _allow.Checked = _document.Default == AclDefault.Allow;
                ShowDetail();
                ShowProfiles();
                ShowClients();
            }
            finally
            {
                _populating = false;
            }
        }

        private void Refuse(string why)
        {
            _readOnly = true;
            _deny.Enabled = false;
            _allow.Enabled = false;
            _profileGrid.Enabled = false;
            _memberships.Enabled = false;
            _warning.Text = why;
            _warning.Visible = true;
        }

        // --- what profiles exist ------------------------------------------------------------

        private void ShowProfiles()
        {
            _populating = true;
            try
            {
                _profileGrid.Rows.Clear();
                foreach (string name in _document.Profiles.Names)
                {
                    int index = _profileGrid.Rows.Add(name, Removable(name) ? ForgetMark : string.Empty);
                    DataGridViewRow row = _profileGrid.Rows[index];

                    // A name is what every rule in the database points at, so it is settled
                    // once it exists. Renaming it here would leave those rules pointing at
                    // nothing, silently, which is a revocation nobody asked for.
                    row.Cells[0].ReadOnly = true;
                    row.Cells[1].ToolTipText = Removable(name)
                        ? Tooltips.Wrapped("Remove this profile. Clients in it fall back to the "
                            + "default profile unless they are in another.")
                        : Tooltips.Wrapped("The default profile cannot be removed. A client is "
                            + "never without a profile, and this is the one it falls back to.");
                }
            }
            finally
            {
                _populating = false;
            }
        }

        private static bool Removable(string name)
        {
            return !string.Equals(name, AclProfiles.DefaultProfile, StringComparison.Ordinal);
        }

        private void ProfileValidating(object sender, DataGridViewCellValidatingEventArgs e)
        {
            if (_populating || _readOnly || _document == null || e.ColumnIndex != 0)
                return;

            // Only the blank row at the bottom, which is the only one that can be typed into.
            // Validating the others refuses every existing name for already existing, and a
            // cancelled validation is not a message: the grid keeps the cursor where it is and
            // swallows every click on the dialog, which reads as the whole page having frozen.
            if (e.RowIndex != _profileGrid.NewRowIndex)
                return;

            string typed = Convert.ToString(e.FormattedValue);
            typed = typed == null ? string.Empty : typed.Trim();
            if (typed.Length == 0)
                return;

            if (!_document.Profiles.CanAdd(typed))
            {
                _profileGrid.Rows[e.RowIndex].ErrorText =
                    "Already a profile, or not a name a profile can have. Two names differing "
                    + "only in case are refused, because a rule naming the wrong one of them "
                    + "looks right and grants nobody anything.";
                e.Cancel = true;
                return;
            }

            _profileGrid.Rows[e.RowIndex].ErrorText = string.Empty;
        }

        private void ProfileChanged(object sender, DataGridViewCellEventArgs e)
        {
            if (_populating || _readOnly || _document == null || e.ColumnIndex != 0 || e.RowIndex < 0)
                return;

            string typed = Convert.ToString(_profileGrid.Rows[e.RowIndex].Cells[0].Value);
            typed = typed == null ? string.Empty : typed.Trim();
            if (typed.Length == 0 || !_document.Profiles.Add(typed))
                return;

            Save();
            Redraw();
        }

        /// <summary>
        /// Rebuild both lists, but not before the grid has finished with the event that asked
        /// for it.
        ///
        /// Clearing a DataGridView's rows from inside its own CellValueChanged or
        /// CellContentClick re-enters the code that is running, and what it leaves behind is a
        /// grid that has focus and swallows every click on the dialog. Nothing is thrown and
        /// nothing is drawn differently: the whole page simply stops responding.
        /// </summary>
        private void Redraw()
        {
            if (!IsHandleCreated || IsDisposed)
                return;

            BeginInvoke((MethodInvoker)delegate
            {
                ShowProfiles();
                ShowClients();
                LayOut();
            });
        }

        private void ProfileClicked(object sender, DataGridViewCellEventArgs e)
        {
            if (_readOnly || _document == null || e.ColumnIndex != 1 || e.RowIndex < 0)
                return;

            string name = Convert.ToString(_profileGrid.Rows[e.RowIndex].Cells[0].Value);
            if (!Removable(name))
                return;

            if (MessageBox.Show(
                    "Remove the profile " + name + "?" + Environment.NewLine + Environment.NewLine
                    + "Every client in it loses that membership, and a client left in nothing "
                    + "falls back to the default profile. Rules naming this profile are left "
                    + "where they are and grant nobody anything until a profile of that name "
                    + "exists again.",
                    "KeePassRPC", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            {
                return;
            }

            _document.Profiles.Remove(name);
            Save();
            Redraw();
        }

        // --- who is in them -----------------------------------------------------------------

        private void ShowClients()
        {
            _assigning = true;
            try
            {
                _clients.Items.Clear();
                foreach (SubjectRegistry.SubjectChoice choice in Paired())
                    _clients.Items.Add(new ClientRow(choice));

                _memberships.Items.Clear();
                foreach (string name in _document.Profiles.Names)
                    _memberships.Items.Add(name);

                if (_clients.Items.Count > 0)
                    _clients.SelectedIndex = 0;
            }
            finally
            {
                _assigning = false;
            }

            ShowMemberships();
        }

        /// <summary>A client in the list: shown by the name it gave, remembered by identity.</summary>
        private sealed class ClientRow
        {
            internal readonly string Subject;
            private readonly string _label;

            internal ClientRow(SubjectRegistry.SubjectChoice choice)
            {
                Subject = choice.Subject;
                _label = string.IsNullOrEmpty(choice.ClientName) ? choice.Subject : choice.ClientName;
            }

            public override string ToString()
            {
                return _label;
            }
        }

        private IList<SubjectRegistry.SubjectChoice> Paired()
        {
            try
            {
                return _host == null
                    ? new List<SubjectRegistry.SubjectChoice>()
                    : SubjectRegistry.KnownChoices(_host);
            }
            catch (Exception)
            {
                return new List<SubjectRegistry.SubjectChoice>();
            }
        }

        private void ClientPicked(object sender, EventArgs e)
        {
            ShowMemberships();
        }

        private void ShowMemberships()
        {
            ClientRow client = _clients.SelectedItem as ClientRow;
            _assigning = true;
            try
            {
                // For(), not the raw assignment: what a client holds is what it was given
                // minus anything deleted since, and the default when that leaves nothing. The
                // list has to show what is in force, not what was typed.
                IList<string> held = client == null || _document == null
                    ? new List<string>() : _document.Profiles.For(client.Subject);

                for (int i = 0; i < _memberships.Items.Count; i++)
                {
                    string name = Convert.ToString(_memberships.Items[i]);
                    _memberships.SetItemChecked(i, held.Contains(name));
                }

                _memberships.Enabled = !_readOnly && client != null;
            }
            finally
            {
                _assigning = false;
            }
        }

        private void MembershipChanged(object sender, ItemCheckEventArgs e)
        {
            if (_assigning || _readOnly || _document == null)
                return;

            ClientRow client = _clients.SelectedItem as ClientRow;
            if (client == null)
                return;

            List<string> wanted = new List<string>();
            for (int i = 0; i < _memberships.Items.Count; i++)
            {
                bool ticked = i == e.Index
                    ? e.NewValue == CheckState.Checked
                    : _memberships.GetItemChecked(i);

                if (ticked)
                    wanted.Add(Convert.ToString(_memberships.Items[i]));
            }

            _document.Profiles.Assign(client.Subject, wanted);
            Save();

            // Unticking the last profile is neither an error nor refused: it stores nothing,
            // and nothing reads back as the default. The ticks are redrawn afterwards so the
            // list says what the client holds rather than what was clicked.
            BeginInvoke((MethodInvoker)ShowMemberships);
        }

        private void DiscardLeftover(object sender, EventArgs e)
        {
            PwDatabase database = _discardLeftover.Tag as PwDatabase;
            if (database == null)
                return;

            if (MessageBox.Show(
                    "Remove the grant document stored on the database itself?\r\n\r\n"
                    + "It is not being used as a rule by this version, and while it is there "
                    + "every client is refused everything. The rules on groups and entries are "
                    + "not touched.",
                    "KeePassRPC", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            {
                return;
            }

            database.CustomData.Remove(AclDocument.CustomDataKey);
            _discardLeftover.Visible = false;
            _readOnly = false;
            _deny.Enabled = true;
            _allow.Enabled = true;
            _warning.Visible = false;
            Load(database);
            LayOut();
        }

        private void ChoiceChanged(object sender, EventArgs e)
        {
            if (_populating || _readOnly || _document == null)
                return;

            AclDefault wanted = _allow.Checked ? AclDefault.Allow : AclDefault.Deny;
            if (wanted == _document.Default)
                return;

            if (wanted == AclDefault.Allow && !Confirmed())
            {
                _populating = true;
                try
                {
                    _deny.Checked = true;
                    _allow.Checked = false;
                }
                finally
                {
                    _populating = false;
                }

                return;
            }

            _document.Default = wanted;
            Save();
            ShowDetail();
            LayOut();
        }

        /// <summary>
        /// Ask before turning the database inside out.
        ///
        /// Only on the way from deny to allow. Going the other way narrows what clients hold,
        /// which is the safe direction and is the state a database starts in; asking there
        /// would train the reader to dismiss the question that matters.
        /// </summary>
        private bool Confirmed()
        {
            return MessageBox.Show(
                "Allow by default reverses what every rule in this database means.\r\n\r\n"
                + "Every client that gets past the method gate will be able to read, change "
                + "and delete every entry, including attachment contents and without a "
                + "confirmation prompt, except where a group or an entry takes that away.\r\n\r\n"
                + "The rules already stored were written as permissions. They now read as "
                + "restrictions, so all of them need reviewing before this database is exposed "
                + "to any client again.\r\n\r\n"
                + "Switch to allow by default?",
                "KeePassRPC", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        private void ShowDetail()
        {
            if (_document == null)
                return;

            _detail.Text = _document.Default == AclDefault.Allow
                ? "Every client holds everything except where a rule takes it away. Each rule "
                    + "in this database is a restriction."
                : "Nothing is reachable except where a rule grants it. The first group that "
                    + "grants something opens it for that group and everything inside it.";

            _warning.Visible = _document.Default == AclDefault.Allow;
            _warning.Text = _document.Default == AclDefault.Allow
                ? "Allow by default: an entry with no rule about it is fully reachable by "
                    + "every client the method gate lets through."
                : string.Empty;
        }

        private void Save()
        {
            if (_rootData == null || _document == null)
                return;

            string stored = _rootData.Exists(AclDocument.CustomDataKey)
                ? _rootData.Get(AclDocument.CustomDataKey)
                : null;

            string wanted = _document.IsEmpty ? null : _document.ToJson();
            if (stored == wanted)
                return;

            if (wanted == null)
                _rootData.Remove(AclDocument.CustomDataKey);
            else
                _rootData.Set(AclDocument.CustomDataKey, wanted);
        }

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

        // Laid out on every layout pass rather than only on resize. A docked control that is
        // added to a tab page before the page is added to its strip is sized once, at whatever
        // width it happened to have, and never resized again: the first version of this wrapped
        // its text into a 180 pixel column on a 460 pixel tab and stayed there.
        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            LayOut();
        }

        protected override void OnVisibleChanged(EventArgs e)
        {
            base.OnVisibleChanged(e);
            LayOut();
        }

        private bool _laying;

        private void LayOut()
        {
            const int Margin = 8;
            int width = ClientSize.Width - (Margin * 2);
            if (width <= 0 || _laying)
                return;

            _laying = true;
            try
            {
                Arrange(Margin, width);
            }
            finally
            {
                _laying = false;
            }
        }

        private void Arrange(int Margin, int width)
        {

            int y = Margin;
            y += Place(_intro, Margin, y, width) + 8;

            // Side by side: they are the two halves of one question, and stacked they read as
            // two settings that happen to be near each other.
            int firstRadio = Math.Max(120, _deny.GetPreferredSize(new Size(width, 0)).Width + 12);
            int radios = Math.Max(
                Place(_deny, Margin, y, firstRadio),
                Place(_allow, Margin + firstRadio, y, width - firstRadio));
            y += radios + 6;

            y += Place(_detail, Margin, y, width) + 8;

            if (_warning.Visible)
                y += Place(_warning, Margin, y, width) + 6;

            if (_discardLeftover.Visible)
            {
                _discardLeftover.SetBounds(Margin, y, 100, 24);
                y += 30;
            }

            y += Place(_profilesLabel, Margin, y, width) + 4;
            _profileGrid.SetBounds(Margin, y, width, ProfileGridHeight);
            _profileColumn.Width = Math.Max(60,
                width - _profileForget.Width - SystemInformation.VerticalScrollBarWidth - 6);
            y += ProfileGridHeight + 10;

            y += Place(_clientsLabel, Margin, y, width) + 4;

            // Side by side, the client on the left because that is what a reader is looking
            // for and the ticks on the right because they answer the question asked about it.
            int listHeight = Math.Max(60, ClientSize.Height - y - Margin);
            int half = (width - 8) / 2;
            _clients.SetBounds(Margin, y, half, listHeight);
            _memberships.SetBounds(Margin + half + 8, y, width - half - 8, listHeight);
        }

        /// <summary>
        /// Enough for the default profile and three more without scrolling, which is about as
        /// many as a database has before somebody is doing something interesting.
        /// </summary>
        private const int ProfileGridHeight = 96;

        /// <summary>
        /// What this page needs before it starts hiding things, for the dialog to grow to.
        /// </summary>
        internal int MinimumHeight()
        {
            return 250 + ProfileGridHeight + 90;
        }

        private static int Place(Control control, int x, int y, int width)
        {
            if (!control.Visible)
                return 0;

            int height = control.GetPreferredSize(new Size(width, 0)).Height;
            control.SetBounds(x, y, width, height);
            return height;
        }

        /// <summary>
        /// Add the page to the plugin's own tab on the database settings dialog.
        /// </summary>
        public static void AttachTo(TabPage keeTabPage, TabControl mainTabControl,
            PwDatabase database, IPluginHost host)
        {
            if (keeTabPage == null || mainTabControl == null || database == null)
                return;

            AclDefaultUserControl control = new AclDefaultUserControl(database, host);
            control.Dock = DockStyle.Fill;
            control.MinimumSize = new Size(0, control.MinimumHeight());

            TabPage page = new TabPage("Access control");
            page.AutoScroll = true;
            page.Controls.Add(control);

            TabControl inner = AclUserControl.InnerTabsOf(keeTabPage);
            inner.TabPages.Add(page);

            DialogGrowth.EnsureTabIsReachable(inner);

            // In height only, like the grant editor: widening would strand the dialog's own
            // buttons, which it pins to the right edge.
            DialogGrowth.EnsureRoomFor(mainTabControl, inner, control.MinimumSize);

            control._revert.Watch(mainTabControl.FindForm());
        }
    }
}
