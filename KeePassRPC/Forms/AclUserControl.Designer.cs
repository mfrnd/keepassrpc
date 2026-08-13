namespace KeePassRPC.Forms
{
    partial class AclUserControl
    {
        private System.ComponentModel.IContainer components = null;

        private System.Windows.Forms.Label labelScope;
        private System.Windows.Forms.Label labelWarning;
        private System.Windows.Forms.DataGridView gridGrants;
        private System.Windows.Forms.DataGridViewComboBoxColumn columnProfile;
        private System.Windows.Forms.DataGridViewComboBoxColumn columnVerb;
        private System.Windows.Forms.DataGridViewCheckBoxColumn columnAttachments;
        private System.Windows.Forms.DataGridViewCheckBoxColumn columnUnattended;
        private System.Windows.Forms.DataGridViewTextBoxColumn columnForget;
        private System.Windows.Forms.Button buttonDiscard;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
                components.Dispose();

            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.labelScope = new System.Windows.Forms.Label();
            this.labelWarning = new System.Windows.Forms.Label();
            this.gridGrants = new System.Windows.Forms.DataGridView();
            this.columnProfile = new System.Windows.Forms.DataGridViewComboBoxColumn();
            this.columnVerb = new System.Windows.Forms.DataGridViewComboBoxColumn();
            this.columnAttachments = new System.Windows.Forms.DataGridViewCheckBoxColumn();
            this.columnUnattended = new System.Windows.Forms.DataGridViewCheckBoxColumn();
            this.columnForget = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.buttonDiscard = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.gridGrants)).BeginInit();
            this.SuspendLayout();
            //
            // labelScope
            //
            this.labelScope.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left;
            this.labelScope.Location = new System.Drawing.Point(8, 8);
            this.labelScope.Name = "labelScope";
            this.labelScope.Size = new System.Drawing.Size(430, 15);
            this.labelScope.TabIndex = 0;
            //
            // labelWarning
            //
            this.labelWarning.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left;
            this.labelWarning.ForeColor = System.Drawing.Color.Firebrick;
            this.labelWarning.Location = new System.Drawing.Point(8, 28);
            this.labelWarning.Name = "labelWarning";
            this.labelWarning.Size = new System.Drawing.Size(470, 32);
            this.labelWarning.TabIndex = 1;
            this.labelWarning.Visible = false;
            //
            // gridGrants
            //
            // Editing happens in the grid itself: the blank row at the bottom adds, Delete
            // removes the selected row, and every cell is edited where it is shown. The
            // separate subject box, verb box, two checkboxes and two buttons this replaces
            // were a second copy of the table, kept in step by hand.
            this.gridGrants.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left;
            this.gridGrants.AllowUserToAddRows = true;
            this.gridGrants.AllowUserToDeleteRows = true;
            this.gridGrants.AllowUserToResizeRows = false;
            this.gridGrants.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.None;
            this.gridGrants.BackgroundColor = System.Drawing.SystemColors.Window;
            this.gridGrants.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.gridGrants.ColumnHeadersHeightSizeMode =
                System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            this.gridGrants.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
                this.columnProfile, this.columnVerb,
                this.columnAttachments, this.columnUnattended, this.columnForget});
            this.gridGrants.EditMode = System.Windows.Forms.DataGridViewEditMode.EditOnEnter;
            this.gridGrants.Location = new System.Drawing.Point(8, 28);
            this.gridGrants.MultiSelect = false;
            this.gridGrants.Name = "gridGrants";
            // No row header. It showed an arrow for the current row and an asterisk for the
            // blank one, which is a column's worth of width spent restating what the cursor
            // and the empty row already say.
            this.gridGrants.RowHeadersVisible = false;
            this.gridGrants.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.gridGrants.Size = new System.Drawing.Size(470, 180);
            this.gridGrants.TabIndex = 2;
            //
            // columnProfile
            //
            // One column, where there were two. A rule used to name a client, which needed the
            // client's name AND the identity it paired under, because a browser extension
            // pairs as a GUID nobody can read and neither half fits a column on the group
            // dialog. A rule names a profile now: one short word somebody chose, which fits.
            //
            // A pick list rather than free text, and for the same reason it always was: a
            // profile name typed with a typo matches nothing, grants nobody anything, and
            // reports nothing about it.
            this.columnProfile.HeaderText = "Profile";
            this.columnProfile.Name = "columnProfile";
            this.columnProfile.Width = 220;
            this.columnProfile.AutoComplete = true;
            //
            // columnVerb
            //
            this.columnVerb.HeaderText = "Verb";
            this.columnVerb.Name = "columnVerb";
            this.columnVerb.Width = 90;
            //
            // columnAttachments
            //
            // One letter each. The cells are tickboxes, so the header is the only thing
            // setting the column width, and two words of it were costing the identity column
            // most of what it needed on the group dialog. The tooltips carry the meaning.
            //
            // Centred, because the tickbox under it is. A header cell defaults to the left,
            // which on a column this narrow puts the letter visibly off to one side of the
            // thing it labels.
            this.columnAttachments.HeaderText = "A";
            this.columnAttachments.Name = "columnAttachments";
            this.columnAttachments.Width = 85;
            this.columnAttachments.HeaderCell.Style.Alignment =
                System.Windows.Forms.DataGridViewContentAlignment.MiddleCenter;
            //
            // columnUnattended
            //
            this.columnUnattended.HeaderText = "U";
            this.columnUnattended.Name = "columnUnattended";
            this.columnUnattended.Width = 85;
            this.columnUnattended.HeaderCell.Style.Alignment =
                System.Windows.Forms.DataGridViewContentAlignment.MiddleCenter;
            //
            // columnForget
            //
            // The same red X the client table uses. It appears only on a row there is
            // something to take back: one this level stores, whether that is a grant of its
            // own or an override of an inherited one. A row that is purely inherited has
            // nothing here to remove, and an X on it would promise otherwise.
            //
            // Headed with one letter and centred over the X, the way the two flag columns
            // above are. A blank heading left the only destructive control in the table
            // unlabelled.
            this.columnForget.HeaderText = "D";
            this.columnForget.HeaderCell.Style.Alignment =
                System.Windows.Forms.DataGridViewContentAlignment.MiddleCenter;
            this.columnForget.Name = "columnForget";
            this.columnForget.ReadOnly = true;
            this.columnForget.Width = 22;
            this.columnForget.DefaultCellStyle.ForeColor = System.Drawing.Color.Firebrick;
            this.columnForget.DefaultCellStyle.SelectionForeColor = System.Drawing.Color.Firebrick;
            this.columnForget.DefaultCellStyle.Alignment =
                System.Windows.Forms.DataGridViewContentAlignment.MiddleCenter;
            //
            // buttonDiscard
            //
            this.buttonDiscard.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left;
            this.buttonDiscard.Location = new System.Drawing.Point(8, 220);
            this.buttonDiscard.Name = "buttonDiscard";
            this.buttonDiscard.Size = new System.Drawing.Size(160, 23);
            this.buttonDiscard.TabIndex = 3;
            this.buttonDiscard.Text = "Discard unreadable grants";
            this.buttonDiscard.UseVisualStyleBackColor = true;
            this.buttonDiscard.Visible = false;
            this.buttonDiscard.Click += new System.EventHandler(this.buttonDiscard_Click);
            //
            // AclUserControl
            //
            this.Controls.Add(this.labelScope);
            this.Controls.Add(this.labelWarning);
            this.Controls.Add(this.gridGrants);
            this.Controls.Add(this.buttonDiscard);
            this.Name = "AclUserControl";
            this.Size = new System.Drawing.Size(486, 256);
            ((System.ComponentModel.ISupportInitialize)(this.gridGrants)).EndInit();
            this.ResumeLayout(false);
        }
    }
}
