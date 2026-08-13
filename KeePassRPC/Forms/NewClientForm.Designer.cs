namespace KeePassRPC.Forms
{
    partial class NewClientForm
    {
        private System.ComponentModel.IContainer components = null;

        private System.Windows.Forms.Label labelPaired;
        private System.Windows.Forms.Label labelNothingYet;
        private System.Windows.Forms.Label labelProfile;
        private System.Windows.Forms.ComboBox comboProfile;
        private System.Windows.Forms.Label labelGrantsStill;
        private System.Windows.Forms.Label labelProfileNote;
        private System.Windows.Forms.Button buttonSave;
        private System.Windows.Forms.Button buttonLater;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
                components.Dispose();

            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.labelPaired = new System.Windows.Forms.Label();
            this.labelNothingYet = new System.Windows.Forms.Label();
            this.labelProfile = new System.Windows.Forms.Label();
            this.comboProfile = new System.Windows.Forms.ComboBox();
            this.labelGrantsStill = new System.Windows.Forms.Label();
            this.labelProfileNote = new System.Windows.Forms.Label();
            this.buttonSave = new System.Windows.Forms.Button();
            this.buttonLater = new System.Windows.Forms.Button();
            this.SuspendLayout();
            //
            // labelPaired
            //
            this.labelPaired.AutoSize = true;
            this.labelPaired.Location = new System.Drawing.Point(12, 12);
            this.labelPaired.MaximumSize = new System.Drawing.Size(420, 0);
            this.labelPaired.Name = "labelPaired";
            this.labelPaired.TabIndex = 0;
            //
            // labelNothingYet
            //
            this.labelNothingYet.AutoSize = true;
            this.labelNothingYet.Location = new System.Drawing.Point(12, 40);
            this.labelNothingYet.MaximumSize = new System.Drawing.Size(420, 0);
            this.labelNothingYet.Name = "labelNothingYet";
            this.labelNothingYet.TabIndex = 1;
            this.labelNothingYet.Text = "It cannot call anything yet. Every paired client is refused by default, so nothing"
                + " reaches this database until you say what this one may do.";
            //
            // labelProfile
            //
            this.labelProfile.AutoSize = true;
            this.labelProfile.Location = new System.Drawing.Point(12, 80);
            this.labelProfile.Name = "labelProfile";
            this.labelProfile.TabIndex = 2;
            this.labelProfile.Text = "This client may call:";
            //
            // comboProfile
            //
            this.comboProfile.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboProfile.Location = new System.Drawing.Point(130, 77);
            this.comboProfile.Name = "comboProfile";
            this.comboProfile.Size = new System.Drawing.Size(220, 21);
            this.comboProfile.TabIndex = 3;
            //
            // labelGrantsStill
            //
            this.labelGrantsStill.AutoSize = true;
            this.labelGrantsStill.Location = new System.Drawing.Point(12, 140);
            this.labelGrantsStill.MaximumSize = new System.Drawing.Size(420, 0);
            this.labelGrantsStill.Name = "labelGrantsStill";
            this.labelGrantsStill.TabIndex = 5;
            //
            // labelProfileNote
            //
            // Which entries a client reaches is a separate question from which API it may
            // call, and it is answered per database rather than here: a client is in the
            // "default" profile of every database until somebody puts it in another one.
            this.labelProfileNote.AutoSize = true;
            this.labelProfileNote.Location = new System.Drawing.Point(12, 170);
            this.labelProfileNote.MaximumSize = new System.Drawing.Size(420, 0);
            this.labelProfileNote.Name = "labelProfileNote";
            this.labelProfileNote.TabIndex = 5;
            this.labelProfileNote.Text = "Which entries it reaches is set per database. In every database it starts in the "
                + "\"default\" profile and holds whatever that profile is granted there. To give it "
                + "something else, put it in another profile: Database Settings, the Kee tab, "
                + "Access control.";
            //
            // buttonSave
            //
            this.buttonSave.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.buttonSave.Location = new System.Drawing.Point(270, 180);
            this.buttonSave.Name = "buttonSave";
            this.buttonSave.Size = new System.Drawing.Size(80, 23);
            this.buttonSave.TabIndex = 6;
            this.buttonSave.Text = "Save";
            this.buttonSave.UseVisualStyleBackColor = true;
            //
            // buttonLater
            //
            this.buttonLater.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.buttonLater.Location = new System.Drawing.Point(356, 180);
            this.buttonLater.Name = "buttonLater";
            this.buttonLater.Size = new System.Drawing.Size(80, 23);
            this.buttonLater.TabIndex = 7;
            this.buttonLater.Text = "Not now";
            this.buttonLater.UseVisualStyleBackColor = true;
            //
            // NewClientForm
            //
            // Escape and the close box leave the client denied, which is the state it is
            // already in, so a hurried person cannot grant anything by accident. There is
            // deliberately no default button: with one, Enter after choosing a profile would
            // either save a choice nobody confirmed or discard one they thought they had
            // made, and both of those are worse than Enter doing nothing.
            this.CancelButton = this.buttonLater;
            this.ClientSize = new System.Drawing.Size(448, 215);
            this.Controls.Add(this.labelPaired);
            this.Controls.Add(this.labelNothingYet);
            this.Controls.Add(this.labelProfile);
            this.Controls.Add(this.comboProfile);
            this.Controls.Add(this.labelGrantsStill);
            this.Controls.Add(this.labelProfileNote);
            this.Controls.Add(this.buttonSave);
            this.Controls.Add(this.buttonLater);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "NewClientForm";
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "A new client has paired";
            this.ResumeLayout(false);
            this.PerformLayout();
        }
    }
}
