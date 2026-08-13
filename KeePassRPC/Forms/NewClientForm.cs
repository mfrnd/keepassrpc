using System;
using System.Drawing;
using System.Windows.Forms;
using KeePassRPC.Acl;

namespace KeePassRPC.Forms
{
    /// <summary>
    /// Asks what a client that has just paired may call.
    ///
    /// Pairing on its own grants nothing: the method gate is default deny, so a client that
    /// has completed SRP can call nothing at all until a profile is set for it, and the place
    /// that is set is three clicks into an options dialog nobody has a reason to open.
    /// Somebody who has just typed a pairing code has to be told that, or their new client
    /// simply appears broken and the obvious fix they reach for is the widest one.
    ///
    /// This is the one moment a human is certainly present, because the code is shown only on
    /// the KeePass host's screen and pairing cannot complete without someone reading it. That
    /// is what makes a prompt here honest rather than a dialog raised by a network event.
    ///
    /// It chooses, it does not write. What is stored is the caller's business, and keeping the
    /// two apart is what lets the defaults below be checked without a running KeePass.
    /// </summary>
    public partial class NewClientForm : Form
    {
        private readonly string _clientName;
        private readonly string _subject;

        public NewClientForm(string subject, string clientName)
        {
            InitializeComponent();

            _subject = subject == null ? string.Empty : subject;
            _clientName = string.IsNullOrEmpty(clientName) ? "A client" : clientName;

            foreach (AccessChoice choice in AccessChoice.All)
                comboProfile.Items.Add(choice);

            // Deny, until somebody chooses otherwise. This dialog exists to make the choice
            // easy to find, not to make it for anybody.
            comboProfile.SelectedItem = AccessChoice.Refused;
            comboProfile.SelectedIndexChanged += delegate { ShowDetail(); };
        }

        /// <summary>What the user chose. Meaningful only when the dialog was accepted.</summary>
        internal AccessChoice Selected
        {
            get { return comboProfile.SelectedItem as AccessChoice ?? AccessChoice.Refused; }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            labelPaired.Text = "\"" + _clientName + "\" has paired, and is now known as "
                + _subject + ".";

            ShowDetail();
            Reflow();
        }

        /// <summary>
        /// Say what the chosen option means, under the box that chose it.
        ///
        /// The options are short enough to compare at a glance and too short to be acted on
        /// safely without this: "with ACL" and "unrestricted" are one word apart and several
        /// databases apart.
        /// </summary>
        private void ShowDetail()
        {
            labelGrantsStill.Text = Selected.Detail;
            Reflow();
        }

        /// <summary>
        /// Place the rows down the dialog, since two of the labels wrap to a height that
        /// depends on how long the client called itself.
        /// </summary>
        private void Reflow()
        {
            const int Margin = 12;
            const int Gap = 10;

            int top = labelPaired.Bottom + Gap;
            labelNothingYet.Location = new Point(Margin, top);

            top = labelNothingYet.Bottom + Gap + 4;
            labelProfile.Location = new Point(Margin, top + 3);
            comboProfile.Location = new Point(Margin + labelProfile.PreferredSize.Width + 8, top);

            top = comboProfile.Bottom + Gap + 4;
            labelGrantsStill.Location = new Point(Margin, top);

            top = labelGrantsStill.Bottom + Gap + 6;
            labelProfileNote.Location = new Point(Margin, top);

            top = labelProfileNote.Bottom + Gap + 6;
            buttonSave.Location = new Point(ClientSize.Width - Margin - buttonSave.Width
                - Gap - buttonLater.Width, top);
            buttonLater.Location = new Point(ClientSize.Width - Margin - buttonLater.Width, top);

            ClientSize = new Size(ClientSize.Width, buttonLater.Bottom + Margin);
        }

        /// <summary>
        /// Store the choice for a subject. Here rather than in the dialog so that the dialog
        /// stays a chooser and this stays the one place a profile is written at pairing time.
        /// </summary>
        internal static void Apply(KeePass.Plugins.IPluginHost host, string subject,
            AccessChoice chosen)
        {
            if (host == null || string.IsNullOrEmpty(subject) || chosen == null)
                return;

            host.CustomConfig.SetString(SubjectRegistry.ProfilePrefix + subject, chosen.Profile);
            host.CustomConfig.SetString(AclScope.SubjectPrefix + subject, chosen.Scope);
        }

        /// <summary>
        /// Whether this subject has been decided about already.
        ///
        /// Re-pairing an existing client is a re-key, not a new decision, and asking again
        /// every time would train people to dismiss the question.
        /// </summary>
        internal static bool NeedsDeciding(KeePass.Plugins.IPluginHost host, string subject)
        {
            if (host == null || string.IsNullOrEmpty(subject))
                return false;

            return string.IsNullOrEmpty(
                host.CustomConfig.GetString(SubjectRegistry.ProfilePrefix + subject, null));
        }
    }
}
