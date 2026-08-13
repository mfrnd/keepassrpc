using System;
using System.Windows.Forms;
using KeePassLib.Collections;

namespace KeePassRPC.Forms
{
    /// <summary>
    /// Puts one <c>CustomData</c> value back when a dialog is dismissed.
    ///
    /// The entry and group dialogs hand out a working copy of their object's custom data and
    /// throw it away themselves if they are cancelled. The database settings dialog keeps no
    /// copy, so a tab on it edits the live database, and without this a rule typed there
    /// outlives the Cancel that was meant to discard it. An access control editor where Cancel
    /// leaves the rule in place is worse than one that cannot edit at all, because the operator
    /// believes they backed out.
    ///
    /// Deliberately does nothing when the value has not changed. Writing an identical value
    /// back stamps a fresh modification time on it, which is how merely opening a dialog used
    /// to leave a database looking edited.
    /// </summary>
    internal sealed class DismissalRevert
    {
        private readonly StringDictionaryEx _data;
        private readonly string _key;
        private readonly string _openedWith;
        private bool _watching;

        internal DismissalRevert(StringDictionaryEx data, string key)
        {
            _data = data;
            _key = key;
            _openedWith = Current();
        }

        /// <summary>
        /// Start watching <paramref name="host"/>. Safe to call more than once and with null,
        /// so a caller can try as soon as it has a handle and again once it knows the dialog.
        /// </summary>
        internal void Watch(Form host)
        {
            if (_watching || host == null || _data == null)
                return;

            _watching = true;

            // FormClosed, not FormClosing: a closing dialog can still be kept open by another
            // handler, and putting the old value back under an editor that is still on screen
            // would silently discard what the operator can see they typed.
            host.FormClosed += Closed;
        }

        private void Closed(object sender, FormClosedEventArgs e)
        {
            Form host = sender as Form;
            if (host != null && host.DialogResult == DialogResult.OK)
                return;

            string now = Current();
            if (now == _openedWith)
                return;

            if (_openedWith == null)
                _data.Remove(_key);
            else
                _data.Set(_key, _openedWith);
        }

        private string Current()
        {
            if (_data == null || !_data.Exists(_key))
                return null;

            return _data.Get(_key);
        }
    }
}
