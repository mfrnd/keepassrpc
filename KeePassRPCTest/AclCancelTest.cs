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
    /// Cancel means cancel, on the tab that edits a live object.
    ///
    /// The entry and group dialogs hand out a working copy of their object's custom data and
    /// discard it themselves, so this is about the database settings dialog, which keeps none:
    /// the editor writes the database as it goes, and without this a grant typed and then
    /// cancelled stayed. An operator who backs out of an access control dialog has to end up
    /// with what they started with, and they have no way to check that they did.
    ///
    /// The tests drive the dictionary directly rather than the grid, because what is under
    /// test is what happens to that dictionary when the dialog closes.
    /// </summary>
    [TestFixture]
    public class AclCancelTest
    {
        private const string Key = "KeePassRPC.ACL";

        /// <summary>
        /// Run a dialog carrying the ACL tab, do <paramref name="whileOpen"/> to the stored
        /// grants, and dismiss it with <paramref name="how"/>.
        ///
        /// Modal, through ShowDialog, because that is the only way the result is still
        /// readable while the form is closing, which is when the tab decides whether to put
        /// the old grants back. A modeless form loses it, and the test then measures the
        /// harness rather than the fork.
        /// </summary>
        private static void Dialog(StringDictionaryEx customData, DialogResult how,
            MethodInvoker whileOpen)
        {
            using (Form form = new Form())
            {
                AclUserControl control = new AclUserControl(customData, "scope", "detail",
                    null, new List<string>(), new List<string>());
                form.Controls.Add(control);

                // The control watches for the dialog itself once its handle exists, which
                // ShowDialog below sees to.

                form.Shown += delegate
                {
                    if (whileOpen != null)
                        whileOpen();
                    form.DialogResult = how;
                };

                form.ShowDialog();
            }
        }

        private static string Granted(string subject, AclVerb verb)
        {
            AclDocument document = new AclDocument();
            document.Set(subject, new AclGrant(verb, false, false));
            return document.ToJson();
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ADismissedDialogLeavesNoGrantBehind()
        {
            StringDictionaryEx customData = new StringDictionaryEx();

            // The Set is what the editor does when a grant is typed into an empty table.
            Dialog(customData, DialogResult.Cancel, delegate
            {
                customData.Set(Key, Granted("docs-agent", AclVerb.Read));
            });

            Assert.IsFalse(customData.Exists(Key),
                "a grant typed and then cancelled was left in the database");
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ADismissedDialogPutsTheOldGrantBack()
        {
            string original = Granted("docs-agent", AclVerb.List);
            StringDictionaryEx customData = new StringDictionaryEx();
            customData.Set(Key, original);

            Dialog(customData, DialogResult.Cancel, delegate
            {
                customData.Set(Key, Granted("docs-agent", AclVerb.Delete));
            });

            Assert.AreEqual(original, customData.Get(Key),
                "a widened grant survived the Cancel that was supposed to discard it");
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnAcceptedDialogKeepsWhatWasTyped()
        {
            StringDictionaryEx customData = new StringDictionaryEx();
            string wanted = Granted("build-agent", AclVerb.Read);

            Dialog(customData, DialogResult.OK, delegate { customData.Set(Key, wanted); });

            Assert.AreEqual(wanted, customData.Get(Key));
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void LookingAndCancellingLeavesTheGrantExactlyAsItWas()
        {
            // The restore is deliberately skipped when nothing was typed, which matters more
            // than it looks: writing a value back stamps a fresh modification time on it even
            // when the value is identical, so an unconditional restore would turn "open the
            // tab, press Cancel" into an unsaved change on a database nobody edited. That is
            // the bug fixed on 2026-08-12 and it must not come back through this door.
            string original = Granted("docs-agent", AclVerb.List);
            StringDictionaryEx customData = new StringDictionaryEx();
            customData.Set(Key, original);

            Dialog(customData, DialogResult.Cancel, null);

            Assert.AreEqual(original, customData.Get(Key));
            Assert.AreEqual(1, customData.Count, "the tab added something of its own");
        }
    }
}
