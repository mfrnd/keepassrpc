using System.Threading;
using System.Windows.Forms;
using KeePassRPC;
using KeePassRPC.Forms;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// The prompt raised when a client finishes pairing.
    ///
    /// It exists because pairing grants nothing and the setting that would is somewhere nobody
    /// looks, so a new client appears broken and the fix reached for is the widest one. That
    /// makes its default the whole point: a dialog that appears at the end of a successful
    /// pairing, when the user is pleased and in a hurry, must not be one where the fastest
    /// answer grants anything.
    /// </summary>
    [TestFixture]
    public class NewClientFormTest
    {
        [Test]
        [Apartment(ApartmentState.STA)]
        public void ItOpensOnRefused()
        {
            using (NewClientForm form = new NewClientForm("agent-fictitious", "Fictitious agent"))
                Assert.AreSame(AccessChoice.Refused, form.Selected);
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void DismissingItGrantsNothing()
        {
            // "Not now" is the cancel button, and there is deliberately no default button, so
            // Escape, the close box and a stray Enter all leave the client where it was.
            using (NewClientForm form = new NewClientForm("agent-fictitious", "Fictitious agent"))
            {
                Assert.IsNull(form.AcceptButton, "Enter would answer this dialog for the user");
                Assert.IsNotNull(form.CancelButton);
                Assert.AreEqual(DialogResult.Cancel, ((Button)form.CancelButton).DialogResult);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ItOffersTheSameChoicesAsTheClientAccessTab()
        {
            // Two lists of the same decision would drift, and the pair that drifted would be
            // the one shown at pairing time and the one shown when reviewing it later.
            using (NewClientForm form = new NewClientForm("agent-fictitious", "Fictitious agent"))
            {
                ComboBox box = null;
                foreach (Control child in form.Controls)
                {
                    box = child as ComboBox;
                    if (box != null)
                        break;
                }

                Assert.IsNotNull(box, "the prompt has no choice on it");
                Assert.AreEqual(AccessChoice.All.Count, box.Items.Count);
                for (int i = 0; i < AccessChoice.All.Count; i++)
                    Assert.AreSame(AccessChoice.All[i], box.Items[i]);
            }
        }

        [Test]
        public void AClientThatAlreadyHoldsASettingIsNotAskedAgain()
        {
            // Re-pairing is a re-key, not a new decision. A host is needed to answer properly,
            // so this covers only the arguments that can be judged without one; both of them
            // are ways the prompt could be raised for nobody.
            Assert.IsFalse(NewClientForm.NeedsDeciding(null, "agent-fictitious"));
            Assert.IsFalse(NewClientForm.NeedsDeciding(null, null));
        }
    }
}
