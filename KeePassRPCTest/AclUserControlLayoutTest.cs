using System.Collections.Generic;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using KeePassLib.Collections;
using KeePassRPC;
using KeePassRPC.Forms;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// The geometry behind fitting the grant editor into a dialog that upstream sized for
    /// something else.
    ///
    /// Worth testing rather than eyeballing, because of how this failed the first time. The
    /// grant list is anchored top and bottom, so in a tab page shorter than the control was
    /// drawn for it does not overflow or clip. It collapses to nothing and disappears,
    /// leaving an editor that looks like it is telling you there are no grants. An access
    /// control editor that silently shows an empty list is worse than one that fails to open:
    /// an operator who believes nothing is granted here is being invited to grant more.
    /// </summary>
    [TestFixture]
    public class AclUserControlLayoutTest
    {
        // The group dialog is the small one: roughly 390x333 outer, offering a tab page of
        // about 350x195, against an editor drawn at 486x400.
        private const int ScreenHeight = 1040;
        private const int Needed = 400;
        private const int GroupDialogHeight = 333;
        private const int GroupTabPageHeight = 195;
        private const int GroupTabPageWidth = 350;

        [Test]
        public void ADialogWithRoomIsLeftAlone()
        {
            // If upstream drew it big enough, we do not touch it.
            Assert.AreEqual(600, DialogGrowth.GrownHeightToFit(600, 520, Needed, ScreenHeight));
        }

        [Test]
        public void ADialogThatIsTooShortGrowsByExactlyTheShortfall()
        {
            Assert.AreEqual(GroupDialogHeight + (Needed - GroupTabPageHeight),
                DialogGrowth.GrownHeightToFit(
                    GroupDialogHeight, GroupTabPageHeight, Needed, ScreenHeight));
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void NothingSticksOutOfTheNarrowestDialogItAppearsIn()
        {
            // Why width is never grown: the editor lays itself out to fit instead. Two things
            // upstream pins to the right edge follow nothing when a dialog widens: the OK
            // and Cancel buttons, and the banner across the top, which is a bitmap generated
            // at the original width and leaves a white band when the dialog outgrows it.
            //
            // So this is the constraint that keeps that decision honest: at the width of the
            // narrowest tab page the editor is attached to, nothing may stick out. It runs
            // the real layout rather than reading designer metadata, because the rows are
            // placed in code now and the designer positions mean nothing.
            using (AclUserControl control = new AclUserControl(new StringDictionaryEx(),
                "scope", "the longer explanation", null,
                new List<string>(), new List<string>()))
            {
                control.Size = new Size(GroupTabPageWidth, control.Height);

                foreach (Control child in control.Controls)
                {
                    if (!child.Visible)
                        continue;

                    Assert.LessOrEqual(child.Right, GroupTabPageWidth,
                        child.Name + " sticks out past the narrowest dialog this tab is added to");
                }
            }
        }

        [Test]
        public void ADialogIsNeverGrownBeyondTheScreen()
        {
            Assert.LessOrEqual(DialogGrowth.GrownHeightToFit(600, 10, Needed, 600), 600);
        }

        [Test]
        public void ADialogAlreadyTallerThanTheScreenIsNotShrunk()
        {
            // Shrinking somebody's dialog to fit our tab would be a rude answer to a small
            // screen, and would hide their controls to reveal ours.
            Assert.GreaterOrEqual(DialogGrowth.GrownHeightToFit(900, 10, Needed, 700), 900);
        }

        // --- staying visible after the growth ---------------------------------------------

        [Test]
        public void AWindowFullyOnScreenIsNotMoved()
        {
            Rectangle window = new Rectangle(100, 100, 500, 400);
            Assert.AreEqual(new Point(100, 100),
                DialogGrowth.KeptOnScreen(window, new Rectangle(0, 0, 1920, 1040)));
        }

        [Test]
        public void AWindowPushedPastTheEdgeComesBack()
        {
            Rectangle window = new Rectangle(1700, 900, 500, 400);
            Point placed = DialogGrowth.KeptOnScreen(window, new Rectangle(0, 0, 1920, 1040));

            Assert.AreEqual(1920 - 500, placed.X);
            Assert.AreEqual(1040 - 400, placed.Y);
        }

        [Test]
        public void TheTopLeftWinsWhenAWindowIsLargerThanTheScreen()
        {
            // Otherwise the correction puts the title bar off the top, which is the one part
            // that has to stay reachable.
            Point placed = DialogGrowth.KeptOnScreen(
                new Rectangle(50, 50, 2000, 1200), new Rectangle(0, 0, 1920, 1040));

            Assert.AreEqual(0, placed.X);
            Assert.AreEqual(0, placed.Y);
        }

        [Test]
        public void AWorkingAreaThatDoesNotStartAtTheOriginIsRespected()
        {
            // A second monitor sits at a non-zero offset, and this fork's own test machine
            // has one to the left of the primary at a negative coordinate.
            Rectangle secondary = new Rectangle(-1920, 0, 1920, 1040);
            Point placed = DialogGrowth.KeptOnScreen(
                new Rectangle(-100, 900, 500, 400), secondary);

            Assert.AreEqual(-1920 + 1920 - 500, placed.X);
            Assert.AreEqual(1040 - 400, placed.Y);
        }
    }
}
