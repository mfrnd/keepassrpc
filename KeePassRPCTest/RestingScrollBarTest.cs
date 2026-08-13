using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using KeePassRPC.Forms;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// The scrollbar that fills the gutter while a grid has nothing to scroll.
    ///
    /// Both grids reserve a scrollbar's width when sizing their columns, so the strip exists
    /// whether or not a bar is in it. A placeholder that is a few pixels out of place is worse
    /// than the blank it replaces: a blank strip reads as unused space, while a scrollbar that
    /// does not line up with the one that replaces it reads as the list jumping about. So the
    /// rectangle is pinned here, measured against a real grid rather than assumed.
    /// </summary>
    [TestFixture]
    public class RestingScrollBarTest
    {
        private static DataGridView Grid(Form form, int rows)
        {
            DataGridView grid = new DataGridView();
            grid.RowHeadersVisible = false;
            grid.AllowUserToAddRows = false;
            grid.SetBounds(10, 10, 350, 120);
            grid.Columns.Add("only", "Only");
            form.Controls.Add(grid);

            for (int i = 0; i < rows; i++)
                grid.Rows.Add("row " + i);

            return grid;
        }

        private static VScrollBar Resting(Form form, DataGridView grid)
        {
            foreach (Control child in form.Controls)
            {
                VScrollBar bar = child as VScrollBar;
                if (bar != null && !grid.Controls.Contains(bar))
                    return bar;
            }

            return null;
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AShortListStillShowsAScrollbar()
        {
            using (Form form = new Form())
            {
                DataGridView grid = Grid(form, 2);
                RestingScrollBar.AttachTo(grid);
                form.Show();

                VScrollBar resting = Resting(form, grid);
                Assert.IsNotNull(resting, "no resting scrollbar was added");
                Assert.IsTrue(resting.Visible, "the gutter was left blank");

                // Greyed, because it scrolls nothing. A bar that looks live and does not
                // respond is a worse answer than a blank strip.
                Assert.IsFalse(resting.Enabled);
                Assert.IsFalse(resting.TabStop);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ItSitsExactlyWhereTheRealOneWould()
        {
            using (Form form = new Form())
            {
                // Two grids side by side in the same form: one short enough to rest, one long
                // enough to have grown a real bar. The rectangles have to agree, because the
                // whole point is that nothing moves when a list crosses that threshold.
                DataGridView shortList = Grid(form, 2);
                RestingScrollBar.AttachTo(shortList);

                DataGridView longList = Grid(form, 200);
                longList.SetBounds(10, 10, 350, 120);
                form.Show();

                VScrollBar real = null;
                foreach (Control child in longList.Controls)
                {
                    VScrollBar bar = child as VScrollBar;
                    if (bar != null)
                        real = bar;
                }

                Assert.IsNotNull(real);
                Assert.IsTrue(real.Visible, "the long list did not grow a real scrollbar");

                VScrollBar resting = Resting(form, shortList);
                Assert.IsNotNull(resting);

                // The real bar's bounds are relative to its grid, the resting one's to the
                // form, and both grids are at the same place.
                Assert.AreEqual(new Rectangle(
                        longList.Left + real.Left, longList.Top + real.Top,
                        real.Width, real.Height),
                    resting.Bounds);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ItGetsOutOfTheWayWhenTheRealOneArrives()
        {
            using (Form form = new Form())
            {
                DataGridView grid = Grid(form, 2);
                RestingScrollBar.AttachTo(grid);
                form.Show();

                VScrollBar resting = Resting(form, grid);
                Assert.IsTrue(resting.Visible);

                for (int i = 0; i < 200; i++)
                    grid.Rows.Add("more " + i);

                Assert.IsFalse(resting.Visible,
                    "two scrollbars in the same rectangle, one of them dead");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ItComesBackWhenTheRowsGoAway()
        {
            using (Form form = new Form())
            {
                DataGridView grid = Grid(form, 200);
                RestingScrollBar.AttachTo(grid);
                form.Show();

                grid.Rows.Clear();

                VScrollBar resting = Resting(form, grid);
                Assert.IsNotNull(resting);
                Assert.IsTrue(resting.Visible, "the gutter went blank again once the list shrank");
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void ItFollowsAGridThatIsResized()
        {
            using (Form form = new Form())
            {
                DataGridView grid = Grid(form, 2);
                RestingScrollBar.AttachTo(grid);
                form.Show();

                grid.SetBounds(20, 30, 200, 90);

                VScrollBar resting = Resting(form, grid);

                // Inside the grid's one-pixel border on three sides, which is where the real
                // bar goes.
                Assert.AreEqual(grid.Right - 1, resting.Right,
                    "the resting bar did not follow the grid's right edge");
                Assert.AreEqual(grid.Top + 1, resting.Top);
                Assert.AreEqual(grid.Height - 2, resting.Height);
            }
        }
    }
}
