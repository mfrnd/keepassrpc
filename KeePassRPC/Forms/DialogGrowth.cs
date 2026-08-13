using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassRPC.Forms
{
    /// <summary>
    /// Making room on somebody else's dialog.
    ///
    /// Two of KeePass's dialogs and this plugin's own options dialog are laid out at fixed
    /// positions and anchor nothing, so a control added to one of them gets whatever space
    /// the original author happened to leave. That is not enough for either editor this fork
    /// adds, and the failure is quiet: a list anchored top and bottom collapses to nothing
    /// rather than overflowing.
    ///
    /// Shared rather than duplicated because the second caller arrived a day after the
    /// first, and the awkward parts are worth getting right once: which siblings to move,
    /// never widening, and clamping to the screen.
    /// </summary>
    internal static class DialogGrowth
    {
        /// <summary>
        /// Let the tab strip wrap if this tab has pushed it past the edge.
        ///
        /// The group dialog fits five tabs and this is the sixth, so without this the tab it
        /// adds is only reachable by clicking a scroll arrow. That is easy to miss entirely, and the
        /// arrows appear at the far right where nobody looks for a tab. Wrapping to a second
        /// row makes every tab visible at once. Widening the dialog would also fix it and is
        /// not an option; see the note on EnsureRoomFor.
        ///
        /// Only when it is actually needed, so a dialog whose tabs already fit keeps the
        /// single row upstream intended.
        /// </summary>
        internal static void EnsureTabIsReachable(TabControl tabs)
        {
            if (tabs.Multiline || tabs.TabCount == 0)
                return;

            try
            {
                if (tabs.GetTabRect(tabs.TabCount - 1).Right <= tabs.ClientSize.Width)
                    return;

                // Upstream's entry strip is the only one in any of these dialogs with a fixed
                // tab width, and at 152px it fits three tabs and not four. Letting the tabs
                // size to their labels is what every other strip here already does, both the
                // dialog's own and the one this code creates for groups, so it both fits
                // and looks less like an exception.
                if (tabs.SizeMode == TabSizeMode.Fixed)
                {
                    tabs.SizeMode = TabSizeMode.Normal;
                    if (tabs.GetTabRect(tabs.TabCount - 1).Right <= tabs.ClientSize.Width)
                        return;
                }

                // Genuinely too many tabs for the width. A second row is ugly but every tab
                // stays reachable, which the scroll arrows barely manage.
                tabs.Multiline = true;
            }
            catch (ArgumentOutOfRangeException)
            {
                // GetTabRect needs the strip to have been measured. If it has not been, the
                // tabs cannot have overflowed anything yet either.
            }
        }

        /// <summary>
        /// Grow the host dialog vertically if its tab strip is too short for this editor.
        ///
        /// Reaching into an upstream dialog's geometry is not done lightly, and it is done
        /// here because the alternative is worse. The entry dialog happens to be large enough;
        /// the group dialog is not, and it is the one that matters most, since the design's
        /// advice is to grant at group level rather than at the database root. Without this
        /// the group tab shows an editor with no list in it.
        ///
        /// Enlarging the dialog alone is not sufficient: upstream's group dialog is laid out at
        /// fixed positions, so the extra space would appear as a blank margin and the tab
        /// control would stay its original size. Nor can the tab control simply be anchored to
        /// all four edges. An earlier attempt did exactly that, and the tab control then grew
        /// straight over the OK and Cancel buttons, which are not bottom-anchored either. So
        /// the controls sitting below the tabs are moved down by the amount the dialog grew,
        /// which is what an anchored layout would have done for them.
        ///
        /// **Height only, deliberately.** Widening the dialog was tried and produced two
        /// visible defects, because two things upstream draws are pinned to the right edge and
        /// follow nothing: the OK and Cancel buttons ended up stranded mid-dialog, and the
        /// banner across the top is a bitmap generated at the original width, so it stopped
        /// short and left a white band. Both are fixable by hand, by re-deriving right margins
        /// and by stretching or regenerating somebody else's banner, and neither is worth it
        /// when the editor can simply be laid out to fit the narrowest dialog it appears in.
        /// It is, so it does. Vertical space is the one dimension that cannot be economised
        /// away, because a list needs rows.
        ///
        /// All of it is one-way, since the dialog is only ever grown and never shrunk, so a dialog
        /// that already has room is left exactly as upstream drew it.
        /// </summary>
        internal static void EnsureRoomFor(TabControl tabs, TabControl innermost, Size needed)
        {
            Form host = tabs.FindForm();
            if (host == null)
                return;

            Rectangle workingArea = Screen.GetWorkingArea(host);
            int grownHeight = GrownHeightToFit(
                host.Height, innermost.DisplayRectangle.Height, needed.Height, workingArea.Height);

            int deltaY = grownHeight - host.Height;
            if (deltaY <= 0)
                return;

            // A MaximumSize set by the dialog would silently swallow the resize.
            if (host.MaximumSize.Height > 0 && host.MaximumSize.Height < grownHeight)
                host.MaximumSize = new Size(host.MaximumSize.Width, grownHeight);

            host.SuspendLayout();
            try
            {
                // Anything already anchored to an edge follows the resize by itself; moving it
                // too would move it twice.
                foreach (Control sibling in host.Controls)
                {
                    if (sibling == tabs)
                        continue;

                    if (sibling.Top >= tabs.Bottom && (sibling.Anchor & AnchorStyles.Bottom) == 0)
                        sibling.Top += deltaY;
                }

                tabs.Height += deltaY;
                host.Height = grownHeight;
            }
            finally
            {
                host.ResumeLayout(true);
            }

            Point placed = KeptOnScreen(host.Bounds, workingArea);
            if (placed != host.Location)
                host.Location = placed;
        }

        /// <summary>
        /// How tall a dialog has to become for a tab page to offer <paramref name="neededHeight"/>.
        ///
        /// Pure arithmetic, separated from the controls so it can be tested: the clamping is
        /// the part that is easy to get subtly wrong, and the part whose failure would be
        /// invisible until somebody opened the dialog on a small screen.
        /// </summary>
        /// <param name="hostHeight">The dialog's current outer height.</param>
        /// <param name="availableHeight">What a tab page currently offers.</param>
        /// <param name="neededHeight">What the editor needs.</param>
        /// <param name="workingAreaHeight">The usable screen height, excluding the taskbar.</param>
        internal static int GrownHeightToFit(int hostHeight, int availableHeight, int neededHeight,
            int workingAreaHeight)
        {
            int shortOf = neededHeight - availableHeight;
            if (shortOf <= 0)
                return hostHeight;

            int grown = hostHeight + shortOf;

            // A dialog taller than the screen is not an improvement, and never shorter than it
            // already was: shrinking somebody's dialog to fit our tab would be a rude answer to
            // a small screen. AutoScroll on the page covers whatever is left over.
            if (grown > workingAreaHeight)
                grown = Math.Max(hostHeight, workingAreaHeight);

            return grown;
        }

        /// <summary>
        /// Widen a dialog, taking its contents with it.
        ///
        /// Width is normally the dimension not to touch, because controls pinned to the right
        /// edge by a fixed position do not follow and end up stranded in the middle. That is
        /// why the entry and group dialogs are only ever grown in height. This form is
        /// different: it is the plugin's own, its banner sits at the left rather than being
        /// stretched across the top, and its client table has five columns to fit.
        ///
        /// So the pinning is done here instead of avoided. A control whose right edge was
        /// near the old right edge either moves or stretches: it moves if it started in the
        /// right-hand half, which is what a button does, and stretches if it started at the
        /// left, which is what a tab control or a full-width label does.
        /// </summary>
        /// <param name="form">The dialog to widen. Its minimum size is widened to match.</param>
        /// <param name="extra">Pixels to add. Nothing happens if this is not positive.</param>
        internal static void Widen(Form form, int extra)
        {
            if (form == null || extra <= 0)
                return;

            int was = form.ClientSize.Width;

            // Anything starting in the right-hand half moves, and anything starting at the
            // left but reaching the right edge stretches. The half is the test rather than a
            // margin from the edge, because a row of buttons is pinned as a group: only the
            // last of them actually touches the edge, and moving that one alone would leave a
            // gap in the middle of the row where the others used to sit beside it.
            const int Margin = 24;

            List<Control> pinned = new List<Control>();
            List<Control> stretched = new List<Control>();

            foreach (Control child in form.Controls)
            {
                if (child.Left > was / 2)
                    pinned.Add(child);
                else if (child.Right >= was - Margin)
                    stretched.Add(child);
            }

            // Tab pages are resized by their tab control after this, so their contents have
            // to be spread afterwards against the width they had before. Recorded now,
            // because by then the old width is gone.
            Dictionary<TabPage, int> pageWidths = new Dictionary<TabPage, int>();
            foreach (Control child in stretched)
            {
                TabControl tabs = child as TabControl;
                if (tabs == null)
                    continue;

                foreach (TabPage page in tabs.TabPages)
                    pageWidths[page] = page.ClientSize.Width;
            }

            form.ClientSize = new Size(was + extra, form.ClientSize.Height);
            if (form.MinimumSize.Width > 0)
                form.MinimumSize = new Size(form.MinimumSize.Width + extra, form.MinimumSize.Height);

            foreach (Control child in pinned)
                child.Left += extra;

            foreach (Control child in stretched)
                child.Width += extra;

            // Laid out now rather than whenever the message loop gets to it, because the
            // caller's next act is to measure the space this has just made.
            form.PerformLayout();

            foreach (KeyValuePair<TabPage, int> entry in pageWidths)
                SpreadWhenSized(entry.Key, entry.Value);

            form.Location = KeptOnScreen(form.Bounds, Screen.GetWorkingArea(form));
        }

        /// <summary>
        /// Spread a page now if it has already taken its new width, and otherwise the moment
        /// it does.
        ///
        /// A tab control only sizes the page it is showing. The others keep the width they
        /// were drawn at until they are selected for the first time, so spreading them all at
        /// once quietly does nothing to any tab but the front one.
        /// </summary>
        /// <summary>
        /// A page that lays itself out, and so must not be spread as well.
        ///
        /// Two layouts on one page fight: whichever runs second undoes half of the first, and
        /// the visible result was a label stretched to a new width while keeping the height
        /// it needed at the old one, so its last line was simply cut off.
        /// </summary>
        internal const string SelfLaidOut = "KeePassRPC.SelfLaidOut";

        private static void SpreadWhenSized(TabPage page, int oldClientWidth)
        {
            if (page == null || oldClientWidth <= 0 || SelfLaidOut.Equals(page.Tag))
                return;

            if (page.ClientSize.Width > oldClientWidth)
            {
                Spread(page, oldClientWidth);
                return;
            }

            bool spread = false;
            page.Resize += delegate
            {
                if (spread || page.ClientSize.Width <= oldClientWidth)
                    return;

                spread = true;
                Spread(page, oldClientWidth);
            };
        }

        /// <summary>
        /// Spread a container's contents across a width it has just gained.
        ///
        /// Widening a dialog is only half of it: the tabs inside were laid out for the old
        /// width, so without this they keep their old shape and the new space is simply blank
        /// down the right-hand side. Everything is scaled by the same ratio, which widens a
        /// paragraph so it wraps to fewer lines and moves a second column of controls out to
        /// where it still balances the first.
        ///
        /// Only what benefits is touched. A group box, a panel and a wrapped label all read
        /// better wider; a checkbox, a text box and a drop-down do not, and stretching a port
        /// field to four hundred pixels would look like a mistake rather than a use of space.
        /// Group boxes are then spread again inside, or their own paragraphs would keep the
        /// wrapping they had before the box around them grew.
        /// </summary>
        internal static void Spread(Control parent, int oldClientWidth)
        {
            if (parent == null || oldClientWidth <= 0)
                return;

            int now = parent.ClientSize.Width;
            if (now <= oldClientWidth)
                return;

            foreach (Control child in parent.Controls)
            {
                if (!Stretches(child))
                    continue;

                int inner = child.ClientSize.Width;
                int left = child.Left * now / oldClientWidth;
                int right = child.Right * now / oldClientWidth;

                child.SetBounds(left, child.Top, Math.Max(1, right - left), child.Height);
                Spread(child, inner);
            }
        }

        /// <summary>Whether a control reads better for being wider.</summary>
        private static bool Stretches(Control child)
        {
            if (child is GroupBox || child is Panel)
                return true;

            // An AutoSize label is as wide as its text and cannot wrap, so widening it does
            // nothing. One with a fixed width is a paragraph, and widening it is the point.
            Label label = child as Label;
            return label != null && !label.AutoSize;
        }

        /// <summary>
        /// Where a window should sit so that growing it has not pushed it off the screen.
        /// Returns the existing location when it is already fully visible.
        /// </summary>
        internal static Point KeptOnScreen(Rectangle window, Rectangle workingArea)
        {
            int x = window.Left;
            int y = window.Top;

            if (x + window.Width > workingArea.Right) x = workingArea.Right - window.Width;
            if (y + window.Height > workingArea.Bottom) y = workingArea.Bottom - window.Height;

            // Left and top win over right and bottom: a window wider than the screen should
            // have its top-left corner visible, not its bottom-right.
            if (x < workingArea.Left) x = workingArea.Left;
            if (y < workingArea.Top) y = workingArea.Top;

            return new Point(x, y);
        }
    }
}
