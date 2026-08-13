using System;
using System.Drawing;
using System.Windows.Forms;

namespace KeePassRPC.Forms
{
    /// <summary>
    /// A scrollbar that sits in a grid's scrollbar gutter while the grid has nothing to
    /// scroll.
    ///
    /// Both grids reserve the width of a vertical scrollbar when they size their columns,
    /// because a bar that arrives with the fourth row would otherwise push the last column
    /// half off the edge. That reservation is right, but it leaves a blank strip down the
    /// right-hand side of a short list, which reads as a rendering fault rather than as space
    /// held back on purpose.
    ///
    /// So the strip holds a real scrollbar, disabled, which is what Windows has always shown
    /// for a list with nothing to scroll. The moment the grid grows its own bar, this one
    /// hides and the real one takes the same rectangle, so nothing moves and nothing is drawn
    /// twice.
    ///
    /// It is deliberately not the grid's own scrollbar forced visible. A DataGridView decides
    /// that in its layout pass and puts it back on the next one, so anything set from outside
    /// is a fight with the control that flickers when it loses.
    /// </summary>
    internal sealed class RestingScrollBar
    {
        private readonly DataGridView _grid;
        private readonly VScrollBar _resting = new VScrollBar();
        private VScrollBar _real;
        private HScrollBar _horizontal;

        /// <summary>
        /// Give a grid a resting scrollbar. Does nothing that has to be undone: the bar
        /// belongs to the grid's parent and dies with it.
        /// </summary>
        internal static void AttachTo(DataGridView grid)
        {
            if (grid != null)
                new RestingScrollBar(grid);
        }

        private RestingScrollBar(DataGridView grid)
        {
            _grid = grid;

            // Disabled rather than merely inert: a working-looking bar that does nothing when
            // dragged is worse than an obviously greyed one, and greyed is the convention.
            _resting.Enabled = false;
            _resting.TabStop = false;
            _resting.Visible = false;

            foreach (Control child in _grid.Controls)
            {
                if (_real == null)
                    _real = child as VScrollBar;
                if (_horizontal == null)
                    _horizontal = child as HScrollBar;
            }

            if (_real != null)
                _real.VisibleChanged += Sync;
            if (_horizontal != null)
                _horizontal.VisibleChanged += Sync;

            _grid.SizeChanged += Sync;
            _grid.LocationChanged += Sync;
            _grid.VisibleChanged += Sync;
            _grid.ParentChanged += Reparent;
            _grid.RowsAdded += RowsAdded;
            _grid.RowsRemoved += RowsRemoved;
            _grid.Disposed += Detach;

            Reparent(null, EventArgs.Empty);
        }

        private void RowsAdded(object sender, DataGridViewRowsAddedEventArgs e)
        {
            Sync(sender, EventArgs.Empty);
        }

        private void RowsRemoved(object sender, DataGridViewRowsRemovedEventArgs e)
        {
            Sync(sender, EventArgs.Empty);
        }

        private void Detach(object sender, EventArgs e)
        {
            if (_resting.Parent != null)
                _resting.Parent.Controls.Remove(_resting);
            _resting.Dispose();
        }

        private void Reparent(object sender, EventArgs e)
        {
            if (_resting.Parent == _grid.Parent)
            {
                Sync(sender, e);
                return;
            }

            if (_resting.Parent != null)
                _resting.Parent.Controls.Remove(_resting);

            if (_grid.Parent != null)
                _grid.Parent.Controls.Add(_resting);

            Sync(sender, e);
        }

        /// <summary>
        /// Put the resting bar exactly where the real one would go, and show it only while the
        /// real one is away.
        /// </summary>
        private void Sync(object sender, EventArgs e)
        {
            if (_grid.Parent == null || !_grid.Visible || (_real != null && _real.Visible))
            {
                _resting.Visible = false;
                return;
            }

            int inset = BorderInset();
            int width = SystemInformation.VerticalScrollBarWidth;
            int height = _grid.Height - (inset * 2)
                - (_horizontal != null && _horizontal.Visible ? _horizontal.Height : 0);

            if (height <= 0 || _grid.Width - (inset * 2) <= width)
            {
                _resting.Visible = false;
                return;
            }

            _resting.Bounds = new Rectangle(
                _grid.Left + _grid.Width - width - inset,
                _grid.Top + inset,
                width,
                height);
            _resting.Visible = true;
            _resting.BringToFront();
        }

        /// <summary>
        /// How far inside its own edge a grid draws. A DataGridView paints its border within
        /// its client area, so the real scrollbar is offset by exactly this much and the
        /// resting one has to be too or the border shows through on one side.
        /// </summary>
        private int BorderInset()
        {
            switch (_grid.BorderStyle)
            {
                case BorderStyle.None:
                    return 0;
                case BorderStyle.Fixed3D:
                    return 2;
                default:
                    return 1;
            }
        }
    }
}
