using System.Collections.Generic;
using System.Threading;
using System.Windows.Forms;
using KeePassLib.Collections;
using KeePassRPC;
using KeePassRPC.Forms;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// Where the grant editor lands when it is attached to one of KeePass's dialogs.
    ///
    /// It used to be a tab of its own beside "Kee", which put two plugin-owned tabs on a
    /// dialog that already has four or five of KeePass's, and pushed the group dialog's strip
    /// into overflow. It now goes inside the tab the plugin already owns, but the two
    /// dialogs are not built the same way, and that is what these cover.
    ///
    /// The entry and database dialogs keep their Kee settings in a nested strip already, so
    /// the editor joins it. The group dialog has one flat control, so a strip has to be made
    /// and the existing content moved into it. Getting the second case wrong would either
    /// lose the group's own settings or leave them behind the editor.
    /// </summary>
    [TestFixture]
    public class AclTabNestingTest
    {
        // The outer strip is passed in rather than made here, because it owns the page this
        // returns: disposing it inside would hand the caller a disposed page, and not
        // disposing it at all leaks a control per test.
        private static TabPage Attach(TabControl outer, Control keeContent)
        {
            TabPage keeTabPage = new TabPage("Kee");
            keeContent.Dock = DockStyle.Fill;
            keeTabPage.Controls.Add(keeContent);
            outer.TabPages.Add(keeTabPage);

            AclUserControl.AttachTo(keeTabPage, outer, new StringDictionaryEx(),
                "scope", "the longer explanation", null,
                new List<string>(), new List<string>());

            Assert.AreEqual(1, outer.TabPages.Count,
                "the editor must not add a second tab beside Kee");
            return keeTabPage;
        }

        private static TabControl InnerOf(TabPage keeTabPage)
        {
            foreach (Control child in keeTabPage.Controls)
            {
                TabControl tabs = child as TabControl;
                if (tabs != null)
                    return tabs;

                foreach (Control grandchild in child.Controls)
                {
                    TabControl nested = grandchild as TabControl;
                    if (nested != null)
                        return nested;
                }
            }

            return null;
        }

        /// <summary>The entry and database shape: a nested strip already exists.</summary>
        [Test]
        [Apartment(ApartmentState.STA)]
        public void AnExistingInnerStripGainsAPage()
        {
            using (TabControl outer = new TabControl())
            {
                UserControl keeContent = new UserControl();
                TabControl existing = new TabControl();
                existing.TabPages.Add(new TabPage("General"));
                existing.TabPages.Add(new TabPage("URLs"));
                keeContent.Controls.Add(existing);

                TabPage keeTabPage = Attach(outer, keeContent);

                Assert.AreSame(existing, InnerOf(keeTabPage), "a second strip was created");
                Assert.AreEqual(3, existing.TabPages.Count);
                Assert.AreEqual("Access control", existing.TabPages[existing.TabPages.Count - 1].Text);
            }
        }

        /// <summary>The group shape: no strip, so one is made without losing anything.</summary>
        [Test]
        [Apartment(ApartmentState.STA)]
        public void AFlatKeeTabIsGivenAStripAndKeepsItsContent()
        {
            using (TabControl outer = new TabControl())
            {
                UserControl keeContent = new UserControl();
                Button ownedByUpstream = new Button();
                keeContent.Controls.Add(ownedByUpstream);

                TabPage keeTabPage = Attach(outer, keeContent);

                TabControl created = InnerOf(keeTabPage);
                Assert.IsNotNull(created, "no strip was created");
                Assert.AreEqual(2, created.TabPages.Count);
                Assert.AreEqual("General", created.TabPages[0].Text);
                Assert.AreEqual("Access control", created.TabPages[1].Text);

                // The group's own settings have to end up on the first page, not be dropped or
                // left underneath the strip where nothing can reach them.
                Assert.AreSame(keeContent, created.TabPages[0].Controls[0]);
                Assert.AreSame(ownedByUpstream, keeContent.Controls[0]);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void TheEditorIsOnTheAclPageAndNowhereElse()
        {
            using (TabControl outer = new TabControl())
            {
                UserControl keeContent = new UserControl();
                TabPage keeTabPage = Attach(outer, keeContent);
                TabControl inner = InnerOf(keeTabPage);

                TabPage acl = inner.TabPages[inner.TabPages.Count - 1];
                Assert.AreEqual(1, acl.Controls.Count);
                Assert.IsInstanceOf<AclUserControl>(acl.Controls[0]);
            }
        }

        [Test]
        [Apartment(ApartmentState.STA)]
        public void AttachingToNothingIsIgnoredRatherThanThrowing()
        {
            // These run inside KeePass's own dialog construction, where an exception would
            // take the dialog with it.
            Assert.DoesNotThrow(delegate
            {
                using (TabControl noPage = new TabControl())
                    AclUserControl.AttachTo(null, noPage, new StringDictionaryEx(),
                        "scope", "the longer explanation", null,
                        new List<string>(), new List<string>());

                using (TabPage noStrip = new TabPage())
                    AclUserControl.AttachTo(noStrip, null, new StringDictionaryEx(),
                        "scope", "the longer explanation", null,
                        new List<string>(), new List<string>());

                using (TabPage page = new TabPage())
                using (TabControl strip = new TabControl())
                    AclUserControl.AttachTo(page, strip, null,
                        "scope", "the longer explanation", null,
                        new List<string>(), new List<string>());
            });
        }
    }
}
