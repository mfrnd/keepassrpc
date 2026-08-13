using System;
using System.Collections.Generic;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.UI;
using KeePass.Util.MultipleValues;
using KeePassLib;
using KeePassLib.Collections;
using KeePassRPC.Acl;
using KeePassRPC.Forms;
using KeePassRPC.Models.DataExchange;
using KeePassRPC.Properties;

namespace KeePassRPC
{
    /// <summary>
    /// Base class for all RPCClient managers.
    /// </summary>
    public abstract class KeePassRPCClientManager
    {
        private string _name;
        private string _callbackMethodName;
        public string Name { get { return _name; } private set { _name = value; } }
        public string CallbackMethodName { get { return _callbackMethodName; } private set { _callbackMethodName = value; } }
        private List<KeePassRPCClientConnection> _RPCClientConnections = new List<KeePassRPCClientConnection>(1);
        private static object _lockRPCClients = new object();

        public KeePassRPCClientManager(string name, string callbackName)
        {
            Name = name;
            CallbackMethodName = callbackName;
        }

        private KeePassRPCClientManager()
        {
        }

        /// <summary>
        /// Signals all clients.
        /// </summary>
        /// <param name="signal">The signal.</param>
        public virtual void SignalAll(Signal signal)
        {
            foreach (KeePassRPCClientConnection client in _RPCClientConnections)
                client.Signal(signal, CallbackMethodName);
        }

        /// <summary>
        /// Adds an RPC client.
        /// </summary>
        /// <param name="client">The client.</param>
        public void AddRPCClientConnection(KeePassRPCClientConnection client)
        {
            lock (_lockRPCClients)
            {
                _RPCClientConnections.Add(client);
            }
        }

        /// <summary>
        /// Removes an RPC client.
        /// </summary>
        /// <param name="client">The client.</param>
        public void RemoveRPCClientConnection(KeePassRPCClientConnection client)
        {
            lock (_lockRPCClients)
            {
                client.ShuttingDown();
                _RPCClientConnections.Remove(client);
            }
        }

        /// <summary>
        /// Gets the current RPC clients. ACTUAL client list may change immediately after this array is returned.
        /// </summary>
        /// <value>The current RPC clients.</value>
        public KeePassRPCClientConnection[] CurrentRPCClientConnections
        {
            get
            {
                lock (_lockRPCClients)
                {
                    KeePassRPCClientConnection[] clients = new KeePassRPCClientConnection[_RPCClientConnections.Count];
                    _RPCClientConnections.CopyTo(clients);
                    return clients;
                }
            }
        }

        /// <summary>
        /// Terminates this server.
        /// </summary>
        public void Terminate()
        {
            lock (_lockRPCClients)
            {
                SignalAll(Signal.EXITING);
                _RPCClientConnections.Clear();
            }
        }

        public virtual void AttachToEntryDialog(KeePassRPCExt plugin, PwEntry entry, TabControl mainTabControl, PwEntryForm form, CustomListViewEx advancedListView, ProtectedStringDictionary strings, StringDictionaryEx customData)
        {
        }

        public virtual void AttachToGroupDialog(KeePassRPCExt plugin, PwGroup group, TabControl mainTabControl)
        {
        }


    }

    public class GeneralRPCClientManager : KeePassRPCClientManager
    {
        public GeneralRPCClientManager()
            : base("General", "KPRPCListener")
        {

        }

        public override void AttachToEntryDialog(KeePassRPCExt plugin, PwEntry entry, TabControl mainTabControl, PwEntryForm form, CustomListViewEx advancedListView, ProtectedStringDictionary strings, StringDictionaryEx customData)
        {
            UserControl entryControl;

            string mvString = MultipleValuesEx.CueString;
            string json1 = strings.ReadSafe("KPRPC JSON");
            string json2 = customData.Get("KPRPC JSON");
            bool multipleEntriesSelected = false;
            if ((!string.IsNullOrEmpty(json1) && mvString == json1) || (!string.IsNullOrEmpty(json2) && mvString == json2))
            {
                entryControl = new KeeMultiEntryUserControl();
                multipleEntriesSelected = true;
            } else
            {
                entryControl = new KeeEntryUserControl(plugin, entry, advancedListView, form, strings, customData);
            }

            TabPage keeTabPage = new TabPage("Kee");
            entryControl.Dock = DockStyle.Fill;
            keeTabPage.Controls.Add(entryControl);
            if (mainTabControl.ImageList == null)
                mainTabControl.ImageList = new ImageList();
            int imageIndex = mainTabControl.ImageList.Images.Add(Resources.KPRPC64, Color.Transparent);
            keeTabPage.ImageIndex = imageIndex;
            mainTabControl.TabPages.Add(keeTabPage);

            // Not offered when several entries are selected: a grant is per entry, and there is
            // no honest way to show one editor for several different sets of rules.
            if (!multipleEntriesSelected)
                AclTabs.AttachToEntry(plugin, keeTabPage, mainTabControl, customData, entry);
        }

        public override void AttachToGroupDialog(KeePassRPCExt plugin, PwGroup group, TabControl mainTabControl)
        {
            KeeGroupUserControl groupControl = new KeeGroupUserControl(plugin, group);
            TabPage keeTabPage = new TabPage("Kee");
            groupControl.Dock = DockStyle.Fill;
            keeTabPage.Controls.Add(groupControl);
            if (mainTabControl.ImageList == null)
                mainTabControl.ImageList = new ImageList();
            int imageIndex = mainTabControl.ImageList.Images.Add(Resources.KPRPC64, Color.Transparent);
            keeTabPage.ImageIndex = imageIndex;
            mainTabControl.TabPages.Add(keeTabPage);

            AclTabs.AttachToGroup(plugin, keeTabPage, mainTabControl, group);
        }

    }

    public class KeeFoxRPCClientManager : KeePassRPCClientManager
    {
        public KeeFoxRPCClientManager()
            : base("KeeFox", "KPRPCListener")
        {

        }

        public override void AttachToEntryDialog(KeePassRPCExt plugin, PwEntry entry, TabControl mainTabControl, PwEntryForm form, CustomListViewEx advancedListView, ProtectedStringDictionary strings, StringDictionaryEx customData)
        {
            KeeEntryUserControl entryControl = new KeeEntryUserControl(plugin, entry, advancedListView, form, strings, customData);
            TabPage keefoxTabPage = new TabPage("KeeFox");
            entryControl.Dock = DockStyle.Fill;
            keefoxTabPage.Controls.Add(entryControl);
            if (mainTabControl.ImageList == null)
                mainTabControl.ImageList = new ImageList();
            int imageIndex = mainTabControl.ImageList.Images.Add(Resources.KPRPC64, Color.Transparent);
            keefoxTabPage.ImageIndex = imageIndex;
            mainTabControl.TabPages.Add(keefoxTabPage);

            AclTabs.AttachToEntry(plugin, keefoxTabPage, mainTabControl, customData, entry);
        }

        public override void AttachToGroupDialog(KeePassRPCExt plugin, PwGroup group, TabControl mainTabControl)
        {
            KeeGroupUserControl groupControl = new KeeGroupUserControl(plugin, group);
            TabPage keefoxTabPage = new TabPage("KeeFox");
            groupControl.Dock = DockStyle.Fill;
            keefoxTabPage.Controls.Add(groupControl);
            if (mainTabControl.ImageList == null)
                mainTabControl.ImageList = new ImageList();
            int imageIndex = mainTabControl.ImageList.Images.Add(Resources.KPRPC64, Color.Transparent);
            keefoxTabPage.ImageIndex = imageIndex;
            mainTabControl.TabPages.Add(keefoxTabPage);

            AclTabs.AttachToGroup(plugin, keefoxTabPage, mainTabControl, group);
        }
    }

    /// <summary>
    /// Where the grant editor is bolted onto KeePass's dialogs.
    ///
    /// Kept apart from the client managers above so that the two attachment points, entry and
    /// group, read the same and cannot drift into describing the same feature two different
    /// ways.
    ///
    /// There is no database attachment. The root group holds the widest grant there is, being
    /// the one group every entry is inside, and it is edited on the ordinary group dialog.
    /// <see cref="DatabaseGrantMigration"/> has the reasoning and moves the grants that used
    /// to live on the database itself.
    /// </summary>
    internal static class AclTabs
    {
        /// <summary>
        /// Which API these grants govern, which is not a fixed answer.
        ///
        /// They always govern V3. Whether they also govern v1 and v2 is a per-client setting,
        /// so a tab that said "the V3 API" was wrong for exactly the clients whose reach a
        /// reader is most likely to be worried about: the ones on the older API that somebody
        /// has deliberately brought under the ACL.
        /// </summary>
        private const string WhichApi =
            "Which API this covers depends on the client: always V3, and the older API too "
            + "for a client set to one of the \"with ACL\" options on the Authorised clients "
            + "tab. ";

        internal static void AttachToEntry(KeePassRPCExt plugin, TabPage keeTabPage,
            TabControl mainTabControl, StringDictionaryEx customData, PwEntry entry)
        {
            AclUserControl.AttachTo(keeTabPage, mainTabControl, customData,
                "Which profiles may reach this entry, and how.",
                "Which PROFILES may reach THIS ENTRY, and how. Rules are about profiles; which "
                + "clients are in a profile is set on the database settings dialog, and a "
                + "client in more than one holds the widest of what they grant. "
                + WhichApi
                + "Rights narrow as they descend: a rule here can only tighten what the "
                + "groups above already allow, never widen it. Rules shown in italic are "
                + "inherited; edit one to narrow it here, and it turns bold. Grant "
                + "'none' to revoke an inherited right.",
                DatabasePath(plugin), ProfilesOf(plugin),
                ChainAbove(plugin, entry == null ? null : entry.ParentGroup),
                null, ModeOf(plugin));
        }

        internal static void AttachToGroup(KeePassRPCExt plugin, TabPage keeTabPage,
            TabControl mainTabControl, PwGroup group)
        {
            if (group == null)
                return;

            // Not group.CustomData where the dialog keeps a copy of its own: see
            // WorkingCopyOf. Where it does not, the live group IS the right place to write,
            // the way the database settings dialog always was, and dismissing the dialog puts
            // the old grants back.
            StringDictionaryEx working = WorkingCopyOf(mainTabControl);

            AclUserControl.AttachTo(keeTabPage, mainTabControl,
                working != null ? working : group.CustomData,
                "Which profiles may reach every entry in this group, and below it.",
                "Which PROFILES may reach EVERY ENTRY IN THIS GROUP, and below it. Rules are "
                + "about profiles; which clients are in a profile is set on the database "
                + "settings dialog, and a client in more than one holds the widest of what "
                + "they grant. "
                + WhichApi
                + "An entry can narrow this but never widen it. Rules shown in italic are "
                + "inherited from a parent group; edit one to narrow it here, and it turns "
                + "bold. On the root group this is the widest grant a database has, because "
                + "every entry is inside it: '*' set to 'none' there denies every profile "
                + "everywhere and cannot be reopened further down.",
                DatabasePath(plugin), ProfilesOf(plugin),
                ChainAbove(plugin, group.ParentGroup),
                null, ModeOf(plugin));
        }

        /// <summary>
        /// The group dialog's own copy of the group's <c>CustomData</c>.
        ///
        /// This is not a detail. <c>GroupForm</c> takes a copy of the group's custom data when
        /// it opens, hands it to its own "Plugin Data" tab, and writes that copy back over the
        /// group when it is accepted. A grant written straight to <c>group.CustomData</c>
        /// therefore survives Cancel and is destroyed by OK, silently and completely, which is
        /// the worst way for an access control editor to fail: the rule is on screen when the
        /// dialog closes and gone from the database.
        ///
        /// Upstream already reaches the same field for the entry dialog, which is why entry
        /// grants were never affected. The database settings dialog keeps no such copy, so
        /// grants there are written to the live database and that is correct.
        ///
        /// Null when the field cannot be reached, either because this KeePass has no such copy
        /// or because it has renamed it. The caller then writes the live group, which is
        /// correct in the first case and is what the editor did before this was understood.
        /// <c>DialogCustomDataTest</c> is what turns the second case into a build failure
        /// rather than a silent loss.
        /// </summary>
        private static StringDictionaryEx WorkingCopyOf(TabControl mainTabControl)
        {
            try
            {
                GroupForm host = mainTabControl == null
                    ? null : mainTabControl.FindForm() as GroupForm;
                if (host == null)
                    return null;

                FieldInfo field = typeof(GroupForm).GetField("m_sdCustomData",
                    BindingFlags.NonPublic | BindingFlags.Instance);
                if (field == null)
                    return null;

                return field.GetValue(host) as StringDictionaryEx;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// The profiles the active database defines, for the grant editor's pick list.
        ///
        /// Empty rather than wrong when the database cannot be reached or its registry cannot
        /// be read: an editor offering no profiles still shows the rules that exist and still
        /// lets one be typed, where an invented list would offer names that grant nobody
        /// anything.
        /// </summary>
        private static IList<string> ProfilesOf(KeePassRPCExt plugin)
        {
            try
            {
                AclProfiles registry = AclResolver.RegistryOf(plugin._host.MainWindow.ActiveDatabase);
                return registry == null ? new List<string>() : registry.Names;
            }
            catch (Exception)
            {
                return new List<string>();
            }
        }

        /// <summary>
        /// Which way round the active database reads, so the table can label its rules the way
        /// they will act. Deny if that cannot be worked out, which is what the resolver
        /// assumes too.
        /// </summary>
        private static AclDefault ModeOf(KeePassRPCExt plugin)
        {
            try
            {
                return AclResolver.DefaultOf(plugin._host.MainWindow.ActiveDatabase);
            }
            catch (Exception)
            {
                return AclDefault.Deny;
            }
        }

        /// <summary>
        /// The grant documents above a level, for the editor to show as inherited.
        ///
        /// Empty rather than wrong when the active database cannot be reached: an editor that
        /// shows no inheritance understates what is granted, which sends a reader looking, and
        /// one that invents an inheritance would send them away satisfied.
        /// </summary>
        private static IList<string> ChainAbove(KeePassRPCExt plugin, PwGroup deepestGroup)
        {
            try
            {
                return AclResolver.ChainAbove(plugin._host.MainWindow.ActiveDatabase, deepestGroup);
            }
            catch (Exception)
            {
                return new List<string>();
            }
        }

        private static string DatabasePath(KeePassRPCExt plugin)
        {
            try
            {
                PwDatabase database = plugin._host.MainWindow.ActiveDatabase;
                if (database == null || database.IOConnectionInfo == null)
                    return null;
                return database.IOConnectionInfo.Path;
            }
            catch (Exception)
            {
                // The format check is advisory. Failing to work out which file is open must not
                // stop the tab from opening.
                return null;
            }
        }
    }
}