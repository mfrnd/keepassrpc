// V3: the full-entry API, and the first API generation in this plugin that is guarded.
//
// READ THIS BEFORE CHANGING ANYTHING HERE.
//
// **V3 reads pwe.Strings and pwe.Binaries DIRECTLY, bypassing the conf.Fields entry-config
// machinery that v1 and v2 filter everything through.** That is not an oversight or a
// shortcut; it is the entire reason this generation exists. In v1 the read loop walks the
// entry's `KPRPC JSON` config rather than its strings, so a custom string added in the
// KeePass UI is invisible until someone registers it on the entry's Kee tab, and on the write
// side anything that is not Title, UserName, URL or Password ends up inside that JSON blob
// where no other reader of the .kdbx can see it. V3 shows the entry as KeePass shows it.
//
// The comprehension trap is that this file looks like DTOV1 and DTOV2 and does something
// categorically different. If you copy a helper from either of those, you will reintroduce
// the config filtering that V3 exists to escape.
//
// Every method here is guarded twice over: the per-subject method gate decides whether the
// call may be made at all, and then the ACL decides which entries it may touch. Neither is
// optional and neither substitutes for the other.

using System;
using System.Collections.Generic;
using Jayrock.JsonRpc;
using KeePass.Resources;
using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Utility;
using KeePassRPC.Acl;
using KeePassRPC.Models.DataExchange.V3;

namespace KeePassRPC
{
    public partial class KeePassRPCService
    {
        /// <summary>
        /// The one string name V3 will not disclose or accept.
        ///
        /// It is upstream's legacy per-entry config, held as a custom STRING on entries whose
        /// config was never migrated to <c>CustomData</c>. That blob decides which fields v1
        /// and v2 expose, so a client able to read or rewrite it could change what other
        /// clients see. Nothing to do with protecting the ACL, which lives in a dictionary V3
        /// cannot reach at all.
        /// </summary>
        public const string ReservedStringName = "KPRPC JSON";

        private const string FeatureV3 = "KPRPC_FEATURE_DTO_V3";

        #region Guards

        private void RequireV3Feature()
        {
            if (ClientMetadata == null || ClientMetadata.Features == null ||
                !Array.Exists(ClientMetadata.Features, f => f == FeatureV3))
            {
                throw new Exception("Client feature missing: " + FeatureV3);
            }
        }

        /// <summary>
        /// The authenticated identity, or an exception.
        ///
        /// The method gate has already refused unidentified callers, so reaching here without
        /// a subject would mean a bug rather than an attack. It still fails rather than
        /// carrying on, because the alternative is resolving an ACL for nobody in particular.
        /// </summary>
        private string RequireSubject()
        {
            string subject = ClientMetadata == null ? null : ClientMetadata.Subject;
            if (string.IsNullOrEmpty(subject))
                throw new Exception("No authenticated subject for this request.");
            return subject;
        }

        /// <summary>
        /// Whether the call being served arrived from beyond this machine, for the audit log.
        ///
        /// Absent metadata reads as remote. It should not happen, because the gate refuses a
        /// request without it long before here, but if it ever does, the wrong answer to write into
        /// an audit log is the reassuring one.
        /// </summary>
        private bool RequestIsRemote()
        {
            return ClientMetadata == null || ClientMetadata.IsRemote;
        }

        /// <summary>
        /// Resolve the ACL for an entry and refuse unless it permits <paramref name="required"/>.
        ///
        /// Both outcomes are recorded. A log of refusals alone answers "what was blocked" but
        /// not "what did it read", which is the question that matters after an agent has
        /// misbehaved.
        /// </summary>
        /// <returns>The effective grant, for callers that also need its flags.</returns>
        private AclGrant RequireGrant(PwDatabase db, PwEntry entry, AclVerb required, string method)
        {
            string subject = RequireSubject();
            AclGrant grant = AclResolver.Resolve(db, entry, subject);
            bool allowed = grant.Permits(required);

            Audit.Record(_host, subject, RequestIsRemote(), method, UuidOf(entry), AclVerbs.ToJsonValue(required), allowed,
                allowed ? "granted " + grant : "no grant permits it");

            if (!allowed)
                throw new Exception("Not permitted.");
            return grant;
        }

        private AclGrant RequireGrant(PwDatabase db, PwGroup group, AclVerb required, string method)
        {
            string subject = RequireSubject();
            AclGrant grant = AclResolver.Resolve(db, group, subject);
            bool allowed = grant.Permits(required);

            Audit.Record(_host, subject, RequestIsRemote(), method, MemUtil.ByteArrayToHexString(group.Uuid.UuidBytes),
                AclVerbs.ToJsonValue(required), allowed,
                allowed ? "granted " + grant : "no grant permits it");

            if (!allowed)
                throw new Exception("Not permitted.");
            return grant;
        }

        /// <summary>
        /// Ask the human sitting at KeePass, unless this subject is trusted to act unattended.
        ///
        /// Runs on the UI thread through a blocking Invoke, because the answer is needed
        /// before the call can be allowed to continue.
        /// </summary>
        private bool ConfirmedByUser(AclGrant grant, string question, string title,
            string method, string target)
        {
            if (grant.Unattended)
            {
                Audit.Record(_host, RequireSubject(), RequestIsRemote(), method, target, null, true,
                    "unattended, no prompt shown");
                return true;
            }

            bool confirmed = (bool)_host.MainWindow.Invoke(new Func<bool>(delegate
            {
                return MessageService.AskYesNo(question, title);
            }));

            // Recorded separately from the ACL decision above: "the rules allowed it and a
            // person said no" is a different event from "the rules refused it", and only the
            // log distinguishes them afterwards.
            Audit.Record(_host, RequireSubject(), RequestIsRemote(), method, target, null, confirmed,
                confirmed ? "confirmed by user" : "refused by user");
            return confirmed;
        }

        #endregion

        #region Lookup

        /// <summary>
        /// Every open database.
        ///
        /// Deliberately does NOT call <c>EnsureDBisOpen</c>. That prompts the user to open a
        /// database, and an unattended agent poking the API must not be able to make a dialog
        /// appear on somebody's screen. With nothing open, V3 simply has nothing to offer.
        /// </summary>
        private List<PwDatabase> OpenDatabases()
        {
            List<PwDatabase> open = new List<PwDatabase>();
            foreach (PwDatabase db in _host.MainWindow.DocumentManager.GetOpenDatabases())
            {
                if (db != null && db.IsOpen)
                    open.Add(db);
            }
            return open;
        }

        private static bool LooksLikeUuid(string identifier)
        {
            if (string.IsNullOrEmpty(identifier) || identifier.Length != 32)
                return false;

            foreach (char c in identifier)
            {
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex)
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Find one entry by UUID, or failing that by exact title.
        ///
        /// Searches every open database from its true root, not the Kee "home group": V3's
        /// reach is decided by the ACL, and making it depend on a display setting belonging to
        /// a browser extension would be a surprising coupling.
        ///
        /// An ambiguous title matches nothing. Returning an arbitrary one of several entries
        /// with the same title is how an automation client ends up reading, or later
        /// overwriting, something it never meant to touch.
        /// </summary>
        private PwEntry FindEntry(string identifier, out PwDatabase database)
        {
            database = null;
            if (string.IsNullOrEmpty(identifier))
                throw new Exception("No entry identifier supplied.");

            List<PwEntry> matches = new List<PwEntry>();
            List<PwDatabase> owners = new List<PwDatabase>();

            if (LooksLikeUuid(identifier))
            {
                PwUuid uuid = new PwUuid(MemUtil.HexStringToByteArray(identifier));
                foreach (PwDatabase db in OpenDatabases())
                {
                    PwEntry found = db.RootGroup.FindEntry(uuid, true);
                    if (found != null)
                    {
                        matches.Add(found);
                        owners.Add(db);
                    }
                }
            }
            else
            {
                foreach (PwDatabase db in OpenDatabases())
                {
                    foreach (PwEntry candidate in db.RootGroup.GetEntries(true))
                    {
                        if (candidate.Strings.ReadSafe(PwDefs.TitleField) == identifier)
                        {
                            matches.Add(candidate);
                            owners.Add(db);
                        }
                    }
                }
            }

            if (matches.Count == 0)
                throw new Exception("No such entry.");
            if (matches.Count > 1)
                throw new Exception("Ambiguous entry identifier: " + matches.Count + " entries match.");

            database = owners[0];
            return matches[0];
        }

        /// <summary>Find one group by UUID, or failing that by exact slash-separated path.</summary>
        private PwGroup FindGroup(string identifier, out PwDatabase database)
        {
            database = null;
            if (string.IsNullOrEmpty(identifier))
                throw new Exception("No group identifier supplied.");

            List<PwGroup> matches = new List<PwGroup>();
            List<PwDatabase> owners = new List<PwDatabase>();

            bool byUuid = LooksLikeUuid(identifier);
            PwUuid uuid = byUuid ? new PwUuid(MemUtil.HexStringToByteArray(identifier)) : null;

            foreach (PwDatabase db in OpenDatabases())
            {
                if (byUuid)
                {
                    PwGroup found = db.RootGroup.FindGroup(uuid, true);
                    if (found != null)
                    {
                        matches.Add(found);
                        owners.Add(db);
                    }
                    continue;
                }

                foreach (PwGroup candidate in db.RootGroup.GetGroups(true))
                {
                    if (GroupPath(candidate) == identifier)
                    {
                        matches.Add(candidate);
                        owners.Add(db);
                    }
                }
                if (GroupPath(db.RootGroup) == identifier)
                {
                    matches.Add(db.RootGroup);
                    owners.Add(db);
                }
            }

            if (matches.Count == 0)
                throw new Exception("No such group.");
            if (matches.Count > 1)
                throw new Exception("Ambiguous group identifier: " + matches.Count + " groups match.");

            database = owners[0];
            return matches[0];
        }

        private static string GroupPath(PwGroup group)
        {
            List<string> parts = new List<string>();
            for (PwGroup g = group; g != null; g = g.ParentGroup)
                parts.Add(g.Name);
            parts.Reverse();
            return string.Join("/", parts.ToArray());
        }

        private static string DatabasePathOf(PwDatabase db)
        {
            if (db == null || db.IOConnectionInfo == null)
                return null;
            return db.IOConnectionInfo.Path;
        }

        private static string UuidOf(PwEntry entry)
        {
            return MemUtil.ByteArrayToHexString(entry.Uuid.UuidBytes);
        }

        #endregion

        #region Conversion

        /// <summary>
        /// Build the wire object straight from the KeePass entry.
        ///
        /// Note what is NOT here: no <c>GetKPRPCConfigNormalised</c>, no <c>conf.Fields</c>, no
        /// matcher evaluation. See the comment at the top of this file.
        /// </summary>
        private Entry3 BuildEntry3(PwDatabase db, PwEntry pwe, bool includeAttachments)
        {
            Entry3 entry = new Entry3();
            entry.Uuid = UuidOf(pwe);
            entry.Db = DatabasePathOf(db);
            entry.Title = pwe.Strings.ReadSafe(PwDefs.TitleField);
            entry.UserName = pwe.Strings.ReadSafe(PwDefs.UserNameField);
            entry.Password = pwe.Strings.ReadSafe(PwDefs.PasswordField);
            entry.Url = pwe.Strings.ReadSafe(PwDefs.UrlField);
            entry.Notes = pwe.Strings.ReadSafe(PwDefs.NotesField);
            entry.Group = pwe.ParentGroup == null ? null : GroupPath(pwe.ParentGroup);

            List<Field3> fields = new List<Field3>();
            foreach (KeyValuePair<string, ProtectedString> pair in pwe.Strings)
            {
                if (PwDefs.IsStandardField(pair.Key))
                    continue;
                if (pair.Key == ReservedStringName)
                    continue;

                // ReadSafe rather than a null check: an empty custom string is a legitimate
                // state that V3 must report as present-and-empty rather than drop, which is
                // exactly what v1 gets wrong.
                fields.Add(new Field3(pair.Key, pwe.Strings.ReadSafe(pair.Key), pair.Value.IsProtected));
            }
            entry.Fields = fields.ToArray();

            List<Attachment3> attachments = new List<Attachment3>();
            if (includeAttachments)
            {
                foreach (KeyValuePair<string, ProtectedBinary> pair in pwe.Binaries)
                    attachments.Add(new Attachment3(pair.Key, (int)pair.Value.Length));
            }
            entry.Attachments = attachments.ToArray();

            return entry;
        }

        #endregion

        #region The API

        /// <summary>
        /// Read one entry in full.
        /// </summary>
        /// <param name="identifier">A 32 character hex UUID, or an exact title.</param>
        /// <returns>The entry, including attachment names but never attachment content.</returns>
        [JsonRpcMethod]
        public Entry3 GetEntry3(string identifier)
        {
            RequireV3Feature();

            PwDatabase db;
            PwEntry pwe = FindEntry(identifier, out db);
            AclGrant grant = RequireGrant(db, pwe, AclVerb.Read, "GetEntry3");

            // Attachment NAMES ride along with read; only their content needs the flag. A
            // client that cannot fetch content has no use for the names, so withhold both.
            return BuildEntry3(db, pwe, grant.Attachments);
        }

        /// <summary>
        /// List the entries directly inside a group.
        /// </summary>
        /// <param name="identifier">A 32 character hex UUID, or an exact slash-separated path.</param>
        /// <returns>
        /// Titles and UUIDs only, and only for entries this subject may at least list. An
        /// entry carved out with <c>none</c> is omitted rather than reported as forbidden,
        /// because "there is something here you may not see" is itself disclosure.
        /// </returns>
        [JsonRpcMethod]
        public LightEntry3[] ListGroup3(string identifier)
        {
            RequireV3Feature();

            PwDatabase db;
            PwGroup group = FindGroup(identifier, out db);
            RequireGrant(db, group, AclVerb.List, "ListGroup3");

            string subject = RequireSubject();
            List<LightEntry3> listed = new List<LightEntry3>();
            foreach (PwEntry pwe in group.Entries)
            {
                if (!AclResolver.Resolve(db, pwe, subject).Permits(AclVerb.List))
                    continue;
                listed.Add(new LightEntry3(UuidOf(pwe), pwe.Strings.ReadSafe(PwDefs.TitleField), DatabasePathOf(db)));
            }
            return listed.ToArray();
        }

        /// <summary>
        /// Fetch one attachment's content, base64 encoded.
        /// </summary>
        /// <param name="identifier">A 32 character hex UUID, or an exact title.</param>
        /// <param name="name">The attachment name, as reported by <c>GetEntry3</c>.</param>
        /// <returns>The content, base64 encoded.</returns>
        [JsonRpcMethod]
        public string GetAttachment3(string identifier, string name)
        {
            RequireV3Feature();

            if (string.IsNullOrEmpty(name))
                throw new Exception("No attachment name supplied.");

            PwDatabase db;
            PwEntry pwe = FindEntry(identifier, out db);
            AclGrant grant = RequireGrant(db, pwe, AclVerb.Read, "GetAttachment3");

            if (!grant.Attachments)
                throw new Exception("Not permitted.");

            ProtectedBinary binary = pwe.Binaries.Get(name);
            if (binary == null)
                throw new Exception("No such attachment.");

            // Attachments are the highest risk payload in a database, so this asks by default
            // and is silent only for a subject explicitly trusted to run unattended.
            if (!ConfirmedByUser(grant,
                    "A paired client is asking to read the attachment '" + name + "' from the entry '"
                    + pwe.Strings.ReadSafe(PwDefs.TitleField) + "'.\n\nAllow it?",
                    "KeePassRPC attachment request", "GetAttachment3", UuidOf(pwe)))
            {
                throw new Exception("Refused by user.");
            }

            return Convert.ToBase64String(binary.ReadData());
        }

        #endregion

        #region Writing

        // Everything below can destroy data, which nothing above could. Three rules hold for
        // all of it, and none of them is optional:
        //
        //   CreateBackup(db) BEFORE mutating. That is what puts the previous state into the
        //   entry's history and makes a mistake recoverable through the KeePass UI. It is the
        //   difference between a bad write being an annoyance and being a loss.
        //
        //   Touch(true) AFTER. The modification timestamp is what lets KeePass's own
        //   synchronisation resolve correctly if the file is ever merged. Skipping it can make
        //   a later merge silently prefer the older copy.
        //
        //   Save through BeginInvoke. Saving steals window focus and touches UI state, so it
        //   belongs on the UI thread; upstream already works around this the same way.
        //
        // And the rule that is about this fork rather than about KeePass: none of this goes
        // through MergeEntries. That helper assigns destConfig.Fields = sourceConfig.Fields
        // wholesale, so routing a V3 write through it would clobber the entry-config state
        // that v1 and v2 clients depend on.

        /// <summary>
        /// Apply a standard field, but only if the caller actually sent one.
        ///
        /// Null means "leave this alone" and an empty string means "set it to empty". That
        /// distinction is the same one V3 exists to preserve on the way out, and it is what
        /// lets a client send a partial update without silently blanking everything it did not
        /// mention.
        /// </summary>
        private static void ApplyStandardField(PwEntry pwe, string name, string value, bool protect)
        {
            if (value == null)
                return;
            pwe.Strings.Set(name, new ProtectedString(protect, value));
        }

        /// <summary>
        /// Replace the entry's non-standard strings with exactly those supplied.
        ///
        /// REPLACE, not merge: a name absent from a non-null <c>Fields</c> array is removed.
        /// The expected shape of a V3 write is read-modify-write of a whole entry, and merge
        /// semantics would make deleting a field impossible. A caller that only wants to touch
        /// the standard fields sends null instead of an array, and nothing here happens.
        ///
        /// <c>KPRPC JSON</c> is stripped rather than rejected, so a client that echoes back an
        /// entry it read does not fail on a name it never asked for and cannot see.
        /// </summary>
        private static void ApplyFields(PwEntry pwe, Field3[] fields)
        {
            if (fields == null)
                return;

            List<string> toRemove = new List<string>();
            foreach (string name in pwe.Strings.GetKeys())
            {
                if (!PwDefs.IsStandardField(name) && name != ReservedStringName)
                    toRemove.Add(name);
            }
            foreach (string name in toRemove)
                pwe.Strings.Remove(name);

            foreach (Field3 field in fields)
            {
                if (field == null || string.IsNullOrEmpty(field.Name))
                    throw new Exception("A field was supplied with no name.");
                if (PwDefs.IsStandardField(field.Name))
                    throw new Exception("Use the standard members for '" + field.Name + "', not a custom field.");
                if (field.Name == ReservedStringName)
                    continue; // stripped, deliberately, rather than failing the whole call

                pwe.Strings.Set(field.Name, new ProtectedString(field.Protected, field.Value ?? string.Empty));
            }
        }

        /// <summary>Persist, the way upstream persists.</summary>
        private void SaveDatabase(PwDatabase db)
        {
            _host.MainWindow.BeginInvoke(new dlgSaveDB(saveDB), db);
        }

        /// <summary>
        /// Create an entry in a group.
        /// </summary>
        /// <param name="groupIdentifier">A 32 character hex UUID, or an exact group path.</param>
        /// <param name="entry">
        /// The entry to create. Null members become empty strings, since there is nothing to
        /// leave alone. Any <c>uuid</c> is ignored: KeePass assigns it. Attachments are ignored
        /// too; they have their own methods.
        /// </param>
        /// <returns>The entry as stored, including its assigned UUID.</returns>
        [JsonRpcMethod]
        public Entry3 AddEntry3(string groupIdentifier, Entry3 entry)
        {
            RequireV3Feature();
            if (entry == null)
                throw new Exception("No entry supplied.");

            PwDatabase db;
            PwGroup group = FindGroup(groupIdentifier, out db);

            // Write on the CONTAINER, because the entry does not exist yet and so has no grant
            // of its own. What it will inherit once created is the group's grant, which is the
            // same one being checked here.
            AclGrant grant = RequireGrant(db, group, AclVerb.Write, "AddEntry3");

            if (!ConfirmedByUser(grant,
                    "A paired client is asking to create the entry '" + (entry.Title ?? "") + "' in the group '"
                    + GroupPath(group) + "'.\n\nAllow it?",
                    "KeePassRPC write request", "AddEntry3", MemUtil.ByteArrayToHexString(group.Uuid.UuidBytes)))
            {
                throw new Exception("Refused by user.");
            }

            PwEntry pwe = new PwEntry(true, true);
            ApplyStandardField(pwe, PwDefs.TitleField, entry.Title ?? string.Empty, db.MemoryProtection.ProtectTitle);
            ApplyStandardField(pwe, PwDefs.UserNameField, entry.UserName ?? string.Empty,
                db.MemoryProtection.ProtectUserName);
            ApplyStandardField(pwe, PwDefs.PasswordField, entry.Password ?? string.Empty,
                db.MemoryProtection.ProtectPassword);
            ApplyStandardField(pwe, PwDefs.UrlField, entry.Url ?? string.Empty, db.MemoryProtection.ProtectUrl);
            ApplyStandardField(pwe, PwDefs.NotesField, entry.Notes ?? string.Empty, db.MemoryProtection.ProtectNotes);
            ApplyFields(pwe, entry.Fields ?? new Field3[0]);

            group.AddEntry(pwe, true);
            pwe.Touch(true, false);
            SaveDatabase(db);

            return BuildEntry3(db, pwe, grant.Attachments);
        }

        /// <summary>
        /// Update an entry in place.
        /// </summary>
        /// <param name="identifier">A 32 character hex UUID, or an exact title.</param>
        /// <param name="entry">
        /// The changes. A null member is left alone; an empty string sets the field empty. A
        /// null <c>fields</c> leaves the custom strings alone, a non-null one REPLACES them.
        /// <c>group</c> is ignored: moving an entry would need write on both the source and the
        /// destination, and that is not something to do as a side effect of an update.
        /// </param>
        /// <returns>The entry as stored afterwards.</returns>
        [JsonRpcMethod]
        public Entry3 UpdateEntry3(string identifier, Entry3 entry)
        {
            RequireV3Feature();
            if (entry == null)
                throw new Exception("No entry supplied.");

            PwDatabase db;
            PwEntry pwe = FindEntry(identifier, out db);
            AclGrant grant = RequireGrant(db, pwe, AclVerb.Write, "UpdateEntry3");

            if (!ConfirmedByUser(grant,
                    "A paired client is asking to modify the entry '" + pwe.Strings.ReadSafe(PwDefs.TitleField)
                    + "'.\n\nAllow it?",
                    "KeePassRPC write request", "UpdateEntry3", UuidOf(pwe)))
            {
                throw new Exception("Refused by user.");
            }

            pwe.CreateBackup(db);

            ApplyStandardField(pwe, PwDefs.TitleField, entry.Title, db.MemoryProtection.ProtectTitle);
            ApplyStandardField(pwe, PwDefs.UserNameField, entry.UserName, db.MemoryProtection.ProtectUserName);
            ApplyStandardField(pwe, PwDefs.PasswordField, entry.Password, db.MemoryProtection.ProtectPassword);
            ApplyStandardField(pwe, PwDefs.UrlField, entry.Url, db.MemoryProtection.ProtectUrl);
            ApplyStandardField(pwe, PwDefs.NotesField, entry.Notes, db.MemoryProtection.ProtectNotes);
            ApplyFields(pwe, entry.Fields);

            pwe.Touch(true, false);
            SaveDatabase(db);

            return BuildEntry3(db, pwe, grant.Attachments);
        }

        /// <summary>
        /// Remove an entry, to the recycle bin where the database has one.
        /// </summary>
        /// <param name="identifier">A 32 character hex UUID, or an exact title.</param>
        /// <returns>True if it was removed.</returns>
        [JsonRpcMethod]
        public bool RemoveEntry3(string identifier)
        {
            RequireV3Feature();

            PwDatabase db;
            PwEntry pwe = FindEntry(identifier, out db);

            // The top of the ladder, and the only verb that reaches this method. Write is not
            // enough: deleting is the one action a backup cannot soften.
            AclGrant grant = RequireGrant(db, pwe, AclVerb.Delete, "RemoveEntry3");

            string title = pwe.Strings.ReadSafe(PwDefs.TitleField);
            if (!ConfirmedByUser(grant,
                    "A paired client is asking to DELETE the entry '" + title + "'.\n\nAllow it?",
                    "KeePassRPC delete request", "RemoveEntry3", UuidOf(pwe)))
            {
                throw new Exception("Refused by user.");
            }

            PwGroup parent = pwe.ParentGroup;
            if (parent == null)
                return false;

            parent.Entries.Remove(pwe);

            if (db.RecycleBinEnabled)
            {
                PwGroup recycleBin = db.RootGroup.FindGroup(db.RecycleBinUuid, true);
                if (recycleBin == null)
                {
                    recycleBin = new PwGroup(true, true, KPRes.RecycleBin, PwIcon.TrashBin);
                    recycleBin.EnableAutoType = false;
                    recycleBin.EnableSearching = false;
                    db.RootGroup.AddGroup(recycleBin, true);
                    db.RecycleBinUuid = recycleBin.Uuid;
                }

                recycleBin.AddEntry(pwe, true);
                pwe.Touch(false);
            }
            else
            {
                // No recycle bin, so this is permanent. Record it as a deleted object, which is
                // what lets a later synchronisation know the entry was removed rather than
                // resurrect it from another copy of the database.
                PwDeletedObject deleted = new PwDeletedObject();
                deleted.Uuid = pwe.Uuid;
                deleted.DeletionTime = DateTime.UtcNow;
                db.DeletedObjects.Add(deleted);
            }

            SaveDatabase(db);
            return true;
        }

        /// <summary>
        /// Add or replace an attachment.
        /// </summary>
        /// <param name="identifier">A 32 character hex UUID, or an exact title.</param>
        /// <param name="name">The attachment name. Replaces any existing one of that name.</param>
        /// <param name="content">The content, base64 encoded.</param>
        /// <returns>The entry as stored afterwards.</returns>
        [JsonRpcMethod]
        public Entry3 SetAttachment3(string identifier, string name, string content)
        {
            RequireV3Feature();
            if (string.IsNullOrEmpty(name))
                throw new Exception("No attachment name supplied.");
            if (content == null)
                throw new Exception("No attachment content supplied.");

            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(content);
            }
            catch (FormatException)
            {
                throw new Exception("Attachment content is not valid base64.");
            }

            PwDatabase db;
            PwEntry pwe = FindEntry(identifier, out db);
            AclGrant grant = RequireGrant(db, pwe, AclVerb.Write, "SetAttachment3");

            // Writing an attachment needs the same flag as reading one. A subject trusted to
            // change a password is not thereby trusted to plant a key file.
            if (!grant.Attachments)
                throw new Exception("Not permitted.");

            if (!ConfirmedByUser(grant,
                    "A paired client is asking to write the attachment '" + name + "' on the entry '"
                    + pwe.Strings.ReadSafe(PwDefs.TitleField) + "' (" + bytes.Length + " bytes).\n\nAllow it?",
                    "KeePassRPC write request", "SetAttachment3", UuidOf(pwe)))
            {
                throw new Exception("Refused by user.");
            }

            pwe.CreateBackup(db);
            pwe.Binaries.Set(name, new ProtectedBinary(true, bytes));
            pwe.Touch(true, false);
            SaveDatabase(db);

            return BuildEntry3(db, pwe, grant.Attachments);
        }

        /// <summary>
        /// Remove an attachment.
        /// </summary>
        /// <param name="identifier">A 32 character hex UUID, or an exact title.</param>
        /// <param name="name">The attachment name.</param>
        /// <returns>True if it was removed.</returns>
        [JsonRpcMethod]
        public bool RemoveAttachment3(string identifier, string name)
        {
            RequireV3Feature();
            if (string.IsNullOrEmpty(name))
                throw new Exception("No attachment name supplied.");

            PwDatabase db;
            PwEntry pwe = FindEntry(identifier, out db);

            // Write rather than delete: this modifies an entry, it does not remove one, and the
            // backup taken below puts the attachment into history where it can be recovered.
            AclGrant grant = RequireGrant(db, pwe, AclVerb.Write, "RemoveAttachment3");
            if (!grant.Attachments)
                throw new Exception("Not permitted.");

            if (pwe.Binaries.Get(name) == null)
                throw new Exception("No such attachment.");

            if (!ConfirmedByUser(grant,
                    "A paired client is asking to remove the attachment '" + name + "' from the entry '"
                    + pwe.Strings.ReadSafe(PwDefs.TitleField) + "'.\n\nAllow it?",
                    "KeePassRPC delete request", "RemoveAttachment3", UuidOf(pwe)))
            {
                throw new Exception("Refused by user.");
            }

            pwe.CreateBackup(db);
            bool removed = pwe.Binaries.Remove(name);
            pwe.Touch(true, false);
            SaveDatabase(db);

            return removed;
        }

        #endregion
    }
}
