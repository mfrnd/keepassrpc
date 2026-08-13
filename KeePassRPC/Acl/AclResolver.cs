using System.Collections.Generic;
using KeePassLib;
using KeePassLib.Collections;

namespace KeePassRPC.Acl
{
    /// <summary>
    /// Works out what a client may do to an entry, by walking the chain of grants from the
    /// root group down to the entry itself, once per profile the client is in.
    ///
    /// The resolution rule is top-down and narrow-only: effective rights are the tightest
    /// value seen along the chain. A level that says nothing about the subject passes its
    /// parent's answer through unchanged, which is what makes a group grant useful. The
    /// corollary is easy to miss and important: because silence inherits, revoking one entry
    /// inside a granted group needs an explicit <c>none</c> on that entry. That is why
    /// <c>none</c> is a real value rather than merely the absence of a key.
    ///
    /// The interesting half of this class is pure: <see cref="Resolve"/> takes the raw strings
    /// and knows nothing about KeePass, so the rules can be tested exhaustively without
    /// building a database. The KeePass-aware half only collects the chain.
    /// </summary>
    public static class AclResolver
    {
        /// <summary>
        /// Resolve a chain of raw grant documents.
        /// </summary>
        /// <param name="chainRootFirst">
        /// The raw <c>CustomData</c> values from the root group down to the object itself, in
        /// that order. A null element means the level carries no grant document at all, which
        /// is different from carrying an empty or broken one.
        /// </param>
        /// <param name="subject">
        /// The PROFILE the rules are being read for, not a client. A client's profiles come
        /// from the database's registry; see the overload that takes a database.
        /// </param>
        /// <returns>
        /// The effective grant, never null. <see cref="AclGrant.Deny"/> whenever anything is
        /// missing, unparseable, or explicitly refused.
        /// </returns>
        public static AclGrant Resolve(IList<string> chainRootFirst, string subject)
        {
            if (chainRootFirst == null || string.IsNullOrEmpty(subject))
                return AclGrant.Deny;

            // The wildcard is a way to write a rule about other subjects; it is not an
            // identity, and a client must never be able to authenticate as one.
            if (subject == AclDocument.WildcardSubject)
                return AclGrant.Deny;

            // Where the chain starts. Deny is the absence of a grant, which the first group
            // that grants something replaces; allow is a full grant that every level below can
            // only cut into. Either way rights narrow as they descend, which is the rule the
            // whole design rests on: the setting decides what they narrow FROM.
            AclGrant effective = StartingPoint(chainRootFirst);

            foreach (string raw in chainRootFirst)
            {
                if (raw == null)
                    continue; // this level carries no document: inherit

                AclDocument document = AclDocument.Parse(raw);
                if (document == null)
                    return AclGrant.Deny; // present but unreadable: refuse, never inherit past it

                AclGrant granted = document.GrantFor(subject);
                if (granted == null)
                    continue; // document exists but is silent about this subject: inherit

                effective = effective == null ? granted : effective.NarrowedBy(granted);

                // none blocks: nothing below can widen it, so stop rather than keep walking.
                if (effective.Verb == AclVerb.None)
                    return AclGrant.Deny;
            }

            return effective ?? AclGrant.Deny;
        }

        /// <summary>
        /// What the chain starts from, which is everything when the root group's document says
        /// the database allows by default and nothing otherwise.
        ///
        /// Read from the first document in the chain and from no other. A <c>default</c> on a
        /// group further down would be a group quietly re-opening what its parents closed,
        /// which is the one thing this model does not permit; the parser accepts the property
        /// anywhere, and this is what makes it mean nothing anywhere else.
        ///
        /// An unreadable root document returns null here, and the walk below refuses on it a
        /// moment later, so nothing is granted on the strength of a document nobody can read.
        /// </summary>
        private static AclGrant StartingPoint(IList<string> chainRootFirst)
        {
            if (chainRootFirst.Count == 0 || chainRootFirst[0] == null)
                return null;

            AclDocument root = AclDocument.Parse(chainRootFirst[0]);
            if (root == null)
                return null;

            return root.Default == AclDefault.Allow ? AclGrant.Everything : null;
        }

        /// <summary>Resolve for an entry, collecting its chain first.</summary>
        public static AclGrant Resolve(PwDatabase database, PwEntry entry, string subject)
        {
            if (database == null || entry == null || UnmigratedDatabaseGrant(database))
                return AclGrant.Deny;

            return ForClient(database, ChainFor(database, entry.ParentGroup, entry.CustomData),
                subject);
        }

        /// <summary>
        /// What a client holds: the widest of what its profiles hold, each resolved down the
        /// chain on its own.
        ///
        /// The order matters and is the whole model in two lines. Narrowing happens WITHIN a
        /// profile, as the chain descends, so no group can hand out more than it was given.
        /// Widening happens ACROSS profiles, at the end, so a client in two profiles holds
        /// what either of them would have given it.
        /// </summary>
        private static AclGrant ForClient(PwDatabase database, IList<string> chainRootFirst,
            string subject)
        {
            if (string.IsNullOrEmpty(subject))
                return AclGrant.Deny;

            // A client never authenticates as a profile, and never as the wildcard. Both are
            // names in a document, not identities anybody can present.
            AclProfiles registry = RegistryOf(database);
            if (registry == null)
                return AclGrant.Deny;

            AclGrant held = AclGrant.Deny;
            foreach (string profile in registry.For(subject))
                held = held.WidenedBy(Resolve(chainRootFirst, profile));

            return held;
        }

        /// <summary>
        /// The database's profile registry, or null if the root group's document cannot be
        /// read.
        ///
        /// Null denies, rather than falling back to an empty registry. An empty one would put
        /// every client into <c>default</c>, which is a real profile that may hold real
        /// grants, so guessing here could hand a client access on the strength of a document
        /// nobody could parse.
        /// </summary>
        public static AclProfiles RegistryOf(PwDatabase database)
        {
            if (database == null || database.RootGroup == null)
                return null;

            string raw = Read(database.RootGroup.CustomData);
            if (raw == null)
                return new AclProfiles();

            AclDocument root = AclDocument.Parse(raw);
            return root == null ? null : root.Profiles;
        }

        /// <summary>
        /// Whether a database still carries a grant document of its own.
        ///
        /// Grants used to be readable at four levels, the database being the widest. That
        /// level is gone: the root group is the same set of entries and says the same things,
        /// and two places that both mean "everything" is one more place to forget to look.
        /// <see cref="DatabaseGrantMigration"/> moves any that exist onto the root group when
        /// the database is opened.
        ///
        /// Until that has happened, everything is refused. The alternative is to ignore the
        /// document, and ignoring a rule that used to deny is the one direction this must
        /// never fail in: an unreadable or unmigrated database grant would silently widen
        /// access rather than narrow it.
        /// </summary>
        public static bool UnmigratedDatabaseGrant(PwDatabase database)
        {
            return database != null
                && database.CustomData != null
                && database.CustomData.Exists(AclDocument.CustomDataKey);
        }

        /// <summary>
        /// Which way round a database reads, for anything that has to show a rule rather than
        /// enforce one. Deny when the root document cannot be read, which is also what the
        /// resolver does with it.
        /// </summary>
        public static AclDefault DefaultOf(PwDatabase database)
        {
            if (database == null || database.RootGroup == null)
                return AclDefault.Deny;

            string raw = Read(database.RootGroup.CustomData);
            if (raw == null)
                return AclDefault.Deny;

            AclDocument root = AclDocument.Parse(raw);
            return root == null ? AclDefault.Deny : root.Default;
        }

        /// <summary>Resolve for a group, which is what <c>list</c> on a container means.</summary>
        public static AclGrant Resolve(PwDatabase database, PwGroup group, string subject)
        {
            if (database == null || group == null || UnmigratedDatabaseGrant(database))
                return AclGrant.Deny;

            return ForClient(database, ChainFor(database, group, null), subject);
        }

        /// <summary>
        /// What every subject named anywhere in a chain ends up holding, for display.
        ///
        /// The same top-down narrow-only rule as <see cref="Resolve"/>, applied to all the
        /// subjects at once instead of one. The grant editor needs this to show what an entry
        /// or group already inherits before anything is written to it, because a rule you
        /// cannot see is a rule you will duplicate or contradict by accident.
        /// </summary>
        /// <param name="chainRootFirst">
        /// The raw documents above the level being edited, root group first. A null element
        /// is a level that carries no document at all.
        /// </param>
        /// <returns>
        /// Subject to effective grant, or null if any level is present but unreadable. Null
        /// rather than a partial answer: a chain with an unintelligible link grants nothing,
        /// and showing the readable half of it would describe rights that are not in force.
        /// </returns>
        public static IDictionary<string, AclGrant> Effective(IList<string> chainRootFirst)
        {
            Dictionary<string, AclGrant> effective =
                new Dictionary<string, AclGrant>(System.StringComparer.Ordinal);
            if (chainRootFirst == null)
                return effective;

            // A database that allows by default inherits down as though the root group granted
            // everything to everyone, so the editor shows exactly that: a wildcard row nobody
            // typed, which is the honest picture of what a client actually holds here.
            AclGrant start = StartingPoint(chainRootFirst);
            if (start != null)
                effective[AclDocument.WildcardSubject] = start;

            foreach (string raw in chainRootFirst)
            {
                if (raw == null)
                    continue;

                AclDocument document = AclDocument.Parse(raw);
                if (document == null)
                    return null;

                foreach (string subject in document.Subjects)
                {
                    AclGrant granted = document.GrantFor(subject);
                    AclGrant above;
                    if (!effective.TryGetValue(subject, out above))
                    {
                        // Not named above, but the wildcard may still have reached it, whether
                        // that wildcard was written or came from an allow-by-default database.
                        effective.TryGetValue(AclDocument.WildcardSubject, out above);
                    }

                    effective[subject] = above == null ? granted : above.NarrowedBy(granted);
                }
            }

            return effective;
        }

        /// <summary>
        /// The raw documents above a level, database first, for showing what it inherits.
        /// </summary>
        /// <param name="deepestGroup">
        /// The group whose grants are the last inherited ones. For an entry that is its parent
        /// group; for a group it is that group's parent. Null leaves an empty chain, which
        /// grants nothing.
        /// </param>
        public static IList<string> ChainAbove(PwDatabase database, PwGroup deepestGroup)
        {
            if (database == null)
                return new List<string>();

            return ChainFor(database, deepestGroup, null);
        }

        /// <summary>
        /// Collect the raw documents from the root group down to the object.
        /// </summary>
        /// <param name="database">
        /// Not read any more, and kept so that every caller still names the database it is
        /// resolving against. The chain is entirely made of groups now.
        /// </param>
        /// <param name="deepestGroup">The entry's parent, or the group itself.</param>
        /// <param name="leaf">
        /// The entry's own <c>CustomData</c>, or null when resolving for a group.
        /// </param>
        private static IList<string> ChainFor(PwDatabase database, PwGroup deepestGroup, StringDictionaryEx leaf)
        {
            // Walking up from the deepest group ends at the root group, which is the widest
            // grant there is: every entry in a KDBX is inside it. There is no separate
            // database level and there is nothing above the root to read.
            List<string> chain = new List<string>();
            for (PwGroup group = deepestGroup; group != null; group = group.ParentGroup)
                chain.Add(Read(group.CustomData));
            chain.Reverse();

            if (leaf != null)
                chain.Add(Read(leaf));

            return chain;
        }

        /// <summary>
        /// The raw document at one level, or null if there is none.
        ///
        /// A key that exists with an empty value is NOT treated as absent. Someone or
        /// something wrote it, and the honest reading of an unintelligible grant is to refuse,
        /// not to pretend it was never there.
        /// </summary>
        private static string Read(StringDictionaryEx customData)
        {
            if (customData == null || !customData.Exists(AclDocument.CustomDataKey))
                return null;

            string raw = customData.Get(AclDocument.CustomDataKey);
            return raw ?? string.Empty;
        }
    }
}
