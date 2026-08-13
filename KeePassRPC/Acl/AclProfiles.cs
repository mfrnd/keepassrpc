using System;
using System.Collections.Generic;

namespace KeePassRPC.Acl
{
    /// <summary>
    /// The profiles a database defines, and which clients are in them.
    ///
    /// Grants name a PROFILE, never a client. A client is a paired identity, which is a fact
    /// about a machine somewhere; a profile is a job, which is what the rules are actually
    /// about. Keeping the two apart means a second agent doing the same work is a one-line
    /// assignment rather than a sweep through every group and entry that mentions the first,
    /// and it means the grant table needs one column to say who a rule is for instead of two.
    ///
    /// Both halves live on the root group's document, edited on the database settings dialog,
    /// because both are statements about the whole file. A profile therefore means nothing
    /// outside the database that defines it: the same client can be an auditor in one database
    /// and hold nothing in another, which is the point.
    ///
    /// <see cref="DefaultProfile"/> always exists and cannot be removed. A client is never
    /// without a profile: an assignment naming profiles that have since been deleted, or no
    /// profiles at all, reads as <c>default</c>. That is a deliberate floor rather than a
    /// convenience. A client with no profile would have to mean something, and both possible
    /// meanings are bad: "nothing", which makes deleting a profile a silent revocation of
    /// access somebody else is relying on, or "everything", which needs no discussion.
    /// </summary>
    public sealed class AclProfiles
    {
        /// <summary>The profile every database has and no database can delete.</summary>
        public const string DefaultProfile = "default";

        // Ordinal, like everything else here. Two names differing only in case are two names
        // as far as matching is concerned; creating the second of them is refused instead, so
        // the leniency is in what can be typed rather than in what a rule means.
        private readonly List<string> _names = new List<string>();

        private readonly Dictionary<string, List<string>> _assignments =
            new Dictionary<string, List<string>>(StringComparer.Ordinal);

        public AclProfiles()
        {
            _names.Add(DefaultProfile);
        }

        /// <summary>Every profile this database defines, <c>default</c> first.</summary>
        public IList<string> Names
        {
            get { return new List<string>(_names); }
        }

        /// <summary>Whether the database defines a profile by this exact name.</summary>
        public bool Defines(string name)
        {
            return name != null && _names.Contains(name);
        }

        /// <summary>
        /// Whether this is a name a profile may have.
        ///
        /// Not empty, not the wildcard, and not something differing from an existing name only
        /// in case: a rule for "Docs" that silently misses the profile called "docs" is the
        /// kind of mistake that reads as correct on screen.
        /// </summary>
        public bool CanAdd(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Trim().Length == 0)
                return false;

            if (name != name.Trim())
                return false;

            if (name == AclDocument.WildcardSubject)
                return false;

            foreach (string existing in _names)
            {
                if (string.Equals(existing, name, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            return true;
        }

        /// <summary>Add a profile. Returns false if the name is not one it may have.</summary>
        public bool Add(string name)
        {
            if (!CanAdd(name))
                return false;

            _names.Add(name);
            return true;
        }

        /// <summary>
        /// Remove a profile, and with it every assignment to it.
        ///
        /// Refuses <c>default</c>. A client left with no profiles by this falls back to
        /// <c>default</c> when it is next asked about, which is what
        /// <see cref="For"/> does rather than something written back here: an assignment list
        /// that empties itself as profiles come and go would lose the operator's intent the
        /// first time a profile was deleted by accident.
        /// </summary>
        public bool Remove(string name)
        {
            if (string.Equals(name, DefaultProfile, StringComparison.Ordinal))
                return false;

            return _names.Remove(name);
        }

        /// <summary>The subjects with an assignment of their own, in no particular order.</summary>
        public ICollection<string> AssignedSubjects
        {
            get { return _assignments.Keys; }
        }

        /// <summary>
        /// Put a client in these profiles, replacing whatever it was in.
        ///
        /// An empty list is stored as no assignment at all, which reads back as
        /// <c>default</c>: "in nothing" and "in the default" are the same state, so there is
        /// no point in being able to write one and read the other.
        /// </summary>
        public void Assign(string subject, IList<string> profiles)
        {
            if (string.IsNullOrEmpty(subject))
                return;

            List<string> wanted = new List<string>();
            if (profiles != null)
            {
                foreach (string profile in profiles)
                {
                    if (Defines(profile) && !wanted.Contains(profile))
                        wanted.Add(profile);
                }
            }

            if (wanted.Count == 0)
                _assignments.Remove(subject);
            else
                _assignments[subject] = wanted;
        }

        /// <summary>
        /// The profiles a client holds: what it was assigned, minus anything since deleted,
        /// and <c>default</c> if that leaves nothing.
        ///
        /// Never empty and never null. Everything that resolves a request goes through here,
        /// so this is the one place the floor has to hold.
        /// </summary>
        public IList<string> For(string subject)
        {
            List<string> held = new List<string>();

            List<string> assigned;
            if (!string.IsNullOrEmpty(subject) && _assignments.TryGetValue(subject, out assigned))
            {
                foreach (string profile in assigned)
                {
                    if (Defines(profile) && !held.Contains(profile))
                        held.Add(profile);
                }
            }

            if (held.Count == 0)
                held.Add(DefaultProfile);

            return held;
        }

        /// <summary>The raw assignment for a subject, for the editor. May be empty.</summary>
        public IList<string> AssignedTo(string subject)
        {
            List<string> assigned;
            if (!string.IsNullOrEmpty(subject) && _assignments.TryGetValue(subject, out assigned))
                return new List<string>(assigned);

            return new List<string>();
        }

        /// <summary>
        /// Whether this is the shape a database starts in: one profile, no assignments.
        /// Used to decide whether the registry is worth writing out at all.
        /// </summary>
        public bool IsEmpty
        {
            get
            {
                return _assignments.Count == 0
                    && _names.Count == 1
                    && _names[0] == DefaultProfile;
            }
        }

        internal AclProfiles Copy()
        {
            AclProfiles copy = new AclProfiles();
            copy._names.Clear();
            copy._names.AddRange(_names);
            foreach (KeyValuePair<string, List<string>> pair in _assignments)
                copy._assignments[pair.Key] = new List<string>(pair.Value);

            return copy;
        }

        /// <summary>
        /// Read a registry from the parsed <c>profiles</c> and <c>clients</c> properties, or
        /// null if either is malformed.
        ///
        /// Strict, like the rest of the document. A registry nobody can read means nobody can
        /// say which profiles a client holds, and guessing at that is guessing at access.
        /// </summary>
        internal static AclProfiles Parse(object namesValue, object clientsValue)
        {
            AclProfiles profiles = new AclProfiles();

            if (namesValue != null)
            {
                System.Collections.IEnumerable names = namesValue as System.Collections.IEnumerable;
                if (names == null || namesValue is string)
                    return null;

                foreach (object item in names)
                {
                    string name = item as string;
                    if (name == null)
                        return null;

                    // default is implied, so a document naming it is not an error.
                    if (string.Equals(name, DefaultProfile, StringComparison.Ordinal))
                        continue;

                    if (!profiles.Add(name))
                        return null;
                }
            }

            if (clientsValue != null)
            {
                System.Collections.IDictionary clients = clientsValue as System.Collections.IDictionary;
                if (clients == null)
                    return null;

                foreach (object key in clients.Keys)
                {
                    string subject = key as string;
                    if (string.IsNullOrEmpty(subject))
                        return null;

                    System.Collections.IEnumerable assigned =
                        clients[key] as System.Collections.IEnumerable;
                    if (assigned == null || clients[key] is string)
                        return null;

                    List<string> wanted = new List<string>();
                    foreach (object item in assigned)
                    {
                        string name = item as string;
                        if (name == null)
                            return null;

                        // A name that is not defined is kept out here rather than refused: a
                        // profile can be deleted while a client is still assigned to it, and
                        // that is a tidy-up rather than a corrupt document.
                        if (profiles.Defines(name) && !wanted.Contains(name))
                            wanted.Add(name);
                    }

                    if (wanted.Count > 0)
                        profiles._assignments[subject] = wanted;
                }
            }

            return profiles;
        }
    }
}
