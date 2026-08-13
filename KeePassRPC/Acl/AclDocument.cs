using System;
using System.Collections;
using System.Collections.Generic;
using Jayrock.Json;
using Jayrock.Json.Conversion;

namespace KeePassRPC.Acl
{
    /// <summary>
    /// The grant document stored under one <c>CustomData</c> key.
    ///
    /// <code>
    /// {
    ///   "version": 1,
    ///   "default": "allow",
    ///   "profiles": [ "default", "deploy", "docs" ],
    ///   "clients": { "docs-agent": [ "docs" ] },
    ///   "grants": {
    ///     "deploy": { "verb": "write" },
    ///     "docs":   { "verb": "read", "attachments": false, "unattended": true },
    ///     "*":      { "verb": "none" }
    ///   }
    /// }
    /// </code>
    ///
    /// **A grant names a profile, not a client.** Which clients are in which profile is the
    /// <c>clients</c> map, and the profiles a database defines are the <c>profiles</c> list;
    /// see <see cref="AclProfiles"/> for why the two are kept apart.
    ///
    /// <c>default</c>, <c>profiles</c> and <c>clients</c> are read from the ROOT GROUP's
    /// document and nowhere else, because all three are statements about the whole database
    /// rather than rules about one group. Each is written only when it says something: an
    /// ordinary group document is the same two properties it always was, and a reader can tell
    /// at a glance which document is the one that starts the chain.
    ///
    /// Parsing is strict to the point of pedantry, and deliberately so. Upstream's own config
    /// reader resets a corrupt blob to a default and carries on, which is right for a display
    /// preference and wrong for an access rule: the safe reading of "I cannot understand this
    /// grant" is to grant nothing, never to substitute something workable. Every rejection
    /// here surfaces as a null document, which the resolver turns into a hard deny rather than
    /// into inheritance from a more generous parent.
    /// </summary>
    public sealed class AclDocument
    {
        /// <summary>
        /// The <c>CustomData</c> key, following upstream's dotted convention for its own keys
        /// (<c>KeePassRPC.Config</c>, <c>KeePassRPC.KeeFox.rootUUID</c>).
        /// </summary>
        public const string CustomDataKey = "KeePassRPC.ACL";

        /// <summary>The subject standing for "any subject with no entry of its own".</summary>
        public const string WildcardSubject = "*";

        // A note on the word "subject", once, rather than a rename through every identifier.
        // Inside a grant document a subject is whatever name the rule is about, and since the
        // move to profiles that is always a profile or the wildcard, never a client identity.
        // The resolver deliberately does not care: it resolves names, and the client-to-profile
        // lookup happens once, in AclResolver.ForClient, before any document is read. Config
        // keys such as KeePassRPC.Profile.<subject> are a different "subject" again, the client
        // identity, and a different "profile" too: the method gate's, not the database's.

        /// <summary>
        /// The only accepted schema version. A newer document is refused rather than read
        /// optimistically: a version bump exists precisely because the meaning changed, and
        /// misreading a grant is the failure this whole design is trying to avoid.
        /// </summary>
        public const int CurrentVersion = 1;

        private const string VersionProperty = "version";
        private const string DefaultProperty = "default";
        private const string ProfilesProperty = "profiles";
        private const string ClientsProperty = "clients";
        private const string GrantsProperty = "grants";
        private const string DenyValue = "deny";
        private const string AllowValue = "allow";
        private const string VerbProperty = "verb";
        private const string AttachmentsProperty = "attachments";
        private const string UnattendedProperty = "unattended";

        // Ordinal, case-sensitive. A subject is an identity established at SRP pairing, and
        // two identities differing only in case are two identities. Matching loosely could
        // hand one subject's rights to another; failing to match merely denies.
        private readonly Dictionary<string, AclGrant> _grants =
            new Dictionary<string, AclGrant>(StringComparer.Ordinal);

        /// <summary>The subjects named by this document, in no particular order.</summary>
        public ICollection<string> Subjects
        {
            get { return _grants.Keys; }
        }

        /// <summary>How many subjects this document names.</summary>
        public int Count
        {
            get { return _grants.Count; }
        }

        /// <summary>
        /// Whether this document says anything at all, either a grant or a default that is not
        /// the default. Used to decide between storing it and removing the key.
        /// </summary>
        public bool IsEmpty
        {
            get
            {
                return _grants.Count == 0
                    && _default == AclDefault.Deny
                    && _profiles.IsEmpty;
            }
        }

        private AclProfiles _profiles = new AclProfiles();

        /// <summary>
        /// The profiles this database defines and who is in them, read from the root group's
        /// document only. A group document carrying one is ignored, the same as its
        /// <see cref="Default"/>.
        /// </summary>
        public AclProfiles Profiles
        {
            get { return _profiles; }
            set { _profiles = value == null ? new AclProfiles() : value; }
        }

        private AclDefault _default = AclDefault.Deny;

        /// <summary>
        /// Where the chain starts, read from the root group's document only.
        ///
        /// <see cref="AclDefault.Deny"/> is a weak deny: nothing is granted to begin with, and
        /// the first group that grants something lifts it for that subtree. It is not the same
        /// as writing <c>"*": "none"</c>, which is a hard floor no group below can raise.
        ///
        /// <see cref="AclDefault.Allow"/> starts every subject holding everything, and groups
        /// and entries can then only take away. Rights still narrow as they descend either
        /// way; the setting decides what they narrow from.
        /// </summary>
        public AclDefault Default
        {
            get { return _default; }
            set { _default = value; }
        }

        /// <summary>
        /// The grant this document makes to <paramref name="subject"/>, or null if it says
        /// nothing about them. Null means "inherit", not "deny": a document that does not
        /// mention a subject does not constrain that subject at this level.
        /// </summary>
        public AclGrant GrantFor(string subject)
        {
            if (string.IsNullOrEmpty(subject))
                return null;

            AclGrant grant;
            if (_grants.TryGetValue(subject, out grant))
                return grant;

            // The wildcard applies only where the subject has no entry of its own, so an
            // explicit grant always wins over "*" regardless of which appears first.
            if (_grants.TryGetValue(WildcardSubject, out grant))
                return grant;

            return null;
        }

        /// <summary>Add or replace a subject's grant.</summary>
        public void Set(string subject, AclGrant grant)
        {
            if (string.IsNullOrEmpty(subject))
                throw new ArgumentException("a grant needs a subject", "subject");
            if (grant == null)
                throw new ArgumentNullException("grant");

            _grants[subject] = grant;
        }

        /// <summary>Remove a subject's grant, if it has one.</summary>
        public bool Remove(string subject)
        {
            if (string.IsNullOrEmpty(subject))
                return false;

            return _grants.Remove(subject);
        }

        /// <summary>
        /// Parse a stored document.
        /// </summary>
        /// <param name="json">The raw <c>CustomData</c> value.</param>
        /// <returns>
        /// The document, or null if it is unparseable, the wrong version, or carries anything
        /// this code does not recognise. Callers MUST treat null as deny.
        /// </returns>
        public static AclDocument Parse(string json)
        {
            if (string.IsNullOrEmpty(json) || json.Trim().Length == 0)
                return null;

            object imported;
            try
            {
                imported = JsonConvert.Import(json);
            }
            catch (Exception)
            {
                return null;
            }

            IDictionary root = imported as IDictionary;
            if (root == null)
                return null;

            if (!HasOnly(root, VersionProperty, DefaultProperty, ProfilesProperty,
                    ClientsProperty, GrantsProperty))
            {
                return null;
            }

            int version;
            if (!TryReadInt(root[VersionProperty], out version) || version != CurrentVersion)
                return null;

            IDictionary grants = root[GrantsProperty] as IDictionary;
            if (grants == null)
                return null;

            AclDocument document = new AclDocument();

            if (root.Contains(ProfilesProperty) || root.Contains(ClientsProperty))
            {
                AclProfiles profiles = AclProfiles.Parse(
                    root.Contains(ProfilesProperty) ? root[ProfilesProperty] : null,
                    root.Contains(ClientsProperty) ? root[ClientsProperty] : null);

                if (profiles == null)
                    return null;

                document._profiles = profiles;
            }

            if (root.Contains(DefaultProperty))
            {
                // Strict, like everything else here. A default nobody can read is not worth
                // guessing at, and guessing "allow" would be the expensive direction.
                string mode = root[DefaultProperty] as string;
                if (string.Equals(mode, AllowValue, StringComparison.Ordinal))
                    document._default = AclDefault.Allow;
                else if (string.Equals(mode, DenyValue, StringComparison.Ordinal))
                    document._default = AclDefault.Deny;
                else
                    return null;
            }

            foreach (object key in grants.Keys)
            {
                string subject = key as string;
                if (string.IsNullOrEmpty(subject) || subject.Trim().Length == 0)
                    return null;

                AclGrant grant = ParseGrant(grants[key]);
                if (grant == null)
                    return null;

                document._grants[subject] = grant;
            }

            return document;
        }

        private static AclGrant ParseGrant(object value)
        {
            IDictionary body = value as IDictionary;
            if (body == null)
                return null;

            if (!HasOnly(body, VerbProperty, AttachmentsProperty, UnattendedProperty))
                return null;

            AclVerb verb;
            if (!AclVerbs.TryParse(body[VerbProperty] as string, out verb))
                return null;

            bool attachments;
            if (!TryReadOptionalBool(body, AttachmentsProperty, out attachments))
                return null;

            bool unattended;
            if (!TryReadOptionalBool(body, UnattendedProperty, out unattended))
                return null;

            return new AclGrant(verb, attachments, unattended);
        }

        /// <summary>
        /// Whether the object carries nothing beyond the named properties.
        ///
        /// An unrecognised property is a rejection rather than something to ignore. If a later
        /// version adds a restriction, a reader that skipped what it did not understand would
        /// apply the grant WITHOUT the restriction, which is the wrong way to be wrong.
        /// </summary>
        private static bool HasOnly(IDictionary body, params string[] allowed)
        {
            foreach (object key in body.Keys)
            {
                string name = key as string;
                if (name == null)
                    return false;

                bool permitted = false;
                foreach (string candidate in allowed)
                {
                    if (string.Equals(name, candidate, StringComparison.Ordinal))
                    {
                        permitted = true;
                        break;
                    }
                }

                if (!permitted)
                    return false;
            }

            return true;
        }

        private static bool TryReadInt(object value, out int result)
        {
            result = 0;

            if (value == null)
                return false;

            // Jayrock hands back JsonNumber for numeric literals, and boxed integers when the
            // document was built in memory. A quoted "1" is refused: a version is a number.
            if (value is string)
                return false;

            // JsonNumber is a struct in Jayrock, so this is a type test rather than an as-cast.
            if (value is JsonNumber)
            {
                try
                {
                    result = ((JsonNumber)value).ToInt32();
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            try
            {
                result = Convert.ToInt32(value);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool TryReadOptionalBool(IDictionary body, string name, out bool result)
        {
            result = false;

            if (!body.Contains(name))
                return true; // absent is false, which is the closed reading

            object value = body[name];
            if (value is bool)
            {
                result = (bool)value;
                return true;
            }

            // A string "true" or a number 1 is refused. A flag that decides whether an agent
            // can pull a private key out of an attachment should not depend on coercion rules.
            return false;
        }

        /// <summary>Serialise for storage in <c>CustomData</c>.</summary>
        public string ToJson()
        {
            JsonObject grants = new JsonObject();
            foreach (KeyValuePair<string, AclGrant> pair in _grants)
            {
                JsonObject body = new JsonObject();
                body[VerbProperty] = AclVerbs.ToJsonValue(pair.Value.Verb);

                // Written only when true, so a stored document stays as small and as readable
                // as the example in the design. Absent already means false on the way back in.
                if (pair.Value.Attachments)
                    body[AttachmentsProperty] = true;
                if (pair.Value.Unattended)
                    body[UnattendedProperty] = true;

                grants[pair.Key] = body;
            }

            JsonObject root = new JsonObject();
            root[VersionProperty] = CurrentVersion;

            // Written only when it is not the default, so an ordinary group document is the
            // same two properties it always was and a reader can tell at a glance which
            // document is the one that starts the chain.
            if (_default == AclDefault.Allow)
                root[DefaultProperty] = AllowValue;

            if (!_profiles.IsEmpty)
            {
                JsonArray names = new JsonArray();
                foreach (string name in _profiles.Names)
                    names.Add(name);
                root[ProfilesProperty] = names;

                JsonObject clients = new JsonObject();
                foreach (string subject in _profiles.AssignedSubjects)
                {
                    JsonArray assigned = new JsonArray();
                    foreach (string name in _profiles.AssignedTo(subject))
                        assigned.Add(name);
                    clients[subject] = assigned;
                }

                if (clients.Count > 0)
                    root[ClientsProperty] = clients;
            }

            root[GrantsProperty] = grants;

            return JsonConvert.ExportToString(root);
        }
    }
}
