using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Xml.Serialization;
using Jayrock.Json;
using Jayrock.Json.Conversion;
using KeePass.Plugins;
using KeePassRPC.Acl;

namespace KeePassRPC
{
    /// <summary>
    /// Which subjects exist, so that granting to one can be a choice rather than a spelling
    /// test.
    ///
    /// Both access controls in this fork are keyed on the subject: the method gate reads
    /// <c>KeePassRPC.Profile.&lt;subject&gt;</c>, and an ACL grant names subjects as JSON keys.
    /// Neither is any use if the person configuring them has to remember an identity exactly,
    /// because a typo produces no error at all. It grants to a subject that does not exist,
    /// silently, which looks identical to having granted nothing.
    ///
    /// Two sources, in order of trust:
    ///
    /// * An index this fork maintains under <c>KeePassRPC.Subjects</c>, written through the
    ///   ordinary public config API whenever a subject pairs or authenticates.
    /// * The <c>KeePassRPC.Key.*</c> entries upstream already writes, read by reflecting into
    ///   <c>AceCustomConfig</c>, which exposes no enumeration of its own.
    ///
    /// The index alone would be correct but slow to fill: it only learns about a subject when
    /// that subject next connects, so a rarely-used agent stays invisible for as long as it
    /// stays idle. Reflection closes that gap immediately for pairings that already exist.
    /// </summary>
    public static class SubjectRegistry
    {
        /// <summary>Upstream's per-subject key prefix.</summary>
        public const string KeyPrefix = "KeePassRPC.Key.";

        /// <summary>This fork's per-subject method profile prefix.</summary>
        public const string ProfilePrefix = "KeePassRPC.Profile.";

        /// <summary>Where this fork's own index of seen subjects lives.</summary>
        public const string IndexKey = "KeePassRPC.Subjects";

        /// <summary>
        /// A subject and the name its client gave for itself, for anywhere a human has to
        /// pick one.
        ///
        /// Worth the trouble because a browser extension pairs under a GUID. A list of those
        /// is not a choice, it is a lottery, and the grant it produces is unverifiable by
        /// eye.
        /// </summary>
        public sealed class SubjectChoice
        {
            /// <summary>The identity the ACL and the method gate are keyed on.</summary>
            public readonly string Subject;

            /// <summary>What the client called itself when it paired. May be empty.</summary>
            public readonly string ClientName;

            public SubjectChoice(string subject, string clientName)
            {
                Subject = subject;
                ClientName = clientName;
            }

            /// <summary>
            /// What a combo box shows. The subject is always present, because it is the thing
            /// actually being granted to and a name alone could not be checked against a
            /// stored grant.
            /// </summary>
            public override string ToString()
            {
                if (string.IsNullOrEmpty(ClientName) || ClientName == Subject)
                    return Subject;

                return ClientName + "  (" + Subject + ")";
            }
        }

        /// <summary>
        /// Every known subject, each with the client name recorded at pairing where one can
        /// be recovered.
        /// </summary>
        public static IList<SubjectChoice> KnownChoices(IPluginHost host)
        {
            List<SubjectChoice> choices = new List<SubjectChoice>();
            foreach (string subject in Known(host))
                choices.Add(new SubjectChoice(subject, ClientNameFor(host, subject)));

            return choices;
        }

        /// <summary>
        /// The name a subject's client gave at pairing, or null.
        ///
        /// Upstream stores it in the same DPAPI-protected blob as the session key, so this
        /// reads that blob and takes only the name out of it. Nothing here needs the key, and
        /// a failure to decrypt is not interesting: it means the blob belongs to another user
        /// or another machine, and the answer is simply that there is no name to show.
        /// </summary>
        public static string ClientNameFor(IPluginHost host, string subject)
        {
            if (host == null || string.IsNullOrEmpty(subject))
                return null;

            try
            {
                string stored = host.CustomConfig.GetString(KeyPrefix + subject, "");
                if (string.IsNullOrEmpty(stored))
                    return null;

                byte[] raw = Convert.FromBase64String(stored);

                // Security level 2 protects it; level 1 stores the same XML in the clear. Try
                // the protected form first and fall back rather than reading the configured
                // level, which would be one more thing to keep in step.
                byte[] plain;
                try
                {
                    plain = ProtectedData.Unprotect(raw,
                        new byte[] { 172, 218, 37, 36, 15 }, DataProtectionScope.CurrentUser);
                }
                catch (CryptographicException)
                {
                    plain = raw;
                }

                using (MemoryStream stream = new MemoryStream(plain))
                {
                    XmlSerializer serialiser = new XmlSerializer(typeof(KeyContainerClass));
                    KeyContainerClass container = (KeyContainerClass)serialiser.Deserialize(stream);
                    if (container == null || string.IsNullOrEmpty(container.ClientName))
                        return null;

                    return container.ClientName;
                }
            }
            catch (Exception)
            {
                // A name is a convenience. Nothing here is worth an exception in a dialog.
                return null;
            }
        }

        /// <summary>
        /// Record that a subject exists. Safe to call repeatedly and on any thread that
        /// already touches the config; a failure is swallowed, because failing to note a name
        /// for a dropdown must never break an authentication that has otherwise succeeded.
        /// </summary>
        public static void Remember(IPluginHost host, string subject)
        {
            if (host == null || string.IsNullOrEmpty(subject))
                return;

            try
            {
                List<string> known = ParseIndex(host.CustomConfig.GetString(IndexKey, ""));
                if (known.Contains(subject))
                    return;

                known.Add(subject);
                known.Sort(StringComparer.Ordinal);
                host.CustomConfig.SetString(IndexKey, FormatIndex(known));
            }
            catch (Exception)
            {
                // Noting a subject is a convenience. It is never worth an exception on the
                // authentication path.
            }
        }

        /// <summary>
        /// Forget a subject completely: its key, its access, and its place in the index.
        ///
        /// All three, deliberately. Clearing only the key would stop the client connecting
        /// while leaving what it was allowed lying around, so pairing again under the same
        /// identity would silently restore its old access and never ask. Forgetting a client
        /// has to mean forgetting what it could do.
        ///
        /// <c>AceCustomConfig</c> has no delete, so a value is cleared by setting it to null,
        /// which is how upstream revokes a key on its own Authorised clients tab.
        /// </summary>
        public static void Forget(IPluginHost host, string subject)
        {
            if (host == null || string.IsNullOrEmpty(subject))
                return;

            host.CustomConfig.SetString(KeyPrefix + subject, null);
            host.CustomConfig.SetString(ProfilePrefix + subject, null);
            host.CustomConfig.SetString(AclScope.SubjectPrefix + subject, null);

            try
            {
                List<string> known = ParseIndex(host.CustomConfig.GetString(IndexKey, ""));
                if (known.Remove(subject))
                    host.CustomConfig.SetString(IndexKey, FormatIndex(known));
            }
            catch (Exception)
            {
                // The index is a convenience, and the key is already gone. A subject left in
                // it merely shows up again with no access rather than reappearing armed.
            }
        }

        /// <summary>
        /// Every subject this installation knows about, sorted, without duplicates.
        ///
        /// Never throws and never returns null. An empty list means "we could not find any",
        /// which is why every caller must still accept a subject typed by hand.
        /// </summary>
        public static IList<string> Known(IPluginHost host)
        {
            List<string> known = new List<string>();
            if (host == null)
                return known;

            try
            {
                foreach (string subject in ParseIndex(host.CustomConfig.GetString(IndexKey, "")))
                {
                    if (!known.Contains(subject))
                        known.Add(subject);
                }
            }
            catch (Exception)
            {
                // Fall through to the reflected names.
            }

            foreach (string subject in ReflectKeyedSubjects(host))
            {
                if (!known.Contains(subject))
                    known.Add(subject);
            }

            known.Sort(StringComparer.Ordinal);
            return known;
        }

        /// <summary>
        /// Read the <c>KeePassRPC.Key.*</c> names straight out of the config dictionary.
        ///
        /// <c>AceCustomConfig</c> offers only Get and Set, so its backing dictionary has to be
        /// reached by reflection. That is not a liberty this fork invented: upstream already
        /// reaches into <c>PwEntryForm.m_sdCustomData</c> and <c>GroupForm.m_pwGroup</c> the
        /// same way. It is acceptable here specifically because the consequence of failure is
        /// a shorter list in a dropdown; nothing is granted, denied or migrated on the
        /// strength of it, and every caller still accepts a name typed by hand.
        /// </summary>
        private static IEnumerable<string> ReflectKeyedSubjects(IPluginHost host)
        {
            List<string> found = new List<string>();

            try
            {
                object config = host.CustomConfig;
                if (config == null)
                    return found;

                FieldInfo field = config.GetType().GetField("m_d", BindingFlags.NonPublic | BindingFlags.Instance);
                if (field == null)
                    return found; // KeePass changed shape; the index still works

                IDictionary items = field.GetValue(config) as IDictionary;
                if (items == null)
                    return found;

                foreach (object key in items.Keys)
                {
                    string name = key as string;
                    if (name == null || !name.StartsWith(KeyPrefix, StringComparison.Ordinal))
                        continue;

                    string subject = name.Substring(KeyPrefix.Length);
                    if (subject.Length > 0)
                        found.Add(subject);
                }
            }
            catch (Exception)
            {
                // Any reflection failure means we simply know less. It must not propagate into
                // a dialog that was only trying to be helpful.
            }

            return found;
        }

        /// <summary>
        /// Parse the stored index.
        ///
        /// JSON rather than a delimited string, because a subject is an arbitrary identity
        /// chosen at pairing and may contain a comma, a colon or a space. Anything unparseable
        /// yields an empty list: the index is a convenience and rebuilds itself as subjects
        /// reconnect, so there is nothing to gain by guessing at a damaged one.
        /// </summary>
        public static List<string> ParseIndex(string stored)
        {
            List<string> subjects = new List<string>();
            if (string.IsNullOrEmpty(stored))
                return subjects;

            try
            {
                JsonArray array = JsonConvert.Import(stored) as JsonArray;
                if (array == null)
                    return subjects;

                foreach (object item in array)
                {
                    string subject = item as string;
                    if (!string.IsNullOrEmpty(subject))
                        subjects.Add(subject);
                }
            }
            catch (Exception)
            {
                return new List<string>();
            }

            return subjects;
        }

        public static string FormatIndex(IEnumerable<string> subjects)
        {
            JsonArray array = new JsonArray();
            foreach (string subject in subjects)
                array.Add(subject);
            return JsonConvert.ExportToString(array);
        }
    }
}
