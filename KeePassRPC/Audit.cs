using System;
using System.Globalization;
using System.IO;
using Jayrock.Json;
using Jayrock.Json.Conversion;
using KeePass.Plugins;

namespace KeePassRPC
{
    /// <summary>
    /// A record of what each client was allowed and refused.
    ///
    /// With one human-driven client an audit log is a nicety. With agents it is the only way
    /// to answer "what did it actually read", after the fact, when something has gone wrong
    /// and the agent cannot be trusted to say. That question is unanswerable from the database
    /// itself: a read leaves no trace in a `.kdbx`.
    ///
    /// **It records what was touched, never what was in it.** The target is an entry UUID and
    /// nothing else. No title, no field name, no value. That is not squeamishness about
    /// secrets alone: a log of titles is an inventory of the database, readable by anything
    /// that can read the log, and it would end up being the easiest place in the system to
    /// learn what exists. Resolving a UUID back to an entry is the reader's job, done in
    /// KeePass, deliberately.
    ///
    /// The log lives outside the `.kdbx`, because a log inside the thing being audited is
    /// worth little, and because writing to the database on every read would be absurd.
    /// </summary>
    public static class Audit
    {
        /// <summary>Turn the log off. On by default: a control nobody records is hard to trust.</summary>
        public const string EnabledKey = "KeePassRPC.Audit.Enabled";

        /// <summary>Rotate at this size, keeping one previous file.</summary>
        private const long MaxBytes = 8 * 1024 * 1024;

        private static readonly object WriteLock = new object();

        /// <summary>Set once by the plugin so the log survives a failure to reach config.</summary>
        private static Action<string> _problemReporter;

        /// <summary>
        /// Where the log goes: <c>%LOCALAPPDATA%\KeePassRPC\audit.jsonl</c>.
        ///
        /// Fixed rather than configurable. The setting it replaces only ever moved the file
        /// to another place the same Windows account can write, which is not what durability
        /// means here: that account can rewrite the log wherever it sits, as THREAT-MODEL.md
        /// says plainly. Getting it somewhere durable means something outside this process
        /// shipping it off the machine, and that reads the default path as happily as any
        /// other. The host parameter stays so callers read unchanged and so a future
        /// per-installation path has an obvious home.
        /// </summary>
        public static string ResolvePath(IPluginHost host)
        {
            string baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(Path.Combine(baseDir, "KeePassRPC"), "audit.jsonl");
        }

        /// <summary>Where to send a complaint if the log itself cannot be written.</summary>
        public static void SetProblemReporter(Action<string> reporter)
        {
            _problemReporter = reporter;
        }

        /// <summary>
        /// Append one decision.
        /// </summary>
        /// <param name="host">Supplies configuration. A null host writes nothing.</param>
        /// <param name="subject">The authenticated identity, or null if there was none.</param>
        /// <param name="remote">Whether the call arrived from beyond this machine.</param>
        /// <param name="method">The RPC method that was called.</param>
        /// <param name="target">An entry or group UUID, or null where the call names neither.</param>
        /// <param name="verb">The verb the call required, or null for a method-gate decision.</param>
        /// <param name="allowed">Whether it went ahead.</param>
        /// <param name="reason">A short, stable phrase. Never interpolate a secret into this.</param>
        public static void Record(IPluginHost host, string subject, bool remote, string method, string target,
            string verb, bool allowed, string reason)
        {
            if (host == null)
                return;

            try
            {
                if (!host.CustomConfig.GetBool(EnabledKey, true))
                    return;

                Append(ResolvePath(host),
                    FormatRecord(DateTime.UtcNow, subject, remote, method, target, verb, allowed, reason));
            }
            catch (Exception exception)
            {
                // Deliberately NOT fatal, and worth being explicit about the trade-off. The
                // stricter reading of this project's fail-closed rule would refuse the call
                // when it cannot be recorded, so that nothing happens unobserved. That rule is
                // about ambiguous ACCESS decisions though, and this is not one: the decision
                // was already made correctly. Refusing here would mean a full disk or a locked
                // file silently revokes every agent's access, which trades a logging outage for
                // an outage of the thing being logged. So the failure is reported and the call
                // proceeds.
                Report("KeePassRPC audit: could not write the audit log: " + exception.Message);
            }
        }

        /// <summary>
        /// Build one line of the log.
        ///
        /// Separate from writing it so the shape can be tested without a KeePass or a
        /// filesystem, since the shape is the part anything reading the log depends on.
        /// </summary>
        public static string FormatRecord(DateTime timestampUtc, string subject, bool remote, string method,
            string target, string verb, bool allowed, string reason)
        {
            JsonObject record = new JsonObject();
            // Round-trip format, UTC, sortable as text. A log that needs a locale to read is a
            // log nobody reads.
            record["time"] = timestampUtc.ToString("o", CultureInfo.InvariantCulture);
            // An unauthenticated caller still gets a line. "Nobody tried" and "somebody tried
            // and could not say who" are different events.
            record["subject"] = string.IsNullOrEmpty(subject) ? "<unidentified>" : subject;
            // Always written, including when false, unlike the optional fields below. During
            // an incident "was this call from the network" is one of the first questions, and
            // a field that is only present sometimes cannot answer it: a missing one would
            // mean "local" and "written by a build that did not record this" at once.
            record["remote"] = remote;
            record["method"] = method ?? "";
            if (!string.IsNullOrEmpty(target))
                record["target"] = target;
            if (!string.IsNullOrEmpty(verb))
                record["verb"] = verb;
            record["decision"] = allowed ? "allow" : "deny";
            if (!string.IsNullOrEmpty(reason))
                record["reason"] = reason;

            return JsonConvert.ExportToString(record);
        }

        private static void Append(string path, string line)
        {
            lock (WriteLock)
            {
                string directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    Directory.CreateDirectory(directory);

                Rotate(path);

                // Append only, and shared for reading so the file can be tailed while KeePass
                // holds it open.
                using (FileStream stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
                using (StreamWriter writer = new StreamWriter(stream))
                {
                    writer.WriteLine(line);
                }
            }
        }

        /// <summary>
        /// Keep one previous file, so an agent in a loop cannot fill the disk.
        ///
        /// Rotation loses the oldest history, which is a real cost for an audit log and the
        /// reason the threshold is generous. Anyone who needs to keep more should ship the
        /// file somewhere durable rather than raise the limit.
        /// </summary>
        private static void Rotate(string path)
        {
            try
            {
                FileInfo current = new FileInfo(path);
                if (!current.Exists || current.Length < MaxBytes)
                    return;

                string previous = path + ".1";
                if (File.Exists(previous))
                    File.Delete(previous);
                File.Move(path, previous);
            }
            catch (Exception exception)
            {
                Report("KeePassRPC audit: could not rotate the audit log: " + exception.Message);
            }
        }

        private static void Report(string message)
        {
            Action<string> reporter = _problemReporter;
            if (reporter == null)
                return;

            try
            {
                reporter(message);
            }
            catch (Exception)
            {
                // There is nowhere left to complain to.
            }
        }
    }
}
