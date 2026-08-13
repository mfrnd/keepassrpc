using System;
using Jayrock.Json;
using Jayrock.Json.Conversion;
using KeePassRPC;
using NUnit.Framework;

namespace KeePassRPCTest
{
    [TestFixture]
    public class AuditTest
    {
        private static readonly DateTime When = new DateTime(2026, 8, 12, 9, 30, 15, DateTimeKind.Utc);

        private static JsonObject Parse(string line)
        {
            return (JsonObject)JsonConvert.Import(line);
        }

        [Test]
        public void RecordsTheFiveThingsThatMatter()
        {
            JsonObject record = Parse(Audit.FormatRecord(
                When, "agent-docs", false, "GetEntry3", "DEADBEEF", "read", true, "granted read"));

            Assert.AreEqual("agent-docs", record["subject"]);
            Assert.AreEqual("GetEntry3", record["method"]);
            Assert.AreEqual("DEADBEEF", record["target"]);
            Assert.AreEqual("read", record["verb"]);
            Assert.AreEqual("allow", record["decision"]);
        }

        [Test]
        public void TheTimestampIsSortableUtc()
        {
            // Text-sortable and locale-free, so the log can be read with a text tool.
            string time = (string)Parse(Audit.FormatRecord(When, "a", false, "m", null, null, true, null))["time"];
            Assert.IsTrue(time.StartsWith("2026-08-12T09:30:15"), time);
            Assert.IsTrue(time.EndsWith("Z"), time);
        }

        [Test]
        public void ADenialIsRecordedAsSuch()
        {
            Assert.AreEqual("deny",
                Parse(Audit.FormatRecord(When, "a", false, "m", null, null, false, "no grant permits it"))["decision"]);
        }

        [Test]
        public void AnUnidentifiedCallerStillProducesALine()
        {
            // "Nobody tried" and "somebody tried and could not say who" are different events,
            // and only one of them is interesting.
            Assert.AreEqual("<unidentified>",
                Parse(Audit.FormatRecord(When, null, false, "m", null, null, false, "no subject"))["subject"]);
            Assert.AreEqual("<unidentified>",
                Parse(Audit.FormatRecord(When, "", false, "m", null, null, false, "no subject"))["subject"]);
        }

        [Test]
        public void AbsentDetailsAreOmittedRatherThanEmpty()
        {
            JsonObject record = Parse(Audit.FormatRecord(When, "a", false, "GetAllLogins", null, null, false, null));

            Assert.IsFalse(record.Contains("target"));
            Assert.IsFalse(record.Contains("verb"));
            Assert.IsFalse(record.Contains("reason"));
        }

        [Test]
        public void EachRecordIsOneLine()
        {
            // The file is JSON Lines. A record containing a newline would split into two
            // unparseable halves, so nothing that reaches it may be multi-line.
            string line = Audit.FormatRecord(When, "agent\nwith\nnewlines", false, "m\nx", "t", "read", true,
                "reason\nwith\nnewlines");

            Assert.AreEqual(1, line.Split('\n').Length, line);
            Assert.AreEqual("agent\nwith\nnewlines", Parse(line)["subject"]);
        }

        [Test]
        public void AwkwardSubjectsSurviveTheRoundTrip()
        {
            const string awkward = "host.example:agent/one \"quoted\" \\ backslash";
            Assert.AreEqual(awkward,
                Parse(Audit.FormatRecord(When, awkward, false, "m", null, null, true, null))["subject"]);
        }

        [Test]
        public void RemotenessIsAlwaysRecorded()
        {
            // Present on every line, including when false, unlike target/verb/reason. A field
            // that appears only sometimes cannot answer "was this call from the network",
            // because a missing one would mean "local" and "older build" at the same time.
            Assert.AreEqual(true,
                Parse(Audit.FormatRecord(When, "a", true, "m", null, null, true, null))["remote"]);
            Assert.AreEqual(false,
                Parse(Audit.FormatRecord(When, "a", false, "m", null, null, true, null))["remote"]);

            Assert.IsTrue(Parse(Audit.FormatRecord(When, "a", false, "m", null, null, true, null))
                .Contains("remote"));
        }

        [Test]
        public void TheDefaultPathIsUnderLocalAppData()
        {
            string path = Audit.ResolvePath(null);
            Assert.IsTrue(path.EndsWith("audit.jsonl"), path);
            Assert.IsTrue(path.Contains("KeePassRPC"), path);
        }

        [Test]
        public void RecordingWithoutAHostIsHarmless()
        {
            // Nothing to write to, and nothing that should throw into an RPC call.
            Assert.DoesNotThrow(delegate { Audit.Record(null, "a", false, "m", null, null, false, "r"); });
        }
    }
}
