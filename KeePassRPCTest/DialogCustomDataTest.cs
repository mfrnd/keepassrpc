using System.Reflection;
using KeePass.Forms;
using KeePassLib.Collections;
using NUnit.Framework;

namespace KeePassRPCTest
{
    /// <summary>
    /// Which dictionary a grant has to be written into, per dialog.
    ///
    /// This is pinned because getting it wrong is invisible. A KeePass dialog that keeps its
    /// own copy of an object's <c>CustomData</c> writes that copy back when it is accepted, so
    /// a grant written straight to the live object survives Cancel and is destroyed by OK. The
    /// rule is on screen as the dialog closes and gone from the database, with no error
    /// anywhere. The group tab did exactly that until 2026-08-13.
    ///
    /// These are private fields of somebody else's dialogs, reached by reflection, so a
    /// KeePass update can rename them. That is the point of the test: a rename should fail
    /// here, at build time, rather than silently take the ACL editor back to losing every
    /// grant made in it.
    /// </summary>
    [TestFixture]
    public class DialogCustomDataTest
    {
        private static FieldInfo WorkingCopy(System.Type formType)
        {
            return formType.GetField("m_sdCustomData",
                BindingFlags.NonPublic | BindingFlags.Instance);
        }

        [Test]
        public void TheGroupDialogStillKeepsACopyToWriteBack()
        {
            FieldInfo field = WorkingCopy(typeof(GroupForm));
            Assert.IsNotNull(field,
                "GroupForm.m_sdCustomData is gone. The group ACL tab edits that dictionary "
                + "because the dialog overwrites the group's own CustomData on OK. Check what "
                + "this KeePass does now before changing the tab back.");
            Assert.AreEqual(typeof(StringDictionaryEx), field.FieldType);
        }

        [Test]
        public void TheEntryDialogStillKeepsOne()
        {
            // Upstream reaches this one itself, for its own entry config. Entry grants ride
            // along with it, which is why they were never affected by the group bug.
            FieldInfo field = WorkingCopy(typeof(PwEntryForm));
            Assert.IsNotNull(field, "PwEntryForm.m_sdCustomData is gone, which breaks "
                + "upstream's entry config as well as entry grants.");
            Assert.AreEqual(typeof(StringDictionaryEx), field.FieldType);
        }

        [Test]
        public void TheDatabaseDialogStillKeepsNone()
        {
            // Not a curiosity: the database tab writes to the live database precisely because
            // this dialog has nothing to write back over it. If KeePass ever adds a copy here,
            // database grants start disappearing on OK the way group grants did, and this
            // failure is the warning.
            Assert.IsNull(WorkingCopy(typeof(DatabaseSettingsForm)),
                "DatabaseSettingsForm now keeps its own copy of CustomData. The database ACL "
                + "tab must write into that copy instead of the live database, or every grant "
                + "made there will be discarded when the dialog is accepted.");
        }
    }
}
