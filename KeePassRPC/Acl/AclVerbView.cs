using System;
using System.Collections.Generic;

namespace KeePassRPC.Acl
{
    /// <summary>
    /// How a stored rule is shown, which depends on which way round the database reads.
    ///
    /// **A rule is always stored as an allowance.** The verb in a document is the most a
    /// profile may do, everywhere, in both modes, and nothing in the resolver knows about any
    /// other form. One representation means one set of combination rules: rights narrow as
    /// they descend and widen across a client's profiles, and that stays true however the
    /// table is labelled.
    ///
    /// What changes is the label. On a database that denies by default, a rule is a permission
    /// and the column says "Allow". On one that allows by default, the same rule is a
    /// restriction and the column says "Deny", showing the same fact from the other side. A
    /// column headed "Allow" on a database where every rule is a restriction is a column that
    /// tells the reader the opposite of what is happening.
    ///
    /// The two readings are exact opposites of each other, not approximations:
    ///
    /// <code>
    /// allow list    permits none and list        =  deny read     forbids read, write, delete
    /// allow read    permits up to read           =  deny write    forbids write and delete
    /// allow write   permits up to write          =  deny delete   forbids delete
    /// allow delete  permits everything           =  deny nothing
    /// allow none    permits nothing              =  deny list     forbids list and everything above
    /// </code>
    ///
    /// An allowance names the strongest verb permitted and carries everything weaker with it; a
    /// denial names the weakest verb forbidden and carries everything stronger. So a denial is
    /// the allowance one rung below it, and the ladder needs one extra word at the top for
    /// "nothing is denied", which is the whole of it.
    /// </summary>
    public static class AclVerbView
    {
        /// <summary>The denial that forbids nothing, which is the same as allowing everything.</summary>
        public const string DeniesNothing = "nothing";

        /// <summary>The ladder, weakest first. The order the pick list is offered in.</summary>
        private static readonly AclVerb[] Ladder = new[]
        {
            AclVerb.None, AclVerb.List, AclVerb.Read, AclVerb.Write, AclVerb.Delete
        };

        /// <summary>What the column is called on a database in this mode.</summary>
        public static string Header(AclDefault mode)
        {
            return mode == AclDefault.Allow ? "Deny" : "Allow";
        }

        /// <summary>
        /// What the column means, for its header tooltip. Said in the same direction as the
        /// header, because a reader checking what a column does has just read the header.
        /// </summary>
        public static string Explanation(AclDefault mode)
        {
            return mode == AclDefault.Allow
                ? "The weakest thing this profile may NOT do here, and everything stronger is "
                    + "refused with it. This database allows by default, so a rule takes access "
                    + "away. 'nothing' takes nothing away."
                : "The most this profile may do here, and everything weaker comes with it. This "
                    + "database denies by default, so a rule grants access. 'none' grants "
                    + "nothing and revokes what a wider rule allows.";
        }

        /// <summary>
        /// The values to offer, in the order they are offered, tightest first so the list does
        /// not lead with the answer that grants the most.
        /// </summary>
        public static IList<string> Items(AclDefault mode)
        {
            List<string> items = new List<string>();
            foreach (AclVerb verb in Ladder)
                items.Add(Text(verb, mode));

            return items;
        }

        /// <summary>How a stored allowance reads in this mode.</summary>
        public static string Text(AclVerb allowed, AclDefault mode)
        {
            if (mode != AclDefault.Allow)
                return AclVerbs.ToJsonValue(allowed);

            int index = IndexOf(allowed);
            if (index < 0 || index + 1 >= Ladder.Length)
                return DeniesNothing;

            return AclVerbs.ToJsonValue(Ladder[index + 1]);
        }

        /// <summary>
        /// Read a value back into the allowance it stands for.
        ///
        /// Refuses anything it does not recognise rather than guessing, the same as every other
        /// parse here: a rule nobody can read is not a rule to interpret generously.
        /// </summary>
        public static bool TryParse(string text, AclDefault mode, out AclVerb allowed)
        {
            allowed = AclVerb.None;
            if (text == null)
                return false;

            string trimmed = text.Trim();

            if (mode != AclDefault.Allow)
                return AclVerbs.TryParse(trimmed, out allowed);

            if (string.Equals(trimmed, DeniesNothing, StringComparison.OrdinalIgnoreCase))
            {
                allowed = AclVerb.Delete;
                return true;
            }

            AclVerb denied;
            if (!AclVerbs.TryParse(trimmed, out denied))
                return false;

            int index = IndexOf(denied);
            if (index <= 0)
                return false; // "deny none" is not a thing: nothing is weaker to allow

            allowed = Ladder[index - 1];
            return true;
        }

        /// <summary>A grant as a phrase, for a message that has to name what a rule amounts to.</summary>
        public static string Describe(AclGrant grant, AclDefault mode)
        {
            if (grant == null)
                return string.Empty;

            return Text(grant.Verb, mode)
                + (grant.Attachments ? "+attachments" : string.Empty)
                + (grant.Unattended ? "+unattended" : string.Empty);
        }

        private static int IndexOf(AclVerb verb)
        {
            for (int i = 0; i < Ladder.Length; i++)
            {
                if (Ladder[i] == verb)
                    return i;
            }

            return -1;
        }
    }
}
