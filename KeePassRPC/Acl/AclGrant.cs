namespace KeePassRPC.Acl
{
    /// <summary>
    /// What one subject may do at one level of the inheritance chain.
    ///
    /// Immutable, because narrowing produces a new grant rather than mutating one: an
    /// accidental in-place widen partway down a chain would be a silent escalation.
    /// </summary>
    public sealed class AclGrant
    {
        private readonly AclVerb _verb;
        private readonly bool _attachments;
        private readonly bool _unattended;

        /// <summary>The grant meaning "nothing", which is also what every failure resolves to.</summary>
        public static readonly AclGrant Deny = new AclGrant(AclVerb.None, false, false);

        /// <summary>
        /// The widest grant there is: the top of the verb ladder with both flags set.
        ///
        /// Only reachable through a database set to allow by default, where it is what every
        /// subject starts from before any group narrows it. Nothing writes it into a document,
        /// and a human granting it would have to tick both flags on <c>delete</c> deliberately.
        /// </summary>
        public static readonly AclGrant Everything = new AclGrant(AclVerb.Delete, true, true);

        public AclGrant(AclVerb verb, bool attachments, bool unattended)
        {
            _verb = verb;
            _attachments = attachments;
            _unattended = unattended;
        }

        /// <summary>Where on the ladder this grant sits.</summary>
        public AclVerb Verb
        {
            get { return _verb; }
        }

        /// <summary>
        /// Whether attachment CONTENT may be reached, at the level of <see cref="Verb"/>.
        /// Separate from the verb because attachments are the highest risk payload in a
        /// database, typically private keys or whole certificate bundles, and a subject
        /// allowed to read a service password should not get the key file beside it free.
        /// </summary>
        public bool Attachments
        {
            get { return _attachments; }
        }

        /// <summary>
        /// Whether this subject is exempt from the confirmation prompt on writes, deletes and
        /// attachment reads. An opt-out from a human check, so it narrows like everything
        /// else: every level of the chain has to agree before it holds.
        /// </summary>
        public bool Unattended
        {
            get { return _unattended; }
        }

        /// <summary>Whether this grant permits <paramref name="required"/>.</summary>
        public bool Permits(AclVerb required)
        {
            return AclVerbs.Permits(_verb, required);
        }

        /// <summary>
        /// Combine with a grant from further down the chain, narrow-only.
        ///
        /// Every field takes the tighter value: the verb is the lower rung, and both flags are
        /// ANDed. That is what stops an entry marked <c>write</c> inside a <c>read</c> group
        /// from being an escalation authored further from the eye of whoever granted the group.
        ///
        /// The consequence for the flags is worth stating plainly: a child grant that simply
        /// omits <c>attachments</c> reads as false and therefore REMOVES an attachment right
        /// held above it. That is the fail-closed reading of an omission, and it means a child
        /// grant should repeat the flags it means to keep.
        /// </summary>
        public AclGrant NarrowedBy(AclGrant child)
        {
            if (child == null)
                return this;

            return new AclGrant(
                _verb <= child.Verb ? _verb : child.Verb,
                _attachments && child.Attachments,
                _unattended && child.Unattended);
        }

        /// <summary>
        /// The wider of two grants: the higher rung and both flags ORed.
        ///
        /// Used for one thing only, and it is worth being explicit about which: a client in
        /// more than one profile holds the widest of what those profiles are given, the way
        /// roles add up everywhere else. The consequence is that a <c>none</c> in one profile
        /// does not revoke what another profile grants, so taking access away means taking it
        /// out of every profile the client is in, or taking the client out of the profile.
        /// That is the same trap every additive role model has, and the alternative is worse:
        /// with narrowest-wins, adding a profile to a client could silently cut access the
        /// client already had, which makes a profile something you cannot reason about on its
        /// own.
        ///
        /// Inheritance is untouched by this. Rights still only narrow as they descend; the
        /// widening happens across a client's profiles at one level, never down a chain.
        /// </summary>
        public AclGrant WidenedBy(AclGrant other)
        {
            if (other == null)
                return this;

            return new AclGrant(
                _verb >= other.Verb ? _verb : other.Verb,
                _attachments || other.Attachments,
                _unattended || other.Unattended);
        }

        public override string ToString()
        {
            return AclVerbs.ToJsonValue(_verb)
                + (_attachments ? "+attachments" : "")
                + (_unattended ? "+unattended" : "");
        }
    }
}
