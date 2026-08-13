using System;
using System.Collections;
using Jayrock.JsonRpc;
using Jayrock.Services;

namespace KeePassRPC.JsonRpc
{
    internal sealed class KprpcJsonRpcDispatcher : JsonRpcDispatcher
    {
        public ClientMetadata ClientMetadata;

        /// <summary>
        /// Called with a one-line description of every refusal. Set by the connection so that
        /// a denied call is visible to the person who has to decide which profile to grant;
        /// a gate whose refusals are silent is a gate nobody can configure.
        /// </summary>
        public Action<string> AuditLog;

        /// <summary>
        /// Called with (subject, method, reason) for every refusal, so the gate's decisions
        /// reach the durable audit log rather than only a debug line.
        /// </summary>
        public Action<string, string, string> AuditDenial;

        public KprpcJsonRpcDispatcher(IService service) : base(service)
        {
        }

        public override IDictionary Invoke(IDictionary request, bool authorised)
        {
            IDictionary refusal = Refuse(request, authorised);
            if (refusal != null)
                return refusal;

            var notice = Service as IJsonRpcRequestLifetimeNotice;
            if (notice != null) notice.OnStart(ClientMetadata);
            try
            {
                var response = base.Invoke(request, authorised);
                return response;
            }
            finally
            {
                if (notice != null) notice.OnEnd();
            }
        }

        /// <summary>
        /// The method gate: a per-subject allowlist, default deny, applied before the request
        /// reaches the service.
        ///
        /// This is the outer boundary of the whole access-control design, and it has to be,
        /// because v1 and v2 are otherwise unguarded: a client that simply declines to use the
        /// newer API reaches every entry in every open database. Guarding only the new API
        /// would be decorative.
        /// </summary>
        /// <returns>An error response to send instead of invoking, or null to proceed.</returns>
        private IDictionary Refuse(IDictionary request, bool authorised)
        {
            // Cases the base dispatcher already rejects, and rejects with a better message
            // than this method could produce. Falling through is not a hole: an unauthorised
            // caller raises "Not authorised." inside base.Invoke.
            if (request == null || !authorised)
                return null;

            string requestedName = request["method"] as string;
            if (string.IsNullOrEmpty(requestedName))
                return null;

            if (ClientMetadata == null)
                return Deny(request, "<unknown>", requestedName, "the request carries no client metadata");

            string subject = ClientMetadata.Subject;
            if (string.IsNullOrEmpty(subject))
                return Deny(request, "<unidentified>", requestedName,
                    "the connection has no authenticated subject");

            // Resolve the name exactly as the base dispatcher will. Jayrock tries a
            // case-sensitive lookup and then falls back to a case-insensitive one
            // (ServiceClass.FindMethodByName), so gating on the name as sent would let a
            // caller walk straight past this check by altering the case of a method it is
            // not permitted to call.
            string canonicalName = CanonicalMethodName(requestedName);
            if (canonicalName == null)
                return null; // no such method; let the base raise its own MethodNotFound

            if (MethodProfiles.IsAllowed(ClientMetadata.MethodProfile, canonicalName))
                return null;

            return Deny(request, subject, canonicalName, "no profile held by this subject grants it");
        }

        private string CanonicalMethodName(string requestedName)
        {
            IService service = Service;
            if (service == null)
                return null;

            ServiceClass serviceClass = service.GetClass();
            if (serviceClass == null)
                return null;

            Method method = serviceClass.FindMethodByName(requestedName);
            if (method == null)
                return null;

            return method.Name;
        }

        private IDictionary Deny(IDictionary request, string subject, string methodName, string reason)
        {
            if (AuditLog != null)
            {
                AuditLog("KeePassRPC method gate: denied " + methodName + " for subject '" + subject
                    + "' because " + reason + ".");
            }

            if (AuditDenial != null)
                AuditDenial(subject, methodName, reason);

            // Shaped by the base class's own error machinery, so the client receives an
            // ordinary JSON-RPC error rather than an exception unwinding into the socket
            // handler, which is what throwing here would cause.
            string message = "Method '" + methodName + "' is not permitted for this client.";
            return CreateResponse(request, null, OnError(new JsonRpcException(message), request));
        }
    }
}
