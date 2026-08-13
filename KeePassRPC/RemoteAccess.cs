using System;
using System.Net;

namespace KeePassRPC
{
    /// <summary>
    /// Whether a connection reached the plugin from beyond this machine.
    ///
    /// The plugin binds loopback and is meant to stay there. Nothing here changes that. What
    /// it supports is the deployment described in NETWORK-EXPOSURE.md, where a reverse proxy
    /// on the same host terminates mTLS and forwards to loopback: in that shape every
    /// connection arrives from 127.0.0.1 and the plugin cannot tell a remote agent from a
    /// local one by looking at the socket. It has to be told.
    ///
    /// Two signals, either of which is enough.
    ///
    /// **A peer address that is not loopback.** Definitive when it happens, which is only if
    /// someone has turned `bindOnlyToLoopback` off. Not a supported deployment, but if the
    /// plugin ever does find itself talking straight to the network it should know.
    ///
    /// **A marker in the request path**, which is the signal the proxy deployment relies on.
    /// The proxy is configured to forward to a fixed path (`proxy_pass ... /remote`), so the
    /// marker is set by the proxy and the client has no say in it. That is the property that
    /// matters: this is a statement by the operator's own infrastructure, not a claim by the
    /// caller. A local caller CAN mark itself remote by connecting to that path, which only
    /// ever costs it access, so it is not worth preventing.
    ///
    /// What this cannot do is notice a remote party who bypasses the proxy and reaches the
    /// port directly. Nothing here can: that is what `bindOnlyToLoopback` is for, and it is
    /// why the proxy deployment requires it to stay on.
    ///
    /// Matching is deliberately generous, accepting any path segment in either case after unescaping,
    /// because every error it can make is in the restrictive direction. A connection wrongly
    /// judged remote is held to a stronger crypto suite than it needed. A connection wrongly
    /// judged local is held to a weaker one across a network, and that is the mistake worth
    /// avoiding.
    /// </summary>
    public static class RemoteAccess
    {
        /// <summary>
        /// The path segment that marks a connection as remote.
        ///
        /// Fixed rather than configurable. Making it a setting bought nothing, since a proxy
        /// can always be pointed at this path, and cost something real: the proxy and the plugin
        /// have to agree, and if they do not the connection is silently treated as local,
        /// which is the permissive direction. One less thing to get wrong.
        /// </summary>
        public const string Marker = "remote";

        /// <summary>
        /// Decide whether a connection is remote.
        /// </summary>
        /// <param name="clientIpAddress">The peer address, as the socket reports it.</param>
        /// <param name="path">The request path from the WebSocket handshake.</param>
        public static bool IsRemote(string clientIpAddress, string path)
        {
            if (!IsLoopbackAddress(clientIpAddress))
                return true;

            return PathIsMarked(path);
        }

        /// <summary>
        /// Whether the request path carries the marker in any of its segments.
        /// </summary>
        public static bool PathIsMarked(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            string candidate = StripQuery(path);

            string decoded;
            try
            {
                candidate = Uri.UnescapeDataString(candidate);
                decoded = candidate;
            }
            catch (Exception)
            {
                // A path that will not unescape is malformed, and this method's job is to
                // answer restrictively when it cannot answer confidently.
                return true;
            }

            foreach (string segment in decoded.Split('/'))
            {
                if (string.Equals(segment.Trim(), Marker, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Whether the peer is on this machine. Anything unparseable or absent counts as not
        /// loopback, because "we do not know where this came from" is not a reason to relax.
        /// </summary>
        public static bool IsLoopbackAddress(string clientIpAddress)
        {
            if (string.IsNullOrEmpty(clientIpAddress))
                return false;

            IPAddress parsed;
            if (!IPAddress.TryParse(clientIpAddress.Trim(), out parsed))
                return false;

            if (IPAddress.IsLoopback(parsed))
                return true;

            // A dual-stack listener reports IPv4 peers as ::ffff:127.0.0.1, which
            // IPAddress.IsLoopback does not recognise on its own.
            try
            {
                if (parsed.IsIPv4MappedToIPv6)
                    return IPAddress.IsLoopback(parsed.MapToIPv4());
            }
            catch (Exception)
            {
                return false;
            }

            return false;
        }

        private static string StripQuery(string path)
        {
            int cut = path.IndexOfAny(new[] { '?', '#' });
            return cut < 0 ? path : path.Substring(0, cut);
        }
    }
}
