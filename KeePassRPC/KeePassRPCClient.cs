using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Xml.Serialization;
using Fleck2.Interfaces;
using Jayrock.Json;
using Jayrock.Json.Conversion;
using Jayrock.JsonRpc;
using KeePassLib.Utility;
using KeePassRPC.Forms;
using KeePassRPC.JsonRpc;
using KeePassRPC.Models.DataExchange;

namespace KeePassRPC
{
    /// <summary>
    /// Represents a client that has connected to this RPC server.
    /// </summary>
    public class KeePassRPCClientConnection
    {
        // wanted to use uint really but that seems to break Jayrock JSON-RPC - presumably because there is no such concept in JavaScript
        static private int _protocolVersion;

        private static int ProtocolVersion { get {
            if (_protocolVersion == 0)
            {
                _protocolVersion = BitConverter.ToInt32(new byte[] {
                    (byte)KeePassRPCExt.PluginVersion.Build,
                    (byte)KeePassRPCExt.PluginVersion.Minor,
                    (byte)KeePassRPCExt.PluginVersion.Major,0},0);
            }
            return _protocolVersion;
        } }
        
        private static string[] featuresOffered = {

            // Full feature set as of KeeFox 1.6
            "KPRPC_FEATURE_VERSION_1_6",

            // Allow clients without the name KeeFox to connect
            "KPRPC_GENERAL_CLIENTS",

            // Renamed KeeFox to Kee
            "KPRPC_FEATURE_KEE_BRAND",

            // GetAllEntries or GetAllChildEntries can be used to 
            // include results even if they have no URL
            "KPRPC_ENTRIES_WITH_NO_URL",

            // Form fields with no configured name or ID will output an empty value
            // Before this feature, default name and IDs were used ("username" and "password")
            "KPRPC_FIELD_DEFAULT_NAME_AND_ID_EMPTY",

            // OpenAndFocusDatabase can focus KeePass with a database, opening it first if required
            "KPRPC_OPEN_AND_FOCUS_DATABASE",

            // Allow replacement of all URLs during entry update
            "KPRPC_FEATURE_ENTRY_URL_REPLACEMENT",

            // Contains critical security fixes
            "KPRPC_SECURITY_FIX_20200729",

            // Can send new DTO format
            "KPRPC_FEATURE_DTO_V2",

            // Ephemeral per-session keys, HMAC-SHA256 and replay protection. Offered to
            // everyone, used only by clients that declare it; see CryptoV2.
            "KPRPC_FEATURE_CRYPTO_V2",

            // Pairing can run in the 2048-bit RFC 5054 group instead of upstream's 512-bit
            // one. Offered to everyone, used only by clients that declare it; see SrpGroup.
            SrpGroup.StrongGroupFeatureName,

            // Full-entry API: real custom strings, notes and attachments, behind the ACL.
            // Offered to every client, but a client only reaches it if its subject holds a
            // profile granting the V3 methods, and then only for entries the ACL allows.
            "KPRPC_FEATURE_DTO_V3"

            // in the rare event that we want to check for the absense of a feature
            // we would add a feature flag along the lines of "KPRPC_FEATURE_REMOVED_INCOMPATIBLE_THING_X"

        };

        private static string[] featuresRequired = {

            // Full feature set as of KeeFox 1.6
            "KPRPC_FEATURE_VERSION_1_6",

            // Trivial example showing how we've required a new client feature
            "KPRPC_FEATURE_WARN_USER_WHEN_FEATURE_MISSING"

        };

        /// <summary>
        /// The ID of the next signal we'll send to the client
        /// </summary>
        private int _currentCallBackId;
        private bool _authorised;
        private IWebSocketConnection _webSocketConnection;
        private SRP _srp;
        private KeyChallengeResponse _kcp;
        private int securityLevel;
        private int securityLevelClientMinimum;
        private string userName;
        private string[] _clientFeatures;
        private readonly bool _isRemote;

        // Set once the newer session crypto has been negotiated and agreed. Null means the
        // original suite, which is what every legacy client keeps using.
        private byte[] _sessionKey;
        private long _expectedClientSequence = 1;
        private long _nextServerSequence = 1;

        // Read-only username is accessible to anyone but only once the connection has been confirmed
        public string UserName { get
        {
            if (Authorised) return userName;
            return "";
        } }

        private KeyChallengeResponse Kcp
        {
            get { return _kcp; }
            set { _kcp = value; }
        }

        private AuthForm _authForm;
        private KeePassRPCExt KPRPC;
        
        /// <summary>
        /// The underlying web socket connection that links us to this client.
        /// </summary>
        public IWebSocketConnection WebSocketConnection
        {
            get { return _webSocketConnection; }
            private set { _webSocketConnection = value; }
        }
        
        /// <summary>
        /// Whether this client has successfully authenticated to the
        /// server and been authorised to communicate with KeePass
        /// </summary>
        public bool Authorised
        {
            get { return _authorised; }
            set { _authorised = value; }
        }
        
        /// <summary>
        /// The features this client claims to support
        /// </summary>
        public string[] ClientFeatures
        {
            get { return _clientFeatures; }
        }

        /// <summary>
        /// Whether this connection reached the plugin from beyond this machine. Decided by
        /// <see cref="RemoteAccess"/> when the socket opened, and read-only thereafter: it is
        /// a property of where the connection came from, not of anything the client says.
        /// </summary>
        public bool IsRemote
        {
            get { return _isRemote; }
        }


        private long KeyExpirySeconds
        {
            get
            {
                // read from config file
                return KPRPC._host.CustomConfig.GetLong("KeePassRPC.AuthorisationExpiryTime", 31536000);
            }
        }

        /// <summary>
        /// The method profiles this subject holds, as a comma-separated spec. Read fresh for
        /// every request, so narrowing a profile takes effect on the next call rather than at
        /// the next restart, and revoking one does not wait for a client to reconnect.
        ///
        /// A subject with no entry of its own gets <c>none</c>, which is what makes a newly
        /// paired client useless until a human grants it something.
        ///
        /// There is no configurable fallback. There was one, so that arriving on a KeePass
        /// with clients already paired did not deny all of them at once, and it has been
        /// replaced by <see cref="LegacyClients"/>, which does that job once and writes a real
        /// setting per client. A fallback that outlives the migration it was for is a control
        /// that can hand every future client the whole database, and a client that reads as
        /// refused on the Authorised clients tab while the gate quietly allows it is worse
        /// than either state on its own.
        /// </summary>
        private string MethodProfile
        {
            get
            {
                string subject = UserName;
                if (string.IsNullOrEmpty(subject))
                    return MethodProfiles.None;

                return KPRPC._host.CustomConfig.GetString(
                    "KeePassRPC.Profile." + subject, MethodProfiles.None);
            }
        }

        /// <summary>
        /// The secret key used to encrypt messages
        /// </summary>
        private KeyContainerClass KeyContainer
        {
            get {
                if (_keyContainer == null)
                {
                    // if we're already authorised to communicate but do not have the key yet, we know it's waiting for us in the recently authenticated SRP object
                    if (Authorised)
                    {
                        _keyContainer = new KeyContainerClass(_srp.Key, DateTime.UtcNow.AddSeconds(KeyExpirySeconds), userName, clientName);
                    }
                        // otherwise we know that the key is going to be stored according to spec (if not we'll return a null key to trigger a fresh SRP auth process)
                    else
                    {
                        byte[] serialisedKeyContainer = null;

                        // check security level and find key in appropriate place
                        if (securityLevel == 1)
                        {
                            // read from config file
                            string serialisedKeyContainerString = KPRPC._host.CustomConfig.GetString("KeePassRPC.Key." + userName, "");
                            if (string.IsNullOrEmpty(serialisedKeyContainerString))
                                return null;
                            serialisedKeyContainer = Convert.FromBase64String(serialisedKeyContainerString);
                        }
                        else if (securityLevel == 2)
                        {
                            // read from encrypted config file
                            string secret = KPRPC._host.CustomConfig.GetString("KeePassRPC.Key." + userName, "");
                            if (string.IsNullOrEmpty(secret))
                                return null;
                            try
                            {
                                byte[] keyBytes = ProtectedData.Unprotect(
                                Convert.FromBase64String(secret),
                                new byte[] { 172, 218, 37, 36, 15 },
                                DataProtectionScope.CurrentUser);
                                serialisedKeyContainer = keyBytes;
                            }
                            catch (Exception)
                            {
                                // This can happen if user changes from medium security to low security
                                // and maybe other operating system / .NET failures
                                return null;
                            }
                        }
                        else
                            return null;

                        if (serialisedKeyContainer == null)
                            return null;
                        try
                        {
                            XmlSerializer mySerializer = new XmlSerializer(typeof(KeyContainerClass));
                            using (MemoryStream ms = new MemoryStream(serialisedKeyContainer))
                            {
                                KeyContainerClass keyContainer = (KeyContainerClass) mySerializer.Deserialize(ms);
                                    
                                // A serialised key equal to sha256('0') suggests previous successful exploit of CVE-2020-16271
                                if (keyContainer == null || 
                                    keyContainer.Key == "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9")
                                {
                                    Utils.ShowMonoSafeMessageBox(@"Your KeePass instance may have previously been exploited by a malicious attacker.

The passwords contained within any databases that were open before this point may have been exposed so you should change them.

See https://forum.kee.pm/t/3143/ for more information.",
                                        "WARNING!",
                                        MessageBoxButtons.OK, 
                                        MessageBoxIcon.Warning);
                                    return null;
                                }

                                _keyContainer = keyContainer;
                            }
                        }
                        catch (Exception)
                        {
                            return null;
                        }
                    }
                }
                return _keyContainer;
            }
            set
            {
                _keyContainer = value;

                KeyContainerClass kc = new KeyContainerClass(_srp.Key, DateTime.UtcNow.AddSeconds(KeyExpirySeconds),
                    userName, clientName);

                XmlSerializer mySerializer = new
                    XmlSerializer(typeof(KeyContainerClass));
                byte[] serialisedKeyContainer;
                using (MemoryStream myWriter = new MemoryStream())
                {
                    mySerializer.Serialize(myWriter, kc);
                    serialisedKeyContainer = myWriter.ToArray();
                }

                // We probably want to store the key somewhere that will persist beyond an application restart
            if (securityLevel == 1)
                {
                    // Store unencrypted in config file
                    KPRPC._host.CustomConfig.SetString("KeePassRPC.Key." + userName, Convert.ToBase64String(serialisedKeyContainer));
                    KPRPC._host.MainWindow.Invoke((MethodInvoker)delegate { KPRPC._host.MainWindow.SaveConfig(); });
                }
                else if (securityLevel == 2)
                {
                    try
                    {
                        // Encrypt the data using DataProtectionScope.CurrentUser. The result can be decrypted 
                        //  only by the same current user. 

                        byte[] secret = ProtectedData.Protect(
                            serialisedKeyContainer,
                            new byte[] { 172, 218, 37, 36, 15 },
                            DataProtectionScope.CurrentUser);

                        KPRPC._host.CustomConfig.SetString("KeePassRPC.Key." + userName, Convert.ToBase64String(secret));
                        KPRPC._host.MainWindow.Invoke((MethodInvoker)delegate { KPRPC._host.MainWindow.SaveConfig(); });
                    }
                    catch (CryptographicException e)
                    {
                        if (KPRPC.logger != null) KPRPC.logger.WriteLine("Could not store KeePassRPC's secret key so you will have to re-authenticate clients such as Kee in your web browser. The following exception caused this problem: " + e);
                    }
                }
                // else we don't persist the key anywhere - no security implications
                // of this fallback behaviour but it will be annoying for the user
            }
        }

        private KeyContainerClass _keyContainer;
        private string clientName;
        
        public KeePassRPCClientConnection(IWebSocketConnection connection, bool isAuthorised, KeePassRPCExt kprpc,
            bool isRemote)
        {
            WebSocketConnection = connection;
            Authorised = isAuthorised;
            _isRemote = isRemote;

            //TODO2: Can we lazy load these since some sessions will require only one of these authentication mechanisms?
            _srp = new SRP();
            Kcp = new KeyChallengeResponse(ProtocolVersion, featuresOffered);

            // Load from config, default to medium security if user has not yet requested anything different
            securityLevel = (int)kprpc._host.CustomConfig.GetLong("KeePassRPC.SecurityLevel", 2);
            securityLevelClientMinimum = (int)kprpc._host.CustomConfig.GetLong("KeePassRPC.SecurityLevelClientMinimum", 2);
            KPRPC = kprpc;
        }

        /// <summary>
        /// Sends the specified signal to the client.
        /// </summary>
        /// <param name="signal">The signal.</param>
        public void Signal(Signal signal, string methodName)
        {
            // User may not have authorised the connection we are trying to signal
            if (KeyContainer == null) return;

            try
            {
                JsonObject call = new JsonObject();
                call["id"] = ++_currentCallBackId;
                call["method"] = methodName;
                call["params"] = new[] { (int)signal };

                StringBuilder sb = new StringBuilder();
                JsonConvert.Export(call, sb);
                KPRPCMessage data2client = new KPRPCMessage();
                data2client.protocol = "jsonrpc";
                data2client.version = ProtocolVersion;
                data2client.jsonrpc = Encrypt(sb.ToString());

                // If there was a problem encrypting our message, just abort - the
                // client won't be able to do anything useful with an error message
                if (data2client.jsonrpc == null)
                {
                    if (KPRPC.logger != null) KPRPC.logger.WriteLine("Encryption error when trying to send signal: " + signal);
                    return;
                }

                // Signalling through the websocket needs to be processed on a different thread becuase handling the incoming messages results in a lock on the list of known connections (which also happens before this Signal function is called) so we want to process this as quickly as possible and avoid deadlocks.
                
                // Respond to each message on a different thread
                ThreadStart work = delegate
                {
                    WebSocketConnection.Send(JsonConvert.ExportToString(data2client));
                };
                Thread messageHandler = new Thread(work);
                messageHandler.Name = "signalDispatcher";
                messageHandler.Start();
            }
            catch (IOException)
            {
                // Sometimes a connection is unexpectedly closed e.g. by Firefox
                // or (more likely) dodgy security "protection". From one year's
                // worth of bug reports (35) 100% of unexpected application
                // exceptions were IOExceptions.
                //
                // We will now ignore this type of exception and allow the client to
                // re-establish the link to KeePass as part of its regular polling loop.
                //
                // The requested KPRPC signal will never be recieved by the client
                // but this should be OK in practice becuase the client will 
                // re-establish the relevant state information as soon as it reconnects.
                //
                // BUT: the exception to this rule is when the client fails to receive the
                // "shutdown" signal - it then gets itself in an inconsistent state
                // and has no opportunity to recover until KeePass is running again.
            }
            catch (Exception ex)
            {
                Utils.ShowMonoSafeMessageBox("ERROR! Please click on this box, press CTRL-C on your keyboard and paste into a new post on the Kee forum (https://forum.kee.pm). Doing this will help other people to use Kee without any unexpected error messages like this. Please briefly describe what you were doing when the problem occurred, which version of Kee, KeePass and web browser you use and what other security software you run on your machine. Thanks! Technical detail follows: " + ex);
            }
        }

        public void ReceiveMessage(string message, KeePassRPCService service)
        {
            // Inspect incoming message
            KPRPCMessage kprpcm;

            try
            {
                kprpcm = (KPRPCMessage)JsonConvert.Import(typeof(KPRPCMessage), message);
            }
            catch (Exception )
            {
                kprpcm = null;
            }

            if (kprpcm == null)
            {
                KPRPCMessage data2client = new KPRPCMessage();
                data2client.protocol = "error";
                data2client.srp = new SRPParams();
                data2client.version = ProtocolVersion;

                data2client.error = new Error(ErrorCode.INVALID_MESSAGE, new[] { "Contents can't be interpreted as an SRPEncapsulatedMessage" });

                AbortWithMessageToClient(data2client);
                return;
            }
            
            // store supplied features until connection reset so we don't have to inject
            // them into every stage of the handshake but can still cleanly handle old 
            // versions of clients that don't send a list of features at any time.
            // Changing features mid-connection seems odd and might be an attack vector
            // so we don't allow that.
            if (kprpcm.features != null && _clientFeatures == null)
            {
                _clientFeatures = kprpcm.features;
            }

            // Assume that a matching client and server protocol version mean that the client supports the required features
            if (kprpcm.version != ProtocolVersion)
            {
                if (!ClientSupportsRequiredFeatures())
                {
                    RejectClientVersion(kprpcm);
                    return;
                }
            }

            if (IsRemote)
            {
                string missing = MissingRemoteRequirement(kprpcm);
                if (missing != null)
                {
                    RefuseRemoteMissingFeature(missing);
                    return;
                }
            }

            switch (kprpcm.protocol)
            {
                case "setup": KPRPCReceiveSetup(kprpcm); break;
                case "jsonrpc": KPRPCReceiveJSONRPC(kprpcm.jsonrpc, service); break;
                default: KPRPCMessage data2client = new KPRPCMessage();
                    data2client.protocol = "error";
                    data2client.srp = new SRPParams();
                    data2client.version = ProtocolVersion;

                    data2client.error = new Error(ErrorCode.UNRECOGNISED_PROTOCOL, new[] { "Use setup or jsonrpc" });

                    AbortWithMessageToClient(data2client);
                    return;
            }

        }

        /// <summary>Whether this client asked for the newer session crypto.</summary>
        private bool ClientWantsCryptoV2()
        {
            return _clientFeatures != null && Array.IndexOf(_clientFeatures, CryptoV2.FeatureName) >= 0;
        }

        /// <summary>Whether this message is an attempt to pair, rather than to reconnect.</summary>
        private static bool IsPairingAttempt(KPRPCMessage kprpcm)
        {
            // Mirrors how KPRPCReceiveSetup tells the two apart: an srp block means SRP
            // pairing, a key block means a key challenge against a key agreed earlier.
            return kprpcm.protocol == "setup" && kprpcm.srp != null;
        }

        /// <summary>
        /// The feature a remote connection has to declare and has not, or null if it meets
        /// every requirement. Local connections are never asked any of this.
        ///
        /// **The session suite.** The original one derives a single key from the paired
        /// secret and keeps it for the life of the pairing, authenticates with a construction
        /// that is not an HMAC, and numbers nothing, so a recorded message can be replayed at
        /// will. That was survivable while the only party who could reach the socket could
        /// also read the key off disk, which is why it is still offered to local clients
        /// unchanged, because Kee depends on it byte for byte. None of it survives a network.
        ///
        /// Checked twice, because a claim and a fact are different things. During the
        /// handshake the declared feature is all there is to go on. Once actual calls start
        /// the session key is the evidence: a client that declared the feature and then did
        /// not complete the key agreement, by omitting its public key or by failing it, would
        /// otherwise fall through to the legacy path and be talking across a network under a
        /// static key.
        ///
        /// **The SRP group.** Pairing may happen remotely, a decision taken deliberately and
        /// recorded in NETWORK-EXPOSURE.md, and a remote pairing is the one case where somebody
        /// could plausibly watch the exchange. A 512-bit discrete log is within reach of a
        /// determined attacker, and solving one yields the paired key, which authenticates
        /// everything afterwards including the negotiated suite's own key agreement. So a
        /// remote pairing must run in the 2048-bit group.
        ///
        /// Asked only of a connection that is actually pairing. A key challenge proves
        /// possession of a key agreed earlier and never touches N, so refusing a reconnect
        /// over a group it does not use would be a rule about the wrong thing.
        ///
        /// Note what this deliberately does not do: it does not record which group a key was
        /// paired in, so a key from an older 512-bit pairing still reconnects remotely. Those
        /// pairings happened over loopback, where the exchange could not be observed, so the
        /// group did not weaken the key they produced. From here on no remote pairing
        /// can produce one at all.
        /// </summary>
        private string MissingRemoteRequirement(KPRPCMessage kprpcm)
        {
            if (!ClientWantsCryptoV2())
                return CryptoV2.FeatureName;

            if (kprpcm.protocol == "jsonrpc" && _sessionKey == null)
                return CryptoV2.FeatureName;

            if (IsPairingAttempt(kprpcm) && SrpGroup.ForFeatures(_clientFeatures) != SrpGroup.Rfc5054_2048)
                return SrpGroup.StrongGroupFeatureName;

            return null;
        }

        private void RefuseRemoteMissingFeature(string featureName)
        {
            KPRPCMessage data2client = new KPRPCMessage();
            data2client.protocol = "error";
            data2client.srp = new SRPParams();
            data2client.version = ProtocolVersion;

            // One code for both requirements, with the missing feature as the parameter, so
            // a client is told exactly what to declare rather than left to guess which of
            // them it fell short of.
            data2client.error = new Error(ErrorCode.AUTH_CRYPTO_TOO_WEAK, new[] { featureName });

            if (KPRPC.logger != null)
                KPRPC.logger.WriteLine("Refused a remote connection that is not using " + featureName + ".");

            // Worth a durable line rather than only a debug one: a remote client failing this
            // is either misconfigured or is an attempt to negotiate weaker crypto from a
            // network, and the two look identical from here.
            Audit.Record(KPRPC._host, UserName, true, "<connection>", null, null, false,
                "remote connections must use " + featureName);

            AbortWithMessageToClient(data2client);
        }

        /// <summary>
        /// Complete the ephemeral key agreement, if the client offered one and asked for the
        /// newer suite. Returns what to send back, or null to leave the reply unchanged.
        ///
        /// Authenticated by <paramref name="pairedKeyHex"/>: the session key is derived from
        /// that as well as the agreed secret, so a party without it cannot reach the same key
        /// and every subsequent message from it fails authentication.
        /// </summary>
        private CryptoParams NegotiateCryptoV2(CryptoParams offered, string pairedKeyHex)
        {
            if (offered == null || string.IsNullOrEmpty(offered.cpub) || !ClientWantsCryptoV2())
                return null;

            try
            {
                byte[] clientPublic = Convert.FromBase64String(offered.cpub);
                using (CryptoV2.Exchange exchange = CryptoV2.BeginExchange())
                {
                    byte[] serverPublic = exchange.PublicKey;
                    byte[] agreed = exchange.AgreeWith(clientPublic);
                    byte[] pairedKey = MemUtil.HexStringToByteArray(pairedKeyHex);

                    _sessionKey = CryptoV2.DeriveSessionKey(pairedKey, clientPublic, serverPublic, agreed);
                    _expectedClientSequence = 1;
                    _nextServerSequence = 1;

                    CryptoParams reply = new CryptoParams();
                    reply.spub = Convert.ToBase64String(serverPublic);
                    reply.proof = Convert.ToBase64String(
                        CryptoV2.KexConfirmation(_sessionKey, clientPublic, serverPublic));
                    return reply;
                }
            }
            catch (Exception ex)
            {
                // Fail back to nothing rather than to the older suite. A client that asked for
                // the stronger one and did not get it must not be silently downgraded: it
                // would carry on believing it had forward secrecy.
                _sessionKey = null;
                if (KPRPC.logger != null) KPRPC.logger.WriteLine("CryptoV2 key agreement failed: " + ex.Message);
                throw new Exception("Key agreement failed");
            }
        }

        private bool ClientSupportsRequiredFeatures()
        {
            return _clientFeatures != null && !featuresRequired.Except(_clientFeatures).Any();
        }

        private void RejectClientVersion(KPRPCMessage kprpcm)
        {
            KPRPCMessage data2client = new KPRPCMessage();
            data2client.protocol = "error";
            data2client.srp = new SRPParams();
            data2client.version = ProtocolVersion;

            // From 1.7 onwards, the client can never be too new but can be too low if we find that it is missing essential features
            data2client.error = new Error(ErrorCode.VERSION_CLIENT_TOO_LOW, new[] { ProtocolVersion.ToString() });
            AbortWithMessageToClient(data2client);
        }

        private void AbortWithMessageToClient(KPRPCMessage data2client)
        {
            Authorised = false;
            _clientFeatures = null;
            string response = JsonConvert.ExportToString(data2client);
            WebSocketConnection.Send(response);
        }

        private void KPRPCReceiveSetup (KPRPCMessage kprpcm) {

            if (Authorised)
            {
                KPRPCMessage data2client = new KPRPCMessage();
                data2client.protocol = "setup";
                data2client.srp = new SRPParams();
                data2client.version = ProtocolVersion;

                data2client.error = new Error(ErrorCode.AUTH_RESTART, new[] { "Already authorised" });

                AbortWithMessageToClient(data2client);
                return;
            }

            if (kprpcm.srp != null)
            {
                KPRPCMessage data2client = new KPRPCMessage();
                data2client.protocol = "setup";
                data2client.version = ProtocolVersion;

                int clientSecurityLevel = kprpcm.srp.securityLevel;

                if (clientSecurityLevel < securityLevelClientMinimum)
                {
                    data2client.error = new Error(ErrorCode.AUTH_CLIENT_SECURITY_LEVEL_TOO_LOW, new[] { securityLevelClientMinimum.ToString() });
                    /* TODO1.3: need to disconnect/delete/reset this connection once we've decided we are not interested in letting the client connect. Maybe 
                     * tie in to finding a way to abort if user clicks a "cancel" button on the auth form.
                     */
                    WebSocketConnection.Send(JsonConvert.ExportToString(data2client));
                }
                else
                {
                    switch (kprpcm.srp.stage)
                    {
                        case "identifyToServer": WebSocketConnection.Send(SRPIdentifyToServer(kprpcm)); break;
                        case "proofToServer": WebSocketConnection.Send(SRPProofToServer(kprpcm)); break;
                        default: return;
                    }
                }
            }
            else
            {
                KPRPCMessage data2client = new KPRPCMessage();
                data2client.protocol = "setup";
                data2client.version = ProtocolVersion;

                int clientSecurityLevel = kprpcm.key.securityLevel;

                if (clientSecurityLevel < securityLevelClientMinimum)
                {
                    data2client.error = new Error(ErrorCode.AUTH_CLIENT_SECURITY_LEVEL_TOO_LOW, new[] { securityLevelClientMinimum.ToString() });
                    /* TODO1.3: need to disconnect/delete/reset this connection once we've decided we are not interested in letting the client connect. Maybe 
                     * tie in to finding a way to abort if user clicks a "cancel" button on the auth form.
                     */
                    WebSocketConnection.Send(JsonConvert.ExportToString(data2client));
                }
                else
                {
                    if (!string.IsNullOrEmpty(kprpcm.key.username))
                    {
                        // confirm username
                        userName = kprpcm.key.username;
                        KeyContainerClass kc = KeyContainer;

                        if (kc == null)
                        {
                            userName = null;
                            data2client.error = new Error(ErrorCode.AUTH_FAILED, new[] { "Stored key not found - Caused by changed Firefox profile or KeePass instance; changed OS user credentials; or KeePass config file may be corrupt" });
                            /* TODO1.3: need to disconnect/delete/reset this connection once we've decided we are not interested in letting the client connect. Maybe 
                             * tie in to finding a way to abort if user clicks a "cancel" button on the auth form.
                             */
                            WebSocketConnection.Send(JsonConvert.ExportToString(data2client));
                            return;
                        } 
                        if (kc.Username != userName)
                        {
                            userName = null;
                            data2client.error = new Error(ErrorCode.AUTH_FAILED, new[] { "Username mismatch - KeePass config file is probably corrupt" });
                            /* TODO1.3: need to disconnect/delete/reset this connection once we've decided we are not interested in letting the client connect. Maybe 
                             * tie in to finding a way to abort if user clicks a "cancel" button on the auth form.
                             */
                            WebSocketConnection.Send(JsonConvert.ExportToString(data2client));
                            return;
                        }
                        if (kc.AuthExpires < DateTime.UtcNow)
                        {
                            userName = null;
                            data2client.error = new Error(ErrorCode.AUTH_EXPIRED);
                            /* TODO1.3: need to disconnect/delete/reset this connection once we've decided we are not interested in letting the client connect. Maybe 
                             * tie in to finding a way to abort if user clicks a "cancel" button on the auth form.
                             */
                            WebSocketConnection.Send(JsonConvert.ExportToString(data2client));
                            return;
                        }

                        WebSocketConnection.Send(Kcp.KeyChallengeResponse1(userName, securityLevel));
                    }
                    else if (!string.IsNullOrEmpty(kprpcm.key.cc) && !string.IsNullOrEmpty(kprpcm.key.cr))
                    {
                        bool authorised = false;
                        string kcrResponse = Kcp.KeyChallengeResponse2(kprpcm.key.cc, kprpcm.key.cr, KeyContainer, securityLevel, out authorised);

                        // Same reasoning as the pairing path: the agreement travels with the
                        // message that completes authentication. Only once the challenge has
                        // actually succeeded, so an unauthenticated peer never gets a key.
                        if (authorised)
                        {
                            CryptoParams agreed = NegotiateCryptoV2(kprpcm.crypto, KeyContainer.Key);
                            if (agreed != null)
                            {
                                KPRPCMessage withCrypto =
                                    (KPRPCMessage)JsonConvert.Import(typeof(KPRPCMessage), kcrResponse);
                                withCrypto.crypto = agreed;
                                kcrResponse = JsonConvert.ExportToString(withCrypto);
                            }
                        }

                        WebSocketConnection.Send(kcrResponse);
                        Authorised = authorised;
                        if (authorised)
                        {
                            // We assume the user has manually verified the client name as part of the initial SRP setup so it's fairly safe to use it to determine the type of client connection to which we want to promote our null connection
                            KPRPC.PromoteGeneralRPCClient(this, KeyContainer.ClientName);
                            // Backfill: a subject paired before this fork existed becomes
                            // offerable the first time it reconnects, without waiting for it
                            // to be paired again.
                            SubjectRegistry.Remember(KPRPC._host, userName);
                        }
                    }
                }
            }

  	    }

        private string SRPIdentifyToServer (KPRPCMessage srpem)
        {
            SRPParams srp = srpem.srp;
            Error error;
            KPRPCMessage data2client = new KPRPCMessage();
            data2client.protocol = "setup";
            data2client.srp = new SRPParams();
            data2client.srp.stage = "identifyToClient";
            data2client.version = ProtocolVersion;
            data2client.features = featuresOffered;

            // Settle the group before computing anything in it. The client has already
            // calculated its public value A in whichever group its own features asked for,
            // and every quantity from here on is relative to N, so this cannot be deferred
            // and cannot change later. Replaces the instance built in the constructor,
            // which predates knowing anything about the client.
            _srp = new SRP(SrpGroup.ForFeatures(_clientFeatures));

            // Generate a new random password
            // SRP isn't very susceptible to brute force attacks but we get 32 bits worth of randomness just in case
            byte[] password = Utils.GetRandomBytes(4);
            string plainTextPassword = Utils.GetTypeablePassword(password);

            // caclulate the hash of our randomly generated password
            _srp.CalculatePasswordHash(plainTextPassword);


            if (string.IsNullOrEmpty(srp.I))
            {
                data2client.error = new Error(ErrorCode.AUTH_MISSING_PARAM, new[] { "I" });
            }
            else if (string.IsNullOrEmpty(srp.A))
            {
                data2client.error = new Error(ErrorCode.AUTH_MISSING_PARAM, new[] { "A" });
            }
            else
            {

                // Init relevant SRP protocol variables
                _srp.Setup();

                // Begin the SRP handshake
                error = _srp.Handshake(srp.I, srp.A);

                if (error.code > 0)
                    data2client.error = error;
                else
                {
                    // store the username and client name for future reference
                    userName = _srp.I;
                    clientName = srpem.clientDisplayName;

                    data2client.srp.s = _srp.s;
                    data2client.srp.B = _srp.Bstr;

                    data2client.srp.securityLevel = securityLevel;

                    //pass the params through to the main kprpcext thread via begininvoke - that function will then create and show the form as a modal dialog
                    string secLevel = "low";
                    if (srp.securityLevel == 2)
                        secLevel = "medium";
                    else if (srp.securityLevel == 3)
                        secLevel = "high";
                    KPRPC.InvokeMainThread (new ShowAuthDialogDelegate(ShowAuthDialog), secLevel, srpem.clientDisplayName, srpem.clientDisplayDescription, plainTextPassword);
                }
            }
	    	    
            return JsonConvert.ExportToString(data2client);
  	    }

        private delegate void ShowAuthDialogDelegate(string securityLevel, string name, string description, string password);

        private delegate void HideAuthDialogDelegate();


        private void ShowAuthDialog(string securityLevel, string name, string description, string password)
        {
            if (_authForm != null)
                _authForm.Hide();
            _authForm = new AuthForm(this, securityLevel, name, description, password);
            _authForm.Show();
        }

        private void HideAuthDialog()
        {
            if (_authForm != null)
                _authForm.Hide();
        }

        private delegate void ShowNewClientDelegate(string subject, string clientName);

        /// <summary>
        /// Offer the access decision that pairing does not make, for a client nobody has
        /// decided about yet.
        ///
        /// Skipped for a subject that already holds a profile: re-pairing an existing client
        /// is a re-key, not a new decision, and asking every time would train people to
        /// dismiss the question. Nothing is written unless the dialog is accepted, so
        /// dismissing it leaves the client refused, which is the state it was already in.
        /// </summary>
        private void ShowNewClientPrompt(string subject, string name)
        {
            if (KPRPC == null || KPRPC._host == null)
                return;

            if (!NewClientForm.NeedsDeciding(KPRPC._host, subject))
                return;

            using (NewClientForm form = new NewClientForm(subject, name))
            {
                if (form.ShowDialog(KPRPC._host.MainWindow) != DialogResult.OK)
                    return;

                NewClientForm.Apply(KPRPC._host, subject, form.Selected);
            }
        }

        public void ShuttingDown()
        {
            // Hide the auth dialog as long as we're not trying to shut down the main thread at the same time
            // (and as long as this isn't a v<1.2 connection)
            if (KPRPC != null && !KPRPC.terminating)
                KPRPC.InvokeMainThread(new HideAuthDialogDelegate(HideAuthDialog));
        }

        private string SRPProofToServer(KPRPCMessage srpem)
        {
            SRPParams srp = srpem.srp;

            KPRPCMessage data2client = new KPRPCMessage();
            data2client.protocol = "setup";
            data2client.srp = new SRPParams();
            data2client.srp.stage = "proofToClient";
            data2client.version = ProtocolVersion;

            if (string.IsNullOrEmpty(srp.M))
            {
                data2client.error = new Error(ErrorCode.AUTH_MISSING_PARAM, new[] { "M" });
            }
            else
            {
                _srp.Authenticate(srp.M);

                if (!_srp.Authenticated)
                    data2client.error = new Error(ErrorCode.AUTH_FAILED, new[] { "Keys do not match" });
                else
                {
                    data2client.srp.M2 = _srp.M2;
                    data2client.srp.securityLevel = securityLevel;
                    KeyContainer = new KeyContainerClass(_srp.Key,DateTime.UtcNow.AddSeconds(KeyExpirySeconds),userName,clientName);
                    // Rides on the message that completes pairing: the server refuses setup
                    // messages once authorised, and before this point there is no shared key
                    // to authenticate an exchange with.
                    data2client.crypto = NegotiateCryptoV2(srpem.crypto, _srp.Key);
                    Authorised = true;
                    // Note the identity so it can be offered when granting, rather than having
                    // to be remembered and retyped exactly.
                    SubjectRegistry.Remember(KPRPC._host, userName);
                    // We assume the user has checked the client name as part of the initial SRP setup so it's fairly safe to use it to determine the type of client connection to which we want to promote our null connection
                    KPRPC.PromoteGeneralRPCClient(this, clientName);
                    KPRPC.InvokeMainThread(new HideAuthDialogDelegate(HideAuthDialog));

                    // If we've never shown the user the welcome screen and have never
                    // known a Kee add-on from the previous KPRPC protocol, show it now
                    bool welcomeDisplayed = KPRPC._host.CustomConfig.GetBool("KeePassRPC.KeeFoxWelcomeDisplayed",false);
                    if (!welcomeDisplayed
                        && string.IsNullOrEmpty(KPRPC._host.CustomConfig.GetString("KeePassRPC.knownClients.KeeFox Firefox add-on")))
                        KPRPC.InvokeMainThread(new KeePassRPCExt.WelcomeKeeUserDelegate(KPRPC.WelcomeKeeUser));
                    if (!welcomeDisplayed)
                        KPRPC._host.CustomConfig.SetBool("KeePassRPC.KeeFoxWelcomeDisplayed",true);

                    // Pairing on its own grants nothing, because the method gate is default
                    // deny, so ask now what this client may call. Now is the only moment a
                    // human is certainly present: the pairing code is shown on this screen
                    // and nobody could have got this far without reading it.
                    KPRPC.InvokeMainThread(
                        new ShowNewClientDelegate(ShowNewClientPrompt), userName, clientName);
                }
            }

            return JsonConvert.ExportToString(data2client);
  	    }

        private void KPRPCReceiveJSONRPC(JSONRPCContainer jsonrpcEncrypted, KeePassRPCService service)
        {
            string jsonrpc = Decrypt(jsonrpcEncrypted);
            StringBuilder sb = new StringBuilder();
            string output;

            JsonRpcDispatcherFactory.Current = s => new KprpcJsonRpcDispatcher(s);
            JsonRpcDispatcher dispatcher = JsonRpcDispatcherFactory.CreateDispatcher(service);
            KprpcJsonRpcDispatcher kprpcDispatcher = (KprpcJsonRpcDispatcher)dispatcher;
            kprpcDispatcher.ClientMetadata = new ClientMetadata
            {
                Features = ClientFeatures,
                // UserName is empty unless the connection is authorised, so an unauthenticated
                // caller cannot reach the gate carrying somebody else's subject.
                Subject = UserName,
                MethodProfile = MethodProfile,
                IsRemote = IsRemote
            };
            kprpcDispatcher.AuditLog = delegate(string message)
            {
                if (KPRPC.logger != null) KPRPC.logger.WriteLine(message);
            };
            kprpcDispatcher.AuditDenial = delegate(string deniedSubject, string deniedMethod, string reason)
            {
                // The gate's refusals belong in the same log as the ACL's. Otherwise "what was
                // this client refused" has two answers in two places, and the method-gate half
                // is the one that only ever appeared in a debug line.
                Audit.Record(KPRPC._host, deniedSubject, IsRemote, deniedMethod, null, null, false, reason);
            };

            using (StringReader request = new StringReader(jsonrpc))
            using (StringWriter response = new StringWriter(sb))
            {
                dispatcher.Process(request, response, Authorised);
                output = sb.ToString();
            }

            KPRPCMessage data2client = new KPRPCMessage();
            data2client.protocol = "jsonrpc";
            data2client.version = ProtocolVersion;
            data2client.jsonrpc = Encrypt(output);

            // If there was a problem encrypting our message, respond to the
            // client with a non-encrypted error message
            if (data2client.jsonrpc == null)
            {
                data2client = new KPRPCMessage();
                data2client.protocol = "error";
                data2client.version = ProtocolVersion;
                data2client.error = new Error(ErrorCode.AUTH_RESTART, new[] { "Encryption error" });
                Authorised = false;
                if (KPRPC.logger != null) KPRPC.logger.WriteLine("Encryption error when trying to reply to client message");
            }
            _webSocketConnection.Send(JsonConvert.ExportToString(data2client));
            
        }

        public JSONRPCContainer Encrypt(string plaintext)
        {
            if (string.IsNullOrEmpty(plaintext))
                return null;

            // Negotiated suite: fresh per-session key, HMAC-SHA256, sequence numbered. The
            // legacy path below is left exactly as it was, because every client that has not
            // asked for the newer suite still depends on it byte for byte.
            if (_sessionKey != null)
            {
                try
                {
                    JSONRPCContainer secured = CryptoV2.Encrypt(plaintext, _sessionKey, _nextServerSequence);
                    _nextServerSequence++;
                    return secured;
                }
                catch (Exception ex)
                {
                    if (KPRPC.logger != null) KPRPC.logger.WriteLine("CryptoV2 encrypt failed: " + ex.Message);
                    return null;
                }
            }

            KeyContainerClass kc = KeyContainer;

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            // Encrypt the client's message
            using (SHA1 sha = new SHA1CryptoServiceProvider())
            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {
                myRijndael.GenerateIV();
                myRijndael.Key = MemUtil.HexStringToByteArray(kc.Key);
                ICryptoTransform encryptor = myRijndael.CreateEncryptor();
                byte[] encrypted;
                using (MemoryStream msEncrypt = new MemoryStream(100))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        try
                        {
                            cryptoStream.Write(plaintextBytes, 0, plaintextBytes.Length);
                        }
                        catch (ArgumentException)
                        {
                            //The sum of the count and offset parameters is longer than the length of the buffer.
                            return null;
                        }
                        catch (NotSupportedException)
                        {
                            // Underlying stream does not support writing (not sure how this could happen)
                            return null;
                        }

                        try
                        {
                            cryptoStream.FlushFinalBlock();
                        }
                        catch (NotSupportedException)
                        {
                            // 	The current stream is not writable. -or- The final block has already been transformed. 
                            return null;
                        }
                        catch (CryptographicException)
                        {
                            // The key is corrupt which can cause invalid padding to the stream. 
                            return null;
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                }


                // Get the raw bytes that are used to calculate the HMAC

                byte[] HmacKey = sha.ComputeHash(myRijndael.Key);
                byte[] ourHmacSourceBytes = new byte[HmacKey.Length + encrypted.Length + myRijndael.IV.Length];

                // These calls can throw a variety of different exceptions but
                // I can't see why they would so we will not try to differentiate the cause of them
                try
                {
                    //TODO2: HMAC calculations might be stengthened against attacks on SHA 
                    // and/or gain improved performance through use of algorithms like AES-CMAC or HKDF

                    Array.Copy(HmacKey, ourHmacSourceBytes, HmacKey.Length);
                    Array.Copy(encrypted, 0, ourHmacSourceBytes, HmacKey.Length, encrypted.Length);
                    Array.Copy(myRijndael.IV, 0, ourHmacSourceBytes, HmacKey.Length + encrypted.Length, myRijndael.IV.Length);

                    // Calculate the HMAC
                    byte[] ourHmac = sha.ComputeHash(ourHmacSourceBytes);

                    // Package the data ready for transmission
                    JSONRPCContainer cont = new JSONRPCContainer();
                    cont.iv = Convert.ToBase64String(myRijndael.IV);
                    cont.message = Convert.ToBase64String(encrypted);
                    cont.hmac = Convert.ToBase64String(ourHmac);

                    return cont;
                }
                catch (ArgumentNullException)
                {
                    return null;
                }
                catch (RankException)
                {
                    return null;
                }
                catch (ArrayTypeMismatchException)
                {
                    return null;
                }
                catch (ArgumentOutOfRangeException)
                {
                    return null;
                }
                catch (ArgumentException)
                {
                    return null;
                }
                catch (ObjectDisposedException)
                {
                    return null;
                }
            }
        }

        public string Decrypt(JSONRPCContainer jsonrpcEncrypted)
        {
            // See Encrypt: the newer suite when negotiated, the original one otherwise.
            if (_sessionKey != null)
            {
                try
                {
                    string plain = CryptoV2.Decrypt(jsonrpcEncrypted, _sessionKey, _expectedClientSequence);
                    _expectedClientSequence++;
                    return plain;
                }
                catch (Exception ex)
                {
                    // A failure here is a forged, replayed or reordered message. Returning
                    // null is how this method already reports "do not act on this".
                    if (KPRPC.logger != null) KPRPC.logger.WriteLine("CryptoV2 decrypt refused: " + ex.Message);
                    return null;
                }
            }

            if (string.IsNullOrEmpty(jsonrpcEncrypted.message)
                || string.IsNullOrEmpty(jsonrpcEncrypted.iv)
                || string.IsNullOrEmpty(jsonrpcEncrypted.hmac))
                return null;

            KeyContainerClass kc = KeyContainer;

                byte[] rawKeyBytes;
                byte[] keyBytes;
                byte[] messageBytes;
                byte[] IVBytes;

            using (SHA1 sha = new SHA1CryptoServiceProvider())
            {
                // Get the raw bytes that are used to calculate the HMAC
                try
                {
                    rawKeyBytes = MemUtil.HexStringToByteArray(kc.Key);
                    keyBytes = sha.ComputeHash(rawKeyBytes);
                    messageBytes = Convert.FromBase64String(jsonrpcEncrypted.message);
                    IVBytes = Convert.FromBase64String(jsonrpcEncrypted.iv);
                }
                catch (FormatException)
                {
                    // Should only happen if there is a fault with the client end
                    // of the protocol or if an attacker tries to inject invalid data
                    return null;
                }
                catch (ArgumentNullException)
                {
                    // kc.Key must = null
                    return null;
                }

            // These calls can throw a variety of different exceptions but
            // I can't see why they would so we will not try to differentiate the cause of them
            try
                {
                    byte[] ourHmacSourceBytes = new byte[keyBytes.Length + messageBytes.Length + IVBytes.Length];
                    Array.Copy(keyBytes, ourHmacSourceBytes, keyBytes.Length);
                    Array.Copy(messageBytes, 0, ourHmacSourceBytes, keyBytes.Length, messageBytes.Length);
                    Array.Copy(IVBytes, 0, ourHmacSourceBytes, keyBytes.Length + messageBytes.Length, IVBytes.Length);

                    // Calculate the HMAC
                    byte[] ourHmac = sha.ComputeHash(ourHmacSourceBytes);

                    // Check our HMAC against the one supplied by the client
                    if (Convert.ToBase64String(ourHmac) != jsonrpcEncrypted.hmac)
                    {
                        //TODO2: If we ever want/need to include some DOS protection we
                        // could use this error condition to throttle requests from badly behaved clients
                        if (KPRPC.logger != null) KPRPC.logger.WriteLine("HMAC did not match");
                        return null;
                    }
                }
                catch (ArgumentNullException)
                {
                    return null;
                }
                catch (RankException)
                {
                    return null;
                }
                catch (ArrayTypeMismatchException)
                {
                    return null;
                }
                catch (ArgumentOutOfRangeException)
                {
                    return null;
                }
                catch (ArgumentException)
                {
                    return null;
                }
                catch (ObjectDisposedException)
                {
                    return null;
                }
            }

            // Decrypt the client's message
            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {
                ICryptoTransform decryptor = myRijndael.CreateDecryptor(rawKeyBytes, IVBytes);
                using (MemoryStream msDecrypt = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                {
                    try
                    {
                        cryptoStream.Write(messageBytes, 0, messageBytes.Length);
                    }
                    catch (ArgumentException)
                    {
                        //The sum of the count and offset parameters is longer than the length of the buffer.
                        return null;
                    }
                    catch (NotSupportedException)
                    {
                        // Underlying stream does not support writing (not sure how this could happen)
                        return null;
                    }

                    try
                    {
                        cryptoStream.FlushFinalBlock();
                    }
                    catch (NotSupportedException)
                    {
                        // 	The current stream is not writable. -or- The final block has already been transformed. 
                        return null;
                    }
                    catch (CryptographicException)
                    {
                        // The key is corrupt which can cause invalid padding to the stream. 
                        return null;
                    }


                    byte[] decrypted = msDecrypt.ToArray();
                    string result = Encoding.UTF8.GetString(decrypted);
                    return result;
                }
            }
        }

    }

    /// <summary>
    /// Tracks requests from RPC clients while they are being authorised
    /// </summary>
    public class PendingRPCClient
    {
        public string ClientId;
        public string Hash;
        public List<string> KnownClientList;

        public PendingRPCClient(string clientId, string hash, List<string> knownClientList)
        {
            ClientId = clientId;
            Hash = hash;
            KnownClientList = knownClientList;
        }
    }

}
