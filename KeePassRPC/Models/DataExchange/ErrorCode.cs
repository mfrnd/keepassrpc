namespace KeePassRPC.Models.DataExchange
{
    public enum ErrorCode
    {
        SUCCESS = 0, // Convention suggests we should not use 0 as an error condition
        UNKNOWN = 1, // A catchall - hopefully won't ever need to use this
        INVALID_MESSAGE = 2,
        UNRECOGNISED_PROTOCOL = 3,
        VERSION_CLIENT_TOO_LOW = 4,
        VERSION_CLIENT_TOO_HIGH = 5,
        AUTH_CLIENT_SECURITY_LEVEL_TOO_LOW = 6,
        AUTH_SERVER_SECURITY_LEVEL_TOO_LOW = 7,
        AUTH_FAILED = 8,
        AUTH_RESTART = 9,
        AUTH_EXPIRED = 10,
        AUTH_INVALID_PARAM = 11,
        AUTH_MISSING_PARAM = 12,

        // The connection came from off this machine and is not using the negotiated session
        // crypto. The message carries the name of the feature the client has to declare.
        AUTH_CRYPTO_TOO_WEAK = 13
    }
}