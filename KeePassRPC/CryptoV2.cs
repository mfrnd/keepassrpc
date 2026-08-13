using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KeePassRPC.Models.DataExchange;

namespace KeePassRPC
{
    /// <summary>
    /// A stronger session crypto suite, negotiated per client so that older clients keep the
    /// original one untouched.
    ///
    /// What it fixes, in the order the problems matter:
    ///
    /// **One key, forever.** The original suite encrypts with the key established at pairing
    /// and never rotates it: the key challenge proves possession and derives nothing, so every
    /// message of every session for the life of the pairing shares one AES key. Combined with
    /// that key living at rest in a DPAPI blob any local process can read, it means captured
    /// traffic can be decrypted retroactively by anyone who later obtains the key. Here an
    /// ephemeral ECDH exchange produces a fresh session key per connection, so a key stolen
    /// tomorrow does not open what was recorded today.
    ///
    /// **The MAC was not an HMAC.** `SHA1(SHA1(key) || ciphertext || iv)` is a
    /// length-extendable construction on a broken hash. Here it is HMAC-SHA256 with a key
    /// derived separately from the encryption key.
    ///
    /// **Nothing detected replay.** Each direction carries a counter inside the encrypted
    /// envelope, so a replayed, reordered or dropped message is refused.
    ///
    /// The exchange is authenticated by the paired key: the session key is derived from both
    /// the ECDH secret AND that key, so it is secure if either is. A local process that cannot
    /// read the paired key cannot complete the exchange, and one that can was already able to
    /// impersonate the subject outright.
    ///
    /// No AEAD is used because .NET Framework 4.5 has none. `AesGcm` arrived in .NET Core
    /// 3.0. This is AES-256-CBC with explicit encrypt-then-MAC, which is the same ordering the
    /// original suite got right.
    /// </summary>
    public static class CryptoV2
    {
        /// <summary>Clients declaring this get the suite below; everything else is unchanged.</summary>
        public const string FeatureName = "KPRPC_FEATURE_CRYPTO_V2";

        /// <summary>P-256 public keys travel as raw X||Y, which both sides can build.</summary>
        private const int CoordinateBytes = 32;

        private const int PublicKeyBytes = CoordinateBytes * 2;

        // BCRYPT_ECDH_PUBLIC_P256_MAGIC. CNG wants an 8 byte header in front of X||Y; the wire
        // format omits it, because it is a Windows detail and the other end is not Windows.
        private const uint P256PublicMagic = 0x314B4345;

        private static readonly byte[] SessionLabel = Encoding.UTF8.GetBytes("KPRPC-CRYPTO-V2 session");
        private static readonly byte[] ConfirmLabel = Encoding.UTF8.GetBytes("KPRPC-CRYPTO-V2 kex-confirm");
        private static readonly byte[] EncryptionLabel = Encoding.UTF8.GetBytes("KPRPC-CRYPTO-V2 enc");
        private static readonly byte[] MacLabel = Encoding.UTF8.GetBytes("KPRPC-CRYPTO-V2 mac");

        /// <summary>An ephemeral key agreement in progress.</summary>
        public sealed class Exchange : IDisposable
        {
            private readonly ECDiffieHellmanCng _ecdh;

            internal Exchange(ECDiffieHellmanCng ecdh)
            {
                _ecdh = ecdh;
            }

            /// <summary>This side's public key, raw X||Y.</summary>
            public byte[] PublicKey
            {
                get
                {
                    byte[] blob = _ecdh.PublicKey.ToByteArray();
                    if (blob.Length < 8 + PublicKeyBytes)
                        throw new CryptographicException("unexpected CNG public key blob length");

                    byte[] raw = new byte[PublicKeyBytes];
                    Array.Copy(blob, 8, raw, 0, PublicKeyBytes);
                    return raw;
                }
            }

            /// <summary>The agreed secret with a peer, already hashed by the CNG KDF.</summary>
            public byte[] AgreeWith(byte[] peerPublicKey)
            {
                if (peerPublicKey == null || peerPublicKey.Length != PublicKeyBytes)
                    throw new CryptographicException("peer public key is not a raw P-256 point");

                byte[] blob = new byte[8 + PublicKeyBytes];
                Buffer.BlockCopy(BitConverter.GetBytes(P256PublicMagic), 0, blob, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(CoordinateBytes), 0, blob, 4, 4);
                Buffer.BlockCopy(peerPublicKey, 0, blob, 8, PublicKeyBytes);

                using (CngKey peer = CngKey.Import(blob, CngKeyBlobFormat.EccPublicBlob))
                {
                    // KDF set to a plain SHA-256 of the agreed point, so the other end can
                    // reach the same bytes with an ordinary hash and no CNG.
                    return _ecdh.DeriveKeyMaterial(peer);
                }
            }

            public void Dispose()
            {
                _ecdh.Dispose();
            }
        }

        /// <summary>Begin a key agreement with a fresh ephemeral P-256 key.</summary>
        public static Exchange BeginExchange()
        {
            ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(256);
            ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecdh.HashAlgorithm = CngAlgorithm.Sha256;
            return new Exchange(ecdh);
        }

        /// <summary>
        /// The session key, bound to both the ephemeral secret and the long-lived paired key.
        ///
        /// Both public keys are included so that neither side can steer the result by choosing
        /// its own key after seeing the other's.
        /// </summary>
        public static byte[] DeriveSessionKey(byte[] pairedKey, byte[] clientPublic, byte[] serverPublic,
            byte[] agreed)
        {
            using (HMACSHA256 hmac = new HMACSHA256(pairedKey))
            {
                return hmac.ComputeHash(Concat(SessionLabel, clientPublic, serverPublic, agreed));
            }
        }

        /// <summary>The server's proof that it reached the same session key.</summary>
        public static byte[] KexConfirmation(byte[] sessionKey, byte[] clientPublic, byte[] serverPublic)
        {
            using (HMACSHA256 hmac = new HMACSHA256(sessionKey))
            {
                return hmac.ComputeHash(Concat(ConfirmLabel, clientPublic, serverPublic));
            }
        }

        /// <summary>
        /// Encrypt one message.
        /// </summary>
        /// <param name="plaintext">The JSON-RPC body.</param>
        /// <param name="sessionKey">The key from <see cref="DeriveSessionKey"/>.</param>
        /// <param name="sequence">This direction's next counter value, starting at 1.</param>
        public static JSONRPCContainer Encrypt(string plaintext, byte[] sessionKey, long sequence)
        {
            if (plaintext == null)
                return null;

            // The counter travels inside the ciphertext rather than beside it, so the wire
            // container keeps exactly the shape the original suite uses. Nothing a legacy
            // client parses changes at all, which is worth more than the microscopic saving
            // of putting the counter in the clear.
            byte[] body = Encoding.UTF8.GetBytes(Envelope(sequence, plaintext));
            byte[] iv = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                rng.GetBytes(iv);

            byte[] ciphertext;
            using (AesManaged aes = new AesManaged())
            {
                aes.Key = SubKey(sessionKey, EncryptionLabel);
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (MemoryStream buffer = new MemoryStream())
                {
                    using (CryptoStream stream = new CryptoStream(buffer, encryptor, CryptoStreamMode.Write))
                        stream.Write(body, 0, body.Length);
                    ciphertext = buffer.ToArray();
                }
            }

            JSONRPCContainer container = new JSONRPCContainer();
            container.iv = Convert.ToBase64String(iv);
            container.message = Convert.ToBase64String(ciphertext);
            container.hmac = Convert.ToBase64String(Mac(sessionKey, iv, ciphertext));
            return container;
        }

        /// <summary>
        /// Verify and decrypt one message.
        /// </summary>
        /// <param name="expectedSequence">
        /// The counter this direction must next produce. A mismatch means a replayed,
        /// reordered or dropped message, and is refused rather than tolerated.
        /// </param>
        /// <returns>The JSON-RPC body.</returns>
        /// <exception cref="CryptographicException">On any failure. Never returns partial data.</exception>
        public static string Decrypt(JSONRPCContainer container, byte[] sessionKey, long expectedSequence)
        {
            if (container == null || container.iv == null || container.message == null || container.hmac == null)
                throw new CryptographicException("incomplete encrypted container");

            byte[] iv = Convert.FromBase64String(container.iv);
            byte[] ciphertext = Convert.FromBase64String(container.message);
            byte[] presented = Convert.FromBase64String(container.hmac);

            // Checked before anything is decrypted, so a forged message never reaches the
            // unpadder, and compared in constant time.
            if (!FixedTimeEquals(Mac(sessionKey, iv, ciphertext), presented))
                throw new CryptographicException("message authentication failed");

            byte[] body;
            using (AesManaged aes = new AesManaged())
            {
                aes.Key = SubKey(sessionKey, EncryptionLabel);
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream buffer = new MemoryStream())
                {
                    using (CryptoStream stream = new CryptoStream(buffer, decryptor, CryptoStreamMode.Write))
                        stream.Write(ciphertext, 0, ciphertext.Length);
                    body = buffer.ToArray();
                }
            }

            long sequence;
            string plaintext;
            if (!TryReadEnvelope(Encoding.UTF8.GetString(body), out sequence, out plaintext))
                throw new CryptographicException("malformed message envelope");

            if (sequence != expectedSequence)
            {
                throw new CryptographicException("message sequence " + sequence + " where "
                    + expectedSequence + " was expected; replayed, reordered or lost");
            }

            return plaintext;
        }

        private static byte[] Mac(byte[] sessionKey, byte[] iv, byte[] ciphertext)
        {
            using (HMACSHA256 hmac = new HMACSHA256(SubKey(sessionKey, MacLabel)))
            {
                return hmac.ComputeHash(Concat(iv, ciphertext));
            }
        }

        /// <summary>Separate keys for encryption and authentication, from the one session key.</summary>
        private static byte[] SubKey(byte[] sessionKey, byte[] label)
        {
            using (HMACSHA256 hmac = new HMACSHA256(sessionKey))
            {
                return hmac.ComputeHash(label);
            }
        }

        /// <summary>
        /// The counter and the body, as a JSON object.
        ///
        /// Hand-built rather than routed through the JSON library: the payload is already
        /// serialised JSON and re-parsing it to nest it would be pointless work on every
        /// message, and a re-serialisation is a chance to change it.
        /// </summary>
        private static string Envelope(long sequence, string plaintext)
        {
            return "{\"seq\":" + sequence + ",\"payload\":" + Quote(plaintext) + "}";
        }

        private static bool TryReadEnvelope(string envelope, out long sequence, out string plaintext)
        {
            sequence = 0;
            plaintext = null;

            try
            {
                var parsed = Jayrock.Json.Conversion.JsonConvert.Import(envelope) as System.Collections.IDictionary;
                if (parsed == null || !parsed.Contains("seq") || !parsed.Contains("payload"))
                    return false;

                sequence = Convert.ToInt64(parsed["seq"].ToString());
                plaintext = parsed["payload"] as string;
                return plaintext != null;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string Quote(string value)
        {
            StringBuilder quoted = new StringBuilder(value.Length + 16);
            quoted.Append('"');
            foreach (char c in value)
            {
                switch (c)
                {
                    case '"': quoted.Append("\\\""); break;
                    case '\\': quoted.Append("\\\\"); break;
                    case '\b': quoted.Append("\\b"); break;
                    case '\f': quoted.Append("\\f"); break;
                    case '\n': quoted.Append("\\n"); break;
                    case '\r': quoted.Append("\\r"); break;
                    case '\t': quoted.Append("\\t"); break;
                    default:
                        if (c < ' ')
                            quoted.Append("\\u").Append(((int)c).ToString("x4"));
                        else
                            quoted.Append(c);
                        break;
                }
            }
            quoted.Append('"');
            return quoted.ToString();
        }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (byte[] part in parts)
                total += part.Length;

            byte[] joined = new byte[total];
            int offset = 0;
            foreach (byte[] part in parts)
            {
                Buffer.BlockCopy(part, 0, joined, offset, part.Length);
                offset += part.Length;
            }
            return joined;
        }

        /// <summary>Comparison whose duration does not depend on where the difference is.</summary>
        public static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length)
                return false;

            int difference = 0;
            for (int i = 0; i < left.Length; i++)
                difference |= left[i] ^ right[i];
            return difference == 0;
        }
    }
}
