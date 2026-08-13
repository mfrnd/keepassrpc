using System;
using System.IO;

namespace KeePassRPC.Acl
{
    /// <summary>
    /// Reads the KDBX major version out of a database file's header.
    ///
    /// Grants live in group and entry <c>CustomData</c>, which arrived with KDBX 4 in KeePass
    /// 2.35. What happens on an older file is not data loss, which an earlier version of this
    /// comment claimed: KeePass does not keep the version a file was read as, it asks
    /// <c>KdbxFile.GetMinKdbxVersion</c> what the data needs and writes that. So a grant made
    /// on a KDBX 3.1 database is kept, and the database is rewritten as KDBX 4.
    ///
    /// That is still worth saying out loud before it happens, because it changes the file
    /// format of somebody's password database: KeePass 2.34 and older cannot open KDBX 4 at
    /// all, so a copy of KeePass elsewhere may stop being able to read it.
    ///
    /// KeePass has no explicit format setting, so the file header is the only honest source.
    /// <c>KdbxVersionTest</c> pins what the format actually requires, by asking KeePass.
    /// </summary>
    public static class KdbxFormat
    {
        private const uint Signature1 = 0x9AA2D903;
        private const uint Signature2 = 0xB54BFB67;

        /// <summary>Returned when the file is missing, unreadable, or not a KDBX at all.</summary>
        public const int Unknown = -1;

        /// <summary>
        /// The major version, or <see cref="Unknown"/>.
        ///
        /// Layout: two 4-byte signatures, then a 4-byte version whose HIGH 16 bits are the
        /// major, so the major is the little-endian 16-bit value at offset 10.
        /// </summary>
        public static int ReadMajorVersion(Stream stream)
        {
            if (stream == null)
                return Unknown;

            byte[] header = new byte[12];
            int read = 0;
            while (read < header.Length)
            {
                int got = stream.Read(header, read, header.Length - read);
                if (got <= 0)
                    return Unknown;
                read += got;
            }

            if (BitConverter.ToUInt32(header, 0) != Signature1)
                return Unknown;
            if (BitConverter.ToUInt32(header, 4) != Signature2)
                return Unknown;

            return BitConverter.ToUInt16(header, 10);
        }

        /// <summary>
        /// The major version of the file at <paramref name="path"/>, or
        /// <see cref="Unknown"/> if it cannot be read. Never throws: a grant dialog asking
        /// whether the format supports grants should not fall over because the database lives
        /// on a share that just went away.
        /// </summary>
        public static int ReadMajorVersion(string path)
        {
            if (string.IsNullOrEmpty(path))
                return Unknown;

            try
            {
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    return ReadMajorVersion(stream);
                }
            }
            catch (Exception)
            {
                return Unknown;
            }
        }

        /// <summary>
        /// Whether the file can store grants. Unknown counts as no, because the point of
        /// asking is to avoid a write that silently disappears.
        /// </summary>
        public static bool SupportsCustomData(string path)
        {
            return ReadMajorVersion(path) >= 4;
        }
    }
}
