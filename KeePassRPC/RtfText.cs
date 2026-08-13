using System;
using System.Text;

namespace KeePassRPC
{
    /// <summary>
    /// Escaping for text that a caller supplied and a dialog is about to render as RTF.
    ///
    /// The authorisation dialog is built by concatenating strings into an RTF document, and
    /// two of those strings arrive from the network before the client has authenticated. The
    /// client name is filtered through an allowlist of letters, digits, spaces and hyphens,
    /// so it cannot carry RTF syntax. The description was not filtered at all, which meant a
    /// caller could close the enclosing group with <c>}</c> and write control words into the
    /// document, that document being the prompt that asks a human whether to hand over
    /// access to their passwords.
    ///
    /// That is worth spelling out because the consequence is not a rendering glitch. The
    /// attacker chooses what the security prompt says. Locally the reach of that is bounded by
    /// everything else a local process can already do, which is the only reason it is a defect
    /// rather than an emergency; it would stop being bounded the moment the socket left
    /// loopback.
    ///
    /// Escaping rather than filtering, because a description is prose and deserves to survive
    /// intact. The name keeps its allowlist as well: it is upstream's behaviour, and it costs
    /// nothing to run untrusted text past two checks instead of one.
    /// </summary>
    public static class RtfText
    {
        /// <summary>
        /// A cap on how much caller-supplied text a dialog will render.
        ///
        /// Not a security boundary now that the text cannot escape its group, but a dialog is
        /// a fixed size and a caller with a few thousand characters to spare could push the
        /// parts a human needs to read out of view.
        /// </summary>
        public const int DefaultMaximumLength = 300;

        /// <summary>
        /// Make text safe to concatenate into an RTF document.
        /// </summary>
        /// <param name="value">Caller-supplied text. Null becomes empty.</param>
        /// <param name="maximumLength">
        /// Truncate beyond this many characters, marking the cut. Zero or less means no cap.
        /// </param>
        public static string Escape(string value, int maximumLength)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            string text = value;
            bool truncated = false;
            if (maximumLength > 0 && text.Length > maximumLength)
            {
                text = text.Substring(0, maximumLength);
                truncated = true;
            }

            StringBuilder escaped = new StringBuilder(text.Length + 16);
            foreach (char c in text)
            {
                switch (c)
                {
                    // The three characters that carry meaning in RTF, and the whole point of
                    // this method.
                    case '\\': escaped.Append("\\\\"); break;
                    case '{': escaped.Append("\\{"); break;
                    case '}': escaped.Append("\\}"); break;

                    default:
                        if (c < ' ' || c == '\u007F')
                        {
                            // Control characters, including newlines and tabs, become spaces.
                            // Escaping them faithfully would let a caller add paragraphs and
                            // scroll the real text out of the dialog, which is the same
                            // problem in a quieter form.
                            escaped.Append(' ');
                        }
                        else if (c > '\u007F')
                        {
                            // The document declares \ansi, so anything above ASCII would
                            // otherwise render as whatever the reader's codepage made of the
                            // bytes. \uN? is the portable spelling, N signed 16-bit, with an
                            // ASCII fallback character after it. Surrogate pairs come out as
                            // two of these, which is what a reader expects.
                            escaped.Append("\\u").Append((short)c).Append('?');
                        }
                        else
                        {
                            escaped.Append(c);
                        }
                        break;
                }
            }

            if (truncated)
                escaped.Append("...");

            return escaped.ToString();
        }

        /// <summary>Escape with the default cap.</summary>
        public static string Escape(string value)
        {
            return Escape(value, DefaultMaximumLength);
        }
    }
}
