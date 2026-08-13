using System;
using System.Text;

namespace KeePassRPC.Forms
{
    /// <summary>
    /// Text handling shared by the plugin's own tabs.
    /// </summary>
    internal static class Tooltips
    {
        /// <summary>Characters per line. Wide enough to read, narrow enough to place.</summary>
        private const int LineLength = 72;

        /// <summary>
        /// Break text into lines a tooltip can show.
        ///
        /// A WinForms tooltip never wraps: given a paragraph it draws one line across every
        /// monitor it can reach. These explanations are paragraphs, so the breaks have to be
        /// put in by hand. Existing line breaks are kept, so a caller can still decide where
        /// a paragraph ends.
        /// </summary>
        internal static string Wrapped(string text)
        {
            if (string.IsNullOrEmpty(text))
                return text;

            StringBuilder wrapped = new StringBuilder(text.Length + 16);

            string[] paragraphs = text.Replace("\r\n", "\n").Split('\n');
            for (int p = 0; p < paragraphs.Length; p++)
            {
                if (p > 0)
                    wrapped.Append(Environment.NewLine);

                int since = 0;
                foreach (string word in paragraphs[p].Split(' '))
                {
                    if (word.Length == 0)
                        continue;

                    if (since > 0 && since + 1 + word.Length > LineLength)
                    {
                        wrapped.Append(Environment.NewLine);
                        since = 0;
                    }
                    else if (since > 0)
                    {
                        wrapped.Append(' ');
                        since++;
                    }

                    wrapped.Append(word);
                    since += word.Length;
                }
            }

            return wrapped.ToString();
        }
    }
}
