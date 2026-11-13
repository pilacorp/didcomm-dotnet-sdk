using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

/// <summary>
/// RFC 8785 JSON Canonicalization Scheme: a port of go-credential-sdk's <c>didv2/did/jsoncanonicalizer</c>
/// (the WebPKI.org reference), so the same inputs are accepted and rejected: the top level must be an object
/// or array, duplicate keys and a lone surrogate escape are errors, numbers go through float64 and the ES6
/// formatter. Errors are <see cref="InvalidOperationException"/>.
/// </summary>
public sealed class Rfc8785
{
    // ponytail: Go's ParseFloat also takes hex floats ("0x1p-2"); those are rejected here.
    private static readonly Regex Number = new(@"\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z", RegexOptions.CultureInvariant);
    private const string AsciiEscapes = "\\\"bfnrt";
    private const string BinaryEscapes = "\\\"\b\f\n\r\t";
    // Go has no cap (and dies with an unrecoverable stack overflow); keep parity with the Python port.
    private const int MaxDepth = 200;

    private readonly byte[] _d;
    private int _i;
    private int _depth;

    private Rfc8785(byte[] data) => _d = data;

    public static byte[] Transform(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return new Rfc8785(Encoding.UTF8.GetBytes(json)).Run();
    }

    private static InvalidOperationException Fail(string msg) => new(msg);

    private byte[] Run()
    {
        byte[] result;
        if (Peek() == '[')
        {
            Scan();
            result = Nested(ParseArray);
        }
        else
        {
            ScanFor('{');
            result = Nested(ParseObject);
        }
        for (; _i < _d.Length; _i++)
        {
            if (!IsWhiteSpace(_d[_i])) throw Fail("Improperly terminated JSON object");
        }
        return result;
    }

    private static bool IsWhiteSpace(int c) => c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09;

    private int NextChar()
    {
        if (_i >= _d.Length) throw Fail("Unexpected EOF reached");
        int c = _d[_i++];
        if (c > 0x7f) throw Fail("Unexpected non-ASCII character");
        return c;
    }

    private int Scan()
    {
        while (true)
        {
            int c = NextChar();
            if (!IsWhiteSpace(c)) return c;
        }
    }

    private void ScanFor(char expected)
    {
        int c = Scan();
        if (c != expected) throw Fail($"Expected '{expected}' but got '{(char)c}'");
    }

    private int Peek()
    {
        int save = _i;
        int c = Scan();
        _i = save;
        return c;
    }

    private int UEscape()
    {
        int start = _i;
        for (int k = 0; k < 4; k++) NextChar();
        var hex = Encoding.ASCII.GetString(_d, start, 4);
        if (!int.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var v))
            throw Fail("invalid \\u escape: " + hex);
        return v;
    }

    private byte[] ParseElement()
    {
        switch (Scan())
        {
            case '{': return Nested(ParseObject);
            case '"': return Decorate(ParseQuotedString());
            case '[': return Nested(ParseArray);
            default: return ParseSimpleType();
        }
    }

    private byte[] Nested(Func<byte[]> parse)
    {
        if (++_depth > MaxDepth) throw Fail("canonicalizer: nesting exceeds maximum depth");
        try { return parse(); }
        finally { _depth--; }
    }

    private byte[] ParseQuotedString()
    {
        var raw = new MemoryStream();
        while (true)
        {
            if (_i >= _d.Length) NextChar(); // EOF error
            int c = _d[_i++];
            if (c == '"') break;
            if (c < ' ') throw Fail("Unterminated string literal");
            if (c == '\\')
            {
                c = NextChar();
                if (c == 'u')
                {
                    int first = UEscape();
                    if (first >= 0xD800 && first <= 0xDFFF)
                    {
                        if (NextChar() != '\\' || NextChar() != 'u') throw Fail("Missing surrogate");
                        int second = UEscape();
                        if (first <= 0xDBFF && second >= 0xDC00 && second <= 0xDFFF)
                            WriteRune(raw, char.ConvertToUtf32((char)first, (char)second));
                        else
                            WriteRune(raw, 0xFFFD);
                    }
                    else WriteRune(raw, first);
                }
                else if (c == '/') raw.WriteByte((byte)'/');
                else
                {
                    int k = AsciiEscapes.IndexOf((char)c);
                    if (k < 0) throw Fail("Unexpected escape: \\" + (char)c);
                    raw.WriteByte((byte)BinaryEscapes[k]);
                }
            }
            else raw.WriteByte((byte)c);
        }
        return raw.ToArray();
    }

    private static void WriteRune(MemoryStream o, int cp)
    {
        var b = Encoding.UTF8.GetBytes(char.ConvertFromUtf32(cp));
        o.Write(b, 0, b.Length);
    }

    private static byte[] Decorate(byte[] raw)
    {
        var q = new MemoryStream(raw.Length + 2);
        q.WriteByte((byte)'"');
        foreach (var b in raw)
        {
            int k = BinaryEscapes.IndexOf((char)b);
            if (b < 0x80 && k >= 0)
            {
                q.WriteByte((byte)'\\');
                q.WriteByte((byte)AsciiEscapes[k]);
            }
            else if (b < 0x20)
            {
                var e = Encoding.ASCII.GetBytes($"\\u{b:x4}");
                q.Write(e, 0, e.Length);
            }
            else q.WriteByte(b);
        }
        q.WriteByte((byte)'"');
        return q.ToArray();
    }

    private byte[] ParseSimpleType()
    {
        _i--;
        var token = new StringBuilder();
        while (true)
        {
            int c = Peek();
            if (c == ',' || c == ']' || c == '}') break;
            c = NextChar();
            if (IsWhiteSpace(c)) break;
            token.Append((char)c);
        }
        if (token.Length == 0) throw Fail("Missing argument");
        var value = token.ToString();
        if (value is "true" or "false" or "null") return Encoding.ASCII.GetBytes(value);
        if (!Number.IsMatch(value)) throw Fail("invalid JSON value: " + value);
        var n = double.Parse(value, NumberStyles.Float, CultureInfo.InvariantCulture);
        return Encoding.ASCII.GetBytes(NumberToJson(n));
    }

    private byte[] ParseArray()
    {
        var o = new MemoryStream();
        o.WriteByte((byte)'[');
        bool next = false;
        while (Peek() != ']')
        {
            if (next)
            {
                ScanFor(',');
                o.WriteByte((byte)',');
            }
            else next = true;
            var el = ParseElement();
            o.Write(el, 0, el.Length);
        }
        Scan();
        o.WriteByte((byte)']');
        return o.ToArray();
    }

    private byte[] ParseObject()
    {
        var members = new List<(byte[] Name, string Sort, byte[] Value)>();
        bool next = false;
        while (Peek() != '}')
        {
            if (next) ScanFor(',');
            next = true;
            ScanFor('"');
            var name = ParseQuotedString();
            // Sorted on UTF-16 code units; invalid UTF-8 decodes to U+FFFD exactly as Go's []rune conversion.
            var sort = Encoding.UTF8.GetString(name);
            ScanFor(':');
            var value = ParseElement();
            int at = members.Count;
            for (int k = 0; k < members.Count; k++)
            {
                int cmp = string.CompareOrdinal(sort, members[k].Sort);
                if (cmp == 0) throw Fail("Duplicate key: " + members[k].Sort);
                if (cmp < 0) { at = k; break; }
            }
            members.Insert(at, (name, sort, value));
        }
        Scan();
        var o = new MemoryStream();
        o.WriteByte((byte)'{');
        for (int k = 0; k < members.Count; k++)
        {
            if (k > 0) o.WriteByte((byte)',');
            var n = Decorate(members[k].Name);
            o.Write(n, 0, n.Length);
            o.WriteByte((byte)':');
            o.Write(members[k].Value, 0, members[k].Value.Length);
        }
        o.WriteByte((byte)'}');
        return o.ToArray();
    }

    /// <summary>ES6 Number-to-string, as Go's NumberToJSON: shortest digits, 'f' form in [1e-6, 1e21).</summary>
    internal static string NumberToJson(double v)
    {
        if (double.IsNaN(v) || double.IsInfinity(v))
            throw Fail("Invalid JSON number: " + BitConverter.DoubleToInt64Bits(v).ToString("x", CultureInfo.InvariantCulture));
        if (v == 0) return "0";
        var sign = v < 0 ? "-" : "";
        var a = Math.Abs(v);
        // "R" is the shortest round-trip form on .NET Core 3.0+, e.g. "0.1", "1E+21", "1.2345E-06".
        var r = a.ToString("R", CultureInfo.InvariantCulture);
        int exp10 = 0;
        int e = r.IndexOfAny(new[] { 'E', 'e' });
        if (e >= 0)
        {
            exp10 = int.Parse(r[(e + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
            r = r[..e];
        }
        int dot = r.IndexOf('.');
        var digits = dot < 0 ? r : r.Remove(dot, 1);
        int dp = (dot < 0 ? r.Length : dot) + exp10; // value = 0.digits * 10^dp
        int lead = digits.Length - digits.TrimStart('0').Length;
        digits = digits.TrimStart('0');
        dp -= lead;
        digits = digits.TrimEnd('0');
        int nd = digits.Length;
        if (a < 1e21 && a >= 1e-6)
        {
            if (dp <= 0) return sign + "0." + new string('0', -dp) + digits;
            if (dp >= nd) return sign + digits + new string('0', dp - nd);
            return sign + digits[..dp] + "." + digits[dp..];
        }
        int x = dp - 1;
        var mant = nd == 1 ? digits : digits[0] + "." + digits[1..];
        return sign + mant + "e" + (x < 0 ? "-" : "+") + Math.Abs(x);
    }
}
