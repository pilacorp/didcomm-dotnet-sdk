using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Pila.CredentialSdk.DidComm.Credential.DigitalCredential;

public static class DigitalCredentialCode
{
    public const string Malformed = "MALFORMED";
}

public sealed class DigitalCredentialException : Exception
{
    public string Code { get; }
    public DigitalCredentialException(string code, string message) : base(message) => Code = code;
}

public sealed class DcCredential
{
    public DcCredential(string compact) => Compact = compact;
    public string Compact { get; }
    public string Serialize() => Compact;
    public string Hash()
    {
        if (string.IsNullOrEmpty(Compact)) throw new InvalidOperationException("Hash of a nil or zero Credential");
        var jwt = Compact.Split('~')[0];
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(jwt))).ToLowerInvariant();
    }

    public static DcCredential Parse(string compact)
    {
        SplitSdJwt(compact);
        return new DcCredential(compact);
    }

    public static (string IssuerJwt, string[] Disclosures, string KbJwt) SplitSdJwt(string compact)
    {
        const int maxBytes = 1 << 20;
        const int maxDisclosures = 1000;
        if (compact.Length > maxBytes)
        {
            throw new DigitalCredentialException(DigitalCredentialCode.Malformed, $"SD-JWT of {compact.Length} bytes, at most {maxBytes}");
        }
        var tildes = compact.Count(c => c == '~');
        if (tildes == 0)
        {
            throw new DigitalCredentialException(DigitalCredentialCode.Malformed, "sdjwt: no ~ separator");
        }
        if (tildes - 1 > maxDisclosures)
        {
            throw new DigitalCredentialException(DigitalCredentialCode.Malformed, "too many disclosures");
        }
        var parts = compact.Split('~');
        var issuerJwt = parts[0];
        var kbJwt = parts[^1];
        if (!IsCompactJws(issuerJwt))
        {
            throw new DigitalCredentialException(DigitalCredentialCode.Malformed, "Issuer-signed JWT is not three non-empty dot-separated parts");
        }
        if (kbJwt != "" && !IsCompactJws(kbJwt))
        {
            throw new DigitalCredentialException(DigitalCredentialCode.Malformed, "the part after the last ~ is not a JWT (missing trailing ~?)");
        }
        var disclosures = parts[1..^1];
        var seen = new HashSet<string>();
        for (var i = 0; i < disclosures.Length; i++)
        {
            if (string.IsNullOrEmpty(disclosures[i]))
            {
                throw new DigitalCredentialException(DigitalCredentialCode.Malformed, $"empty disclosure at position {i + 1}");
            }
            if (!seen.Add(disclosures[i]))
            {
                throw new DigitalCredentialException(DigitalCredentialCode.Malformed, "disclosure given twice");
            }
        }
        return (issuerJwt, disclosures, kbJwt);
    }

    private static bool IsCompactJws(string s)
    {
        var parts = s.Split('.');
        return parts.Length == 3 && parts.All(p => p.Length > 0);
    }
}

public sealed class StatusList
{
    private const int MaxListBytes = 16 << 20;
    public int Bits { get; }
    private readonly byte[] _b;

    private StatusList(int bits, byte[] b)
    {
        Bits = bits;
        _b = b;
    }

    public static StatusList New(int size, int bits)
    {
        if (!ValidBits(bits)) throw new InvalidOperationException($"statuslist: bits {bits}, want 1, 2, 4 or 8");
        if (size < 0 || size > MaxListBytes * 8 / bits)
        {
            throw new InvalidOperationException($"statuslist: size {size} out of range for {bits}-bit entries");
        }
        return new StatusList(bits, new byte[(size * bits + 7) / 8]);
    }

    public static StatusList FromBytes(byte[] b, int bits)
    {
        if (!ValidBits(bits)) throw new InvalidOperationException($"statuslist: bits {bits}, want 1, 2, 4 or 8");
        if (b.Length > MaxListBytes) throw new InvalidOperationException($"statuslist: {b.Length} bytes, want at most {MaxListBytes}");
        return new StatusList(bits, (byte[])b.Clone());
    }

    public static StatusList Decode(string lst, int bits)
    {
        if (!ValidBits(bits)) throw new InvalidOperationException($"statuslist: bits {bits}, want 1, 2, 4 or 8");
        var raw = Base64UrlDecode(lst);
        if (raw.Length >= 2 && (raw[1] & 0x20) != 0) throw new InvalidOperationException("statuslist: lst uses a preset dictionary");
        using var input = new MemoryStream(raw);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);
        var b = output.ToArray();
        if (b.Length > MaxListBytes) throw new InvalidOperationException($"statuslist: lst inflates past {MaxListBytes} bytes");
        return new StatusList(bits, b);
    }

    public int Entries() => _b.Length * 8 / Bits;
    public byte[] Bytes() => (byte[])_b.Clone();

    public int Get(int i)
    {
        var (at, shift) = Position(i);
        return (_b[at] >> shift) & Mask();
    }

    public void Set(int i, int v)
    {
        var (at, shift) = Position(i);
        if (v > Mask()) throw new InvalidOperationException($"statuslist: value {v} does not fit in {Bits} bits");
        _b[at] = (byte)((_b[at] & ~(Mask() << shift)) | (v << shift));
    }

    public string Encode()
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            zlib.Write(_b, 0, _b.Length);
        }
        return Base64UrlEncode(output.ToArray());
    }

    private int Mask() => (1 << Bits) - 1;

    private (int At, int Shift) Position(int i)
    {
        var n = Entries();
        if (i < 0 || i >= n) throw new InvalidOperationException($"statuslist: index {i} outside [0, {n})");
        var perByte = 8 / Bits;
        return (i / perByte, (i % perByte) * Bits);
    }

    private static bool ValidBits(int bits) => bits is 1 or 2 or 4 or 8;

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static byte[] Base64UrlDecode(string input)
    {
        var base64 = input.Replace('-', '+').Replace('/', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}
