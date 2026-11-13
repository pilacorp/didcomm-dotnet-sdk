using System.Globalization;
using System.Numerics;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public static class Hex
{
    public static string Normalize(string hex)
    {
        var s = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex;
        return s.ToLowerInvariant();
    }

    public static byte[] ToBytes(string hex)
    {
        var s = Normalize(hex);
        if (s.Length % 2 == 1)
        {
            s = "0" + s;
        }
        return Convert.FromHexString(s);
    }

    public static string ToHex(byte[] bytes, bool prefix = true)
    {
        var h = Convert.ToHexString(bytes).ToLowerInvariant();
        return prefix ? "0x" + h : h;
    }

    public static byte[] Pad32(BigInteger value)
    {
        var raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length > 32)
        {
            return raw[^32..];
        }
        var outBytes = new byte[32];
        Buffer.BlockCopy(raw, 0, outBytes, 32 - raw.Length, raw.Length);
        return outBytes;
    }

    public static byte[] Pad32(byte[] value)
    {
        if (value.Length == 32)
        {
            return value;
        }
        if (value.Length > 32)
        {
            return value[^32..];
        }
        var outBytes = new byte[32];
        Buffer.BlockCopy(value, 0, outBytes, 32 - value.Length, value.Length);
        return outBytes;
    }

    public static bool IsAddress(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }
        var s = Normalize(value);
        return s.Length == 40 && s.All(Uri.IsHexDigit);
    }

    public static string ToAddress(string value)
    {
        var s = Normalize(value);
        if (s.Length > 40)
        {
            s = s[^40..];
        }
        return "0x" + s.PadLeft(40, '0');
    }
}
