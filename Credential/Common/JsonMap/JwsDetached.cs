using System.Text;
using System.Text.Json;

namespace Pila.CredentialSdk.DidComm.Credential.Common.JsonMap;

/// <summary>RFC 7797 detached JWS helpers (b64:false, crit:[b64]).</summary>
public static class JwsDetached
{
    public const string AlgEs256K = "ES256K";

    public static string EncodeHeader(string alg)
    {
        var header = new Dictionary<string, object>
        {
            ["alg"] = alg,
            ["b64"] = false,
            ["crit"] = new[] { "b64" }
        };
        var json = JsonSerializer.Serialize(header);
        return Base64UrlEncode(Encoding.UTF8.GetBytes(json));
    }

    public static string AlgFromEncodedHeader(string encHeader)
    {
        var headerBytes = Base64UrlDecode(encHeader);
        using var doc = JsonDocument.Parse(headerBytes);
        var root = doc.RootElement;
        if (!root.TryGetProperty("alg", out var algEl))
        {
            throw new InvalidOperationException("jws header missing alg");
        }
        if (!root.TryGetProperty("b64", out var b64El) || b64El.ValueKind != JsonValueKind.False)
        {
            throw new InvalidOperationException("jws header b64 must be false");
        }
        if (!root.TryGetProperty("crit", out var critEl) || critEl.ValueKind != JsonValueKind.Array
            || !critEl.EnumerateArray().Any(e => e.GetString() == "b64"))
        {
            throw new InvalidOperationException("jws header crit must include b64");
        }
        return algEl.GetString() ?? throw new InvalidOperationException("jws header missing alg");
    }

    public static byte[] SigningInput(string encHeader, byte[] payload)
    {
        var headerBytes = Encoding.ASCII.GetBytes(encHeader);
        var result = new byte[headerBytes.Length + 1 + payload.Length];
        Array.Copy(headerBytes, result, headerBytes.Length);
        result[headerBytes.Length] = (byte)'.';
        Array.Copy(payload, 0, result, headerBytes.Length + 1, payload.Length);
        return result;
    }

    public static string[]? SplitDetachedJws(string jws)
    {
        var idx = jws.IndexOf("..", StringComparison.Ordinal);
        if (idx <= 0)
        {
            return null;
        }
        var header = jws[..idx];
        var sig = jws[(idx + 2)..];
        if (header.Length == 0 || sig.Length == 0)
        {
            return null;
        }
        return new[] { header, sig };
    }

    public static byte[] DecodeCanonicalSignature(string encSig)
    {
        var decoded = Base64UrlDecode(encSig);
        var reencoded = Base64UrlEncode(decoded);
        if (!reencoded.Equals(encSig, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("non-canonical base64url jws signature");
        }
        return decoded;
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}
