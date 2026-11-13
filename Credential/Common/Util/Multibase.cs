using System.Numerics;
using System.Text;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Util;

/// <summary>
/// Multibase base58btc ('z') encoding for ecdsa-rdfc-2019 proofValue.
/// </summary>
public static class Multibase
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static string EncodeBase58Btc(byte[] raw)
    {
        if (raw.Length == 0)
        {
            return "z";
        }
        return "z" + Encode(raw);
    }

    public static byte[] DecodeBase58Btc(string multibase)
    {
        if (string.IsNullOrEmpty(multibase) || multibase[0] != 'z')
        {
            throw new ArgumentException("expected base58btc multibase prefix 'z'");
        }
        return Decode(multibase[1..]);
    }

    private static string Encode(byte[] input)
    {
        var zeros = input.TakeWhile(b => b == 0).Count();
        var value = new BigInteger(input, isUnsigned: true, isBigEndian: true);
        var sb = new StringBuilder();
        while (value > BigInteger.Zero)
        {
            value = BigInteger.DivRem(value, 58, out var rem);
            sb.Insert(0, Alphabet[(int)rem]);
        }
        sb.Insert(0, new string('1', zeros));
        return sb.ToString();
    }

    private static byte[] Decode(string input)
    {
        if (input.Length == 0)
        {
            return Array.Empty<byte>();
        }
        var value = BigInteger.Zero;
        foreach (var c in input)
        {
            var idx = Alphabet.IndexOf(c);
            if (idx < 0)
            {
                throw new ArgumentException("invalid base58 character");
            }
            value = value * 58 + idx;
        }
        var decoded = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var zeros = input.TakeWhile(ch => ch == '1').Count();
        if (decoded.Length > 1 && decoded[0] == 0)
        {
            decoded = decoded[1..];
        }
        var withZeros = new byte[zeros + decoded.Length];
        Array.Copy(decoded, 0, withZeros, zeros, decoded.Length);
        return withZeros;
    }
}
