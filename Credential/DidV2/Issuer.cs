using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public sealed class IssueDidPayload
{
    public string ContractAddress { get; set; } = "";
    public string IssuerAddress { get; set; } = "";
    public string DidAddress { get; set; } = "";
    public byte DidType { get; set; }
    public string CapId { get; set; } = "";
    public ulong Epoch { get; set; }
}

public sealed class IssuerSignature
{
    public BigInteger V { get; set; }
    public BigInteger R { get; set; }
    public BigInteger S { get; set; }
}

public static class Issuer
{
    public const string CapCreateAction = "CAP_CREATE";
    public const int CapIdLength = 32;

    public static void ValidateIssueDidPayload(IssueDidPayload p)
    {
        if (!Hex.IsAddress(p.ContractAddress)) throw new InvalidOperationException($"invalid contract address: {p.ContractAddress}");
        if (!Hex.IsAddress(p.IssuerAddress)) throw new InvalidOperationException($"invalid issuer address: {p.IssuerAddress}");
        if (!Hex.IsAddress(p.DidAddress)) throw new InvalidOperationException($"invalid did address: {p.DidAddress}");
        var cap = Hex.Normalize(p.CapId);
        if (p.CapId.Length != CapIdLength * 2 + 2 || cap.Length != CapIdLength * 2)
        {
            throw new InvalidOperationException($"invalid cap id length: expected {CapIdLength}, got {p.CapId.Length}");
        }
    }

    public static byte[] BuildIssueDidPayload(IssueDidPayload input)
    {
        ValidateIssueDidPayload(input);
        var packed = AbiEncodePacked(
            ["string", "address", "address", "uint8", "uint64", "bytes32"],
            [CapCreateAction, input.IssuerAddress, input.DidAddress, input.DidType.ToString(), input.Epoch.ToString(), input.CapId]);
        var prefix = new byte[] { 0x19, 0x00 };
        var addressBytes = Hex.ToBytes(Hex.ToAddress(input.ContractAddress));
        return EthCrypto.Packed(prefix, addressBytes, packed);
    }

    public static IssuerSignature GenerateIssueDidSignature(IssueDidPayload input, IDidSigner issuerSigner)
    {
        if (issuerSigner == null) throw new InvalidOperationException("issuer signer is required");
        var payload = BuildIssueDidPayload(input);
        var hash = EthCrypto.Keccak256(payload);
        return SignatureFromBytes(issuerSigner.Sign(hash));
    }

    public static string GenerateCapId()
    {
        var b = RandomNumberGenerator.GetBytes(CapIdLength);
        return Hex.ToHex(b);
    }

    public static IssuerSignature SignatureFromBytes(byte[] sig)
    {
        if (sig.Length != 65) throw new InvalidOperationException($"signature must be 65 bytes, got {sig.Length}");
        var v = sig[64];
        if (v < 27) v += 27;
        return new IssuerSignature
        {
            R = new BigInteger(sig[..32], isUnsigned: true, isBigEndian: true),
            S = new BigInteger(sig[32..64], isUnsigned: true, isBigEndian: true),
            V = v
        };
    }

    public static byte[] AbiEncodePacked(string[] types, string[] values)
    {
        if (types.Length != values.Length) throw new InvalidOperationException("types and values length mismatch");
        var result = new List<byte>();
        for (var i = 0; i < types.Length; i++)
        {
            result.AddRange(EncodePacked(types[i], values[i]));
        }
        return result.ToArray();
    }

    private static byte[] EncodePacked(string type, string value)
    {
        return type switch
        {
            "string" => Encoding.UTF8.GetBytes(value),
            "address" => Hex.ToBytes(Hex.ToAddress(value)),
            "uint8" => [(byte)ulong.Parse(value)],
            "uint64" => ToBe(ulong.Parse(value), 8),
            "bytes32" => Hex.Pad32(Hex.ToBytes(value)),
            _ => throw new InvalidOperationException($"unsupported type: {type}")
        };
    }

    private static byte[] ToBe(ulong value, int size)
    {
        var bytes = new byte[size];
        for (var i = size - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xff);
            value >>= 8;
        }
        return bytes;
    }
}
