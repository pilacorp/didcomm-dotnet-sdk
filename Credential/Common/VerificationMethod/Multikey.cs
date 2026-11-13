using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;

namespace Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

/// <summary>
/// W3C Multikey (publicKeyMultibase). p256-pub multicodec 0x1200 is varint 0x80 0x24.
/// </summary>
public static class Multikey
{
    public static readonly byte[] P256PubMulticodec = [0x80, 0x24];

    public static VerificationMethodKeyKind KindFromMultibase(string multibase)
    {
        var raw = Util.Multibase.DecodeBase58Btc(multibase);
        if (raw.Length < 3)
        {
            throw new InvalidOperationException("multikey: value too short");
        }
        if (raw[0] == P256PubMulticodec[0] && raw[1] == P256PubMulticodec[1])
        {
            return VerificationMethodKeyKind.P256;
        }
        throw new InvalidOperationException($"multikey: unsupported multicodec prefix 0x{raw[0]:x2}{raw[1]:x2}");
    }

    public static ECPublicKeyParameters PublicKeyFromMultibase(string multibase)
    {
        var raw = Util.Multibase.DecodeBase58Btc(multibase);
        if (raw.Length < 3 || raw[0] != P256PubMulticodec[0] || raw[1] != P256PubMulticodec[1])
        {
            throw new InvalidOperationException("multikey: not a p256-pub multikey");
        }
        var compressed = raw[2..];
        var curve = SecNamedCurves.GetByName("secp256r1")
            ?? SecNamedCurves.GetByName("prime256v1")
            ?? SecNamedCurves.GetByName("P-256");
        var domain = new ECDomainParameters(curve!.Curve, curve.G, curve.N, curve.H);
        var point = curve.Curve.DecodePoint(compressed);
        return new ECPublicKeyParameters("EC", point, domain);
    }

    public static string EncodeP256(ECPublicKeyParameters publicKey)
    {
        var compressed = publicKey.Q.GetEncoded(true);
        var raw = new byte[P256PubMulticodec.Length + compressed.Length];
        Buffer.BlockCopy(P256PubMulticodec, 0, raw, 0, P256PubMulticodec.Length);
        Buffer.BlockCopy(compressed, 0, raw, P256PubMulticodec.Length, compressed.Length);
        return Util.Multibase.EncodeBase58Btc(raw);
    }
}
