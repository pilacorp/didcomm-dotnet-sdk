using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

/// <summary>P-256 signer for ecdsa-rdfc-2019 (64-byte r||s only).</summary>
public static class P256Signer
{
    public static byte[] Sign(byte[] digest32, string privateKeyHex)
    {
        if (digest32.Length != 32)
        {
            throw new ArgumentException("digest must be 32 bytes");
        }
        var hex = privateKeyHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? privateKeyHex[2..]
            : privateKeyHex;
        var d = new BigInteger(1, Convert.FromHexString(hex));
        var curve = SecNamedCurves.GetByName("secp256r1")
            ?? SecNamedCurves.GetByName("prime256v1")
            ?? SecNamedCurves.GetByName("P-256");
        if (d.CompareTo(BigInteger.One) < 0 || d.CompareTo(curve.N) >= 0)
        {
            throw new ArgumentException("P-256 private key must satisfy 1 <= d < curve order");
        }
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        var priv = new ECPrivateKeyParameters("EC", d, domain);
        var signer = new ECDsaSigner();
        signer.Init(true, priv);
        var rs = signer.GenerateSignature(digest32);
        var r = rs[0].ToByteArrayUnsigned();
        var s = rs[1].ToByteArrayUnsigned();
        var outBytes = new byte[64];
        Buffer.BlockCopy(r, 0, outBytes, 32 - r.Length, r.Length);
        Buffer.BlockCopy(s, 0, outBytes, 64 - s.Length, s.Length);
        return outBytes;
    }

    public static ECPublicKeyParameters PublicFromPrivate(string privateKeyHex)
    {
        var hex = privateKeyHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? privateKeyHex[2..]
            : privateKeyHex;
        var d = new BigInteger(1, Convert.FromHexString(hex));
        var curve = SecNamedCurves.GetByName("secp256r1")
            ?? SecNamedCurves.GetByName("prime256v1")
            ?? SecNamedCurves.GetByName("P-256");
        var q = curve.G.Multiply(d).Normalize();
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        return new ECPublicKeyParameters("EC", q, domain);
    }
}
