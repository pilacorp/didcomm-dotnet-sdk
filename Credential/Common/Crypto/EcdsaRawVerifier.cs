using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

/// <summary>
/// Verifies raw ECDSA (r||s) over a pre-hashed 32-byte digest (P-256 or secp256k1).
/// </summary>
public static class EcdsaRawVerifier
{
    public static bool Verify(ECPublicKeyParameters publicKey, byte[] digest32, byte[] signature64)
    {
        if (digest32.Length != 32 || signature64.Length != 64)
        {
            return false;
        }

        var r = new BigInteger(1, signature64, 0, 32);
        var s = new BigInteger(1, signature64, 32, 32);
        var signer = new ECDsaSigner();
        signer.Init(false, publicKey);
        return signer.VerifySignature(digest32, r, s);
    }

    public static ECPublicKeyParameters PublicKeyFromHex(string publicKeyHex, string curveName)
    {
        var pubBytes = Convert.FromHexString(
            Pila.CredentialSdk.DidComm.Credential.Common.Util.Util.RemoveHexPrefix(publicKeyHex));
        var curve = SecNamedCurves.GetByName(curveName);
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        if (pubBytes.Length == 33)
        {
            pubBytes = curve.Curve.DecodePoint(pubBytes).GetEncoded(false);
        }
        var point = curve.Curve.DecodePoint(pubBytes);
        return new ECPublicKeyParameters("EC", point, domain);
    }
}
