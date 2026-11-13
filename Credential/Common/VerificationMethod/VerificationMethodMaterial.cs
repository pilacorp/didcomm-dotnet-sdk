using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

namespace Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

/// <summary>
/// Extracts an EC public key from a verification method entry, regardless of the
/// key encoding it carries (JWK, Multikey or legacy secp256k1 hex). Static mirror
/// of the logic the HTTP resolver uses, so offline / injected resolvers can share it.
/// </summary>
public static class VerificationMethodMaterial
{
    public static ECPublicKeyParameters EcPublicKeyFromEntry(VerificationMethodEntry vm)
    {
        if (vm.PublicKeyJwk != null)
        {
            return JwkToPublicKey(vm.PublicKeyJwk);
        }
        if (!string.IsNullOrEmpty(vm.PublicKeyMultibase))
        {
            return Multikey.PublicKeyFromMultibase(vm.PublicKeyMultibase);
        }
        if (!string.IsNullOrEmpty(vm.PublicKeyHex))
        {
            if (VerificationMethodKeyKindExtensions.FromEntry(vm) != VerificationMethodKeyKind.Secp256k1)
            {
                throw new InvalidOperationException(
                    $"publicKeyHex is only valid for secp256k1 verification methods, got type {vm.Type}");
            }
            var hex = Util.Util.RemoveHexPrefix(vm.PublicKeyHex);
            return EcdsaRawVerifier.PublicKeyFromHex(hex, "secp256k1");
        }
        throw new InvalidOperationException($"No public key in verification method {vm.Id}");
    }

    private static ECPublicKeyParameters JwkToPublicKey(Jwk jwk)
    {
        if (jwk.Kty != "EC")
        {
            throw new NotSupportedException($"Unsupported key type: {jwk.Kty}");
        }
        var curveName = jwk.Crv switch
        {
            "secp256k1" => "secp256k1",
            "P-256" => "P-256",
            _ => throw new NotSupportedException($"Unsupported curve: {jwk.Crv}")
        };
        var xBytes = Base64UrlDecode(jwk.X);
        var yBytes = Base64UrlDecode(jwk.Y);
        var curve = SecNamedCurves.GetByName(curveName)
            ?? SecNamedCurves.GetByName("prime256v1");
        var domain = new ECDomainParameters(curve!.Curve, curve.G, curve.N, curve.H);
        var point = curve.Curve.CreatePoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
        return new ECPublicKeyParameters("EC", point, domain);
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
