using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

/// <summary>
/// ECDSA key pair verification utilities.
/// </summary>
public static class EcdsaKeyVerifier
{
    /// <summary>
    /// Verifies if a private key (hex) and public key (hex) match.
    /// </summary>
    public static bool VerifyKeyPairFromHex(string privateKeyHex, string publicKeyHex)
    {
        try
        {
            // Remove 0x prefix if present
            var privKeyHex = privateKeyHex.StartsWith("0x") ? privateKeyHex.Substring(2) : privateKeyHex;
            var pubKeyHex = publicKeyHex.StartsWith("0x") ? publicKeyHex.Substring(2) : publicKeyHex;

            var privKeyBytes = Convert.FromHexString(privKeyHex);
            var pubKeyBytes = Convert.FromHexString(pubKeyHex);

            // Create secp256k1 curve parameters
            var curve = SecNamedCurves.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

            // Parse private key
            var privKey = new ECPrivateKeyParameters("EC", new BigInteger(1, privKeyBytes), domainParams);

            // Derive public key from private key
            var derivedPubKeyPoint = curve.G.Multiply(privKey.D);
            var derivedPubKeyBytes = derivedPubKeyPoint.GetEncoded(false);

            // Handle compressed public key (33 bytes) by converting to uncompressed (65 bytes)
            if (pubKeyBytes.Length == 33 && (pubKeyBytes[0] == 0x02 || pubKeyBytes[0] == 0x03))
            {
                var point = curve.Curve.DecodePoint(pubKeyBytes);
                pubKeyBytes = point.GetEncoded(false);
            }

            // Compare the derived public key with the provided public key
            return derivedPubKeyBytes.SequenceEqual(pubKeyBytes);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Key pair verification failed: {ex.Message}", ex);
        }
    }
}

