using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

/// <summary>
/// ECDSA signature verification utilities for secp256k1.
/// </summary>
public static class EcdsaVerifier
{
    /// <summary>
    /// Verifies an ECDSA signature.
    /// </summary>
    /// <param name="publicKeyHex">Public key in hex format (without 0x prefix)</param>
    /// <param name="signatureHex">Signature in hex format (64 or 65 bytes)</param>
    /// <param name="message">Message bytes to verify</param>
    /// <returns>True if signature is valid, false otherwise</returns>
    public static bool VerifySignature(string publicKeyHex, string signatureHex, byte[] message)
    {
        try
        {
            // Decode hex-encoded public key
            var pubKeyBytes = Convert.FromHexString(publicKeyHex);

            // Handle compressed public key (33 bytes)
            if (pubKeyBytes.Length == 33 && (pubKeyBytes[0] == 0x02 || pubKeyBytes[0] == 0x03))
            {
                var curve = SecNamedCurves.GetByName("secp256k1");
                var point = curve.Curve.DecodePoint(pubKeyBytes);
                pubKeyBytes = point.GetEncoded(false); // Uncompressed format
            }

            // Decode hex-encoded signature
            var sigBytes = Convert.FromHexString(signatureHex);

            // Handle signature length (64 bytes for r,s or 65 bytes for r,s,v where v is last)
            byte[] rsBytes;
            if (sigBytes.Length == 65)
            {
                rsBytes = sigBytes.Take(64).ToArray(); // drop trailing v
            }
            else if (sigBytes.Length == 64)
            {
                rsBytes = sigBytes;
            }
            else
            {
                throw new ArgumentException($"Invalid signature length: got {sigBytes.Length}, want 64 or 65 bytes");
            }

            // Create secp256k1 curve parameters
            var curveParams = SecNamedCurves.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            // Parse public key
            var publicKeyPoint = curveParams.Curve.DecodePoint(pubKeyBytes);
            var publicKey = new ECPublicKeyParameters("EC", publicKeyPoint, domainParams);

            // Create ECDSA signer for verification
            var signer = new ECDsaSigner();
            signer.Init(false, publicKey);

            // Parse signature (r, s format)
            var r = new BigInteger(1, rsBytes, 0, 32);
            var s = new BigInteger(1, rsBytes, 32, 32);

            // Verify signature
            return signer.VerifySignature(message, r, s);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"ECDSA verification failed: {ex.Message}", ex);
        }
    }
}

