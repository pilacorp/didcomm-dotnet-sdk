using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

/// <summary>
/// ECDSA signing utilities for secp256k1.
/// </summary>
public static class EcdsaSigner
{
    /// <summary>
    /// Signs a message using ECDSA with secp256k1, producing a 65-byte [r, s, v] signature.
    /// </summary>
    public static byte[] Sign(byte[] message, string hexPrivateKey)
    {
        try
        {
            // Remove 0x prefix if present
            var privKeyHex = hexPrivateKey.StartsWith("0x") ? hexPrivateKey.Substring(2) : hexPrivateKey;
            var privKeyBytes = Convert.FromHexString(privKeyHex);

            // Create secp256k1 curve parameters
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

            // Parse private key
            var privKey = new ECPrivateKeyParameters("EC", new BigInteger(1, privKeyBytes), domainParams);

            // Create ECDSA signer
            var signer = new ECDsaSigner();
            signer.Init(true, privKey);

            // Sign
            var signature = signer.GenerateSignature(message);

            // Convert to 65-byte format [r, s, v]
            var r = signature[0].ToByteArrayUnsigned();
            var s = signature[1].ToByteArrayUnsigned();

            // Ensure r and s are 32 bytes each
            var rBytes = new byte[32];
            var sBytes = new byte[32];
            Array.Copy(r, 0, rBytes, 32 - r.Length, r.Length);
            Array.Copy(s, 0, sBytes, 32 - s.Length, s.Length);

            // Combine r, s, and recovery ID (v = 0 for now, can be computed if needed)
            var result = new byte[65];
            Array.Copy(rBytes, 0, result, 0, 32);
            Array.Copy(sBytes, 0, result, 32, 32);
            result[64] = 0; // Recovery ID

            return result;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"ECDSA signing failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Signs a string message using ECDSA with secp256k1.
    /// </summary>
    public static byte[] SignString(string message, string hexPrivateKey)
    {
        var messageBytes = Encoding.UTF8.GetBytes(message);
        return Sign(messageBytes, hexPrivateKey);
    }

    /// <summary>
    /// Signs a string and returns the signature as base64url-encoded string (for JWT).
    /// </summary>
    public static string SignStringBase64Url(string message, string hexPrivateKey)
    {
        var signature = SignString(message, hexPrivateKey);
        // For JWT, return only r and s (64 bytes), excluding recovery ID
        var rAndS = new byte[64];
        Array.Copy(signature, 0, rAndS, 0, 64);
        return Base64UrlEncode(rAndS);
    }

    private static string Base64UrlEncode(byte[] input)
    {
        var base64 = Convert.ToBase64String(input);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}

