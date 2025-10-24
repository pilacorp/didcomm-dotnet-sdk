using System;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;

namespace Pila.CredentialSdk.DidComm;

public static class Verifier
{
    public static bool VerifyVPSignature(string vpJson, string senderPublicKeyHex)
    {
        try
        {
            // Parse VP JSON
            var vp = JsonSerializer.Deserialize<JsonElement>(vpJson);
            
            // Extract proof from VP
            if (!vp.TryGetProperty("proof", out var proof))
            {
                Console.WriteLine("No proof found in VP");
                return false;
            }
            
            // Get JWS from proof
            if (!proof.TryGetProperty("jws", out var jwsElement))
            {
                Console.WriteLine("No jws found in proof");
                return false;
            }
            
            var jws = jwsElement.GetString();
            if (string.IsNullOrEmpty(jws))
            {
                Console.WriteLine("Empty jws");
                return false;
            }
            
            // Parse JWS (format: header.payload.signature)
            var jwsParts = jws.Split('.');
            if (jwsParts.Length != 3)
            {
                Console.WriteLine($"Invalid JWS format: {jwsParts.Length} parts");
                return false;
            }
            
            var header = jwsParts[0];
            var payload = jwsParts[1];
            var signature = jwsParts[2];
            
            // Decode header and payload
            var headerBytes = Base64UrlDecode(header);
            var payloadBytes = Base64UrlDecode(payload);
            var signatureBytes = Base64UrlDecode(signature);
            
            // Parse header to get algorithm
            var headerJson = JsonSerializer.Deserialize<JsonElement>(Encoding.UTF8.GetString(headerBytes));
            var algorithm = headerJson.GetProperty("alg").GetString();
            
            if (algorithm != "ES256K")
            {
                Console.WriteLine($"Unsupported algorithm: {algorithm}");
                return false;
            }
            
            // Create message to verify (header.payload)
            var messageToVerify = $"{header}.{payload}";
            var messageBytes = Encoding.UTF8.GetBytes(messageToVerify);
            
            // Parse sender public key
            var senderPubBytes = Convert.FromHexString(senderPublicKeyHex);
            
            // Verify signature using secp256k1
            return VerifySecp256k1Signature(senderPubBytes, messageBytes, signatureBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Verification failed: {ex.Message}");
            return false;
        }
    }
    
    private static bool VerifySecp256k1Signature(byte[] publicKeyBytes, byte[] messageBytes, byte[] signatureBytes)
    {
        try
        {
            // Create secp256k1 curve parameters
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            
            // Parse public key
            var publicKey = new ECPublicKeyParameters("EC", 
                curve.Curve.DecodePoint(publicKeyBytes), domainParams);
            
            // Create ECDSA signer
            var signer = new ECDsaSigner();
            signer.Init(false, publicKey);
            
            // Hash message with SHA256
            using var sha256 = SHA256.Create();
            var messageHash = sha256.ComputeHash(messageBytes);
            
            // Parse signature (r, s format)
            var r = new BigInteger(1, signatureBytes, 0, 32);
            var s = new BigInteger(1, signatureBytes, 32, 32);
            
            // Verify signature
            return signer.VerifySignature(messageHash, r, s);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Signature verification failed: {ex.Message}");
            return false;
        }
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
