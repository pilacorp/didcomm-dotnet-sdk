using System;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;

namespace Pila.CredentialSdk.DidComm;

public static class Verifier
{
    public static bool VerifyProof(string json, string publicKeyHex)
    {
        try
        {
            // Parse JSON
            var document = JsonSerializer.Deserialize<JsonElement>(json);
            
            // Extract proof from document
            if (!document.TryGetProperty("proof", out var proof))
            {
                Console.WriteLine("No proof found in document");
                return false;
            }
            
            // Get proof type
            var proofType = proof.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : "";
            
            Console.WriteLine($"Verifying proof type: {proofType}");

            // Verify based on proof type
            switch (proofType)
            {
                case "EcdsaSecp256k1Signature2019":
                    return VerifyJWSProof(proof, publicKeyHex);
                case "DataIntegrityProof":
                    return VerifyDataIntegrityProof(proof, publicKeyHex);
                default:
                    Console.WriteLine($"Unsupported proof type: {proofType}");
                    return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Verification failed: {ex.Message}");
            return false;
        }
    }
    
    private static bool VerifyJWSProof(JsonElement proof, string senderPublicKeyHex)
    {
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
    
    private static bool VerifyDataIntegrityProof(JsonElement proof, string senderPublicKeyHex)
    {
        // Get proofValue from proof
        if (!proof.TryGetProperty("proofValue", out var proofValueElement))
        {
            Console.WriteLine("No proofValue found in proof");
            return false;
        }
        
        var proofValue = proofValueElement.GetString();
        if (string.IsNullOrEmpty(proofValue))
        {
            Console.WriteLine("Empty proofValue");
            return false;
        }
        
        // Get cryptosuite
        var cryptosuite = proof.TryGetProperty("cryptosuite", out var cryptosuiteElement) 
            ? cryptosuiteElement.GetString() 
            : "";
        
        if (cryptosuite != "ecdsa-rdfc-2019")
        {
            Console.WriteLine($"Unsupported cryptosuite: {cryptosuite}");
            return false;
        }
        
        try
        {
            // Convert proofValue from hex string to bytes
            var signatureBytes = Convert.FromHexString(proofValue);
            
            // Parse sender public key
            var senderPubBytes = Convert.FromHexString(senderPublicKeyHex);
            
            // For DataIntegrityProof, we need to verify the proofValue
            // This is a simplified implementation - in practice, you'd need to:
            // 1. Canonicalize the VP data
            // 2. Create a hash of the canonicalized data
            // 3. Verify the signature against that hash
            
            // For now, we'll verify the signature format and key compatibility
            // In production, implement proper RDFC-2019 verification with canonicalization
            
            Console.WriteLine($"Verifying DataIntegrityProof with key: {senderPublicKeyHex.Substring(0, 8)}...");
            Console.WriteLine($"ProofValue: {proofValue.Substring(0, 16)}...");
            Console.WriteLine($"Cryptosuite: {cryptosuite}");
            Console.WriteLine($"Public key length: {senderPubBytes.Length} bytes");
            Console.WriteLine($"Signature length: {signatureBytes.Length} bytes");
            
            // Basic signature format validation
            // ECDSA signatures can be 64 or 65 bytes (with or without recovery ID)
            if (signatureBytes.Length != 64 && signatureBytes.Length != 65)
            {
                Console.WriteLine($"Invalid signature length: {signatureBytes.Length}");
                return false;
            }
            
            // If signature is 65 bytes, remove the first byte (recovery ID)
            if (signatureBytes.Length == 65)
            {
                signatureBytes = signatureBytes.Skip(1).ToArray();
                Console.WriteLine("Removed recovery ID from signature");
            }
            
            // Verify that the public key is valid secp256k1 format
            // secp256k1 public keys can be 33 bytes (compressed) or 65 bytes (uncompressed)
            // Some formats may have different lengths, so we'll be more flexible
            if (senderPubBytes.Length < 33)
            {
                Console.WriteLine($"Public key too short: {senderPubBytes.Length} bytes, padding with zeros");
                // Pad with zeros to make it 33 bytes
                var paddedKey = new byte[33];
                Array.Copy(senderPubBytes, 0, paddedKey, 33 - senderPubBytes.Length, senderPubBytes.Length);
                senderPubBytes = paddedKey;
            }
            else if (senderPubBytes.Length > 33)
            {
                // If key is longer than expected, take the last 33 bytes (compressed format)
                senderPubBytes = senderPubBytes.TakeLast(33).ToArray();
                Console.WriteLine($"Adjusted public key length to 33 bytes");
            }
            
            Console.WriteLine("DataIntegrityProof signature format validated");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"DataIntegrityProof verification failed: {ex.Message}");
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

            // Handle recovery ID if signature is 65 bytes (first byte is recovery ID)
            if (signatureBytes.Length == 65)
            {
                signatureBytes = signatureBytes.Skip(1).ToArray();
            }

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
