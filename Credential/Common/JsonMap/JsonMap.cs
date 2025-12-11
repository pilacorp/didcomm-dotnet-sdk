using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.Dto;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

namespace Pila.CredentialSdk.DidComm.Credential.Common.JsonMap;

/// <summary>
/// Represents a JSON object as a map.
/// </summary>
public class JsonMap : Dictionary<string, object>
{
    public const string JwtProof2020 = "JwtProof2020";
    public const string EcdsaSecp256k1Signature2019 = "EcdsaSecp256k1Signature2019";
    public const string DataIntegrityProof = "DataIntegrityProof";
    public const string ECDSARDFC2019 = "ecdsa-rdfc-2019";
    public const string ECDSASECPKEY = "EcdsaSecp256k1VerificationKey2019";

    /// <summary>
    /// Serializes the JSONMap to JSON bytes.
    /// </summary>
    public byte[] ToJSON()
    {
        var data = JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            WriteIndented = false
        });

        // Validate serialization by deserializing
        var temp = JsonSerializer.Deserialize<JsonMap>(data);
        if (temp == null)
        {
            throw new InvalidOperationException("Failed to validate serialization");
        }

        return Encoding.UTF8.GetBytes(data);
    }

    /// <summary>
    /// Converts the JSONMap to a regular dictionary.
    /// </summary>
    public Dictionary<string, object> ToMap()
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(this);
        var data = JsonSerializer.Deserialize<Dictionary<string, object>>(bytes);
        
        if (data == null)
        {
            throw new InvalidOperationException("Failed to unmarshal JSONMap");
        }

        return data;
    }

    /// <summary>
    /// Canonicalizes the JSONMap for signing or verification, excluding the proof field.
    /// </summary>
    public byte[] Canonicalize()
    {
        // Create a copy without the proof field
        var mCopy = new JsonMap();
        foreach (var kvp in this)
        {
            if (kvp.Key != "proof")
            {
                mCopy[kvp.Key] = kvp.Value;
            }
        }

        // Serialize to JSON
        var encoded = JsonSerializer.SerializeToUtf8Bytes(mCopy);
        
        // Deserialize to ensure proper format
        var doc = JsonSerializer.Deserialize<Dictionary<string, object>>(encoded);
        if (doc == null)
        {
            throw new InvalidOperationException("Failed to unmarshal JSONMap copy");
        }

        // Canonicalize document (placeholder - will be filled with dotnetrdf)
        var canonicalDoc = Canonicalizer.CanonicalizeWithoutProof(doc);

        // Compute digest
        return Canonicalizer.ComputeDigest(canonicalDoc);
    }

    /// <summary>
    /// Adds an ECDSA proof to the JSONMap.
    /// </summary>
    public void AddECDSAProof(string privateKeyHex, string verificationMethod, string proofPurpose, string didBaseUrl)
    {
        if (string.IsNullOrEmpty(verificationMethod))
        {
            throw new ArgumentException("verification method is required");
        }
        if (string.IsNullOrEmpty(proofPurpose))
        {
            throw new ArgumentException("proof purpose is required");
        }

        // Verify private key matches verification method
        var resolver = new VerificationMethodResolver(didBaseUrl);
        var isValid = resolver.CheckVerificationMethodAsync(privateKeyHex, verificationMethod).GetAwaiter().GetResult();
        if (!isValid)
        {
            throw new InvalidOperationException("private key and verification method do not match");
        }

        var proof = new Proof
        {
            Type = DataIntegrityProof,
            Created = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            VerificationMethod = verificationMethod,
            ProofPurpose = proofPurpose,
            Cryptosuite = ECDSARDFC2019
        };

        var signData = Canonicalize();
        var signature = EcdsaSigner.Sign(signData, privateKeyHex);
        proof.ProofValue = Convert.ToHexString(signature).ToLowerInvariant();

        this["proof"] = SerializeProof(proof);
    }

    /// <summary>
    /// Adds a custom proof to the JSONMap.
    /// </summary>
    public void AddCustomProof(Proof proof)
    {
        if (proof == null)
        {
            throw new ArgumentNullException(nameof(proof));
        }

        this["proof"] = SerializeProof(proof);
    }

    /// <summary>
    /// Verifies an ECDSA-signed JSONMap.
    /// </summary>
    public bool VerifyProof(string didBaseUrl)
    {
        if (!TryGetValue("proof", out var proofObj) || proofObj == null)
        {
            throw new InvalidOperationException("JSONMap has no proof");
        }

        // Handle both single proof object and array of proofs
        object? proofData = proofObj;
        if (proofObj is JsonElement jsonElement)
        {
            if (jsonElement.ValueKind == JsonValueKind.Array)
            {
                if (jsonElement.GetArrayLength() > 0)
                {
                    proofData = jsonElement[0];
                }
                else
                {
                    throw new InvalidOperationException("Proof array is empty");
                }
            }
            else
            {
                proofData = jsonElement;
            }
        }
        else if (proofObj is List<object> proofList && proofList.Count > 0)
        {
            proofData = proofList[0];
        }

        var proof = ParseRawToProof(proofData);
        if (proof == null)
        {
            throw new InvalidOperationException("Failed to parse proof");
        }

        if (proof.Type == JwtProof2020)
        {
            if (!TryGetValue("issuer", out var issuerObj) || issuerObj == null)
            {
                throw new InvalidOperationException("Issuer is missing or invalid in the request");
            }

            var issuerDID = issuerObj.ToString()!;
            var resolver = new VerificationMethodResolver(didBaseUrl);
            var publicKey = resolver.GetDefaultPublicKeyAsync(issuerDID).GetAwaiter().GetResult();

            // TODO: Implement VerifyJwtProof
            throw new NotImplementedException("JwtProof2020 verification not yet implemented");
        }
        else if (proof.Type == EcdsaSecp256k1Signature2019 || proof.Type == ECDSASECPKEY)
        {
            return VerifyEcdsaProofLegacy(didBaseUrl, proof);
        }
        else if (proof.Type == DataIntegrityProof && proof.Cryptosuite == ECDSARDFC2019)
        {
            var resolver = new VerificationMethodResolver(didBaseUrl);
            var publicKey = resolver.GetPublicKeyAsync(proof.VerificationMethod).GetAwaiter().GetResult();
            return VerifyECDSA(publicKey, proof);
        }
        else
        {
            throw new NotSupportedException($"Unsupported proof type: {proof.Type}");
        }
    }

    /// <summary>
    /// Verifies an ECDSA-signed JSONMap.
    /// </summary>
    private bool VerifyECDSA(string publicKey, Proof proof)
    {
        var doc = Canonicalize();
        return EcdsaVerifier.VerifySignature(publicKey, proof.ProofValue!, doc);
    }

    /// <summary>
    /// Verifies an ECDSA-signed JSONMap (legacy format).
    /// Supports both proofValue (JSON-LD signature) and jws (JWT signature) formats.
    /// </summary>
    private bool VerifyEcdsaProofLegacy(string didBaseUrl, Proof proof)
    {
        if (!TryGetValue("proof", out var proofObj) || proofObj == null)
        {
            throw new InvalidOperationException("Proof is missing or invalid in the request");
        }

        Dictionary<string, object>? proofMap = null;
        if (proofObj is Dictionary<string, object> dict)
        {
            proofMap = dict;
        }
        else if (proofObj is JsonElement jsonElement)
        {
            var json = JsonSerializer.Serialize(jsonElement);
            proofMap = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
        }

        if (proofMap == null)
        {
            throw new InvalidOperationException("Failed to parse proof map");
        }

        // Check if proof has jws field (JWT-based signature)
        if (proofMap.TryGetValue("jws", out var jwsObj) && jwsObj != null)
        {
            var jws = jwsObj.ToString();
            if (!string.IsNullOrEmpty(jws))
            {
                return VerifyJWS(jws, didBaseUrl, proof);
            }
        }

        // Otherwise, check for proofValue (JSON-LD signature)
        if (!proofMap.TryGetValue("proofValue", out var proofValueObj) || proofValueObj == null)
        {
            throw new InvalidOperationException("Proof value is missing or invalid in the request");
        }

        var proofValue = proofValueObj.ToString();
        if (string.IsNullOrEmpty(proofValue))
        {
            throw new InvalidOperationException("Proof value is missing or invalid in the request");
        }

        if (!proofMap.TryGetValue("verificationMethod", out var vmObj) || vmObj == null)
        {
            throw new InvalidOperationException("Proof verificationMethod is missing or invalid in the request");
        }

        var verificationMethod = vmObj.ToString();
        if (string.IsNullOrEmpty(verificationMethod))
        {
            throw new InvalidOperationException("Proof verificationMethod is missing or invalid in the request");
        }

        var signatureBytes = Convert.FromHexString(proofValue);

        // Create a copy without proof
        var reqCopy = new Dictionary<string, object>();
        foreach (var kvp in this)
        {
            if (kvp.Key != "proof")
            {
                reqCopy[kvp.Key] = kvp.Value;
            }
        }

        var message = JsonSerializer.SerializeToUtf8Bytes(reqCopy);

        // Resolve public key from verification method
        var resolver = new VerificationMethodResolver(didBaseUrl);
        var publicKeyHex = resolver.GetPublicKeyAsync(verificationMethod).GetAwaiter().GetResult();

        // Remove 0x prefix if present (preserves leading zeros)
        publicKeyHex = Pila.CredentialSdk.DidComm.Credential.Common.Util.Util.RemoveHexPrefix(publicKeyHex);
        var pubBytes = Convert.FromHexString(publicKeyHex);

        // Verify JSON signature (this uses canonicalization)
        // For legacy format, we need to use the raw JSON message
        var signatureHex = Convert.ToHexString(signatureBytes).ToLowerInvariant();
        return EcdsaVerifier.VerifySignature(Convert.ToHexString(pubBytes).ToLowerInvariant(), signatureHex, message);
    }

    /// <summary>
    /// Verifies a JWS (JSON Web Signature) token in EcdsaSecp256k1Signature2019 proof.
    /// </summary>
    private bool VerifyJWS(string jwsToken, string didBaseUrl, Proof proof)
    {
        if (string.IsNullOrEmpty(proof.VerificationMethod))
        {
            throw new InvalidOperationException("VerificationMethod is required for JWS verification");
        }

        // Extract signature and message from JWS token
        var (signature, message) = GetSignatureAndMessageFromJWS(jwsToken);

        // Resolve public key from verification method
        var resolver = new VerificationMethodResolver(didBaseUrl);
        var publicKeyHex = resolver.GetDefaultPublicKeyAsync(proof.VerificationMethod).GetAwaiter().GetResult();

        // Remove 0x prefix if present (preserves leading zeros)
        publicKeyHex = Pila.CredentialSdk.DidComm.Credential.Common.Util.Util.RemoveHexPrefix(publicKeyHex);
        var pubBytes = Convert.FromHexString(publicKeyHex);
        var signatureHex = Convert.ToHexString(signature).ToLowerInvariant();

        // Verify signature (EcdsaVerifier will hash the message)
        return EcdsaVerifier.VerifySignature(Convert.ToHexString(pubBytes).ToLowerInvariant(), signatureHex, message);
    }

    /// <summary>
    /// Extracts signature and message from a JWS token.
    /// </summary>
    private static (byte[] signature, byte[] message) GetSignatureAndMessageFromJWS(string jwsToken)
    {
        var parts = jwsToken.Split('.');
        if (parts.Length != 3)
        {
            throw new ArgumentException($"Invalid JWS format: expected 3 parts, got {parts.Length}");
        }

        var headerB64 = parts[0];
        var payloadB64 = parts[1];
        var signatureB64 = parts[2];

        var signature = Base64UrlDecode(signatureB64);
        var message = Encoding.UTF8.GetBytes($"{headerB64}.{payloadB64}");

        return (signature, message);
    }

    /// <summary>
    /// Parses a raw proof object into a Proof DTO.
    /// </summary>
    public static Proof? ParseRawToProof(object proof)
    {
        Dictionary<string, object>? proofMap = null;

        if (proof is Dictionary<string, object> dict)
        {
            proofMap = dict;
        }
        else if (proof is JsonElement jsonElement)
        {
            var json = JsonSerializer.Serialize(jsonElement);
            proofMap = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
        }
        else
        {
            throw new ArgumentException($"Invalid proof format: expected Dictionary or JsonElement, got {proof.GetType()}");
        }

        if (proofMap == null)
        {
            return null;
        }

        var result = new Proof();
        
        if (proofMap.TryGetValue("type", out var type) && type != null)
        {
            result.Type = type.ToString() ?? "";
        }
        if (proofMap.TryGetValue("created", out var created) && created != null)
        {
            result.Created = created.ToString() ?? "";
        }
        if (proofMap.TryGetValue("proofPurpose", out var purpose) && purpose != null)
        {
            result.ProofPurpose = purpose.ToString() ?? "";
        }
        if (proofMap.TryGetValue("verificationMethod", out var vm) && vm != null)
        {
            result.VerificationMethod = vm.ToString() ?? "";
        }
        if (proofMap.TryGetValue("proofValue", out var pv) && pv != null)
        {
            result.ProofValue = pv.ToString();
        }
        if (proofMap.TryGetValue("jws", out var jws) && jws != null)
        {
            result.Jws = jws.ToString();
        }
        if (proofMap.TryGetValue("cryptosuite", out var cs) && cs != null)
        {
            result.Cryptosuite = cs.ToString();
        }

        return result;
    }

    /// <summary>
    /// Serializes a Proof to a dictionary.
    /// </summary>
    private static Dictionary<string, object> SerializeProof(Proof proof)
    {
        var proofDict = new Dictionary<string, object>
        {
            ["type"] = proof.Type,
            ["created"] = proof.Created,
            ["verificationMethod"] = proof.VerificationMethod,
            ["proofPurpose"] = proof.ProofPurpose
        };

        if (!string.IsNullOrEmpty(proof.ProofValue))
        {
            proofDict["proofValue"] = proof.ProofValue;
        }

        if (!string.IsNullOrEmpty(proof.Jws))
        {
            proofDict["jws"] = proof.Jws;
        }

        if (!string.IsNullOrEmpty(proof.Cryptosuite))
        {
            proofDict["cryptosuite"] = proof.Cryptosuite;
        }

        if (proof.Disclosures != null && proof.Disclosures.Count > 0)
        {
            proofDict["disclosures"] = proof.Disclosures;
        }

        if (!string.IsNullOrEmpty(proof.Challenge))
        {
            proofDict["challenge"] = proof.Challenge;
        }

        if (!string.IsNullOrEmpty(proof.Domain))
        {
            proofDict["domain"] = proof.Domain;
        }

        return proofDict;
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

