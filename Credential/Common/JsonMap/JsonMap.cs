using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.Dto;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

namespace Pila.CredentialSdk.DidComm.Credential.Common.JsonMap;

/// <summary>
/// JSON-LD map with Go go-credential-sdk jsonmap parity for signing and verification.
/// </summary>
public class JsonMap : Dictionary<string, object>
{
    public const string JwtProof2020 = "JwtProof2020";
    public const string EcdsaSecp256k1Signature2019 = "EcdsaSecp256k1Signature2019";
    public const string DataIntegrityProof = "DataIntegrityProof";
    public const string ECDSARDFC2019 = "ecdsa-rdfc-2019";
    public const string ECDSASECPKEY = "EcdsaSecp256k1VerificationKey2019";

    public byte[] ToJSON()
    {
        var data = JsonSerializer.Serialize(this);
        return Encoding.UTF8.GetBytes(data);
    }

    public Dictionary<string, object> ToMap()
    {
        var json = JsonSerializer.Serialize(this);
        return JsonSerializer.Deserialize<Dictionary<string, object>>(json)
            ?? throw new InvalidOperationException("Failed to unmarshal JSONMap");
    }

    public void AddECDSAProof(string privateKeyHex, string verificationMethod, string proofPurpose, string didBaseUrl)
    {
        var proof = new Proof
        {
            Type = DataIntegrityProof,
            Created = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            VerificationMethod = verificationMethod,
            ProofPurpose = proofPurpose,
            Cryptosuite = ECDSARDFC2019
        };
        var hashData = EcdsaHashData(proof);
        var signDigest = SHA256.HashData(hashData);
        var signature = P256Signer.Sign(signDigest, privateKeyHex);
        if (signature.Length != 64)
        {
            throw new InvalidOperationException(
                $"ecdsa-rdfc-2019 expects a 64-byte P-256 signature (r||s) but got {signature.Length}");
        }
        proof.ProofValue = Multibase.EncodeBase58Btc(signature);
        AppendProof(proof);
    }

    public byte[] GetDocumentDigest() => DocumentDigest();

    public byte[] CreateProofSigning(byte[] docHash, Proof proof) => ProofHashData(docHash, proof);

    public byte[] DocumentDigest()
    {
        var body = BodyWithoutProof();
        var canonical = Canonicalizer.CanonicalizeWithoutProof(body);
        return Canonicalizer.ComputeDigest(canonical);
    }

    public void AddCustomProof(Proof proof)
    {
        if (proof == null)
        {
            throw new ArgumentNullException(nameof(proof));
        }
        AppendProof(proof);
    }

    public bool VerifyProof(string didBaseUrl)
    {
        var proofs = RawProofList();
        if (proofs.Count == 0)
        {
            throw new InvalidOperationException("JSONMap has no proof");
        }
        foreach (var raw in proofs)
        {
            var proof = ParseRawToProof(raw)!;
            if (!VerifyOneProof(didBaseUrl, proof))
            {
                return false;
            }
        }
        return true;
    }

    private bool VerifyOneProof(string didBaseUrl, Proof proof)
    {
        var resolver = new VerificationMethodResolver(didBaseUrl);
        if (proof.Type == EcdsaSecp256k1Signature2019 || proof.Type == ECDSASECPKEY)
        {
            return VerifyEcdsaSecp256k1Proof(resolver, proof);
        }
        if (proof.Type == DataIntegrityProof && proof.Cryptosuite == ECDSARDFC2019)
        {
            var vmEntry = resolver.FindVerificationMethodAsync(proof.VerificationMethod).GetAwaiter().GetResult();
            var didPart = DidFromVerificationMethod(proof.VerificationMethod);
            var doc = resolver.ResolveDocumentAsync(didPart).GetAwaiter().GetResult();
            var pubKey = resolver.EcPublicKeyFromEntryAsync(vmEntry).GetAwaiter().GetResult();
            if (!VerifyEcdsaRdfc(pubKey, proof))
            {
                return false;
            }
            StrictPurposeCheck.Enforce(doc, vmEntry, proof.ProofPurpose, proof.Created);
            return true;
        }
        throw new NotSupportedException($"Unsupported proof type: {proof.Type}");
    }

    private bool VerifyEcdsaRdfc(Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters publicKey, Proof proof)
    {
        if (proof.ProofValue != null && proof.ProofValue.StartsWith('z'))
        {
            var signature = Multibase.DecodeBase58Btc(proof.ProofValue);
            if (signature.Length != 64)
            {
                return false;
            }
            var hashData = EcdsaHashData(proof);
            var digest = SHA256.HashData(hashData);
            return EcdsaRawVerifier.Verify(publicKey, digest, signature);
        }
        var legacyDoc = DocumentDigest();
        var hexKey = publicKey.Q.GetEncoded(false);
        return EcdsaVerifier.VerifySignature(
            Convert.ToHexString(hexKey).ToLowerInvariant(),
            proof.ProofValue!,
            legacyDoc);
    }

    private bool VerifyEcdsaSecp256k1Proof(VerificationMethodResolver resolver, Proof proof)
    {
        if (string.IsNullOrEmpty(proof.Jws))
        {
            throw new InvalidOperationException($"{EcdsaSecp256k1Signature2019}: malformed detached JWS");
        }
        var parts = JwsDetached.SplitDetachedJws(proof.Jws)
            ?? throw new InvalidOperationException($"{EcdsaSecp256k1Signature2019}: malformed detached JWS");
        var alg = JwsDetached.AlgFromEncodedHeader(parts[0]);
        if (alg != JwsDetached.AlgEs256K)
        {
            throw new InvalidOperationException($"{EcdsaSecp256k1Signature2019}: jws alg must be {JwsDetached.AlgEs256K}, got {alg}");
        }
        var vmEntry = resolver.FindVerificationMethodAsync(proof.VerificationMethod).GetAwaiter().GetResult();
        if (VerificationMethodKeyKindExtensions.FromEntry(vmEntry) != VerificationMethodKeyKind.Secp256k1)
        {
            throw new InvalidOperationException($"{EcdsaSecp256k1Signature2019}: verification method does not hold a secp256k1 key");
        }
        var didPart = DidFromVerificationMethod(proof.VerificationMethod);
        var doc = resolver.ResolveDocumentAsync(didPart).GetAwaiter().GetResult();
        var publicKey = resolver.EcPublicKeyFromEntryAsync(vmEntry).GetAwaiter().GetResult();
        var hashData = EcdsaHashData(proof);
        var signingInput = JwsDetached.SigningInput(parts[0], hashData);
        var digest = SHA256.HashData(signingInput);
        var signature = JwsDetached.DecodeCanonicalSignature(parts[1]);
        if (signature.Length == 65)
        {
            signature = signature[..64];
        }
        if (signature.Length != 64)
        {
            throw new InvalidOperationException($"{EcdsaSecp256k1Signature2019}: jws signature is {signature.Length} bytes, want 64");
        }
        var curve = SecNamedCurves.GetByName("secp256k1");
        var halfN = curve.N.ShiftRight(1);
        var s = new BigInteger(1, signature, 32, 32);
        if (s.CompareTo(halfN) > 0)
        {
            throw new InvalidOperationException($"{EcdsaSecp256k1Signature2019}: jws signature is not low-S");
        }
        if (!EcdsaRawVerifier.Verify(publicKey, digest, signature))
        {
            return false;
        }
        StrictPurposeCheck.Enforce(doc, vmEntry, proof.ProofPurpose, proof.Created);
        return true;
    }

    private static string DidFromVerificationMethod(string verificationMethodUrl)
    {
        var hashIndex = verificationMethodUrl.IndexOf('#');
        if (hashIndex <= 0)
        {
            throw new InvalidOperationException($"verification method {verificationMethodUrl} is not a DID URL");
        }
        return verificationMethodUrl[..hashIndex];
    }

    private byte[] EcdsaHashData(Proof proof)
    {
        var docHash = DocumentDigest();
        return ProofHashData(docHash, proof);
    }

    private byte[] ProofHashData(byte[] docHash, Proof proof)
    {
        if (docHash.Length != 32)
        {
            throw new ArgumentException("document digest must be 32 bytes");
        }
        var cfg = EcdsaProofConfig(proof);
        var cfgCanonical = Canonicalizer.CanonicalizeWithoutProof(cfg);
        var cfgHash = Canonicalizer.ComputeDigest(cfgCanonical);
        var hashData = new byte[64];
        Array.Copy(cfgHash, 0, hashData, 0, 32);
        Array.Copy(docHash, 0, hashData, 32, 32);
        return hashData;
    }

    private Dictionary<string, object> EcdsaProofConfig(Proof proof)
    {
        var json = JsonSerializer.Serialize(proof);
        var cfg = JsonSerializer.Deserialize<Dictionary<string, object>>(json)
            ?? throw new InvalidOperationException("failed to build proof configuration");
        var sigField = proof.Type == EcdsaSecp256k1Signature2019 ? "jws" : "proofValue";
        cfg.Remove(sigField);
        cfg["@context"] = this.TryGetValue("@context", out var ctx) ? ctx : new object();
        return cfg;
    }

    private Dictionary<string, object> BodyWithoutProof()
    {
        var body = new Dictionary<string, object>();
        foreach (var kvp in this)
        {
            if (kvp.Key != "proof")
            {
                body[kvp.Key] = kvp.Value;
            }
        }
        return body;
    }

    private void AppendProof(Proof proof)
    {
        var merged = new List<Proof>();
        foreach (var raw in RawProofList())
        {
            merged.Add(ParseRawToProof(raw)!);
        }
        merged.Add(proof);
        this["proof"] = SerializeProofs(merged);
    }

    private List<object> RawProofList()
    {
        if (!TryGetValue("proof", out var proofObj) || proofObj == null)
        {
            return new List<object>();
        }
        if (proofObj is JsonElement el)
        {
            if (el.ValueKind == JsonValueKind.Array)
            {
                return el.EnumerateArray().Select(e => (object)e).ToList();
            }
            return new List<object> { el };
        }
        if (proofObj is List<object> list)
        {
            return list;
        }
        return new List<object> { proofObj };
    }

    private static object SerializeProofs(List<Proof> proofs)
    {
        var maps = proofs.Select(SerializeProof).ToList();
        return maps.Count == 1 ? maps[0] : maps;
    }

    private static Dictionary<string, object> SerializeProof(Proof proof)
    {
        var d = new Dictionary<string, object>
        {
            ["type"] = proof.Type,
            ["created"] = proof.Created,
            ["verificationMethod"] = proof.VerificationMethod,
            ["proofPurpose"] = proof.ProofPurpose
        };
        if (!string.IsNullOrEmpty(proof.ProofValue))
        {
            d["proofValue"] = proof.ProofValue;
        }
        if (!string.IsNullOrEmpty(proof.Jws))
        {
            d["jws"] = proof.Jws;
        }
        if (!string.IsNullOrEmpty(proof.Cryptosuite))
        {
            d["cryptosuite"] = proof.Cryptosuite;
        }
        return d;
    }

    public static Proof? ParseRawToProof(object proof)
    {
        Dictionary<string, object>? proofMap = null;
        if (proof is Dictionary<string, object> dict)
        {
            proofMap = dict;
        }
        else if (proof is JsonElement jsonElement)
        {
            proofMap = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonElement.GetRawText());
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

    /// <summary>Canonical document digest (alias for DocumentDigest).</summary>
    public byte[] Canonicalize() => DocumentDigest();
}
