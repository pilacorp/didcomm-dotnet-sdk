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

    /// <summary>
    /// LOW-LEVEL / EXPERT. Signs the document with a raw P-256 private-key hex,
    /// binding the proof to the caller-supplied <paramref name="verificationMethod"/>
    /// and <paramref name="proofPurpose"/> as-is — nothing is resolved and the
    /// suite is fixed to ecdsa-rdfc-2019. The caller is responsible for making the
    /// VM id, the purpose and the key agree. Prefer the high-level
    /// <see cref="Pila.CredentialSdk.DidComm.Credential.Vc.JsonCredential.AddProofByKey"/>,
    /// which resolves the VM for the issuer and selects the suite by key kind.
    /// </summary>
    public void AddECDSAProof(string privateKeyHex, string verificationMethod, string proofPurpose, string didBaseUrl)
        => AddECDSAProof(privateKeyHex, verificationMethod, proofPurpose, didBaseUrl, null);

    /// <summary>
    /// LOW-LEVEL / EXPERT. As the four-argument overload, but when
    /// <paramref name="vmPublicKey"/> is supplied the freshly produced signature
    /// is checked against it before the proof is attached, so a signer bound to
    /// the wrong verification method fails here instead of at the verifier.
    /// </summary>
    public void AddECDSAProof(string privateKeyHex, string verificationMethod, string proofPurpose, string didBaseUrl,
        Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters? vmPublicKey,
        string? challenge = null, string? domain = null)
    {
        var proof = new Proof
        {
            Type = DataIntegrityProof,
            Created = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            VerificationMethod = verificationMethod,
            ProofPurpose = proofPurpose,
            Cryptosuite = ECDSARDFC2019,
            // Bound into the signature: EcdsaProofConfig serializes challenge/domain,
            // so they are part of the signed proof configuration (Data Integrity 3.2.5).
            Challenge = string.IsNullOrEmpty(challenge) ? null : challenge,
            Domain = string.IsNullOrEmpty(domain) ? null : domain
        };
        var hashData = EcdsaHashData(proof);
        var signDigest = SHA256.HashData(hashData);
        var signature = P256Signer.Sign(signDigest, privateKeyHex);
        if (signature.Length != 64)
        {
            throw new InvalidOperationException(
                $"ecdsa-rdfc-2019 expects a 64-byte P-256 signature (r||s) but got {signature.Length}");
        }
        if (vmPublicKey != null && !EcdsaRawVerifier.Verify(vmPublicKey, signDigest, signature))
        {
            throw new InvalidOperationException(
                $"the signature does not verify against verification method '{verificationMethod}'; the signer does not hold that key");
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

    // Legacy hex proofs (SDK &lt;= v1.7.0) were signed over the body canonicalized
    // with string-typed scalars. Only the legacy verify path uses this; the
    // modern ecdsa-rdfc-2019 path keeps DocumentDigest's spec-conformant typing.
    private byte[] LegacyDocumentDigest()
    {
        var body = BodyWithoutProof();
        var canonical = Canonicalizer.CanonicalizeWithoutProof(body, legacyStringScalars: true);
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

    /// <summary>
    /// Verifies every proof over HTTP, resolving DID documents from
    /// <paramref name="didBaseUrl"/>.
    /// </summary>
    public bool VerifyProof(string didBaseUrl)
    {
        var resolver = new VerificationMethodResolver(didBaseUrl);
        return VerifyProofInternal(did => resolver.ResolveDocumentAsync(did).GetAwaiter().GetResult());
    }

    /// <summary>
    /// Verifies every proof using an injected DID document resolver. This is the
    /// offline-capable path: the resolver never touches the network unless it is
    /// an HTTP resolver, so a static/in-memory resolver verifies without any I/O.
    /// </summary>
    public bool VerifyProof(IDidDocumentResolver resolver)
    {
        if (resolver == null) throw new ArgumentNullException(nameof(resolver));
        return VerifyProofInternal(resolver.ResolveDocument);
    }

    private bool VerifyProofInternal(Func<string, DidDocument> resolveDoc)
    {
        var proofs = RawProofList();
        if (proofs.Count == 0)
        {
            throw new InvalidOperationException("JSONMap has no proof");
        }
        foreach (var raw in proofs)
        {
            var proof = ParseRawToProof(raw)!;
            var did = DidFromVerificationMethod(proof.VerificationMethod);
            var doc = resolveDoc(did);
            if (!VerifyOneProofWithDoc(doc, proof))
            {
                return false;
            }
        }
        return true;
    }

    private bool VerifyOneProofWithDoc(DidDocument doc, Proof proof)
    {
        var vmEntry = FindVmInDoc(doc, proof.VerificationMethod);
        var pubKey = VerificationMethodMaterial.EcPublicKeyFromEntry(vmEntry);
        if (proof.Type == EcdsaSecp256k1Signature2019 || proof.Type == ECDSASECPKEY)
        {
            return VerifyEcdsaSecp256k1Proof(doc, vmEntry, pubKey, proof);
        }
        if (proof.Type == DataIntegrityProof && proof.Cryptosuite == ECDSARDFC2019)
        {
            if (!VerifyEcdsaRdfc(pubKey, proof))
            {
                return false;
            }
            StrictPurposeCheck.Enforce(doc, vmEntry, proof.ProofPurpose, proof.Created);
            return true;
        }
        throw new NotSupportedException($"Unsupported proof type: {proof.Type}");
    }

    private static VerificationMethodEntry FindVmInDoc(DidDocument doc, string vmUrl)
    {
        foreach (var vm in doc.VerificationMethod)
        {
            if (vm.Id == vmUrl)
            {
                return vm;
            }
        }
        throw new InvalidOperationException($"Verification method '{vmUrl}' not found in DID document");
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
        var legacyDoc = LegacyDocumentDigest();
        var hexKey = publicKey.Q.GetEncoded(false);
        return EcdsaVerifier.VerifySignature(
            Convert.ToHexString(hexKey).ToLowerInvariant(),
            proof.ProofValue!,
            legacyDoc);
    }

    private bool VerifyEcdsaSecp256k1Proof(DidDocument doc, VerificationMethodEntry vmEntry,
        Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters publicKey, Proof proof)
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
        if (VerificationMethodKeyKindExtensions.FromEntry(vmEntry) != VerificationMethodKeyKind.Secp256k1)
        {
            throw new InvalidOperationException($"{EcdsaSecp256k1Signature2019}: verification method does not hold a secp256k1 key");
        }
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
        // Proof configuration (Data Integrity 3.2.5): the proof object with the
        // signature field removed, plus the unsecured document's @context. The
        // keys are the JSON-LD property names (lowercase), matching the Go SDK's
        // proof.ToMap() so the canonicalized bytes are identical across SDKs.
        var cfg = SerializeProof(proof);
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
        if (!string.IsNullOrEmpty(proof.Challenge))
        {
            d["challenge"] = proof.Challenge;
        }
        if (!string.IsNullOrEmpty(proof.Domain))
        {
            d["domain"] = proof.Domain;
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
        if (proofMap.TryGetValue("challenge", out var ch) && ch != null)
        {
            result.Challenge = ch.ToString();
        }
        if (proofMap.TryGetValue("domain", out var dm) && dm != null)
        {
            result.Domain = dm.ToString();
        }
        return result;
    }

    /// <summary>Canonical document digest (alias for DocumentDigest).</summary>
    public byte[] Canonicalize() => DocumentDigest();

    /// <summary>
    /// Returns the parsed proofs attached to the document (empty when unsigned).
    /// Used by presentation verification to enforce challenge/domain on every
    /// verified proof after the signature check.
    /// </summary>
    public List<Proof> Proofs()
    {
        var result = new List<Proof>();
        foreach (var raw in RawProofList())
        {
            var p = ParseRawToProof(raw);
            if (p != null)
            {
                result.Add(p);
            }
        }
        return result;
    }
}
