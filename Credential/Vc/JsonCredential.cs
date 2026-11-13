using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Dto;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using JsonMapType = Pila.CredentialSdk.DidComm.Credential.Common.JsonMap.JsonMap;

namespace Pila.CredentialSdk.DidComm.Credential.Vc;

/// <summary>
/// JSON-LD Verifiable Credential implementation.
/// </summary>
public class JsonCredential : ICredential
{
    private JsonMapType _jsonMap;
    private string _verificationMethod;

    private JsonCredential(Dictionary<string, object> credentialData, string verificationMethod)
    {
        _jsonMap = new JsonMapType();
        foreach (var kvp in credentialData)
        {
            _jsonMap[kvp.Key] = kvp.Value;
        }
        _verificationMethod = verificationMethod;
    }

    /// <summary>
    /// Creates a new JSON credential from CredentialContents.
    /// </summary>
    public static JsonCredential NewJsonCredential(CredentialContents vcc, params CredentialOpt[] opts)
    {
        var options = Credential.GetOptions(opts);

        var credentialData = CredentialHelper.SerializeCredentialContents(vcc);

        var credential = new JsonCredential(credentialData, options.VerificationMethodKey);

        // Execute options if needed
        credential.ExecuteOptions(opts);

        return credential;
    }

    /// <summary>
    /// Parses a JSON credential from raw JSON bytes.
    /// </summary>
    public static JsonCredential ParseJsonCredential(byte[] rawJson, params CredentialOpt[] opts)
    {
        var options = Credential.GetOptions(opts);

        if (rawJson == null || rawJson.Length == 0)
        {
            throw new ArgumentException("JSON string is empty");
        }

        var jsonString = Encoding.UTF8.GetString(rawJson);
        var credentialData = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonString, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        if (credentialData == null)
        {
            throw new ArgumentException("Failed to parse JSON credential");
        }

        var credential = new JsonCredential(credentialData, options.VerificationMethodKey);

        // Execute options if needed
        credential.ExecuteOptions(opts);

        return credential;
    }

    /// <summary>
    /// LOW-LEVEL / EXPERT. Adds a P-256 ecdsa-rdfc-2019 proof with a raw
    /// private-key hex. The verification method is <c>issuer#verificationMethodKey</c>,
    /// resolved through <see cref="CredentialOptions.Resolver"/> when one is set,
    /// and the suite is fixed to ecdsa-rdfc-2019 regardless of the key's kind.
    /// Prefer <see cref="AddProofByKey"/>, which resolves the signing VM for the
    /// issuer, selects the proof suite by the resolved key's kind, binds the
    /// signer to that key, and honours offline mode.
    /// </summary>
    public void AddProof(string privateKeyHex, params CredentialOpt[] opts)
    {
        var options = Credential.GetOptions(opts);

        if (!_jsonMap.TryGetValue("issuer", out var issuerObj) || issuerObj == null)
        {
            throw new InvalidOperationException("Issuer is required to add proof");
        }

        var issuer = issuerObj.ToString()!;
        var vmKey = string.IsNullOrEmpty(options.VerificationMethodKey) ? _verificationMethod : options.VerificationMethodKey;
        var verificationMethod = $"{issuer}#{vmKey}";
        if (options.Resolver != null)
        {
            verificationMethod = ResolveSigningVm.Resolve(issuer, "assertionMethod", vmKey, options.Resolver).Url;
        }

        // Use JsonMap to add proof
        _jsonMap.AddECDSAProof(privateKeyHex, verificationMethod, "assertionMethod", options.DidBaseUrl);
    }

    /// <summary>
    /// HIGH-LEVEL issuance. Resolves the signing verification method for the
    /// credential's issuer (DID + assertionMethod + key) through the configured
    /// resolver, selects the proof suite from the resolved key's kind
    /// (P-256 =&gt; DataIntegrityProof / ecdsa-rdfc-2019), binds the signer to that
    /// key, signs, and returns the serialized credential. The caller supplies
    /// only the private key and options (resolver / offline / verificationMethodKey);
    /// it never picks a verification-method id, a proof purpose or a suite.
    /// Mirrors Go <c>vc.JSONCredential.AddProofByProvider</c>.
    /// </summary>
    /// <returns>The serialized credential (with its proof attached).</returns>
    public object AddProofByKey(string privateKeyHex, params CredentialOpt[] opts)
    {
        if (string.IsNullOrEmpty(privateKeyHex))
        {
            throw new ArgumentException("private key is required", nameof(privateKeyHex));
        }

        var options = Credential.GetOptions(opts);

        if (!_jsonMap.TryGetValue("issuer", out var issuerObj) || issuerObj == null)
        {
            throw new InvalidOperationException("Issuer is required to add proof");
        }

        var issuer = issuerObj.ToString()!;
        var vmKey = string.IsNullOrEmpty(options.VerificationMethodKey) ? _verificationMethod : options.VerificationMethodKey;

        // A resolver is required at signing time: the suite is chosen from the
        // resolved VM's key type. Offline mode forbids falling back to HTTP.
        var resolver = options.Resolver;
        if (resolver == null)
        {
            if (options.IsOffline)
            {
                throw new InvalidOperationException(
                    "offline signing requires an injected resolver (use WithResolver)");
            }
            resolver = new VerificationMethodResolver(options.DidBaseUrl);
        }

        var signingVm = ResolveSigningVm.Resolve(issuer, "assertionMethod", vmKey, resolver);
        var kind = VerificationMethodKeyKindExtensions.FromEntry(signingVm.Vm);
        switch (kind)
        {
            case VerificationMethodKeyKind.P256:
                var vmPub = VerificationMethodMaterial.EcPublicKeyFromEntry(signingVm.Vm);
                _jsonMap.AddECDSAProof(privateKeyHex, signingVm.Url, "assertionMethod", options.DidBaseUrl, vmPub);
                break;
            case VerificationMethodKeyKind.Secp256k1:
                throw new NotSupportedException(
                    "secp256k1 EcdsaSecp256k1Signature2019 linked-data signing is not implemented in the .NET SDK yet; " +
                    "sign with a P-256 (ecdsa-rdfc-2019) verification method, or supply a secp256k1 detached-JWS signer. " +
                    "secp256k1 proofs can still be verified.");
            default:
                throw new NotSupportedException(
                    $"verification method '{signingVm.Url}' has an unsupported key type");
        }

        return Serialize();
    }

    /// <summary>
    /// Gets the signing input (canonicalized document without proof).
    /// </summary>
    public byte[] GetSigningInput()
    {
        return _jsonMap.GetDocumentDigest();
    }

    public byte[] CreateProofSigning(byte[] docHash, Proof proof)
    {
        return _jsonMap.CreateProofSigning(docHash, proof);
    }

    /// <summary>
    /// Adds a custom proof to the credential.
    /// </summary>
    public void AddCustomProof(Proof proof, params CredentialOpt[] opts)
    {
        if (proof == null)
        {
            throw new ArgumentNullException(nameof(proof));
        }

        if (string.IsNullOrEmpty(proof.ProofValue) && string.IsNullOrEmpty(proof.Jws))
        {
            throw new ArgumentException("Proof must have either proofValue or jws");
        }

        // Use JsonMap to add custom proof
        _jsonMap.AddCustomProof(proof);
    }

    /// <summary>
    /// Verifies the credential proof.
    /// </summary>
    public void Verify(params CredentialOpt[] opts)
    {
        VerifyInternal(Credential.GetOptions(opts));
    }

    /// <summary>
    /// Verifies the proof honouring the injected resolver and offline mode:
    /// an injected resolver is used directly (no network); offline mode without a
    /// resolver is refused; otherwise DID documents are resolved over HTTP.
    /// </summary>
    private void VerifyInternal(CredentialOptions options)
    {
        bool isValid;
        if (options.Resolver != null)
        {
            isValid = _jsonMap.VerifyProof(options.Resolver);
        }
        else if (options.IsOffline)
        {
            throw new InvalidOperationException(
                "offline verification requires an injected resolver (use WithResolver)");
        }
        else
        {
            isValid = _jsonMap.VerifyProof(options.DidBaseUrl);
        }

        if (!isValid)
        {
            throw new InvalidOperationException("Proof verification failed");
        }
    }

    /// <summary>
    /// Serializes the credential to a dictionary.
    /// </summary>
    public object Serialize()
    {
        if (!_jsonMap.ContainsKey("proof"))
        {
            throw new InvalidOperationException("Credential must have proof before serialization");
        }

        return _jsonMap.ToMap();
    }

    /// <summary>
    /// Gets the credential contents as JSON bytes.
    /// </summary>
    public byte[] GetContents()
    {
        return _jsonMap.ToJSON();
    }

    /// <summary>
    /// Gets the credential type.
    /// </summary>
    public new string GetType()
    {
        return "JSON";
    }

    /// <summary>
    /// Executes credential options (internal).
    /// </summary>
    public void ExecuteOptions(params CredentialOpt[] opts)
    {
        var options = Credential.GetOptions(opts);

        if (options.IsValidateSchema)
        {
            throw new NotImplementedException("Schema validation is not implemented yet.");
        }

        if (options.IsVerifyProof)
        {
            VerifyInternal(options);
        }
    }
}

