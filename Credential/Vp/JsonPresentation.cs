using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using JsonMapType = Pila.CredentialSdk.DidComm.Credential.Common.JsonMap.JsonMap;

namespace Pila.CredentialSdk.DidComm.Credential.Vp;

/// <summary>
/// JSON-LD Verifiable Presentation. Signed with the holder's authentication key
/// (ecdsa-rdfc-2019), challenge/domain bound into the proof. Mirrors Go
/// credential/vp json_presentation.go.
/// </summary>
public class JsonPresentation : IPresentation
{
    private readonly JsonMapType _jsonMap;

    private JsonPresentation(JsonMapType map) => _jsonMap = map;

    public static JsonPresentation NewJsonPresentation(PresentationContents vpc, params PresentationOpt[] opts)
    {
        var data = PresentationHelper.SerializePresentationContents(vpc);
        var e = new JsonPresentation(data);
        e.ExecuteOptions(opts);
        return e;
    }

    public static JsonPresentation ParseJsonPresentation(byte[] rawJson, params PresentationOpt[] opts)
    {
        if (rawJson == null || rawJson.Length == 0)
        {
            throw new ArgumentException("JSON string is empty");
        }
        if (!Presentation.IsJsonPresentation(rawJson))
        {
            throw new ArgumentException("invalid JSON format");
        }

        var map = JsonSerializer.Deserialize<PresentationData>(Encoding.UTF8.GetString(rawJson),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = false })
            ?? throw new ArgumentException("failed to unmarshal presentation");

        var e = new JsonPresentation(map);
        e.ExecuteOptions(opts);
        return e;
    }

    /// <summary>
    /// HIGH-LEVEL signing. Resolves the holder's authentication verification
    /// method through the configured resolver, selects the suite from the resolved
    /// key kind (P-256 =&gt; ecdsa-rdfc-2019), binds the signer to that key, and
    /// signs with any challenge/domain bound into the proof. Returns the serialized
    /// presentation. A resolver is required (offline forbids the HTTP fallback).
    /// </summary>
    public object AddProofByKey(string privateKeyHex, params PresentationOpt[] opts)
    {
        if (string.IsNullOrEmpty(privateKeyHex))
        {
            throw new ArgumentException("private key is required", nameof(privateKeyHex));
        }

        var options = Presentation.GetOptions(opts);

        var holder = HolderDid()
            ?? throw new InvalidOperationException("holder is missing or invalid");

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

        var signingVm = ResolveSigningVm.Resolve(holder, "authentication", options.VerificationMethodKey, resolver);
        var kind = VerificationMethodKeyKindExtensions.FromEntry(signingVm.Vm);
        switch (kind)
        {
            case VerificationMethodKeyKind.P256:
                var vmPub = VerificationMethodMaterial.EcPublicKeyFromEntry(signingVm.Vm);
                _jsonMap.AddECDSAProof(privateKeyHex, signingVm.Url, "authentication", options.DidBaseUrl, vmPub,
                    options.Challenge, options.Domain);
                break;
            case VerificationMethodKeyKind.Secp256k1:
                throw new NotSupportedException(
                    "secp256k1 EcdsaSecp256k1Signature2019 linked-data signing is not implemented in the .NET SDK yet; " +
                    "sign a JSON-LD presentation with a P-256 (ecdsa-rdfc-2019) authentication key. " +
                    "secp256k1 proofs can still be verified.");
            default:
                throw new NotSupportedException(
                    $"verification method '{signingVm.Url}' has an unsupported key type");
        }

        return Serialize();
    }

    public void Verify(params PresentationOpt[] opts)
    {
        var list = new List<PresentationOpt>(opts) { PresentationOpts.WithVerifyProof() };
        ExecuteOptions(list.ToArray());
    }

    public object Serialize()
    {
        if (!_jsonMap.ContainsKey("proof"))
        {
            throw new InvalidOperationException("presentation must have proof before serialization");
        }
        return _jsonMap.ToMap();
    }

    public byte[] GetContents() => _jsonMap.ToJSON();

    public new string GetType() => "JSON";

    public object? ExtractField(string path) => PresentationHelper.ExtractFieldFromMap((PresentationData)_jsonMap, path);

    internal void ExecuteOptions(params PresentationOpt[] opts)
    {
        var options = Presentation.GetOptions(opts);

        if (options.IsValidateVC)
        {
            PresentationHelper.VerifyCredentials((PresentationData)_jsonMap, options);
        }

        if (options.IsVerifyProof)
        {
            VerifyInternal(options);
            CheckChallengeAndDomain(options);
        }
    }

    private void VerifyInternal(PresentationOptions options)
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
            throw new InvalidOperationException("invalid proof");
        }
    }

    /// <summary>
    /// Enforces WithExpectedChallenge / WithExpectedDomain on EVERY verified proof,
    /// after signature verification (mirror Go checkChallengeAndDomain).
    /// </summary>
    private void CheckChallengeAndDomain(PresentationOptions options)
    {
        if (options.RequireAudience && string.IsNullOrEmpty(options.ExpectedDomain))
        {
            throw new InvalidOperationException(Presentation.ErrAudienceUnbound);
        }
        if (string.IsNullOrEmpty(options.ExpectedChallenge) && string.IsNullOrEmpty(options.ExpectedDomain))
        {
            return;
        }

        foreach (var p in _jsonMap.Proofs())
        {
            if (!string.IsNullOrEmpty(options.ProofVerificationMethod)
                && p.VerificationMethod != options.ProofVerificationMethod)
            {
                continue;
            }
            if (!string.IsNullOrEmpty(options.ExpectedChallenge) && p.Challenge != options.ExpectedChallenge)
            {
                throw new InvalidOperationException(
                    $"proof ({p.VerificationMethod}): challenge \"{p.Challenge}\" does not match expected \"{options.ExpectedChallenge}\"");
            }
            if (!string.IsNullOrEmpty(options.ExpectedDomain) && p.Domain != options.ExpectedDomain)
            {
                throw new InvalidOperationException(
                    $"proof ({p.VerificationMethod}): domain \"{p.Domain}\" does not match expected \"{options.ExpectedDomain}\"");
            }
        }
    }

    private string? HolderDid()
    {
        if (!_jsonMap.TryGetValue("holder", out var h) || h == null)
        {
            return null;
        }
        switch (h)
        {
            case string s when !string.IsNullOrEmpty(s):
                return s;
            case JsonElement je when je.ValueKind == JsonValueKind.String:
                return je.GetString();
            case JsonElement je when je.ValueKind == JsonValueKind.Object
                                     && je.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String:
                return id.GetString();
            case IDictionary<string, object> dict when dict.TryGetValue("id", out var idObj) && idObj is string idStr:
                return idStr;
            default:
                return null;
        }
    }
}
