using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.Jwt;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

namespace Pila.CredentialSdk.DidComm.Credential.Vp;

/// <summary>
/// JWT Verifiable Presentation (vp+jwt). Signed with the holder's authentication
/// key; verification binds the header kid to the holder the payload names via
/// <see cref="JwtVerifier"/>. Mirrors Go credential/vp jwt_presentation.go.
/// </summary>
public class JwtPresentation : IPresentation
{
    private string _signingInput;                   // header.payload (base64url)
    private readonly PresentationData _payloadData; // the vp claim
    private Dictionary<string, object> _jwtClaims;  // top-level claims (iss, aud, nonce, ...)
    private string _signature;
    private readonly VerificationMethodKeyKind _kind; // zero (Unknown) for a parsed presentation

    private JwtPresentation(string signingInput, PresentationData payloadData,
        Dictionary<string, object> jwtClaims, string signature, VerificationMethodKeyKind kind)
    {
        _signingInput = signingInput;
        _payloadData = payloadData;
        _jwtClaims = jwtClaims;
        _signature = signature;
        _kind = kind;
    }

    public static JwtPresentation NewJwtPresentation(PresentationContents vpc, params PresentationOpt[] opts)
    {
        var payloadData = PresentationHelper.SerializePresentationContents(vpc);
        var options = Presentation.GetOptions(opts);

        var payload = new Dictionary<string, object> { ["vp"] = payloadData };
        if (!string.IsNullOrEmpty(vpc.Holder))
        {
            payload["iss"] = vpc.Holder;
            payload["sub"] = vpc.Holder;
        }
        if (vpc.ValidUntil != default)
        {
            payload["exp"] = ((DateTimeOffset)vpc.ValidUntil.ToUniversalTime()).ToUnixTimeSeconds();
        }
        if (vpc.ValidFrom != default)
        {
            var iat = ((DateTimeOffset)vpc.ValidFrom.ToUniversalTime()).ToUnixTimeSeconds();
            payload["iat"] = iat;
            payload["nbf"] = iat;
        }
        if (!string.IsNullOrEmpty(vpc.Id))
        {
            payload["jti"] = vpc.Id;
        }
        if (!string.IsNullOrEmpty(options.Challenge))
        {
            payload["nonce"] = options.Challenge;
        }
        if (!string.IsNullOrEmpty(options.Domain))
        {
            payload["aud"] = options.Domain;
        }

        // Resolve the holder's authentication VM so alg reflects the key it holds
        // and the kid is caught here if it is absent or ungranted.
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
        var signingVm = ResolveSigningVm.Resolve(vpc.Holder, "authentication", options.VerificationMethodKey, resolver);
        var kind = VerificationMethodKeyKindExtensions.FromEntry(signingVm.Vm);
        var alg = kind switch
        {
            VerificationMethodKeyKind.P256 => JwtVerifier.AlgES256,
            VerificationMethodKeyKind.Secp256k1 => JwtVerifier.AlgES256K,
            _ => throw new NotSupportedException(
                $"verification method '{signingVm.Url}' has an unsupported key type for JWT")
        };

        var header = new Dictionary<string, object>
        {
            ["typ"] = "JWT",
            ["alg"] = alg,
            ["kid"] = signingVm.Url
        };

        var signingInput = Encode(header) + "." + Encode(payload);
        var e = new JwtPresentation(signingInput, payloadData, payload, "", kind);
        e.ExecuteOptions(opts);
        return e;
    }

    public static JwtPresentation ParseJwtPresentation(string rawJwt, params PresentationOpt[] opts)
    {
        if (!Presentation.IsJwtPresentation(rawJwt))
        {
            throw new ArgumentException("invalid JWT format");
        }
        rawJwt = rawJwt.Trim('"');
        var parts = rawJwt.Split('.');

        var headerEncoded = parts[0];
        var payloadEncoded = parts[1];
        var signature = parts.Length == 3 ? parts[2] : "";

        var payloadMap = JsonSerializer.Deserialize<Dictionary<string, object>>(
            Encoding.UTF8.GetString(Util.Base64UrlDecode(payloadEncoded)))
            ?? throw new ArgumentException("failed to unmarshal payload");

        if (!payloadMap.TryGetValue("vp", out var vpData) || vpData == null)
        {
            throw new ArgumentException("vp claim not found in JWT payload");
        }

        var vpMap = JsonSerializer.Deserialize<PresentationData>(
            vpData is JsonElement je ? je.GetRawText() : JsonSerializer.Serialize(vpData))
            ?? throw new ArgumentException("vp claim is not a valid JSON object");

        var signingInput = headerEncoded + "." + payloadEncoded;
        var e = new JwtPresentation(signingInput, vpMap, payloadMap, signature, VerificationMethodKeyKind.Unknown);
        e.ExecuteOptions(opts);
        return e;
    }

    /// <summary>
    /// Signs the presentation with the holder's key resolved at construction and
    /// returns the serialized token. The suite follows that key's kind.
    /// </summary>
    public object AddProofByKey(string privateKeyHex, params PresentationOpt[] opts)
    {
        if (string.IsNullOrEmpty(privateKeyHex))
        {
            throw new ArgumentException("private key is required", nameof(privateKeyHex));
        }
        if (!string.IsNullOrEmpty(_signature))
        {
            throw new InvalidOperationException(
                "presentation is already signed; a JWT holds one signature");
        }

        var digest = Canonicalizer.ComputeDigest(Encoding.UTF8.GetBytes(_signingInput));
        byte[] sig = _kind switch
        {
            VerificationMethodKeyKind.P256 => P256Signer.Sign(digest, privateKeyHex),
            VerificationMethodKeyKind.Secp256k1 => EcdsaSigner.Sign(digest, privateKeyHex)[..64],
            _ => throw new InvalidOperationException(
                "signing key kind is unknown; build the presentation with NewJwtPresentation")
        };
        _signature = Util.Base64UrlEncode(sig);

        ExecuteOptions(Presentation.SigningOptions(opts));
        return Serialize();
    }

    public void Verify(params PresentationOpt[] opts)
    {
        var list = new List<PresentationOpt>(opts) { PresentationOpts.WithVerifyProof() };
        ExecuteOptions(list.ToArray());
    }

    public object Serialize() =>
        string.IsNullOrEmpty(_signature) ? _signingInput : _signingInput + "." + _signature;

    public byte[] GetContents() => _payloadData.ToJSON();

    public new string GetType() => "JWT";

    public object? ExtractField(string path) => PresentationHelper.ExtractFieldFromMap(_payloadData, path);

    internal void ExecuteOptions(params PresentationOpt[] opts)
    {
        var options = Presentation.GetOptions(opts);

        if (options.IsValidateVC)
        {
            PresentationHelper.VerifyCredentials(_payloadData, options);
        }

        if (options.IsVerifyProof)
        {
            if (string.IsNullOrEmpty(_signature))
            {
                throw new InvalidOperationException("presentation is not signed");
            }
            var resolver = ResolveResolver(options);
            JwtVerifier.Verify(_signingInput + "." + _signature, resolver);
            CheckChallengeAndDomain(options);
        }
    }

    private static IDidDocumentResolver ResolveResolver(PresentationOptions options)
    {
        if (options.Resolver != null)
        {
            return options.Resolver;
        }
        if (options.IsOffline)
        {
            throw new InvalidOperationException(
                "offline verification requires an injected resolver (use WithResolver)");
        }
        return new VerificationMethodResolver(options.DidBaseUrl);
    }

    /// <summary>
    /// Enforces WithExpectedChallenge / WithExpectedDomain against the nonce and
    /// aud claims, after signature verification (so the values are the signed ones).
    /// </summary>
    private void CheckChallengeAndDomain(PresentationOptions options)
    {
        if (!string.IsNullOrEmpty(options.ExpectedChallenge))
        {
            var nonce = GetStringClaim("nonce");
            if (nonce != options.ExpectedChallenge)
            {
                throw new InvalidOperationException(
                    $"nonce \"{nonce}\" does not match expected challenge \"{options.ExpectedChallenge}\"");
            }
        }

        _jwtClaims.TryGetValue("aud", out var aud);
        if (!string.IsNullOrEmpty(options.ExpectedDomain))
        {
            if (!AudContains(aud, options.ExpectedDomain))
            {
                throw new InvalidOperationException(
                    $"aud does not match expected domain \"{options.ExpectedDomain}\"");
            }
            return;
        }
        if (options.RequireAudience)
        {
            throw new InvalidOperationException(Presentation.ErrAudienceUnbound);
        }
    }

    private string GetStringClaim(string key)
    {
        if (!_jwtClaims.TryGetValue(key, out var v) || v == null)
        {
            return "";
        }
        return v switch
        {
            string s => s,
            JsonElement je when je.ValueKind == JsonValueKind.String => je.GetString() ?? "",
            _ => ""
        };
    }

    private static bool AudContains(object? aud, string domain)
    {
        switch (aud)
        {
            case string s:
                return s == domain;
            case JsonElement je when je.ValueKind == JsonValueKind.String:
                return je.GetString() == domain;
            case JsonElement je when je.ValueKind == JsonValueKind.Array:
                return je.EnumerateArray().Any(x => x.ValueKind == JsonValueKind.String && x.GetString() == domain);
            case IEnumerable<object> list:
                return list.Any(x => x?.ToString() == domain);
            default:
                return false;
        }
    }

    private static string Encode(object o) =>
        Util.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(o)));
}
