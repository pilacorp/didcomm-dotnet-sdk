using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using JsonMapType = Pila.CredentialSdk.DidComm.Credential.Common.JsonMap.JsonMap;

namespace Pila.CredentialSdk.DidComm.Credential.Vp;

/// <summary>
/// Package-level configuration for presentations. Mirrors Go credential/vp Init.
/// </summary>
public static class PresentationConfig
{
    public static string BaseUrl { get; private set; } = "https://api.ndadid.vn/api/v1/did";

    public static void Init(string baseUrl)
    {
        if (!string.IsNullOrEmpty(baseUrl))
        {
            BaseUrl = baseUrl;
        }
    }
}

/// <summary>
/// Presentation data in JSON form (suitable for both JWT and JSON-LD presentations).
/// Equivalent to Go's type PresentationData jsonmap.JSONMap.
/// </summary>
public class PresentationData : JsonMapType
{
}

/// <summary>
/// Structured contents of a Verifiable Presentation.
/// </summary>
public class PresentationContents
{
    public List<object> Context { get; set; } = new();
    public string Id { get; set; } = string.Empty;
    public List<string> Types { get; set; } = new();
    public string Holder { get; set; } = string.Empty;
    public DateTime ValidFrom { get; set; }
    public DateTime ValidUntil { get; set; }

    /// <summary>Embedded credentials (already-signed ICredential instances).</summary>
    public List<ICredential> VerifiableCredentials { get; set; } = new();
}

/// <summary>Interface for Verifiable Presentations.</summary>
public interface IPresentation
{
    void Verify(params PresentationOpt[] opts);
    object Serialize();
    byte[] GetContents();
    string GetType();
    object? ExtractField(string path);
}

/// <summary>Presentation option function type.</summary>
public delegate void PresentationOpt(PresentationOptions options);

/// <summary>Configuration options for presentation processing.</summary>
public class PresentationOptions
{
    public bool IsValidateVC { get; set; } = false;

    /// <summary>Forwarded to every embedded credential's Verify when IsValidateVC is set.</summary>
    public List<CredentialOpt> VcOpts { get; set; } = new();

    public bool IsVerifyProof { get; set; } = false;
    public string DidBaseUrl { get; set; } = PresentationConfig.BaseUrl;
    public string VerificationMethodKey { get; set; } = string.Empty;
    public IDidDocumentResolver? Resolver { get; set; }
    public bool IsOffline { get; set; } = false;
    public string ProofVerificationMethod { get; set; } = string.Empty;

    // Signing: written into proof.challenge / proof.domain (JSON-LD) or nonce / aud (JWT).
    public string Challenge { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;

    // Verifying: every checked proof must carry exactly these values.
    public string ExpectedChallenge { get; set; } = string.Empty;
    public string ExpectedDomain { get; set; } = string.Empty;
    public bool RequireAudience { get; set; } = false;
}

/// <summary>Helper functions for creating presentation options.</summary>
public static class PresentationOpts
{
    /// <summary>
    /// Verifies every embedded credential; extra vc options are forwarded to each
    /// credential's Verify. The presentation resolver/offline are passed along.
    /// </summary>
    public static PresentationOpt WithVCValidation(params CredentialOpt[] opts)
    {
        return (o) =>
        {
            o.IsValidateVC = true;
            o.VcOpts.AddRange(opts);
        };
    }

    public static PresentationOpt WithBaseUrl(string baseUrl) => (o) => o.DidBaseUrl = baseUrl;

    public static PresentationOpt WithVerificationMethodKey(string key) => (o) =>
    {
        if (!string.IsNullOrEmpty(key)) o.VerificationMethodKey = key;
    };

    public static PresentationOpt WithVerifyProof() => (o) => o.IsVerifyProof = true;

    public static PresentationOpt WithResolver(IDidDocumentResolver resolver) => (o) => o.Resolver = resolver;

    public static PresentationOpt WithOffline() => (o) => o.IsOffline = true;

    public static PresentationOpt WithProofVerificationMethod(string vm) => (o) => o.ProofVerificationMethod = vm;

    public static PresentationOpt WithChallenge(string challenge) => (o) => o.Challenge = challenge;

    public static PresentationOpt WithDomain(string domain) => (o) => o.Domain = domain;

    // WithExpected* / WithRequireAudience imply proof verification: the value is
    // only trustworthy on a verified proof (Go parity).
    public static PresentationOpt WithExpectedChallenge(string challenge) => (o) =>
    {
        o.ExpectedChallenge = challenge;
        o.IsVerifyProof = true;
    };

    public static PresentationOpt WithExpectedDomain(string domain) => (o) =>
    {
        o.ExpectedDomain = domain;
        o.IsVerifyProof = true;
    };

    public static PresentationOpt WithRequireAudience() => (o) =>
    {
        o.RequireAudience = true;
        o.IsVerifyProof = true;
    };
}

/// <summary>Static helpers for presentations (option resolution + parsing).</summary>
public static class Presentation
{
    /// <summary>
    /// Thrown when WithRequireAudience is set without WithExpectedDomain. The
    /// option asks for the presentation to be bound to this verifier, which takes
    /// both halves: the claim in the presentation, and the identity of whoever is
    /// reading it.
    /// </summary>
    public const string ErrAudienceUnbound = "WithRequireAudience needs WithExpectedDomain";

    public static PresentationOptions GetOptions(params PresentationOpt[] opts)
    {
        var options = new PresentationOptions
        {
            DidBaseUrl = PresentationConfig.BaseUrl
        };
        foreach (var opt in opts)
        {
            opt(options);
        }
        return options;
    }

    /// <summary>
    /// Returns opts for a signing call, minus proof verification: there is no
    /// signature to verify before signing. Verify-only options (WithExpected*)
    /// imply verification, so clearing the flag leaves them without effect here.
    /// </summary>
    public static PresentationOpt[] SigningOptions(PresentationOpt[] opts)
    {
        var result = new PresentationOpt[opts.Length + 1];
        Array.Copy(opts, result, opts.Length);
        result[^1] = (o) => o.IsVerifyProof = false;
        return result;
    }

    /// <summary>
    /// Parses a presentation (JSON-LD object or compact JWS) into an IPresentation.
    /// A vp+jwt / three-segment token routes to JWT verification; a JSON object to
    /// JSON-LD verification.
    /// </summary>
    public static IPresentation ParsePresentation(byte[] rawPresentation, params PresentationOpt[] opts)
    {
        if (rawPresentation == null || rawPresentation.Length == 0)
        {
            throw new ArgumentException("presentation is empty");
        }

        if (IsJsonPresentation(rawPresentation))
        {
            return JsonPresentation.ParseJsonPresentation(rawPresentation, opts);
        }

        var valStr = Encoding.UTF8.GetString(rawPresentation).Trim().Trim('"');
        if (IsJwtPresentation(valStr))
        {
            return JwtPresentation.ParseJwtPresentation(valStr, opts);
        }

        throw new ArgumentException("failed to parse presentation");
    }

    public static IPresentation ParsePresentationWithValidation(byte[] rawPresentation)
    {
        return ParsePresentation(rawPresentation,
            PresentationOpts.WithVCValidation(), PresentationOpts.WithVerifyProof());
    }

    internal static bool IsJsonPresentation(byte[] rawPresentation)
    {
        if (rawPresentation == null || rawPresentation.Length == 0)
        {
            return false;
        }
        try
        {
            var jsonString = Encoding.UTF8.GetString(rawPresentation);
            using var doc = JsonDocument.Parse(jsonString);
            return doc.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch
        {
            return false;
        }
    }

    internal static bool IsJwtPresentation(string valStr)
    {
        valStr = valStr.Trim('"');
        var regex = new System.Text.RegularExpressions.Regex(@"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$");
        return regex.IsMatch(valStr);
    }
}
