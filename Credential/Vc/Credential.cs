using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Pila.CredentialSdk.DidComm.Credential.Common.Dto;
using JsonMapType = Pila.CredentialSdk.DidComm.Credential.Common.JsonMap.JsonMap;

namespace Pila.CredentialSdk.DidComm.Credential.Vc;

/// <summary>
/// Package-level configuration for credentials.
/// </summary>
public static class CredentialConfig
{
    /// <summary>
    /// Base URL for DID resolution.
    /// </summary>
    public static string BaseUrl { get; private set; } = "https://api.ndadid.vn/api/v1/did";

    /// <summary>
    /// Initializes the package with a base URL.
    /// </summary>
    public static void Init(string baseUrl)
    {
        if (!string.IsNullOrEmpty(baseUrl))
        {
            BaseUrl = baseUrl;
        }
    }
}

/// <summary>
/// Represents credential data in JSON format (suitable for both JWT and JSON credentials).
/// Equivalent to Go's type CredentialData jsonmap.JSONMap
/// </summary>
public class CredentialData : JsonMapType
{
}

/// <summary>
/// Represents the structured contents of a Verifiable Credential.
/// </summary>
public class CredentialContents
{
    /// <summary>
    /// JSON-LD contexts
    /// </summary>
    public List<object> Context { get; set; } = new();

    /// <summary>
    /// Credential identifier
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Credential types
    /// </summary>
    public List<string> Types { get; set; } = new();

    /// <summary>
    /// Issuer identifier
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Issuance date
    /// </summary>
    public DateTime ValidFrom { get; set; }

    /// <summary>
    /// Expiration date
    /// </summary>
    public DateTime ValidUntil { get; set; }

    /// <summary>
    /// Credential status entries
    /// </summary>
    public List<Status> CredentialStatus { get; set; } = new();

    /// <summary>
    /// Credential subjects
    /// </summary>
    public List<Subject> Subject { get; set; } = new();

    /// <summary>
    /// Credential schemas
    /// </summary>
    public List<Schema> Schemas { get; set; } = new();
}

/// <summary>
/// Represents the credentialStatus field as per W3C Verifiable Credentials.
/// </summary>
public class Status
{
    [Newtonsoft.Json.JsonProperty("id", NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
    public string? Id { get; set; }

    [Newtonsoft.Json.JsonProperty("type")]
    public string Type { get; set; } = string.Empty;

    [Newtonsoft.Json.JsonProperty("statusPurpose", NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
    public string? StatusPurpose { get; set; }

    [Newtonsoft.Json.JsonProperty("statusListIndex", NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
    public string? StatusListIndex { get; set; }

    [Newtonsoft.Json.JsonProperty("statusListCredential", NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore)]
    public string? StatusListCredential { get; set; }
}

/// <summary>
/// Represents the credentialSubject field.
/// </summary>
public class Subject
{
    /// <summary>
    /// Subject identifier
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Additional subject data
    /// </summary>
    public Dictionary<string, object> CustomFields { get; set; } = new();
}

/// <summary>
/// Represents a credential schema with an ID and type.
/// </summary>
public class Schema
{
    /// <summary>
    /// Schema identifier
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Schema type
    /// </summary>
    public string Type { get; set; } = string.Empty;
}

/// <summary>
/// Interface for Verifiable Credentials.
/// </summary>
public interface ICredential
{
    /// <summary>
    /// Adds a proof to the credential using a private key.
    /// </summary>
    void AddProof(string privateKeyHex, params CredentialOpt[] opts);

    /// <summary>
    /// Gets the signing input (canonicalized document without proof).
    /// </summary>
    byte[] GetSigningInput();

    /// <summary>
    /// Adds a custom proof to the credential.
    /// </summary>
    void AddCustomProof(Proof proof, params CredentialOpt[] opts);

    /// <summary>
    /// Verifies the credential.
    /// </summary>
    void Verify(params CredentialOpt[] opts);

    /// <summary>
    /// Serializes the credential in its native format.
    /// </summary>
    object Serialize();

    /// <summary>
    /// Gets the credential contents as bytes.
    /// </summary>
    byte[] GetContents();

    /// <summary>
    /// Gets the credential type (JWT or JSON).
    /// </summary>
    string GetType();

    /// <summary>
    /// Executes credential options (internal).
    /// </summary>
    void ExecuteOptions(params CredentialOpt[] opts);
}

/// <summary>
/// Credential option function type.
/// </summary>
public delegate void CredentialOpt(CredentialOptions options);

/// <summary>
/// Configuration options for credential processing.
/// </summary>
public class CredentialOptions
{
    /// <summary>
    /// Enable schema validation during credential parsing.
    /// </summary>
    public bool IsValidateSchema { get; set; } = false;

    /// <summary>
    /// Enable proof verification during credential parsing.
    /// </summary>
    public bool IsVerifyProof { get; set; } = false;

    /// <summary>
    /// DID base URL for credential processing.
    /// </summary>
    public string DidBaseUrl { get; set; } = CredentialConfig.BaseUrl;

    /// <summary>
    /// Verification method key (default: "key-1").
    /// </summary>
    public string VerificationMethodKey { get; set; } = "key-1";
}

/// <summary>
/// Helper functions for creating credential options.
/// </summary>
public static class CredentialOpts
{
    /// <summary>
    /// Sets the DID base URL for credential processing.
    /// </summary>
    public static CredentialOpt WithBaseUrl(string baseUrl)
    {
        return (options) => options.DidBaseUrl = baseUrl;
    }

    /// <summary>
    /// Sets the verification method key (default: "key-1").
    /// </summary>
    public static CredentialOpt WithVerificationMethodKey(string key)
    {
        return (options) => options.VerificationMethodKey = key;
    }

    /// <summary>
    /// Enables schema validation during credential parsing.
    /// </summary>
    public static CredentialOpt WithSchemaValidation()
    {
        return (options) => options.IsValidateSchema = true;
    }

    /// <summary>
    /// Enables proof verification during credential parsing.
    /// </summary>
    public static CredentialOpt WithVerifyProof()
    {
        return (options) => options.IsVerifyProof = true;
    }
}

/// <summary>
/// Helper functions for credential operations.
/// </summary>
public static class Credential
{
    /// <summary>
    /// Gets credential options from option functions.
    /// </summary>
    public static CredentialOptions GetOptions(params CredentialOpt[] opts)
    {
        var options = new CredentialOptions
        {
            IsValidateSchema = false,
            IsVerifyProof = false,
            DidBaseUrl = CredentialConfig.BaseUrl,
            VerificationMethodKey = "key-1"
        };

        foreach (var opt in opts)
        {
            opt(options);
        }

        return options;
    }

    /// <summary>
    /// Parses a credential from various formats into an ICredential.
    /// </summary>
    public static ICredential ParseCredential(byte[] rawCredential, params CredentialOpt[] opts)
    {
        if (rawCredential == null || rawCredential.Length == 0)
        {
            throw new ArgumentException("JSON string is empty");
        }

        if (IsJsonCredential(rawCredential))
        {
            return JsonCredential.ParseJsonCredential(rawCredential, opts);
        }

        var valStr = Encoding.UTF8.GetString(rawCredential);
        if (IsJwtCredential(valStr))
        {
            return JwtCredential.ParseJwtCredential(valStr, opts);
        }

        throw new ArgumentException("Failed to parse credential: not a valid JWT or embedded credential");
    }

    /// <summary>
    /// Parses a credential with validation enabled.
    /// </summary>
    public static ICredential ParseCredentialWithValidation(byte[] rawCredential)
    {
        return ParseCredential(rawCredential, CredentialOpts.WithSchemaValidation(), CredentialOpts.WithVerifyProof());
    }

    private static bool IsJsonCredential(byte[] rawCredential)
    {
        if (rawCredential == null || rawCredential.Length == 0)
        {
            return false;
        }

        try
        {
            var jsonString = Encoding.UTF8.GetString(rawCredential);
            JsonSerializer.Deserialize<Dictionary<string, object>>(jsonString);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsJwtCredential(string valStr)
    {
        valStr = valStr.Trim('"');
        var regex = new Regex(@"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$");
        return regex.IsMatch(valStr);
    }
}

