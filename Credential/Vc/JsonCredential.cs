using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Dto;
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
    /// Adds an ECDSA proof to the credential.
    /// </summary>
    public void AddProof(string privateKeyHex, params CredentialOpt[] opts)
    {
        var options = Credential.GetOptions(opts);

        if (!_jsonMap.TryGetValue("issuer", out var issuerObj) || issuerObj == null)
        {
            throw new InvalidOperationException("Issuer is required to add proof");
        }

        var issuer = issuerObj.ToString()!;
        var verificationMethod = $"{issuer}#{_verificationMethod}";

        // Use JsonMap to add proof
        _jsonMap.AddECDSAProof(privateKeyHex, verificationMethod, "assertionMethod", options.DidBaseUrl);
    }

    /// <summary>
    /// Gets the signing input (canonicalized document without proof).
    /// </summary>
    public byte[] GetSigningInput()
    {
        return _jsonMap.Canonicalize();
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
        var options = Credential.GetOptions(opts);
        options.IsVerifyProof = true;

        // Use JsonMap to verify proof
        var isValid = _jsonMap.VerifyProof(options.DidBaseUrl);

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
            var isValid = _jsonMap.VerifyProof(options.DidBaseUrl);
            if (!isValid)
            {
                throw new InvalidOperationException("Proof verification failed");
            }
        }
    }
}

