using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.Dto;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Vc;

namespace Pila.CredentialSdk.DidComm.Credential.Vc;

/// <summary>
/// JWT Verifiable Credential implementation.
/// </summary>
public class JwtCredential : ICredential
{
    private string _signingInput; // JWT header.payload (base64 encoded)
    private Dictionary<string, object> _payloadData; // Parsed payload as CredentialData
    private string _signature; // JWT signature (if signed)

    private JwtCredential(string signingInput, Dictionary<string, object> payloadData, string signature = "")
    {
        _signingInput = signingInput;
        _payloadData = payloadData;
        _signature = signature;
    }

    /// <summary>
    /// Creates a new JWT credential from CredentialContents.
    /// </summary>
    public static JwtCredential NewJwtCredential(CredentialContents vcc, params CredentialOpt[] opts)
    {
        var options = Credential.GetOptions(opts);

        // Convert CredentialContents to CredentialData
        var credentialData = CredentialHelper.SerializeCredentialContents(vcc);

        // Extract other claims from credentialContents
        var otherClaims = new Dictionary<string, object>();
        if (!string.IsNullOrEmpty(vcc.Issuer))
        {
            otherClaims["iss"] = vcc.Issuer;
        }
        if (vcc.Subject.Count > 0 && !string.IsNullOrEmpty(vcc.Subject[0].Id))
        {
            otherClaims["sub"] = vcc.Subject[0].Id;
        }
        if (vcc.ValidUntil != default(DateTime))
        {
            otherClaims["exp"] = ((DateTimeOffset)vcc.ValidUntil.ToUniversalTime()).ToUnixTimeSeconds();
        }
        if (vcc.ValidFrom != default(DateTime))
        {
            var unixTime = ((DateTimeOffset)vcc.ValidFrom.ToUniversalTime()).ToUnixTimeSeconds();
            otherClaims["iat"] = unixTime;
            otherClaims["nbf"] = unixTime;
        }
        if (!string.IsNullOrEmpty(vcc.Id))
        {
            otherClaims["jti"] = vcc.Id;
        }

        // Build payload with vc claim and other claims
        var payload = new Dictionary<string, object>
        {
            ["vc"] = credentialData
        };

        // Add other claims to payload
        foreach (var claim in otherClaims)
        {
            payload[claim.Key] = claim.Value;
        }

        // Build header
        var header = new Dictionary<string, object>
        {
            ["typ"] = "JWT",
            ["alg"] = "ES256K",
            ["kid"] = $"{vcc.Issuer}#{options.VerificationMethodKey}"
        };

        // Encode header and payload
        var headerJson = JsonSerializer.Serialize(header, new JsonSerializerOptions
        {
            WriteIndented = false
        });
        var headerEncoded = Util.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));

        var payloadJson = JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = false
        });
        var payloadEncoded = Util.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

        // Create signing input (header.payload)
        var signingInput = $"{headerEncoded}.{payloadEncoded}";

        var credential = new JwtCredential(signingInput, credentialData);
        
        // Execute options if needed
        credential.ExecuteOptions(opts);

        return credential;
    }

    /// <summary>
    /// Parses a JWT credential from a JWT string.
    /// </summary>
    public static JwtCredential ParseJwtCredential(string rawJwt, params CredentialOpt[] opts)
    {
        var options = Credential.GetOptions(opts);

        if (string.IsNullOrEmpty(rawJwt))
        {
            throw new ArgumentException("JWT string is empty");
        }

        // Remove quotes if present
        rawJwt = rawJwt.Trim('"');

        // Split JWT into parts
        var parts = rawJwt.Split('.');
        if (parts.Length < 2)
        {
            throw new ArgumentException("Invalid JWT format");
        }

        // Extract the payload and header
        var headerEncoded = parts[0];
        var payloadEncoded = parts[1];
        var signature = parts.Length == 3 ? parts[2] : "";

        // Decode the payload
        var payloadBytes = Util.Base64UrlDecode(payloadEncoded);
        var payloadMap = JsonSerializer.Deserialize<Dictionary<string, object>>(
            Encoding.UTF8.GetString(payloadBytes),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
        );

        if (payloadMap == null)
        {
            throw new ArgumentException("Failed to unmarshal payload");
        }

        // Store the vc claim in payload as payloadData
        if (!payloadMap.TryGetValue("vc", out var vcData) || vcData == null)
        {
            throw new ArgumentException("vc claim not found in JWT payload");
        }

        var vcMap = JsonSerializer.Deserialize<Dictionary<string, object>>(
            JsonSerializer.Serialize(vcData),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
        );

        if (vcMap == null)
        {
            throw new ArgumentException("vc claim is not a valid JSON object");
        }

        // Create signing input (header.payload)
        var signingInput = $"{headerEncoded}.{payloadEncoded}";

        var credential = new JwtCredential(signingInput, vcMap, signature);
        
        // Execute options if needed
        credential.ExecuteOptions(opts);

        return credential;
    }

    /// <summary>
    /// Adds a proof (signature) to the JWT credential.
    /// </summary>
    public void AddProof(string privateKeyHex, params CredentialOpt[] opts)
    {
        // Sign the existing signing input
        var signature = EcdsaSigner.SignStringBase64Url(_signingInput, privateKeyHex);

        // Update signature
        _signature = signature;
    }

    /// <summary>
    /// Gets the signing input (header.payload).
    /// </summary>
    public byte[] GetSigningInput()
    {
        return Encoding.UTF8.GetBytes(_signingInput);
    }

    /// <summary>
    /// Adds a custom proof to the JWT credential.
    /// </summary>
    public void AddCustomProof(Proof proof, params CredentialOpt[] opts)
    {
        if (proof == null)
        {
            throw new ArgumentNullException(nameof(proof));
        }

        if (proof.Signature == null || proof.Signature.Length == 0)
        {
            throw new ArgumentException("Proof signature cannot be empty");
        }

        // Use the provided signature directly (base64url encoded)
        _signature = Util.Base64UrlEncode(proof.Signature);
    }

    /// <summary>
    /// Verifies the JWT credential.
    /// </summary>
    public void Verify(params CredentialOpt[] opts)
    {
        var options = Credential.GetOptions(opts);
        options.IsVerifyProof = true;

        // TODO: Implement JWT verification
        // This would require:
        // 1. Decoding the header to get the kid
        // 2. Resolving the public key from the DID
        // 3. Verifying the signature
    }

    /// <summary>
    /// Serializes the credential to a JWT string.
    /// </summary>
    public object Serialize()
    {
        if (!string.IsNullOrEmpty(_signature))
        {
            // Signed JWT
            return $"{_signingInput}.{_signature}";
        }
        else
        {
            // Unsigned JWT
            return _signingInput;
        }
    }

    /// <summary>
    /// Gets the credential contents as JSON bytes.
    /// </summary>
    public byte[] GetContents()
    {
        var json = JsonSerializer.Serialize(_payloadData, new JsonSerializerOptions
        {
            WriteIndented = false
        });
        return Encoding.UTF8.GetBytes(json);
    }

    /// <summary>
    /// Gets the credential type.
    /// </summary>
    public new string GetType()
    {
        return "JWT";
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
            VerifyProof(options.DidBaseUrl);
        }
    }

    /// <summary>
    /// Verifies the JWT proof.
    /// </summary>
    private void VerifyProof(string didBaseUrl)
    {
        if (string.IsNullOrEmpty(_signature))
        {
            throw new InvalidOperationException("JWT signature is missing");
        }

        // Split signing input to get header and payload
        var parts = _signingInput.Split('.');
        if (parts.Length != 2)
        {
            throw new InvalidOperationException("Invalid JWT signing input format");
        }

        var headerEncoded = parts[0];
        var payloadEncoded = parts[1];

        // Decode header to get kid
        var headerBytes = Util.Base64UrlDecode(headerEncoded);
        var headerJson = Encoding.UTF8.GetString(headerBytes);
        var header = JsonSerializer.Deserialize<Dictionary<string, object>>(headerJson);

        if (header == null || !header.TryGetValue("kid", out var kidObj) || kidObj == null)
        {
            throw new InvalidOperationException("JWT header missing 'kid' (key ID)");
        }

        var kid = kidObj.ToString();
        if (string.IsNullOrEmpty(kid))
        {
            throw new InvalidOperationException("JWT header 'kid' is empty");
        }

        // Extract DID from kid (format: {DID}#{keyId})
        var kidParts = kid.Split('#');
        if (kidParts.Length == 0 || string.IsNullOrEmpty(kidParts[0]))
        {
            throw new InvalidOperationException($"Invalid kid format: {kid}");
        }

        var did = kidParts[0];

        // Resolve public key from DID
        var resolver = new VerificationMethodResolver(didBaseUrl);
        var publicKeyHex = resolver.GetDefaultPublicKeyAsync(did).GetAwaiter().GetResult();

        // Decode signature from base64url to bytes
        var signatureBytes = Util.Base64UrlDecode(_signature);

        // Convert signature to hex (JWT uses 64-byte r,s format)
        var signatureHex = Convert.ToHexString(signatureBytes).ToLowerInvariant();

        // Verify signature
        // The message to verify is the signing input (header.payload)
        var messageBytes = Encoding.UTF8.GetBytes(_signingInput);
        var isValid = EcdsaVerifier.VerifySignature(publicKeyHex, signatureHex, messageBytes);

        if (!isValid)
        {
            throw new InvalidOperationException("JWT signature verification failed");
        }
    }
}

