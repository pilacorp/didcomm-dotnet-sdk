using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

namespace Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

/// <summary>
/// Resolves verification methods from DID documents.
/// </summary>
public class VerificationMethodResolver
{
    private readonly string _baseUrl;
    private readonly HttpClient _httpClient;

    public VerificationMethodResolver(string baseUrl)
    {
        _baseUrl = baseUrl;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
    }

    /// <summary>
    /// Gets the public key in hex format for a given verification method URL.
    /// </summary>
    public async Task<string> GetPublicKeyAsync(string verificationMethodUrl)
    {
        // Extract DID from verification method URL
        var parts = verificationMethodUrl.Split('#');
        if (parts.Length == 0 || string.IsNullOrEmpty(parts[0]))
        {
            throw new ArgumentException($"Invalid verification method URL, could not extract DID: {verificationMethodUrl}");
        }

        var did = parts[0];

        // Resolve DID document
        var doc = await ResolveToDocAsync(did);

        // Find matching verification method
        foreach (var vm in doc.VerificationMethod)
        {
            if (vm.Id == verificationMethodUrl)
            {
                // Format publicKeyHex
                if (!string.IsNullOrEmpty(vm.PublicKeyHex))
                {
                    return Pila.CredentialSdk.DidComm.Credential.Common.Util.Util.RemoveHexPrefix(vm.PublicKeyHex);
                }

                // Format publicKeyJwk
                if (vm.PublicKeyJwk != null)
                {
                    // Convert JWK to hex format
                    return JwkToHex(vm.PublicKeyJwk);
                }

                throw new InvalidOperationException($"No public key found in verification method '{verificationMethodUrl}'");
            }
        }

        throw new InvalidOperationException($"Verification method '{verificationMethodUrl}' not found in DID document");
    }

    /// <summary>
    /// Gets the default public key for an issuer DID.
    /// </summary>
    public async Task<string> GetDefaultPublicKeyAsync(string issuer)
    {
        // Resolve DID document
        var doc = await ResolveToDocAsync(issuer);

        if (doc.VerificationMethod.Count > 0)
        {
            var vm = doc.VerificationMethod[0];

            // Format publicKeyHex
            if (!string.IsNullOrEmpty(vm.PublicKeyHex))
            {
                return Pila.CredentialSdk.DidComm.Credential.Common.Util.Util.RemoveHexPrefix(vm.PublicKeyHex);
            }

            // Format publicKeyJwk
            if (vm.PublicKeyJwk != null)
            {
                // Convert JWK to hex format
                return JwkToHex(vm.PublicKeyJwk);
            }

            throw new InvalidOperationException($"No public key found in verification method for DID '{issuer}'");
        }

        throw new InvalidOperationException($"Verification method not found in DID '{issuer}' document");
    }

    /// <summary>
    /// Resolves a DID to its document.
    /// </summary>
    private async Task<DidDocument> ResolveToDocAsync(string did)
    {
        // Construct and encode API URL
        var encodedDid = Uri.EscapeDataString(did);
        var apiUrl = $"{_baseUrl.TrimEnd('/')}/{encodedDid}";

        // Perform HTTP GET request
        var response = await _httpClient.GetAsync(apiUrl);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"DID resolver API returned non-200 status: {response.StatusCode}");
        }

        // Read and parse response
        var json = await response.Content.ReadAsStringAsync();
        var doc = JsonSerializer.Deserialize<DidDocument>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        if (doc == null)
        {
            throw new InvalidOperationException("Failed to parse DID document JSON");
        }

        return doc;
    }

    /// <summary>
    /// Converts a JWK to hex format for secp256k1 keys.
    /// </summary>
    private string JwkToHex(Jwk jwk)
    {
        if (jwk.Kty != "EC")
        {
            throw new NotSupportedException($"Unsupported key type: {jwk.Kty}");
        }

        if (jwk.Crv != "secp256k1")
        {
            throw new NotSupportedException($"Unsupported curve: {jwk.Crv}");
        }

        // Decode base64url encoded coordinates
        var xBytes = Base64UrlDecode(jwk.X);
        var yBytes = Base64UrlDecode(jwk.Y);

        // Convert to uncompressed format (0x04 + x + y)
        var uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        Array.Copy(xBytes, 0, uncompressed, 1, 32);
        Array.Copy(yBytes, 0, uncompressed, 33, 32);

        // Return as hex string
        return Convert.ToHexString(uncompressed).ToLowerInvariant();
    }

    /// <summary>
    /// Verifies if the provided private key matches the public key associated with the given verification method.
    /// </summary>
    public async Task<bool> CheckVerificationMethodAsync(string privateKeyHex, string verificationMethod)
    {
        if (string.IsNullOrEmpty(privateKeyHex) || string.IsNullOrEmpty(verificationMethod))
        {
            throw new ArgumentException("Private key or verification method is empty");
        }

        // Get public key from verification method
        var publicKey = await GetPublicKeyAsync(verificationMethod);

        // Verify key pair
        return EcdsaKeyVerifier.VerifyKeyPairFromHex(privateKeyHex, publicKey);
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

/// <summary>
/// Represents a JSON Web Key structure.
/// </summary>
public class Jwk
{
    [JsonPropertyName("kty")]
    public string Kty { get; set; } = string.Empty;

    [JsonPropertyName("crv")]
    public string Crv { get; set; } = string.Empty;

    [JsonPropertyName("x")]
    public string X { get; set; } = string.Empty;

    [JsonPropertyName("y")]
    public string Y { get; set; } = string.Empty;
}

/// <summary>
/// Represents a verification method entry in a DID Document.
/// </summary>
public class VerificationMethodEntry
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("controller")]
    public string? Controller { get; set; }

    [JsonPropertyName("publicKeyHex")]
    public string? PublicKeyHex { get; set; }

    [JsonPropertyName("publicKeyJwk")]
    public Jwk? PublicKeyJwk { get; set; }
}

/// <summary>
/// Represents the structure of a resolved DID Document.
/// </summary>
public class DidDocument
{
    [JsonPropertyName("@context")]
    public List<string> Context { get; set; } = new();

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("verificationMethod")]
    public List<VerificationMethodEntry> VerificationMethod { get; set; } = new();

    [JsonPropertyName("authentication")]
    public List<string>? Authentication { get; set; }

    [JsonPropertyName("assertionMethod")]
    public List<string>? AssertionMethod { get; set; }
}

