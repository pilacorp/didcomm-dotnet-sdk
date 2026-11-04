using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

namespace Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

/// <summary>
/// Resolves verification methods from DID documents.
/// </summary>
public class VerificationMethodResolver : IDidDocumentResolver
{
    // SSRF response-size cap: a DID document is small; refuse oversized bodies.
    private const int MaxResponseBytes = 1 * 1024 * 1024;

    private readonly string _baseUrl;
    private readonly bool _allowPrivateHosts;
    private readonly HttpClient _httpClient;

    public VerificationMethodResolver(string baseUrl, bool allowPrivateHosts = true)
    {
        _baseUrl = baseUrl;
        _allowPrivateHosts = allowPrivateHosts;
        // Disable auto-redirects so a resolver response cannot bounce the client
        // onto an internal host; cap the overall request time.
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
    }

    /// <summary>
    /// Synchronous DID document resolution (<see cref="IDidDocumentResolver"/>).
    /// </summary>
    public DidDocument ResolveDocument(string did) =>
        ResolveToDocAsync(did).GetAwaiter().GetResult();

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

    public Task<VerificationMethodEntry> FindVerificationMethodAsync(string verificationMethodUrl)
    {
        var parts = verificationMethodUrl.Split('#');
        if (parts.Length == 0 || string.IsNullOrEmpty(parts[0]))
        {
            throw new ArgumentException($"Invalid verification method URL: {verificationMethodUrl}");
        }
        return FindInDocAsync(parts[0], verificationMethodUrl);
    }

    public Task<DidDocument> ResolveDocumentAsync(string did) => ResolveToDocAsync(did);

    public async Task<ECPublicKeyParameters> EcPublicKeyFromEntryAsync(VerificationMethodEntry vm)
    {
        if (vm.PublicKeyJwk != null)
        {
            return JwkToPublicKey(vm.PublicKeyJwk);
        }
        if (!string.IsNullOrEmpty(vm.PublicKeyMultibase))
        {
            return Multikey.PublicKeyFromMultibase(vm.PublicKeyMultibase);
        }
        if (!string.IsNullOrEmpty(vm.PublicKeyHex))
        {
            if (VerificationMethodKeyKindExtensions.FromEntry(vm) != VerificationMethodKeyKind.Secp256k1)
            {
                throw new InvalidOperationException(
                    $"publicKeyHex is only valid for secp256k1 verification methods, got type {vm.Type}");
            }
            var hex = Util.Util.RemoveHexPrefix(vm.PublicKeyHex);
            return EcdsaRawVerifier.PublicKeyFromHex(hex, "secp256k1");
        }
        throw new InvalidOperationException($"No public key in verification method {vm.Id}");
    }

    private async Task<VerificationMethodEntry> FindInDocAsync(string did, string verificationMethodUrl)
    {
        var doc = await ResolveToDocAsync(did);
        foreach (var vm in doc.VerificationMethod)
        {
            if (vm.Id == verificationMethodUrl)
            {
                return vm;
            }
        }
        throw new InvalidOperationException($"Verification method '{verificationMethodUrl}' not found in DID document");
    }

    private ECPublicKeyParameters JwkToPublicKey(Jwk jwk)
    {
        if (jwk.Kty != "EC")
        {
            throw new NotSupportedException($"Unsupported key type: {jwk.Kty}");
        }
        var curveName = jwk.Crv switch
        {
            "secp256k1" => "secp256k1",
            "P-256" => "P-256",
            _ => throw new NotSupportedException($"Unsupported curve: {jwk.Crv}")
        };
        var xBytes = Base64UrlDecode(jwk.X);
        var yBytes = Base64UrlDecode(jwk.Y);
        var curve = SecNamedCurves.GetByName(curveName)
            ?? SecNamedCurves.GetByName("prime256v1");
        var domain = new ECDomainParameters(curve!.Curve, curve.G, curve.N, curve.H);
        var point = curve.Curve.CreatePoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
        return new ECPublicKeyParameters("EC", point, domain);
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
        // Construct and encode API URL (the DID is escaped into the path, so it
        // cannot alter the host), then validate the target before any request.
        var encodedDid = Uri.EscapeDataString(did);
        var apiUrl = $"{_baseUrl.TrimEnd('/')}/{encodedDid}";
        ResolverGuard.ValidateUrl(apiUrl, _allowPrivateHosts);

        // Perform HTTP GET request. Auto-redirects are disabled on the handler,
        // so a 3xx here is a failure rather than a bounce to another host.
        var response = await _httpClient.GetAsync(apiUrl, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"DID resolver API returned non-200 status: {response.StatusCode}");
        }

        // Read and parse response, capping the body size (SSRF/DoS guard).
        if (response.Content.Headers.ContentLength is long len && len > MaxResponseBytes)
        {
            throw new InvalidOperationException($"DID resolver response too large: {len} bytes");
        }
        var json = await ReadCappedAsync(response);
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

    private static async Task<string> ReadCappedAsync(HttpResponseMessage response)
    {
        await using var stream = await response.Content.ReadAsStreamAsync();
        var buffer = new byte[MaxResponseBytes + 1];
        var total = 0;
        int read;
        while (total < buffer.Length
               && (read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total))) > 0)
        {
            total += read;
        }
        if (total > MaxResponseBytes)
        {
            throw new InvalidOperationException("DID resolver response exceeds size cap");
        }
        return System.Text.Encoding.UTF8.GetString(buffer, 0, total);
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

    [JsonPropertyName("publicKeyMultibase")]
    public string? PublicKeyMultibase { get; set; }

    [JsonPropertyName("revoked")]
    public string? Revoked { get; set; }

    [JsonPropertyName("revocationReason")]
    public string? RevocationReason { get; set; }
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

    [JsonPropertyName("controller")]
    public string? Controller { get; set; }

    [JsonPropertyName("didDocumentMetadata")]
    public Dictionary<string, object>? DidDocumentMetadata { get; set; }
}

