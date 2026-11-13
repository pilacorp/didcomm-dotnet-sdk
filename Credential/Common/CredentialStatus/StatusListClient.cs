using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.DigitalCredential;
using Pila.CredentialSdk.DidComm.Credential.Vc;

namespace Pila.CredentialSdk.DidComm.Credential.Common.CredentialStatus;

/// <summary>Top-level wrapper returned by the status list endpoint: {"data": {...vc...}}.</summary>
public sealed class StatusListCredentialResponse
{
    [JsonPropertyName("data")]
    public StatusListCredential Data { get; set; } = new();

    /// <summary>Raw JSON of the "data" object, kept verbatim so the credential's own
    /// DataIntegrity proof can be re-verified without a lossy DTO round-trip.</summary>
    [JsonIgnore]
    public string DataRawJson { get; set; } = "{}";
}

/// <summary>The BitstringStatusListCredential returned by the status list endpoint.</summary>
public sealed class StatusListCredential
{
    [JsonPropertyName("credentialSubject")]
    public StatusListCredentialSubject CredentialSubject { get; set; } = new();

    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }
}

/// <summary>credentialSubject of the status list credential, holding the encoded bitstring.</summary>
public sealed class StatusListCredentialSubject
{
    [JsonPropertyName("encodedList")]
    public string EncodedList { get; set; } = string.Empty;

    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("statusPurpose")]
    public string StatusPurpose { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string? Type { get; set; }
}

/// <summary>
/// Client for BitstringStatusList revocation/suspension checks, mirroring the Go
/// credentialstatus package. The HTTP fetch is injectable so tests run fully
/// offline; the default fetch goes through <see cref="ResolverGuard"/> (scheme
/// allow-list + loopback/link-local/private/metadata block) with a disabled
/// redirect, a request timeout and a response-size cap.
/// </summary>
public sealed class StatusListClient
{
    private const int MaxResponseBytes = 16 << 20; // 16 MiB, matches StatusList.MaxListBytes.

    // url -> raw JSON body. Injected fetchers bypass the network and the guard entirely.
    private readonly Func<string, string> _fetch;

    private static readonly HttpClient SharedHttpClient = CreateHttpClient();

    /// <summary>Default client: real HTTP fetch through the SSRF guard.</summary>
    public StatusListClient(bool allowPrivateHosts = false)
    {
        _fetch = url => HttpGet(url, allowPrivateHosts);
    }

    /// <summary>Offline client: the injected fetcher is used instead of the network.</summary>
    public StatusListClient(Func<string, string> fetch)
    {
        _fetch = fetch ?? throw new ArgumentNullException(nameof(fetch));
    }

    /// <summary>Fetches and parses the status list credential at the given URL.</summary>
    public StatusListCredentialResponse FetchStatusListCredential(string url)
    {
        if (string.IsNullOrEmpty(url))
        {
            throw new InvalidOperationException("statusListCredential URL is empty");
        }

        var body = _fetch(url);

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("data", out var dataEl))
        {
            throw new InvalidOperationException("status list response missing 'data'");
        }

        var dataRaw = dataEl.GetRawText();
        var data = JsonSerializer.Deserialize<StatusListCredential>(dataRaw)
                   ?? throw new InvalidOperationException("failed to parse status list credential");

        return new StatusListCredentialResponse { Data = data, DataRawJson = dataRaw };
    }

    /// <summary>
    /// Fetches the status list credential, optionally verifies its own proof (when a
    /// resolver is supplied — strictly stronger than Go, which never verifies it),
    /// checks the status purpose matches, and returns whether the bit at
    /// <paramref name="position"/> is set.
    /// </summary>
    public bool FetchAndCheckRevocation(
        string url,
        int position,
        string? expectedPurpose = null,
        IDidDocumentResolver? resolver = null)
    {
        var resp = FetchStatusListCredential(url);

        if (resolver != null)
        {
            // Verify the status list credential's own DataIntegrity proof before trusting it.
            var cred = JsonCredential.ParseJsonCredential(Encoding.UTF8.GetBytes(resp.DataRawJson));
            cred.Verify(CredentialOpts.WithResolver(resolver), CredentialOpts.WithOffline());
        }

        return IsRevoked(position, resp.Data.CredentialSubject, expectedPurpose);
    }

    /// <summary>
    /// Returns whether the bit at <paramref name="position"/> is set in the decoded
    /// bitstring. When <paramref name="expectedPurpose"/> is given it must equal the
    /// list's statusPurpose (e.g. revocation vs suspension), else an error is raised.
    /// </summary>
    public static bool IsRevoked(int position, StatusListCredentialSubject subject, string? expectedPurpose = null)
    {
        if (!string.IsNullOrEmpty(expectedPurpose) && subject.StatusPurpose != expectedPurpose)
        {
            throw new InvalidOperationException(
                $"status purpose mismatch: credential expects '{expectedPurpose}', list is '{subject.StatusPurpose}'");
        }

        var bytes = DecodeList(subject.EncodedList);
        // Reuse the vetted 1-bit LSB-first lookup primitive (bounds-checked).
        return StatusList.FromBytes(bytes, 1).Get(position) == 1;
    }

    /// <summary>gzip + base64url (no padding), mirroring Go's util.CompressToBase64URL.</summary>
    public static string EncodeList(byte[] raw)
    {
        using var output = new MemoryStream();
        using (var gz = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gz.Write(raw, 0, raw.Length);
        }
        return Base64UrlEncode(output.ToArray());
    }

    /// <summary>base64url (no padding) + gzip inflate, mirroring Go's util.DecompressFromBase64URL.</summary>
    public static byte[] DecodeList(string encoded)
    {
        var compressed = Base64UrlDecode(encoded);
        using var input = new MemoryStream(compressed);
        using var gz = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        long total = 0;
        while ((read = gz.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > MaxResponseBytes)
            {
                throw new InvalidOperationException($"encodedList inflates past {MaxResponseBytes} bytes");
            }
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static HttpClient CreateHttpClient()
    {
        // Disable auto-redirects so the response cannot bounce onto an internal host.
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    private static string HttpGet(string url, bool allowPrivateHosts)
    {
        ResolverGuard.ValidateUrl(url, allowPrivateHosts);

        var response = SharedHttpClient
            .GetAsync(url, HttpCompletionOption.ResponseHeadersRead)
            .GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"status list credential API returned non-200 status: {(int)response.StatusCode}");
        }
        if (response.Content.Headers.ContentLength is long len && len > MaxResponseBytes)
        {
            throw new InvalidOperationException($"status list response too large: {len} bytes");
        }

        using var stream = response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();
        var buffer = new byte[MaxResponseBytes + 1];
        var totalRead = 0;
        int n;
        while (totalRead < buffer.Length
               && (n = stream.Read(buffer, totalRead, buffer.Length - totalRead)) > 0)
        {
            totalRead += n;
        }
        if (totalRead > MaxResponseBytes)
        {
            throw new InvalidOperationException("status list response exceeds size cap");
        }
        return Encoding.UTF8.GetString(buffer, 0, totalRead);
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).Replace('+', '-').Replace('/', '_').TrimEnd('=');

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
