using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using VDS.RDF.JsonLd;
using VDS.RDF.JsonLd.Syntax;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Processor;

// Refusals of this SDK. All derive from JsonLdLimitException so entry points can
// surface them even when dotNetRDF wraps them in its own exception.
public class JsonLdLimitException : InvalidOperationException
{
    public JsonLdLimitException(string message, Exception? inner = null) : base(message, inner) { }
}
/// <summary>Every failed remote @context fetch; the cause is on InnerException only, never in the text.</summary>
public sealed class ContextLoadException : JsonLdLimitException
{
    public ContextLoadException(Exception cause) : base("remote context could not be loaded", cause) { }
}
public sealed class ContextAddressException : JsonLdLimitException { public ContextAddressException() : base("context address is not public") { } }
public sealed class ContextSchemeException : JsonLdLimitException { public ContextSchemeException() : base("context URL is not http or https") { } }
public sealed class ContextRequestsException : JsonLdLimitException { public ContextRequestsException() : base("context fetch made too many requests") { } }
public sealed class ContextOverflowException : JsonLdLimitException { public ContextOverflowException() : base("the operation's context budget is used up") { } }
public sealed class TooManyContextTermsException : JsonLdLimitException { public TooManyContextTermsException(string m) : base(m) { } }
public sealed class ContextTermTooLongException : JsonLdLimitException { public ContextTermTooLongException(string m) : base(m) { } }
/// <summary>ErrBlankNodeWork equivalent: a dataset refused for the URDNA2015 search it would take.</summary>
public sealed class BlankNodeWorkException : JsonLdLimitException { public BlankNodeWorkException(string m) : base(m) { } }

/// <summary>Process-wide, bounded fetcher and cache of remote @context documents (port of Go cachingDocumentLoader).</summary>
public static class ContextFetcher
{
    public const int MaxContextBytes = 1 << 20;
    public const int MaxContextRequests = 16;
    public const int MaxCachedContexts = 64;

    /// <summary>Bounds one fetch: all its requests, each body included. Mutable so tests can shorten it.</summary>
    public static TimeSpan FetchTimeout { get; set; } = TimeSpan.FromSeconds(10);

    private sealed record Cached(string Raw, int Size, Uri DocumentUrl);

    private static readonly object Gate = new();
    private static readonly Dictionary<string, Cached> Cache = new();
    private static readonly HttpClient DefaultClient = CreatePublicOnlyClient();
    private static HttpClient _client = DefaultClient;

    public static int CacheCount { get { lock (Gate) return Cache.Count; } }

    /// <summary>
    /// Replaces the process-wide HTTP client and empties the cache (tests, or a service behind an egress proxy).
    /// The non-public address refusal lives in the default client, so a client set here drops it; the time,
    /// size, scheme and request limits still apply. null restores the default.
    /// </summary>
    public static void SetHttpClient(HttpClient? client)
    {
        lock (Gate) { _client = client ?? DefaultClient; Cache.Clear(); }
    }

    /// <summary>Loads a remote context: a fresh parse per caller, plus the size of the cached bytes.</summary>
    public static (RemoteDocument Doc, int Size) Load(Uri uri)
    {
        var key = uri.AbsoluteUri;
        Cached? entry;
        lock (Gate) Cache.TryGetValue(key, out entry);
        if (entry == null)
        {
            try { entry = Fetch(uri); }
            catch (Exception e) { throw new ContextLoadException(e); }
            lock (Gate)
            {
                if (Cache.Count >= MaxCachedContexts) Cache.Remove(Cache.Keys.First()); // evict rather than stop caching
                Cache[key] = entry;
            }
        }
        try
        {
            return (new RemoteDocument { DocumentUrl = entry.DocumentUrl, Document = JToken.Parse(entry.Raw) }, entry.Size);
        }
        catch (Exception e) { throw new ContextLoadException(e); }
    }

    private static Cached Fetch(Uri uri)
    {
        HttpClient client;
        lock (Gate) client = _client;
        if (!IsHttp(uri)) throw new ContextSchemeException();

        using var cts = new CancellationTokenSource(FetchTimeout);
        var current = uri;
        for (var requests = 1; ; requests++)
        {
            if (requests > MaxContextRequests) throw new ContextRequestsException();
            using var req = new HttpRequestMessage(HttpMethod.Get, current);
            req.Headers.TryAddWithoutValidation("Accept", "application/ld+json, application/json;q=0.9");
            using var resp = client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).GetAwaiter().GetResult();

            if ((int)resp.StatusCode is >= 300 and < 400 && resp.Headers.Location is { } loc)
            {
                current = Resolve(current, loc.OriginalString);
                continue;
            }
            // An alternate is loaded by following it, so it faces the scheme check too.
            Uri? alternate = null;
            foreach (var target in AlternateTargets(resp))
            {
                var next = Resolve(current, target);
                alternate ??= next;
            }
            resp.EnsureSuccessStatusCode();
            var media = resp.Content.Headers.ContentType?.MediaType ?? "";
            if (alternate != null && !(media == "application/json" || media.EndsWith("+json", StringComparison.Ordinal)))
            {
                current = alternate;
                continue;
            }
            var raw = ReadCapped(resp.Content.ReadAsStream(cts.Token), cts.Token);
            return new Cached(raw.Item1, raw.Item2, current);
        }
    }

    private static (string, int) ReadCapped(Stream s, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        var buf = new byte[16 << 10];
        int n;
        while ((n = s.ReadAsync(buf, 0, buf.Length, ct).GetAwaiter().GetResult()) > 0)
        {
            ms.Write(buf, 0, n);
            if (ms.Length > MaxContextBytes) throw new InvalidOperationException("context response is too large");
        }
        return (Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length), (int)ms.Length);
    }

    private static readonly Regex LinkRe = new(@"<([^>]*)>([^,<]*)", RegexOptions.Compiled);

    /// <summary>Targets of Link rel=alternate type=application/ld+json headers.</summary>
    private static IEnumerable<string> AlternateTargets(HttpResponseMessage resp)
    {
        if (!resp.Headers.TryGetValues("Link", out var values)) yield break;
        foreach (var m in values.SelectMany(v => LinkRe.Matches(v).Cast<Match>()))
        {
            var p = m.Groups[2].Value;
            if (Regex.IsMatch(p, @"rel\s*=\s*""?alternate""?") && Regex.IsMatch(p, @"type\s*=\s*""?application/ld\+json""?"))
                yield return m.Groups[1].Value;
        }
    }

    /// <summary>Resolves target against base; refuses an unparsable or non-http result.</summary>
    private static Uri Resolve(Uri baseUri, string target)
    {
        if (!Uri.TryCreate(baseUri, target, out var u) || !IsHttp(u)) throw new ContextSchemeException();
        return u;
    }

    public static bool IsHttp(Uri u) => u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps;

    // A proxy would connect on its behalf and hide the address, so the default uses none. The address is
    // judged where it is connected to: after DNS resolution, on every redirect and every attempt.
    private static HttpClient CreatePublicOnlyClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            MaxResponseHeadersLength = 64,
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(90),
            ConnectCallback = async (ctx, ct) =>
            {
                var addrs = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct).ConfigureAwait(false);
                var pub = addrs.Where(ResolverGuard.IsPublicAddress).ToArray();
                if (pub.Length == 0) throw new ContextAddressException();
                Exception? last = null;
                foreach (var a in pub)
                {
                    var socket = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(a, ctx.DnsEndPoint.Port), ct).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception e) { socket.Dispose(); last = e; }
                }
                throw last!;
            },
        };
        return new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
    }
}

/// <summary>
/// The loader of one JSON-LD operation (port of Go contextBudget): stops recursion and chains via the load,
/// time and byte limits, and holds the operation's terms. Create one per operation, never share it.
/// </summary>
public sealed class ContextBudget
{
    public const int MaxContextLoads = 1024;
    public static readonly TimeSpan MaxContextLoadTime = TimeSpan.FromSeconds(30);
    public const int MaxContextBytesPerOperation = 4 << 20;

    // Bundled W3C contexts resolve offline. Their loads include no remote context and spend bytes, not loads.
    private static readonly Dictionary<string, string> WellKnown = new()
    {
        ["https://www.w3.org/ns/credentials/v2"] = "w3c.credential.v2.json",
        ["https://www.w3.org/ns/credentials/v2.jsonld"] = "w3c.credential.v2.json",
        ["https://www.w3.org/ns/credentials/examples/v2"] = "w3c.credential.examples.v2.json",
        ["https://www.w3.org/ns/credentials/examples/v2.jsonld"] = "w3c.credential.examples.v2.json",
        ["https://w3id.org/citizenship/v4rc1"] = "w3c.citizenship.v4rc1.json",
        ["https://w3id.org/citizenship/v4rc1.jsonld"] = "w3c.citizenship.v4rc1.json",
    };

    public int Loads { get; set; }
    public int Bytes { get; set; }
    public DateTime Deadline { get; set; } = DateTime.UtcNow + MaxContextLoadTime;
    public ContextTerms Terms { get; } = new();

    /// <summary>The dotNetRDF DocumentLoader delegate.</summary>
    public RemoteDocument Load(Uri uri, JsonLdLoaderOptions? options)
    {
        if (WellKnown.TryGetValue(uri.ToString(), out var name))
        {
            var path = new[] { name, Path.Combine("Credential", "Common", "Crypto", name), $"Credential/Common/Crypto/{name}", Path.Combine(AppContext.BaseDirectory, "Credential", "Common", "Crypto", name) }
                .FirstOrDefault(File.Exists);
            if (path != null)
            {
                var text = File.ReadAllText(path);
                if ((Bytes += Encoding.UTF8.GetByteCount(text)) > MaxContextBytesPerOperation) throw new ContextOverflowException();
                return new RemoteDocument { DocumentUrl = uri, Document = JToken.Parse(text) };
            }
        }
        if (++Loads > MaxContextLoads || DateTime.UtcNow > Deadline) throw new ContextOverflowException();
        var (doc, size) = ContextFetcher.Load(uri);
        if ((Bytes += size) > MaxContextBytesPerOperation) throw new ContextOverflowException();
        Terms.AddDocument(doc.Document as JToken);
        Terms.Check(ContextTerms.MaxContextTerms);
        return doc;
    }

    /// <summary>
    /// Options for one operation: a fresh budget as the loader. When <paramref name="inlineDoc"/> is given its own
    /// contexts go on that budget before the library processes them.
    /// </summary>
    public static JsonLdProcessorOptions NewOptions(JToken? inlineDoc, bool safeMode = false, bool nativeTypes = false)
    {
        var budget = new ContextBudget();
        if (inlineDoc != null)
        {
            budget.Terms.AddDocument(inlineDoc);
            budget.Terms.Check(ContextTerms.MaxInlineContextTerms);
        }
        return new JsonLdProcessorOptions
        {
            ProcessingMode = JsonLdProcessingMode.JsonLd11,
            SafeMode = safeMode,
            UseNativeTypes = nativeTypes,
            DocumentLoader = budget.Load,
        };
    }

    /// <summary>
    /// Runs a library call so only clean errors escape: this SDK's refusals pass through (found on the chain if the
    /// library wrapped them), anything else the library throws becomes an InvalidOperationException.
    /// </summary>
    public static T Guard<T>(string op, Func<T> f)
    {
        try { return f(); }
        catch (JsonLdLimitException) { throw; }
        catch (Exception e) when (e is not ArgumentException and not OperationCanceledException)
        {
            for (Exception? x = e; x != null; x = x.InnerException)
                if (x is JsonLdLimitException limit) throw limit;
            throw new InvalidOperationException($"{op}: {e.Message}", e);
        }
    }
}
