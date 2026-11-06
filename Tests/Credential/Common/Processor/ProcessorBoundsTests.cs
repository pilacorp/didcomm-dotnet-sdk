using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json.Linq;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd;
using Pila.CredentialSdk.DidComm.Credential.Common.Processor;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.Parsing;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.Processor;

/// <summary>Port of go-credential-sdk #165 tests (document_loader, canonicalize_blanknode, context_terms).</summary>
[Collection("ContextFetcher")]
public class ProcessorBoundsTests : IDisposable
{
    public ProcessorBoundsTests() => ContextFetcher.SetHttpClient(null);
    public void Dispose()
    {
        ContextFetcher.FetchTimeout = TimeSpan.FromSeconds(10);
        ContextFetcher.SetHttpClient(null);
    }

    // ---- helpers ----------------------------------------------------------------------------

    private sealed class CtxServer : IDisposable
    {
        private readonly HttpListener _l = new();
        public string Url { get; }
        public int Hits;
        public CtxServer(Action<HttpListenerContext> handler)
        {
            var tcp = new TcpListener(IPAddress.Loopback, 0); tcp.Start();
            var port = ((IPEndPoint)tcp.LocalEndpoint).Port; tcp.Stop();
            Url = $"http://127.0.0.1:{port}";
            _l.Prefixes.Add(Url + "/");
            _l.Start();
            _ = Task.Run(async () =>
            {
                while (_l.IsListening)
                {
                    HttpListenerContext c;
                    try { c = await _l.GetContextAsync(); } catch { return; }
                    _ = Task.Run(() =>
                    {
                        Interlocked.Increment(ref Hits);
                        try { handler(c); } catch { /* client went away */ }
                        try { c.Response.Close(); } catch { }
                    });
                }
            });
        }
        public void Dispose() { try { _l.Close(); } catch { } }
    }

    private static CtxServer UseServer(Action<HttpListenerContext> handler)
    {
        var srv = new CtxServer(handler);
        ContextFetcher.SetHttpClient(new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }));
        return srv;
    }

    private static void Write(HttpListenerContext c, string body, string type = "application/ld+json")
    {
        c.Response.ContentType = type;
        var b = Encoding.UTF8.GetBytes(body);
        c.Response.OutputStream.Write(b, 0, b.Length);
    }

    private static void WriteContext(HttpListenerContext c, string term = "term") =>
        Write(c, $"{{\"@context\":{{\"{term}\":\"https://example.org/{term}\"}}}}");

    private static JObject DocUsing(string contextUrl, string term) =>
        new() { ["@context"] = contextUrl, ["@id"] = "https://example.org/subject", [term] = "value" };

    private static bool Has<T>(Exception? e) where T : Exception
    {
        for (; e != null; e = e.InnerException) if (e is T) return true;
        return false;
    }

    private static void Refuses<T>(Action a) where T : Exception
    {
        var e = Record.Exception(a);
        Assert.True(Has<T>(e), $"expected {typeof(T).Name}, got {e?.GetType().Name}: {e?.Message}");
    }

    private static Dictionary<string, object?> Dict(JObject o) =>
        JsonSerializer.Deserialize<Dictionary<string, object?>>(o.ToString())!;

    private static readonly JObject LinkContext = new()
    {
        ["knows"] = new JObject { ["@id"] = "https://example.org/knows", ["@type"] = "@id" },
        ["name"] = "https://example.org/name",
    };

    private static Dictionary<string, Action<JObject>> Canonicalizers() => new()
    {
        ["CanonicalizeWithoutProof"] = d => Canonicalizer.CanonicalizeWithoutProof(Dict(d)),
        ["Canonicalize"] = d => SdJsonLd.Canonicalize(d),
        ["CanonicalizeWithIdMap"] = d => SdJsonLd.CanonicalizeWithIdMap(d),
        ["CanonicalizeNQuadsWithIdMap"] = d => SdJsonLd.CanonicalizeNQuadsWithIdMap(SdJsonLd.ToRdfNQuads(d)),
    };

    private static Dictionary<string, Action<JObject>> TermEntries()
    {
        var e = Canonicalizers();
        e["ExpandJsonLd"] = d => SdJsonLd.ExpandJsonLd(d);
        e["ToRdfNQuads"] = d => SdJsonLd.ToRdfNQuads(d);
        return e;
    }

    private static ITripleStore Store(JObject doc)
    {
        var store = new TripleStore();
        using var r = new StringReader(doc.ToString());
        new JsonLdParser(ContextBudget.NewOptions(null, safeMode: true)).Load(store, r);
        return store;
    }

    private static JObject GraphOf(int nodes, Func<int, int[]> targets)
    {
        var graph = new JArray();
        for (var i = 0; i < nodes; i++)
            graph.Add(new JObject
            {
                ["@id"] = $"_:n{i}",
                ["knows"] = new JArray(targets(i).Select(j => (JToken)new JObject { ["@id"] = $"_:n{j}" })),
            });
        return new JObject { ["@context"] = LinkContext.DeepClone(), ["@graph"] = graph };
    }

    private static JObject BlankClique(int n) => GraphOf(n, i => Enumerable.Range(0, n).Where(j => j != i).ToArray());
    private static JObject BlankCycle(int n) => GraphOf(n, i => new[] { (i + 1) % n });

    private static JArray Repeated(string v, int n) => new(Enumerable.Repeat((object)v, n));

    private static JObject ListDoc(int n) => new()
    {
        ["@context"] = new JObject { ["values"] = new JObject { ["@id"] = "https://example.org/values", ["@container"] = "@list" } },
        ["values"] = Repeated("x", n),
    };

    // ---- blank-node work cap ------------------------------------------------------------------

    public static IEnumerable<object[]> ExpensiveDocs() => new[]
    {
        new object[] { "clique of 9", 9, "clique" }, new object[] { "clique of 40", 40, "clique" },
        new object[] { "cycle of 1000", 1000, "cycle" },
    };

    [Theory, MemberData(nameof(ExpensiveDocs))]
    public void Canonicalize_RefusesExpensiveBlankNodes(string name, int n, string shape)
    {
        var doc = shape == "clique" ? BlankClique(n) : BlankCycle(n);
        foreach (var (fn, canon) in Canonicalizers())
        {
            var sw = Stopwatch.StartNew();
            var e = Record.Exception(() => canon(doc));
            Assert.True(e is BlankNodeWorkException, $"{name}/{fn}: {e?.GetType().Name} {e?.Message}");
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3), $"{name}/{fn} refusal took {sw.Elapsed}");
        }
    }

    [Fact]
    public void Canonicalize_AcceptsCredentialShapes()
    {
        var anonymous = new JArray(Enumerable.Range(0, 300).Select(i => (JToken)new JObject { ["name"] = $"course {i}" }));
        var identical = new JArray(Enumerable.Range(0, 300).Select(_ => (JToken)new JObject { ["name"] = "same" }));
        JObject Proof(string graph, string id) => new()
        {
            ["@id"] = graph,
            ["@graph"] = new JArray(new JObject { ["@id"] = id, ["name"] = "same proof" }),
        };
        var docs = new Dictionary<string, JObject>
        {
            ["300 anonymous objects"] = new() { ["@context"] = LinkContext.DeepClone(), ["knows"] = anonymous },
            ["300 identical objects"] = new() { ["@context"] = LinkContext.DeepClone(), ["knows"] = identical },
            ["interchangeable proofs"] = new() { ["@context"] = LinkContext.DeepClone(), ["@graph"] = new JArray(Proof("_:g1", "_:p1"), Proof("_:g2", "_:p2")) },
            ["list of one value"] = new() { ["@context"] = ListDoc(1)["@context"]!.DeepClone(), ["values"] = Repeated("x", 60) },
        };
        foreach (var (name, doc) in docs)
            foreach (var (fn, canon) in Canonicalizers())
            {
                var e = Record.Exception(() => canon(doc));
                Assert.True(e == null, $"{name}/{fn}: {e}");
            }
    }

    [Fact]
    public void BlankNodeWork_LimitIsCheap()
    {
        var store = Store(BlankClique(3));
        var work = BlankNodeWork.Score(store);
        Assert.InRange(work, 1, BlankNodeWork.MaxBlankNodeWork);
        var sw = Stopwatch.StartNew();
        BlankNodeWork.Normalize(store);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Canonicalize_RefusesManyEdges()
    {
        var nodes = new JArray();
        for (var i = 0; i < 100; i++)
        {
            var node = new JObject { ["@id"] = $"_:b{i}" };
            for (var p = 0; p < 96; p++) node[$"p{p}"] = new JObject { ["@id"] = $"_:b{(i + p + 1) % 100}" };
            nodes.Add(node);
        }
        var doc = new JObject { ["@context"] = new JObject { ["@vocab"] = "https://example.org/" }, ["@graph"] = nodes };
        var sw = Stopwatch.StartNew();
        Assert.Throws<BlankNodeWorkException>(() => SdJsonLd.Canonicalize(doc));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"refusal took {sw.Elapsed}");
    }

    // A list of one repeated value is the real document nearest the limit.
    [Fact]
    public void Canonicalize_BlankNodeWorkLimit()
    {
        Assert.Equal(BlankNodeWork.MaxBlankNodeWork, BlankNodeWork.Score(Store(ListDoc(102))));
        SdJsonLd.Canonicalize(ListDoc(102));
        Assert.Throws<BlankNodeWorkException>(() => SdJsonLd.Canonicalize(ListDoc(103)));
    }

    [Fact]
    public void BlankNodeWork_IgnoresGroupsWithNoSearch()
    {
        var children = new JArray(Enumerable.Range(0, 500).Select(i => (JToken)new JObject
        {
            ["name"] = "same",
            ["knows"] = new JObject { ["name"] = i.ToString() },
        }));
        var doc = new JObject { ["@context"] = LinkContext.DeepClone(), ["knows"] = new JObject { ["knows"] = children } };
        Assert.Equal(0, BlankNodeWork.Score(Store(doc)));
    }

    [Fact]
    public void BlankNodeWork_AllocatesLinearly()
    {
        var children = new JArray(Enumerable.Range(0, 1500).Select(_ => (JToken)new JObject { ["name"] = "same" }));
        var store = Store(new JObject { ["@context"] = LinkContext.DeepClone(), ["knows"] = new JObject { ["knows"] = children } });
        var before = GC.GetAllocatedBytesForCurrentThread();
        var work = BlankNodeWork.Score(store);
        Assert.Equal(0, work);
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 100L << 20);
    }

    // The legacy canonicalizer keeps its lenient semantics: an undefined term is silently dropped.
    [Fact]
    public void LegacyCanonicalize_StaysLenient()
    {
        var doc = new JObject
        {
            ["@context"] = LinkContext.DeepClone(),
            ["@id"] = "https://example.org/s", ["name"] = "n",
            ["undefinedTerm"] = "x",
        };
        var legacy = Encoding.UTF8.GetString(Canonicalizer.CanonicalizeWithoutProof(Dict(doc)));
        Assert.DoesNotContain("undefinedTerm", legacy);
    }

    // ---- term definition bounds -----------------------------------------------------------------

    private static JObject InlineTerms(int n)
    {
        var o = new JObject();
        for (var i = 0; i < n; i++) o[$"t{i}"] = $"https://example.org/vocab#t{i}";
        return o;
    }

    private static JObject DocWithContext(JToken ctx, string term) =>
        new() { ["@context"] = ctx, ["@id"] = "https://example.org/subject", [term] = "value" };

    private static JObject PrefixChain(int links, int value)
    {
        var ctx = new JObject { ["t0"] = "https://example.org/" };
        for (var i = 1; i <= links; i++)
        {
            var name = $"t{i - 1}";
            ctx[$"t{i}"] = name + ":" + new string('x', value - name.Length - 2) + "/";
        }
        ctx["last"] = $"t{links}:last";
        return ctx;
    }

    [Fact]
    public void ContextTerms_InlineLimit()
    {
        foreach (var (fn, entry) in TermEntries())
        {
            var e = Record.Exception(() => entry(DocWithContext(InlineTerms(ContextTerms.MaxInlineContextTerms), "t0")));
            Assert.True(e == null, $"{fn} at the limit: {e}");
            Assert.True(Record.Exception(() => entry(DocWithContext(InlineTerms(ContextTerms.MaxInlineContextTerms + 1), "t0"))) is TooManyContextTermsException, fn);
        }
    }

    [Fact]
    public void ContextTerms_InlineCountReachesEveryContext()
    {
        var over = InlineTerms(ContextTerms.MaxInlineContextTerms + 1);
        var docs = new Dictionary<string, JObject>
        {
            ["node"] = new() { ["@context"] = new JObject { ["knows"] = "https://example.org/knows" }, ["knows"] = new JArray(new JObject { ["@context"] = over, ["t0"] = "value" }) },
            ["array"] = new() { ["@context"] = new JArray(InlineTerms(1), over), ["t0"] = "value" },
            ["nested"] = new() { ["@context"] = new JArray(new JObject { ["@context"] = over }), ["t0"] = "value" },
            ["scoped"] = new() { ["@context"] = new JObject { ["t0"] = new JObject { ["@id"] = "https://example.org/t0", ["@context"] = over } }, ["t0"] = "value" },
        };
        foreach (var (name, doc) in docs)
            Assert.True(Record.Exception(() => SdJsonLd.ExpandJsonLd(doc)) is TooManyContextTermsException, name);
    }

    private static string TermsContext(int n)
    {
        var b = new StringBuilder("{\"@context\":{\"t0\":\"https://example.org/t0\"");
        for (var i = 1; i < n; i++) b.Append($",\"t{i}\":\"https://example.org/t{i}\"");
        return b.Append("}}").ToString();
    }

    [Fact]
    public void ContextTerms_RemoteLimit()
    {
        using var srv = UseServer(c => Write(c, c.Request.Url!.AbsolutePath == "/at" ? TermsContext(ContextTerms.MaxContextTerms) : TermsContext(ContextTerms.MaxContextTerms + 1)));
        Canonicalizer.CanonicalizeWithoutProof(Dict(DocUsing(srv.Url + "/at", "t0")));
        Assert.Throws<TooManyContextTermsException>(() => Canonicalizer.CanonicalizeWithoutProof(Dict(DocUsing(srv.Url + "/past", "t0"))));
    }

    // A context named many times is many parses of the same terms, not more terms.
    [Fact]
    public void ContextTerms_RepeatedContextCountsOnce()
    {
        using var srv = UseServer(c => Write(c, TermsContext(ContextTerms.MaxContextTerms / 2)));
        var ctx = new JArray(srv.Url, new JObject { ["knows"] = "https://example.org/knows" });
        var doc = DocUsing(srv.Url, "t0");
        doc["knows"] = new JObject { ["@context"] = ctx.DeepClone(), ["t0"] = "value" };
        doc["@context"] = ctx;
        SdJsonLd.Canonicalize(doc);
    }

    [Fact]
    public void ContextTerms_LengthLimit()
    {
        string Long(int n) { const string p = "https://example.org/"; return p + new string('x', n - p.Length); }
        var shapes = new Dictionary<string, Func<int, JObject>>
        {
            ["term IRI"] = n => DocWithContext(new JObject { ["term"] = Long(n) }, "term"),
            ["term @id"] = n => DocWithContext(new JObject { ["term"] = new JObject { ["@id"] = Long(n) } }, "term"),
            ["term name"] = n => { var name = new string('x', n); return DocWithContext(new JObject { ["@vocab"] = "https://example.org/", [name] = "https://example.org/term" }, name); },
            ["@vocab"] = n => DocWithContext(new JObject { ["@vocab"] = Long(n) }, "term"),
            ["@base"] = n => new JObject { ["@context"] = new JObject { ["@base"] = Long(n), ["term"] = "https://example.org/term" }, ["@id"] = "https://example.org/subject", ["term"] = "value" },
        };
        foreach (var (name, doc) in shapes)
        {
            var ok = Record.Exception(() => SdJsonLd.Canonicalize(doc(ContextTerms.MaxContextTermBytes)));
            Assert.True(ok == null, $"{name} at the limit: {ok}");
            Assert.True(Record.Exception(() => SdJsonLd.Canonicalize(doc(ContextTerms.MaxContextTermBytes + 1))) is ContextTermTooLongException, name);
        }
    }

    [Fact]
    public void ContextTerms_ChainLimit()
    {
        const int value = 100;
        var links = ContextTerms.MaxContextTermBytes / value;
        var spare = ContextTerms.MaxContextTermBytes % value;
        var at = PrefixChain(links, value);
        at["t0"] = "urn:" + new string('x', spare - 6) + ":/";
        SdJsonLd.Canonicalize(DocWithContext(at, "last"));
        var past = PrefixChain(links, value);
        past["t0"] = "urn:" + new string('x', spare - 5) + ":/";
        Assert.Throws<ContextTermTooLongException>(() => SdJsonLd.Canonicalize(DocWithContext(past, "last")));
    }

    [Fact]
    public void ContextTerms_ChainShapes()
    {
        var suffix = new string('x', 1000) + "/";
        var vocabChain = new JArray(new JObject { ["@vocab"] = "https://example.org/" });
        for (var i = 0; i < 4; i++) vocabChain.Add(new JObject { ["@vocab"] = suffix });
        var aliases = new JObject { ["t0"] = "https://example.org/" };
        for (var i = 1; i < 4; i++)
        {
            aliases[$"a{i - 1}"] = $"t{i - 1}";
            aliases[$"t{i}"] = $"a{i - 1}:{suffix}";
        }
        aliases["last"] = "t3:last";
        var twoNames = new JArray(
            new JObject { ["a"] = "https://example.org/", ["b"] = "a:" + suffix },
            new JObject { ["a"] = "b:" + suffix },
            new JObject { ["b"] = "a:" + suffix },
            new JObject { ["a"] = "b:" + suffix, ["last"] = "a:last" });
        var compactNames = new JArray(new JObject { ["t0"] = "https://example.org/" });
        for (var i = 1; i < 4; i++)
            compactNames.Add(new JObject { ["@vocab"] = $"t{i - 1}:{suffix}", [$"t{i}"] = new JObject() });

        foreach (var (name, ctx) in new Dictionary<string, JToken> { ["@vocab"] = vocabChain, ["aliases"] = aliases, ["two names"] = twoNames, ["compact names"] = compactNames })
            Assert.True(Record.Exception(() => SdJsonLd.ExpandJsonLd(DocWithContext(ctx, "last"))) is ContextTermTooLongException, name);
    }

    // A chain that crosses from the document into a remote context and back is one chain.
    [Fact]
    public void ContextTerms_ChainCrossesInlineAndRemote()
    {
        var suffix = new string('x', 1000) + "/";
        using var srv = UseServer(c => Write(c, $"{{\"@context\":{{\"t1\":\"t0:{suffix}\",\"t3\":\"t2:{suffix}\"}}}}"));
        var ctx = new JArray(
            new JObject { ["t0"] = "https://example.org/" },
            srv.Url,
            new JObject { ["t2"] = "t1:" + suffix, ["t4"] = "t3:" + suffix, ["last"] = "t4:last" });
        Assert.Throws<ContextTermTooLongException>(() => SdJsonLd.ExpandJsonLd(DocWithContext(ctx, "last")));
    }

    // Many terms over a few prefixes, and aliases, none of which is a chain.
    [Fact]
    public void ContextTerms_AcceptsRealShapes()
    {
        var ctx = new JObject
        {
            ["schema"] = "https://schema.org/", ["xsd"] = "http://www.w3.org/2001/XMLSchema#",
            ["ex"] = "urn:example:", ["id"] = "@id", ["type"] = "@type",
        };
        for (var i = 0; i < ContextTerms.MaxInlineContextTerms - 5 - 2; i++)
            ctx[$"t{i}"] = new JObject { ["@id"] = $"schema:t{i}", ["@type"] = "xsd:string" };
        ctx["alias"] = "t0";
        ctx["self"] = "self";
        ctx["@vocab"] = "https://example.org/vocab#";
        SdJsonLd.Canonicalize(DocWithContext(ctx, "alias"));
    }

    // ---- remote context loading ---------------------------------------------------------------

    [Fact]
    public void LoadDocument_ConcurrentCustomContexts()
    {
        using var srv = UseServer(c => WriteContext(c));
        Parallel.For(0, 32, _ => Canonicalizer.CanonicalizeWithoutProof(Dict(DocUsing(srv.Url + "/", "term"))));
    }

    [Fact]
    public void LoadDocument_CachesACopyPerCaller()
    {
        using var srv = UseServer(c => WriteContext(c));
        var uri = new Uri(srv.Url + "/ctx");
        var (first, _) = ContextFetcher.Load(uri);
        ((JObject)first.Document)["@context"] = "mutated";
        var (second, _) = ContextFetcher.Load(uri);
        Assert.Equal("https://example.org/term", (string)((JObject)second.Document)["@context"]!["term"]!);
        Assert.Equal(1, srv.Hits);
    }

    [Fact]
    public void LoadDocument_CacheIsBounded()
    {
        using var srv = UseServer(c => WriteContext(c));
        for (var i = 0; i < ContextFetcher.MaxCachedContexts; i++) ContextFetcher.Load(new Uri($"{srv.Url}/{i}"));
        Assert.Equal(ContextFetcher.MaxCachedContexts, ContextFetcher.CacheCount);
        ContextFetcher.Load(new Uri($"{srv.Url}/{ContextFetcher.MaxCachedContexts}"));
        Assert.Equal(ContextFetcher.MaxCachedContexts, ContextFetcher.CacheCount);
    }

    [Fact]
    public void DefaultClient_RefusesLoopback()
    {
        using var srv = new CtxServer(c => WriteContext(c)); // default (public-only) client stays installed
        var e = Record.Exception(() => ContextFetcher.Load(new Uri(srv.Url + "/ctx")));
        Assert.IsType<ContextLoadException>(e);
        Assert.True(Has<ContextAddressException>(e));
        Assert.Equal(0, srv.Hits);
    }

    [Theory]
    [InlineData("8.8.8.8", true)] [InlineData("1.1.1.1", true)] [InlineData("2606:4700:4700::1111", true)]
    [InlineData("127.0.0.1", false)] [InlineData("0.0.0.0", false)] [InlineData("10.0.0.1", false)]
    [InlineData("100.64.0.1", false)] [InlineData("100.100.100.200", false)] [InlineData("169.254.169.254", false)]
    [InlineData("172.16.0.1", false)] [InlineData("192.168.1.1", false)] [InlineData("198.18.0.1", false)]
    [InlineData("224.0.0.1", false)] [InlineData("255.255.255.255", false)] [InlineData("::", false)]
    [InlineData("::1", false)] [InlineData("fe80::1", false)] [InlineData("fe80::1%1", false)]
    [InlineData("fc00::1", false)] [InlineData("fd00:ec2::254", false)] [InlineData("ff02::1", false)]
    [InlineData("::ffff:127.0.0.1", false)] [InlineData("::ffff:169.254.169.254", false)]
    [InlineData("::169.254.169.254", false)] [InlineData("64:ff9b::a9fe:a9fe", false)] [InlineData("2002:a9fe:a9fe::", false)]
    public void IsPublicAddress(string addr, bool want) => Assert.Equal(want, ResolverGuard.IsPublicAddress(IPAddress.Parse(addr)));

    [Theory]
    [InlineData("file:///etc/hosts")] [InlineData("ftp://example.org/context")]
    public void LoadDocument_RefusesOtherSchemes(string url)
    {
        var e = Record.Exception(() => new ContextBudget().Load(new Uri(url), null));
        Assert.True(Has<ContextSchemeException>(e), e?.ToString());
    }

    [Fact]
    public void LoadDocument_RefusesAlternateWithOtherScheme()
    {
        using var srv = UseServer(c =>
        {
            c.Response.AddHeader("Link", "<ftp://example.org/context.json>; rel=\"alternate\"; type=\"application/ld+json\"");
            Write(c, "", "text/html");
        });
        Refuses<ContextSchemeException>(() => ContextFetcher.Load(new Uri(srv.Url + "/")));
    }

    [Fact]
    public void LoadDocument_RefusesUnparsableAlternate()
    {
        using var srv = UseServer(c =>
        {
            c.Response.AddHeader("Link", "<http://[>; rel=\"alternate\"; type=\"application/ld+json\">");
            WriteContext(c);
        });
        Refuses<ContextSchemeException>(() => SdJsonLd.ToRdfNQuads(DocUsing(srv.Url, "term")));
    }

    [Fact]
    public void LoadDocument_RefusesOversizedResponse()
    {
        using var srv = UseServer(c =>
        {
            var pad = ContextFetcher.MaxContextBytes - 100;
            var over = c.Request.Url!.AbsolutePath == "/over" ? 1000 : 0;
            Write(c, "{\"@context\":{\"term\":\"https://example.org/term\"},\"pad\":\"" + new string('x', pad + over - 40) + "\"}");
        });
        ContextFetcher.Load(new Uri(srv.Url + "/ok"));
        Assert.IsType<ContextLoadException>(Record.Exception(() => ContextFetcher.Load(new Uri(srv.Url + "/over"))));
    }

    [Fact]
    public void LoadDocument_TimesOut()
    {
        ContextFetcher.FetchTimeout = TimeSpan.FromMilliseconds(300);
        using var srv = UseServer(c => { Thread.Sleep(3000); WriteContext(c); });
        var sw = Stopwatch.StartNew();
        Assert.IsType<ContextLoadException>(Record.Exception(() => ContextFetcher.Load(new Uri(srv.Url + "/slow"))));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"took {sw.Elapsed}");
    }

    // A Link rel=alternate chain is bounded by the request count.
    [Fact]
    public void LoadDocument_BoundsAlternateChain()
    {
        var n = 0;
        using var srv = UseServer(c =>
        {
            c.Response.AddHeader("Link", $"</{Interlocked.Increment(ref n)}>; rel=\"alternate\"; type=\"application/ld+json\"");
            Write(c, "", "text/html");
        });
        Refuses<ContextRequestsException>(() => ContextFetcher.Load(new Uri(srv.Url + "/")));
        Assert.Equal(ContextFetcher.MaxContextRequests, srv.Hits);
    }

    // Without the budget a context that names itself recurses until the stack overflows.
    [Fact]
    public void Canonicalize_ContextIncludingItself()
    {
        using var srv = UseServer(c => Write(c, $"{{\"@context\":\"http://{c.Request.UserHostName}/\"}}"));
        foreach (var (fn, entry) in Canonicalizers().Concat(new[] { KeyValuePair.Create<string, Action<JObject>>("ToRdfNQuads", d => SdJsonLd.ToRdfNQuads(d)) }))
            Assert.True(Record.Exception(() => entry(DocUsing(srv.Url + "/", "term"))) != null, fn);
    }

    [Fact]
    public void ContextBudget_StopsAtDeadline()
    {
        var budget = new ContextBudget { Deadline = DateTime.UtcNow.AddSeconds(-1) };
        Assert.Throws<ContextOverflowException>(() => budget.Load(new Uri("https://example.org/context"), null));
        budget.Load(new Uri("https://www.w3.org/ns/credentials/v2"), null); // a bundled context needs no budget
    }

    [Fact]
    public void CustomContext_LoadsThroughHookOnly()
    {
        using var srv = UseServer(c =>
        {
            switch (c.Request.Url!.AbsolutePath)
            {
                case "/context": WriteContext(c); break;
                case "/redirect": c.Response.StatusCode = 302; c.Response.RedirectLocation = "/page"; break;
                default: // how schema.org answers: a page pointing at its context
                    c.Response.AddHeader("Link", "</context>; rel=\"alternate\"; type=\"application/ld+json\"");
                    Write(c, "", "text/html"); break;
            }
        });
        foreach (var path in new[] { "/context", "/redirect" })
            Assert.Contains("<https://example.org/term> \"value\"", Encoding.UTF8.GetString(SdJsonLd.Canonicalize(DocUsing(srv.Url + path, "term"))));

        ContextFetcher.SetHttpClient(null);
        var before = srv.Hits;
        Assert.ThrowsAny<Exception>(() => SdJsonLd.Canonicalize(DocUsing(srv.Url + "/context", "term")));
        Assert.Equal(before, srv.Hits);
    }

    // A log wants the cause and a caller must not see it.
    [Fact]
    public void LoadDocument_CauseIsOnTheChainOnly()
    {
        var e = Record.Exception(() => new ContextBudget().Load(new Uri("ftp://secret-host.example/ctx"), null));
        var load = Assert.IsType<ContextLoadException>(e);
        Assert.Equal("remote context could not be loaded", load.Message);
        Assert.IsType<ContextSchemeException>(load.InnerException);
    }

    [Fact]
    public void ContextBudget_BytesPerOperation()
    {
        using var srv = UseServer(c => WriteContext(c));
        var uri = new Uri(srv.Url + "/ctx");
        var (_, remote) = ContextFetcher.Load(uri);
        var bundledPath = Path.Combine(AppContext.BaseDirectory, "Credential", "Common", "Crypto", "w3c.credential.v2.json");
        foreach (var (u, size) in new[] { (uri, remote), (new Uri("https://www.w3.org/ns/credentials/v2"), Encoding.UTF8.GetByteCount(File.ReadAllText(bundledPath))) })
        {
            new ContextBudget { Bytes = ContextBudget.MaxContextBytesPerOperation - size }.Load(u, null);
            Assert.Throws<ContextOverflowException>(() => new ContextBudget { Bytes = ContextBudget.MaxContextBytesPerOperation - size + 1 }.Load(u, null));
        }
    }

    [Fact]
    public void Canonicalize_ContextIncludingItselfStopsAtTheByteLimit()
    {
        const int pad = 64 << 10;
        string? body = null;
        using var srv = UseServer(c => Write(c, body!));
        body = $"{{\"@context\":[\"{srv.Url}/\"{string.Concat(Enumerable.Repeat(",{}", pad / 3))}]}}";
        var budget = new ContextBudget();
        var e = Record.Exception(() => SdJsonLd.ExpandJsonLd(DocUsing(srv.Url + "/", "term")));
        Assert.NotNull(e);
        // Direct drive of the budget: each load spends the body's bytes.
        Exception? last = null;
        for (var i = 0; i < 100 && last == null; i++) last = Record.Exception(() => budget.Load(new Uri(srv.Url + "/"), null));
        Assert.IsType<ContextOverflowException>(last);
        Assert.True(budget.Loads <= ContextBudget.MaxContextBytesPerOperation / pad + 1, $"{budget.Loads} loads");
    }

    // Library failures become clean errors: no raw library exception escapes the entry points.
    [Fact]
    public void LibraryFailures_BecomeCleanErrors()
    {
        var bad = new JObject { ["@context"] = new JObject { ["@base"] = 5 }, ["@id"] = "x", ["a"] = "b" };
        foreach (var (fn, entry) in TermEntries())
        {
            var e = Record.Exception(() => entry(bad));
            Assert.True(e == null || e is InvalidOperationException, $"{fn}: {e?.GetType().FullName}");
        }
    }
}
