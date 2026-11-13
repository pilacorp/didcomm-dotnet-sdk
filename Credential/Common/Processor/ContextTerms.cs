using System.Text;
using Newtonsoft.Json.Linq;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Processor;

/// <summary>
/// Sizes the term definitions of one JSON-LD operation before the library
/// processes them (port of Go contextTerms). A term's IRI is built by joining it
/// to the IRI of the term it names, so a context within the byte limits can still
/// expand to thousands of IRIs of megabytes each. Order of contexts is ignored:
/// every definition of every term another one expands through is counted.
/// </summary>
public sealed class ContextTerms
{
    public const int MaxContextTerms = 10000;
    public const int MaxInlineContextTerms = 1000;
    public const int MaxContextTermBytes = 1 << 10;

    private readonly Dictionary<string, List<string>> _defs = new();
    private readonly HashSet<string> _used = new();
    private int _chain;
    private int _longest;

    public int TermCount => _defs.Count;

    public void Check(int limit)
    {
        if (_defs.Count > limit)
            throw new TooManyContextTermsException($"too many context term definitions: limit is {limit}");
        if (_longest > MaxContextTermBytes || _chain > MaxContextTermBytes)
            throw new ContextTermTooLongException($"context term is too long: limit is {MaxContextTermBytes} bytes");
    }

    /// <summary>Adds the @context values anywhere under <paramref name="v"/>.</summary>
    public void AddDocument(JToken? v)
    {
        switch (v)
        {
            case JArray arr:
                foreach (var item in arr) AddDocument(item);
                break;
            case JObject obj:
                foreach (var p in obj.Properties())
                {
                    if (p.Name == "@context") Add(p.Value);
                    else AddDocument(p.Value);
                }
                break;
        }
    }

    private void Add(JToken? ctx)
    {
        switch (ctx)
        {
            case JArray arr:
                foreach (var item in arr) Add(item);
                break;
            case JObject obj:
                foreach (var p in obj.Properties())
                {
                    if (p.Name == "@context") Add(p.Value);
                    else if (p.Name is "@vocab" or "@base")
                    {
                        if (p.Value.Type == JTokenType.String)
                        {
                            var iri = (string)p.Value!;
                            _longest = Math.Max(_longest, Len(iri));
                            Link(iri);
                        }
                    }
                    else if (!p.Name.StartsWith('@')) Define(p.Name, p.Value);
                }
                break;
        }
    }

    private void Define(string term, JToken def)
    {
        var iri = term; // with no IRI of its own a term is its name, joined to @vocab or a prefix
        if (def.Type == JTokenType.String) iri = (string)def!;
        else if (def is JObject d)
        {
            if (d["@id"] is { Type: JTokenType.String } id) iri = (string)id!;
            else if (d["@reverse"] is { Type: JTokenType.String } rev) iri = (string)rev!;
            Add(d["@context"]);
        }
        _longest = Math.Max(_longest, Math.Max(Len(term), Len(iri)));
        if (!_defs.TryGetValue(term, out var list)) _defs[term] = list = new();
        list.Add(iri);
        if (_used.Contains(term)) Link(iri);
        if (iri.Contains(':')) Use(ExpandsThrough(iri));
    }

    private void Use(string term)
    {
        if (!_used.Add(term)) return;
        if (_defs.TryGetValue(term, out var list))
            foreach (var iri in list.ToArray()) Link(iri);
    }

    private void Link(string iri)
    {
        var term = ExpandsThrough(iri);
        if (term.Length == 0) return;
        _chain += Len(iri);
        Use(term);
    }

    /// <summary>
    /// The term the library may expand iri through: the part before the colon of a
    /// compact IRI, or all of an alias. "" for a keyword, a blank node, or scheme://.
    /// </summary>
    private static string ExpandsThrough(string iri)
    {
        var i = iri.IndexOf(':');
        var prefix = i < 0 ? iri : iri[..i];
        var suffix = i < 0 ? "" : iri[(i + 1)..];
        if (iri.StartsWith('@') || prefix == "_" || suffix.StartsWith("//")) return "";
        return prefix;
    }

    private static int Len(string s) => Encoding.UTF8.GetByteCount(s);
}
