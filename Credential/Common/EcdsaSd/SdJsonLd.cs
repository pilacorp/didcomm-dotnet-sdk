using System.IO;
using Newtonsoft.Json.Linq;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.JsonLd.Syntax;
using VDS.RDF.Parsing;
using VDS.RDF.Writing;
using Pila.CredentialSdk.DidComm.Credential.Common.Processor;

namespace Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd;

/// <summary>
/// JSON-LD processing for the ecdsa-sd-2023 selective-disclosure cryptosuite,
/// built on dotNetRDF (RDFC-1.0 / URDNA2015). Mirrors the Go
/// credential/common/processor canonicalize_idmap.go primitives: expand,
/// compact, toRDF N-Quads, and canonicalize with a blank-node id map.
///
/// The id map returned here uses bare blank-node labels on both sides,
/// e.g. "b0" =&gt; "c14n0" (dotNetRDF's RdfCanonicalizer reports input labels
/// without the "_:" prefix as keys and canonical labels with it as values; we
/// strip the prefix from the value).
/// </summary>
public static class SdJsonLd
{
    // Options() builds a fresh per-operation ContextBudget (remote @context bounds, term bounds,
    // bundled W3C contexts offline). SafeMode fails on undefined terms instead of silently dropping
    // them (lossless), matching the Go sdOptions SafeMode=true.
    private static JsonLdProcessorOptions Options(JToken? inlineDoc) =>
        ContextBudget.NewOptions(inlineDoc, safeMode: true, nativeTypes: true);

    /// <summary>Expands a compact JSON-LD document (SafeMode: fails on undefined terms).</summary>
    public static JArray ExpandJsonLd(JToken doc) =>
        ContextBudget.Guard("expand", () => JsonLdProcessor.Expand(doc, Options(doc)));

    /// <summary>Compacts an expanded JSON-LD document against <paramref name="context"/>.</summary>
    public static JObject CompactJsonLd(JToken expanded, JToken? context) =>
        ContextBudget.Guard("compact", () => JsonLdProcessor.Compact(expanded, context, Options(null)));

    /// <summary>
    /// Converts a JSON-LD document to N-Quads (each ending in "\n"), in toRDF
    /// order (not canonicalized). Accepts compact or expanded input.
    /// </summary>
    public static List<string> ToRdfNQuads(JToken doc)
    {
        var store = ContextBudget.Guard("to rdf", () => ParseToStore(doc));
        var sw = new System.IO.StringWriter();
        new NQuadsWriter(NQuadsSyntax.Rdf11).Save(store, sw);
        // dotNetRDF's N-Quads writer emits the redundant explicit datatype on
        // simple string literals ("x"^^xsd:string); RDFC-1.0 canonical output and
        // the JSON-LD reference serializers write the RDF 1.1 plain form ("x").
        // Drop it so selection N-Quads match the canonicalized full-document ones.
        var text = sw.ToString().Replace("^^<http://www.w3.org/2001/XMLSchema#string>", "");
        return SplitNQuadsKeepNl(text);
    }

    /// <summary>
    /// Canonicalizes a JSON-LD document with RDFC-1.0 and returns the canonical
    /// N-Quads plus a bare-label id map (input label =&gt; canonical label).
    /// </summary>
    public static (List<string> NQuads, Dictionary<string, string> IdMap) CanonicalizeWithIdMap(JToken doc)
    {
        return ContextBudget.Guard("canonicalize", () => CanonicalizeStore(ParseToStore(doc)));
    }

    /// <summary>
    /// Canonicalizes an N-Quads dataset (the label-replacement step of SD).
    /// </summary>
    public static (List<string> NQuads, Dictionary<string, string> IdMap) CanonicalizeNQuadsWithIdMap(IEnumerable<string> nquads)
    {
        return ContextBudget.Guard("canonicalize", () =>
        {
            var store = new TripleStore();
            using var reader = new StringReader(string.Concat(nquads));
            new NQuadsParser(NQuadsSyntax.Rdf11).Load(store, reader);
            return CanonicalizeStore(store);
        });
    }

    /// <summary>
    /// Returns the document's canonical N-Quads as a single byte string. Fails
    /// on an empty dataset so a signature never commits to nothing. Used for the
    /// proof-configuration hash (hashProofConfig).
    /// </summary>
    public static byte[] Canonicalize(JToken doc)
    {
        var (nquads, _) = CanonicalizeWithIdMap(doc);
        var joined = string.Concat(nquads);
        if (joined.Length == 0)
        {
            throw new InvalidOperationException(
                "ecdsasd: canonicalization produced no N-Quads; the document has no @context or no JSON-LD terms");
        }
        return System.Text.Encoding.UTF8.GetBytes(joined);
    }

    private static TripleStore ParseToStore(JToken doc)
    {
        var store = new TripleStore();
        using var reader = new StringReader(doc.ToString());
        new JsonLdParser(Options(doc)).Load(store, reader);
        return store;
    }

    private static (List<string>, Dictionary<string, string>) CanonicalizeStore(TripleStore store)
    {
        var result = BlankNodeWork.Normalize(store);
        var idMap = new Dictionary<string, string>();
        foreach (var kv in result.IssuedIdentifiersMap)
        {
            idMap[StripBnodePrefix(kv.Key)] = StripBnodePrefix(kv.Value);
        }
        return (SplitNQuadsKeepNl(result.SerializedNQuads), idMap);
    }

    private static string StripBnodePrefix(string s) => s.StartsWith("_:") ? s.Substring(2) : s;

    /// <summary>Splits a serialized N-Quads document into quads, keeping each trailing "\n".</summary>
    internal static List<string> SplitNQuadsKeepNl(string s)
    {
        var outList = new List<string>();
        if (string.IsNullOrEmpty(s))
        {
            return outList;
        }
        foreach (var part in s.Split('\n'))
        {
            if (part.Trim().Length == 0)
            {
                continue;
            }
            outList.Add(part + "\n");
        }
        return outList;
    }
}
