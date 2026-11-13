using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json.Linq;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.JsonLd.Syntax;
using VDS.RDF.Parsing;
using Pila.CredentialSdk.DidComm.Credential.Common.Processor;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

/// <summary>
/// Canonicalization utilities for JSON-LD documents using RDFC-1.0 algorithm.
/// </summary>
public static class Canonicalizer
{
    /// <summary>
    /// Canonicalizes a JSON document excluding the proof field using RDFC-1.0 algorithm.
    /// Returns the canonicalized N-Quads bytes ready for hashing/signing.
    /// </summary>
    /// <param name="document">The document to canonicalize</param>
    /// <returns>Canonicalized N-Quads as UTF-8 bytes</returns>
    /// <exception cref="ArgumentNullException">Thrown when document is null</exception>
    public static byte[] CanonicalizeWithoutProof(Dictionary<string, object?> document, bool legacyStringScalars = false)
    {
        ArgumentNullException.ThrowIfNull(document);

        var documentWithoutProof = RemoveProofField(document);
        var standardized = CredentialHelper.StandardizeToJsonLd(documentWithoutProof, legacyStringScalars);
        var jsonString = JsonSerializer.Serialize(standardized);

        // Legacy lenient semantics: SafeMode stays off (undefined terms are dropped, as in Go's CanonicalizeDocument),
        // but remote-context, term and blank-node-work bounds apply.
        return ContextBudget.Guard("failed to normalize document", () =>
        {
            var options = ContextBudget.NewOptions(JToken.Parse(jsonString));
            var store = ParseJsonLdToRdf(jsonString, options);
            return Encoding.UTF8.GetBytes(BlankNodeWork.Normalize(store).SerializedNQuads);
        });
    }

    /// <summary>
    /// Computes the SHA-256 digest of the canonicalized document.
    /// </summary>
    /// <param name="canonicalizedData">The canonicalized data to hash</param>
    /// <returns>SHA-256 hash bytes</returns>
    /// <exception cref="ArgumentNullException">Thrown when canonicalizedData is null</exception>
    public static byte[] ComputeDigest(byte[] canonicalizedData)
    {
        ArgumentNullException.ThrowIfNull(canonicalizedData);

        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(canonicalizedData);
    }

    private static Dictionary<string, object?> RemoveProofField(Dictionary<string, object?> document)
    {
        return document
            .Where(kvp => kvp.Key != "proof")
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
    }

    private static TripleStore ParseJsonLdToRdf(string jsonString, JsonLdProcessorOptions options)
    {
        var store = new TripleStore();
        var parser = new JsonLdParser(options);
        using var reader = new StringReader(jsonString);
        parser.Load(store, reader);
        return store;
    }
}
