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

namespace Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

/// <summary>
/// Canonicalization utilities for JSON-LD documents using RDFC-1.0 algorithm.
/// </summary>
public static class Canonicalizer
{
    // Well-known W3C context URLs mapped to their local file names
    private static readonly Dictionary<string, string> WellKnownContexts = new()
    {
        { "https://www.w3.org/ns/credentials/v2", "w3c.credential.v2.json" },
        { "https://www.w3.org/ns/credentials/v2.jsonld", "w3c.credential.v2.json" },
        { "https://www.w3.org/ns/credentials/examples/v2", "w3c.credential.examples.v2.json" },
        { "https://www.w3.org/ns/credentials/examples/v2.jsonld", "w3c.credential.examples.v2.json" }
    };

    /// <summary>
    /// Canonicalizes a JSON document excluding the proof field using RDFC-1.0 algorithm.
    /// Returns the canonicalized N-Quads bytes ready for hashing/signing.
    /// </summary>
    /// <param name="document">The document to canonicalize</param>
    /// <returns>Canonicalized N-Quads as UTF-8 bytes</returns>
    /// <exception cref="ArgumentNullException">Thrown when document is null</exception>
    public static byte[] CanonicalizeWithoutProof(Dictionary<string, object?> document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var documentWithoutProof = RemoveProofField(document);
        var standardized = CredentialHelper.StandardizeToJsonLd(documentWithoutProof);
        var jsonString = JsonSerializer.Serialize(standardized);

        var options = CreateJsonLdOptions();
        var store = ParseJsonLdToRdf(jsonString, options);
        
        var canonicalizer = new RdfCanonicalizer();
        var canonicalized = canonicalizer.Canonicalize(store);

        return Encoding.UTF8.GetBytes(canonicalized.SerializedNQuads);
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

    private static JsonLdProcessorOptions CreateJsonLdOptions()
    {
        return new JsonLdProcessorOptions
        {
            ProcessingMode = JsonLdProcessingMode.JsonLd11,
            DocumentLoader = (uri, loaderOptions) =>
            {
                var url = uri.ToString();

                // Check if this is a well-known context that should be loaded locally
                if (WellKnownContexts.TryGetValue(url, out var localFileName))
                {
                    return LoadLocalContext(uri, localFileName, loaderOptions);
                }

                // Fallback to default loader (network) for unknown contexts
                return DefaultDocumentLoader.LoadJson(uri, loaderOptions);
            }
        };
    }

    private static TripleStore ParseJsonLdToRdf(string jsonString, JsonLdProcessorOptions options)
    {
        var store = new TripleStore();
        var parser = new JsonLdParser(options);
        using var reader = new StringReader(jsonString);
        parser.Load(store, reader);
        return store;
    }

    private static RemoteDocument LoadLocalContext(Uri uri, string localFileName, JsonLdLoaderOptions loaderOptions)
    {
        var filePath = GetSearchPaths(localFileName).FirstOrDefault(File.Exists);
        
        if (filePath != null)
        {
            return LoadContextFromFile(uri, filePath);
        }

        // File not found locally, fallback to network
        return DefaultDocumentLoader.LoadJson(uri, loaderOptions);
    }

    private static IEnumerable<string> GetSearchPaths(string fileName)
    {
        return new[]
        {
            fileName,
            $"Credential\\Common\\Crypto\\{fileName}",
            $"Credential/Common/Crypto/{fileName}"
        };
    }

    private static RemoteDocument LoadContextFromFile(Uri uri, string filePath)
    {
        try
        {
            var jsonContent = File.ReadAllText(filePath);
            var jsonObject = JObject.Parse(jsonContent);

            return new RemoteDocument
            {
                DocumentUrl = uri,
                Document = jsonObject
            };
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Failed to load local context file '{filePath}': {ex.Message}", ex);
        }
    }
}
