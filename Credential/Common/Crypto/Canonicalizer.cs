using System.IO;
using System.Reflection;
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
    private static RemoteDocument LoadCredentialsV2Context(Uri uri)
    {
        try
        {
            var assembly = typeof(Canonicalizer).Assembly;
            // Adjust namespace + path to your actual project structure
            const string resourceName = "Pila.CredentialSdk.DidComm.Credential.Common.Crypto.CredentialsV2.json";

            using var stream = assembly.GetManifestResourceStream(resourceName)
                ?? throw new FileNotFoundException($"Embedded resource '{resourceName}' not found.");

            using var reader = new StreamReader(stream);
            var jsonContent = reader.ReadToEnd();
            var jsonObject = JObject.Parse(jsonContent);

            return new RemoteDocument
            {
                DocumentUrl = uri,
                Document = jsonObject
            };
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to load embedded CredentialsV2 context: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Canonicalizes a JSON document excluding the proof field using RDFC-1.0 algorithm.
    /// Returns the canonicalized N-Quads bytes ready for hashing/signing.
    /// </summary>
    public static byte[] CanonicalizeWithoutProof(Dictionary<string, object> document)
    {
        if (document == null)
        {
            throw new ArgumentNullException(nameof(document));
        }

        // Create a copy without the proof field
        var documentCopy = new Dictionary<string, object>();
        foreach (var kvp in document)
        {
            if (kvp.Key != "proof")
            {
                documentCopy[kvp.Key] = kvp.Value;
            }
        }

        // Standardize the document to JSON-LD-friendly strings
        var standardized = CredentialHelper.StandardizeToJsonLd(documentCopy);

        // Convert Dictionary to JSON string
        var jsonString = JsonSerializer.Serialize(standardized);

        // Configure JsonLdParser with custom document loader that handles remote context loading
        var options = new JsonLdProcessorOptions
        {
            ProcessingMode = JsonLdProcessingMode.JsonLd11,
            DocumentLoader = (uri, loaderOptions) =>
            {
                // Try to load from local first
                if (uri.ToString() == "https://www.w3.org/ns/credentials/v2")
                {
                    return LoadCredentialsV2Context(uri);
                }
                return DefaultDocumentLoader.LoadJson(uri, loaderOptions);
            }
        };

        // Parse JSON-LD into RDF TripleStore using TextReader
        var store = new TripleStore();
        var parser = new JsonLdParser(options);
        using (var reader = new StringReader(jsonString))
        {
            parser.Load(store, reader);
        }

        // Canonicalize using RDFC-1.0 algorithm
        var canonicalizer = new RdfCanonicalizer();
        var canonicalized = canonicalizer.Canonicalize(store);

        // Return canonicalized N-Quads as bytes
        return Encoding.UTF8.GetBytes(canonicalized.SerializedNQuads);
    }

    /// <summary>
    /// Computes the SHA-256 digest of the canonicalized document.
    /// </summary>
    public static byte[] ComputeDigest(byte[] canonicalizedData)
    {
        if (canonicalizedData == null)
        {
            throw new ArgumentNullException(nameof(canonicalizedData));
        }

        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(canonicalizedData);
    }
}
