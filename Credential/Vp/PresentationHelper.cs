using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Vc;

namespace Pila.CredentialSdk.DidComm.Credential.Vp;

/// <summary>
/// Helper functions for presentation serialization, embedded-credential
/// verification and field extraction. Mirrors Go credential/vp presentation_helper.go.
/// </summary>
internal static class PresentationHelper
{
    /// <summary>
    /// Serializes PresentationContents into presentation data. Embedded
    /// credentials must already be signed (their Serialize is called here).
    /// </summary>
    public static PresentationData SerializePresentationContents(PresentationContents vpc)
    {
        if (vpc == null)
        {
            throw new ArgumentNullException(nameof(vpc));
        }

        if (vpc.Context.Count == 0 && string.IsNullOrEmpty(vpc.Id) && string.IsNullOrEmpty(vpc.Holder))
        {
            throw new ArgumentException("contents must have context, ID, or holder");
        }

        var vpJson = new PresentationData();

        if (vpc.Context.Count > 0)
        {
            vpJson["@context"] = Common.Util.Util.SerializeContexts(vpc.Context);
        }
        if (!string.IsNullOrEmpty(vpc.Id))
        {
            vpJson["id"] = vpc.Id;
        }
        if (vpc.Types.Count > 0)
        {
            vpJson["type"] = Common.Util.Util.SerializeTypes(vpc.Types);
        }
        if (!string.IsNullOrEmpty(vpc.Holder))
        {
            vpJson["holder"] = vpc.Holder;
        }
        if (vpc.ValidFrom != default)
        {
            vpJson["validFrom"] = vpc.ValidFrom.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }
        if (vpc.ValidUntil != default)
        {
            vpJson["validUntil"] = vpc.ValidUntil.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }
        if (vpc.VerifiableCredentials.Count > 0)
        {
            var credentialList = new List<object>(vpc.VerifiableCredentials.Count);
            for (var i = 0; i < vpc.VerifiableCredentials.Count; i++)
            {
                var cred = vpc.VerifiableCredentials[i];
                if (cred == null)
                {
                    throw new ArgumentException($"credential at index {i} is nil");
                }
                credentialList.Add(cred.Serialize());
            }
            vpJson["verifiableCredential"] = credentialList;
        }

        return vpJson;
    }

    /// <summary>
    /// Verifies every embedded credential's proof, forwarding the presentation's
    /// resolver / offline / base-url plus any extra vc options. A caller-supplied
    /// option wins because it is appended last.
    /// </summary>
    public static void VerifyCredentials(PresentationData data, PresentationOptions options)
    {
        if (!data.TryGetValue("verifiableCredential", out var raw) || raw == null)
        {
            throw new InvalidOperationException("credential input is nil");
        }

        var items = AsList(raw);
        if (items.Count == 0)
        {
            throw new InvalidOperationException("credential input is nil");
        }

        var forwarded = new List<CredentialOpt>();
        if (options.Resolver != null)
        {
            forwarded.Add(CredentialOpts.WithResolver(options.Resolver));
        }
        else
        {
            forwarded.Add(CredentialOpts.WithBaseUrl(options.DidBaseUrl));
        }
        if (options.IsOffline)
        {
            forwarded.Add(CredentialOpts.WithOffline());
        }
        forwarded.AddRange(options.VcOpts);

        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            if (item == null)
            {
                throw new InvalidOperationException($"credential at index {i} is nil");
            }

            byte[] rawCred = item is string s
                ? Encoding.UTF8.GetBytes(s)
                : Encoding.UTF8.GetBytes(JsonSerializer.Serialize(item));

            ICredential cred;
            try
            {
                cred = Vc.Credential.ParseCredential(rawCred);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"failed to parse credential at index {i}: {ex.Message}", ex);
            }

            try
            {
                cred.Verify(forwarded.ToArray());
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"failed to verify credential at index {i}: {ex.Message}", ex);
            }
        }
    }

    /// <summary>
    /// Returns the value at a dot-notation path, or null if any segment is missing
    /// or a non-object is traversed.
    /// </summary>
    public static object? ExtractFieldFromMap(PresentationData data, string path)
    {
        object? current = data;
        foreach (var part in path.Split('.'))
        {
            switch (current)
            {
                case IDictionary<string, object> dict:
                    if (!dict.TryGetValue(part, out current))
                    {
                        return null;
                    }
                    break;
                case JsonElement je when je.ValueKind == JsonValueKind.Object:
                    if (!je.TryGetProperty(part, out var child))
                    {
                        return null;
                    }
                    current = child;
                    break;
                default:
                    return null;
            }
        }
        return current;
    }

    private static List<object?> AsList(object raw)
    {
        if (raw is JsonElement je)
        {
            return je.ValueKind == JsonValueKind.Array
                ? je.EnumerateArray().Select(e => (object?)e).ToList()
                : new List<object?> { je };
        }
        if (raw is not string && raw is System.Collections.IEnumerable en)
        {
            return en.Cast<object?>().ToList();
        }
        return new List<object?> { raw };
    }
}
