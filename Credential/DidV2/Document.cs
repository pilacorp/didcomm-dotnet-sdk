using System.Text.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Did;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public static class DidV2Document
{
    public static DidDocument? GenerateDidDocument(
        string didPublicKey,
        string did,
        string hash,
        string issuerDid,
        byte didType = DidTypes.People,
        Dictionary<string, object>? metadata = null,
        params VerificationMethodSpec[] extraVms)
    {
        var docMetadata = metadata == null ? new Dictionary<string, object>() : new Dictionary<string, object>(metadata);
        var typeName = DidTypes.ToName(didType);
        if (!string.IsNullOrEmpty(typeName) && typeName != "unknown") docMetadata["type"] = typeName;
        if (!string.IsNullOrEmpty(hash)) docMetadata["hash"] = hash;

        var specs = new List<VerificationMethodSpec> { NewSpec(NewSecp256k1Vm(did, "#key-1", didPublicKey)) };
        specs.AddRange(extraVms);
        var built = NewVerificationMethods(specs.ToArray());
        if (built == null) return null;
        return new DidDocument
        {
            Context = DocumentContext(built.Value.Vms),
            Id = did,
            Controller = issuerDid,
            VerificationMethod = built.Value.Vms,
            Authentication = built.Value.Authentication,
            AssertionMethod = built.Value.AssertionMethod,
            DidDocumentMetadata = SortObject(docMetadata)
        };
    }

    public static VerificationMethodSpec NewSpec(VerificationMethodEntry vm, params string[] purposes) =>
        new() { Vm = vm, Purposes = purposes.Length == 0 ? [] : purposes.ToList() };

    public static VerificationMethodEntry NewSecp256k1Vm(string did, string fragment, string publicKeyHex) =>
        new()
        {
            Id = DidDocuments.CanonicalVmId(did, fragment),
            Type = DidDocuments.Secp256k1VmType,
            Controller = did,
            PublicKeyHex = publicKeyHex
        };

    public static VerificationMethodEntry NewP256MultikeyVm(string did, string fragment, P256Xy xy)
    {
        var uncompressed = Hex.ToBytes("04" + xy.X + xy.Y);
        var curve = SecNamedCurves.GetByName("secp256r1") ?? SecNamedCurves.GetByName("prime256v1");
        var domain = new ECDomainParameters(curve!.Curve, curve.G, curve.N, curve.H);
        var point = curve.Curve.DecodePoint(uncompressed);
        var pub = new ECPublicKeyParameters("EC", point, domain);
        return new VerificationMethodEntry
        {
            Id = DidDocuments.CanonicalVmId(did, fragment),
            Type = DidDocuments.MultikeyVmType,
            Controller = did,
            PublicKeyMultibase = Multikey.EncodeP256(pub)
        };
    }

    public static (List<VerificationMethodEntry> Vms, List<string> Authentication, List<string> AssertionMethod)? NewVerificationMethods(params VerificationMethodSpec[] specs)
    {
        var vms = new List<VerificationMethodEntry>();
        var authentication = new List<string>();
        var assertionMethod = new List<string>();
        foreach (var s in specs)
        {
            vms.Add(s.Vm);
            var purposes = s.Purposes.Count == 0
                ? new List<string> { VerificationPurposes.Authentication, VerificationPurposes.AssertionMethod }
                : s.Purposes;
            foreach (var p in purposes)
            {
                if (p == VerificationPurposes.Authentication) authentication.Add(s.Vm.Id);
                else if (p == VerificationPurposes.AssertionMethod) assertionMethod.Add(s.Vm.Id);
                else return null;
            }
        }
        return (vms, authentication, assertionMethod);
    }

    public static void ValidateDidDocument(DidDocument doc)
    {
        var seen = new HashSet<string>();
        for (var i = 0; i < doc.VerificationMethod.Count; i++)
        {
            var vm = doc.VerificationMethod[i];
            if (string.IsNullOrEmpty(vm.Id)) throw new InvalidOperationException($"verificationMethod[{i}]: id is empty");
            if (!seen.Add(vm.Id))
            {
                throw new InvalidOperationException($"verificationMethod: duplicate id {vm.Id} (#key-1 and #key-2 are reserved by GenerateDID)");
            }
            var expected = VmTypeFor(vm);
            if (vm.Type != expected)
            {
                throw new InvalidOperationException(
                    $"verificationMethod[{i}] ({vm.Id}): type \"{vm.Type}\" does not match its key material: expected {expected}");
            }
        }
        foreach (var (name, refs) in new[] { ("authentication", doc.Authentication ?? []), ("assertionMethod", doc.AssertionMethod ?? []) })
        {
            foreach (var r in refs)
            {
                if (!seen.Contains(DidDocuments.CanonicalVmId(doc.Id, r)))
                {
                    throw new InvalidOperationException($"{name} references unknown verification method \"{r}\"");
                }
            }
        }
    }

    public static string HashDidDocument(DidDocument doc)
    {
        var marshaled = ToHashJson(doc);
        var canonical = Rfc8785.Transform(marshaled);
        return EthCrypto.Keccak256Hex(canonical);
    }

    public static string ToJson(DidDocument doc)
    {
        var obj = new JObject
        {
            ["@context"] = new JArray(doc.Context),
            ["id"] = doc.Id,
            ["controller"] = doc.Controller ?? "",
            ["verificationMethod"] = new JArray(doc.VerificationMethod.Select(VmToken)),
            ["authentication"] = new JArray(doc.Authentication ?? []),
            ["assertionMethod"] = new JArray(doc.AssertionMethod ?? []),
            ["didDocumentMetadata"] = JObject.FromObject(SortObject(doc.DidDocumentMetadata ?? new Dictionary<string, object>()))
        };
        return obj.ToString(Newtonsoft.Json.Formatting.None);
    }

    public static string ToHashJson(DidDocument doc) => ToJson(doc);

    public static DidDocument ParseDidDocumentJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var result = new DidDocument
        {
            Context = ReadStringList(root, "@context"),
            Id = root.GetProperty("id").GetString() ?? "",
            Controller = root.TryGetProperty("controller", out var c) ? c.GetString() : null,
            Authentication = ReadStringList(root, "authentication"),
            AssertionMethod = ReadStringList(root, "assertionMethod"),
            DidDocumentMetadata = ReadMetadata(root)
        };
        if (root.TryGetProperty("verificationMethod", out var vms))
        {
            foreach (var vm in vms.EnumerateArray())
            {
                result.VerificationMethod.Add(new VerificationMethodEntry
                {
                    Id = vm.GetProperty("id").GetString() ?? "",
                    Type = vm.GetProperty("type").GetString() ?? "",
                    Controller = vm.TryGetProperty("controller", out var ctrl) ? ctrl.GetString() : null,
                    PublicKeyHex = vm.TryGetProperty("publicKeyHex", out var hex) ? hex.GetString() : null,
                    PublicKeyMultibase = vm.TryGetProperty("publicKeyMultibase", out var mb) ? mb.GetString() : null,
                    Revoked = vm.TryGetProperty("revoked", out var rev) ? rev.GetString() : null,
                    RevocationReason = vm.TryGetProperty("revocationReason", out var rr) ? rr.GetString() : null
                });
            }
        }
        return result;
    }

    private static JObject VmToken(VerificationMethodEntry vm)
    {
        var o = new JObject
        {
            ["id"] = vm.Id,
            ["type"] = vm.Type,
            ["controller"] = vm.Controller
        };
        if (!string.IsNullOrEmpty(vm.PublicKeyHex)) o["publicKeyHex"] = vm.PublicKeyHex;
        if (!string.IsNullOrEmpty(vm.PublicKeyMultibase)) o["publicKeyMultibase"] = vm.PublicKeyMultibase;
        if (!string.IsNullOrEmpty(vm.Revoked)) o["revoked"] = vm.Revoked;
        if (!string.IsNullOrEmpty(vm.RevocationReason)) o["revocationReason"] = vm.RevocationReason;
        return o;
    }

    private static List<string> DocumentContext(List<VerificationMethodEntry> vms)
    {
        var ctx = new List<string> { "https://www.w3.org/ns/did/v1", "https://w3id.org/security/v1" };
        if (vms.Any(vm => vm.Type == DidDocuments.MultikeyVmType)) ctx.Add(DidDocuments.CidContext);
        return ctx;
    }

    private static string VmTypeFor(VerificationMethodEntry vm)
    {
        if (vm.PublicKeyJwk != null)
        {
            throw new InvalidOperationException("publicKeyJwk is not supported: publish secp256k1 as publicKeyHex or P-256 as publicKeyMultibase");
        }
        var hasHex = !string.IsNullOrEmpty(vm.PublicKeyHex);
        var hasMultibase = !string.IsNullOrEmpty(vm.PublicKeyMultibase);
        if (hasHex && hasMultibase) throw new InvalidOperationException("verification method must have publicKeyHex or publicKeyMultibase, not both");
        if (hasHex) return DidDocuments.Secp256k1VmType;
        if (hasMultibase) return DidDocuments.MultikeyVmType;
        throw new InvalidOperationException("verification method must have either publicKeyHex or publicKeyMultibase");
    }

    public static Dictionary<string, object> SortObject(Dictionary<string, object> input)
    {
        var output = new Dictionary<string, object>();
        foreach (var key in input.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var v = input[key];
            output[key] = v is Dictionary<string, object> nested ? SortObject(nested) : v;
        }
        return output;
    }

    private static List<string> ReadStringList(JsonElement root, string name)
    {
        var list = new List<string>();
        if (!root.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.Array) return list;
        foreach (var item in el.EnumerateArray()) list.Add(item.GetString() ?? "");
        return list;
    }

    private static Dictionary<string, object> ReadMetadata(JsonElement root)
    {
        var map = new Dictionary<string, object>();
        if (!root.TryGetProperty("didDocumentMetadata", out var el) || el.ValueKind != JsonValueKind.Object) return map;
        foreach (var p in el.EnumerateObject())
        {
            map[p.Name] = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString()! : p.Value.GetRawText();
        }
        return map;
    }
}
