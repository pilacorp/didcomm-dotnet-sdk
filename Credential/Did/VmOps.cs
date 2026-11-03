using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.DidV2;

namespace Pila.CredentialSdk.DidComm.Credential.Did;

public static class VmOps
{
    private static readonly string[] Supported = [VerificationPurposes.Authentication, VerificationPurposes.AssertionMethod];

    public static VerificationMethodEntry? FindVerificationMethod(DidDocument? doc, string idOrFragment)
    {
        if (doc == null) return null;
        var target = DidDocuments.CanonicalVmId(doc.Id, idOrFragment);
        return doc.VerificationMethod.FirstOrDefault(vm => DidDocuments.CanonicalVmId(doc.Id, vm.Id) == target);
    }

    public static string AddVerificationMethod(DidDocument doc, VerificationMethodEntry vm, IReadOnlyList<string>? purposes = null)
    {
        ArgumentNullException.ThrowIfNull(doc);
        if (string.IsNullOrEmpty(doc.Id)) throw new InvalidOperationException("document.id is required");
        purposes ??= [];
        var expectedType = VmTypeFor(vm);
        ValidatePurposes(purposes);
        var next = new VerificationMethodEntry
        {
            Id = string.IsNullOrEmpty(vm.Id) ? NextSequentialKid(doc) : DidDocuments.CanonicalVmId(doc.Id, vm.Id),
            Type = string.IsNullOrEmpty(vm.Type) ? expectedType : vm.Type,
            Controller = string.IsNullOrEmpty(vm.Controller) ? doc.Id : vm.Controller,
            PublicKeyHex = vm.PublicKeyHex,
            PublicKeyMultibase = vm.PublicKeyMultibase,
            PublicKeyJwk = vm.PublicKeyJwk,
            Revoked = vm.Revoked,
            RevocationReason = vm.RevocationReason
        };
        if (next.Type != expectedType)
        {
            throw new InvalidOperationException(
                $"verification method type \"{next.Type}\" does not match its key material: expected {expectedType}");
        }
        if (FindVerificationMethod(doc, next.Id) != null)
        {
            throw new InvalidOperationException($"verification method already exists: {next.Id}");
        }
        var existing = FindByKeyFingerprint(doc, KeyFingerprint(next));
        if (!string.IsNullOrEmpty(existing))
        {
            throw new InvalidOperationException($"verification method with the same public key already exists: {existing}");
        }
        doc.VerificationMethod.Add(next);
        if (next.Type == DidDocuments.MultikeyVmType) EnsureContext(doc, DidDocuments.CidContext);
        foreach (var p in purposes) AddPurpose(doc, p, next.Id);
        return next.Id;
    }

    public static string RotateVerificationMethod(DidDocument doc, string oldKid, VerificationMethodEntry newVm, string reason = "superseded", DateTimeOffset? revokedAt = null)
    {
        ArgumentNullException.ThrowIfNull(doc);
        if (string.IsNullOrEmpty(oldKid)) throw new InvalidOperationException("old_kid is required");
        var old = FindVerificationMethod(doc, oldKid) ?? throw new InvalidOperationException($"verification method not found: {oldKid}");
        if (!string.IsNullOrEmpty(old.Revoked)) throw new InvalidOperationException($"verification method \"{old.Id}\" is already revoked");
        var purposes = PurposesOfKid(doc, old.Id);
        var newId = AddVerificationMethod(doc, newVm, purposes);
        var after = FindVerificationMethod(doc, oldKid) ?? throw new InvalidOperationException($"verification method index mismatch after append: {oldKid}");
        after.Revoked = (revokedAt ?? DateTimeOffset.UtcNow).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        after.RevocationReason = string.IsNullOrEmpty(reason) ? "superseded" : reason;
        EnsureContext(doc, DidDocuments.CidContext);
        return newId;
    }

    public static void RevokeVerificationMethod(DidDocument doc, string kid, string reason, DateTimeOffset? revokedAt = null)
    {
        ArgumentNullException.ThrowIfNull(doc);
        if (string.IsNullOrEmpty(kid)) throw new InvalidOperationException("kid is required");
        if (string.IsNullOrEmpty(reason)) throw new InvalidOperationException("reason is required");
        var vm = FindVerificationMethod(doc, kid) ?? throw new InvalidOperationException($"verification method not found: {kid}");
        if (!string.IsNullOrEmpty(vm.Revoked))
        {
            var at = DateTimeOffset.Parse(vm.Revoked).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
            throw new InvalidOperationException($"verification method \"{vm.Id}\" is already revoked at {at} (reason: {vm.RevocationReason})");
        }
        vm.Revoked = (revokedAt ?? DateTimeOffset.UtcNow).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        vm.RevocationReason = reason;
        EnsureContext(doc, DidDocuments.CidContext);
    }

    public static void AddVerificationMethodPurposes(DidDocument doc, string kid, IReadOnlyList<string> purposes)
    {
        ArgumentNullException.ThrowIfNull(doc);
        if (string.IsNullOrEmpty(kid)) throw new InvalidOperationException("kid is required");
        if (purposes.Count == 0) throw new InvalidOperationException("purposes is required");
        var vm = FindVerificationMethod(doc, kid) ?? throw new InvalidOperationException($"verification method not found: {kid}");
        if (!string.IsNullOrEmpty(vm.Revoked)) throw new InvalidOperationException($"verification method \"{vm.Id}\" is revoked");
        ValidatePurposes(purposes);
        foreach (var p in purposes) AddPurpose(doc, p, kid);
    }

    public static void RemoveVerificationMethodPurposes(DidDocument doc, string kid, IReadOnlyList<string> purposes)
    {
        ArgumentNullException.ThrowIfNull(doc);
        if (string.IsNullOrEmpty(kid)) throw new InvalidOperationException("kid is required");
        if (purposes.Count == 0) throw new InvalidOperationException("purposes is required");
        if (FindVerificationMethod(doc, kid) == null) throw new InvalidOperationException($"verification method not found: {kid}");
        ValidatePurposes(purposes);
        foreach (var p in purposes) RemovePurpose(doc, p, kid);
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

    private static void EnsureContext(DidDocument doc, string ctx)
    {
        if (!doc.Context.Contains(ctx)) doc.Context.Add(ctx);
    }

    private static string FindByKeyFingerprint(DidDocument doc, string fp)
    {
        if (string.IsNullOrEmpty(fp)) return "";
        return doc.VerificationMethod.FirstOrDefault(vm => KeyFingerprint(vm) == fp)?.Id ?? "";
    }

    private static string KeyFingerprint(VerificationMethodEntry vm)
    {
        if (!string.IsNullOrEmpty(vm.PublicKeyHex)) return "publicKeyHex:" + NormalizeSecp256k1Hex(vm.PublicKeyHex);
        if (!string.IsNullOrEmpty(vm.PublicKeyMultibase)) return "publicKeyMultibase:" + vm.PublicKeyMultibase;
        return "";
    }

    private static string NormalizeSecp256k1Hex(string h)
    {
        var trimmed = Hex.Normalize(h);
        try
        {
            return Hex.ToHex(EthCrypto.CompressSecp256k1(Hex.ToBytes(trimmed)), prefix: false);
        }
        catch
        {
            return trimmed;
        }
    }

    private static void ValidatePurposes(IReadOnlyList<string> purposes)
    {
        foreach (var p in purposes)
        {
            if (!Supported.Contains(p)) throw new InvalidOperationException($"unsupported purpose: {p}");
        }
    }

    private static void AddPurpose(DidDocument doc, string p, string kid)
    {
        if (p == VerificationPurposes.Authentication) doc.Authentication = AddRefNormalized(doc.Authentication, kid, doc.Id);
        else doc.AssertionMethod = AddRefNormalized(doc.AssertionMethod, kid, doc.Id);
    }

    private static void RemovePurpose(DidDocument doc, string p, string kid)
    {
        if (p == VerificationPurposes.Authentication) doc.Authentication = RemoveRefNormalized(doc.Authentication, kid, doc.Id);
        else doc.AssertionMethod = RemoveRefNormalized(doc.AssertionMethod, kid, doc.Id);
    }

    private static List<string> AddRefNormalized(List<string>? arr, string kid, string did)
    {
        var target = DidDocuments.CanonicalVmId(did, kid);
        var seen = new HashSet<string>();
        var output = new List<string>();
        foreach (var x in arr ?? [])
        {
            var c = DidDocuments.CanonicalVmId(did, x);
            if (!seen.Add(c)) continue;
            output.Add(c);
        }
        if (!seen.Contains(target)) output.Add(target);
        return output;
    }

    private static List<string> RemoveRefNormalized(List<string>? arr, string kid, string did)
    {
        var target = DidDocuments.CanonicalVmId(did, kid);
        var seen = new HashSet<string>();
        var output = new List<string>();
        foreach (var x in arr ?? [])
        {
            var c = DidDocuments.CanonicalVmId(did, x);
            if (c == target || !seen.Add(c)) continue;
            output.Add(c);
        }
        return output;
    }

    private static List<string> PurposesOfKid(DidDocument doc, string kid)
    {
        var output = new List<string>();
        if (ContainsKidRef(doc.Authentication, kid, doc.Id)) output.Add(VerificationPurposes.Authentication);
        if (ContainsKidRef(doc.AssertionMethod, kid, doc.Id)) output.Add(VerificationPurposes.AssertionMethod);
        return output;
    }

    private static bool ContainsKidRef(List<string>? arr, string kid, string did)
    {
        var target = DidDocuments.CanonicalVmId(did, kid);
        return (arr ?? []).Any(x => DidDocuments.CanonicalVmId(did, x) == target);
    }

    private static string NextSequentialKid(DidDocument doc)
    {
        var maxN = 0;
        foreach (var vm in doc.VerificationMethod)
        {
            var frag = vm.Id.StartsWith(doc.Id, StringComparison.Ordinal) ? vm.Id[doc.Id.Length..] : vm.Id;
            if (!frag.StartsWith("#key-", StringComparison.Ordinal)) continue;
            if (int.TryParse(frag["#key-".Length..], out var n) && n > maxN) maxN = n;
        }
        return $"{doc.Id}#key-{maxN + 1}";
    }
}
