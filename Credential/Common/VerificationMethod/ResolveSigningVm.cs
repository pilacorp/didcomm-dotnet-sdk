using Pila.CredentialSdk.DidComm.Credential.DidV2;

namespace Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

public interface IDidDocumentResolver
{
    DidDocument ResolveDocument(string did);
}

public sealed class MemoryDidDocumentResolver : IDidDocumentResolver
{
    private readonly DidDocument _doc;

    public MemoryDidDocumentResolver(DidDocument doc) => _doc = doc;

    public DidDocument ResolveDocument(string did) => _doc;
}

public sealed class SigningVm
{
    public required VerificationMethodEntry Vm { get; init; }
    public required string Url { get; init; }
}

public static class ResolveSigningVm
{
    public static string NormalizeVerificationMethodUrl(string did, string kid)
    {
        if (string.IsNullOrEmpty(kid)) return "";
        if (kid.StartsWith("did:", StringComparison.Ordinal)) return kid;
        if (kid.StartsWith('#')) return did + kid;
        return did + "#" + kid;
    }

    public static SigningVm Resolve(string did, string purpose, string pinnedKid, IDidDocumentResolver? resolver)
    {
        if (resolver == null) throw new InvalidOperationException("document resolver is not configured");
        var url = NormalizeVerificationMethodUrl(did, pinnedKid);
        var vmDid = DidFromVmUrl(url);
        if (string.IsNullOrEmpty(vmDid)) vmDid = did;
        var doc = resolver.ResolveDocument(vmDid);
        var vm = string.IsNullOrEmpty(pinnedKid)
            ? SelectDefaultSigningVm(doc, purpose)
            : FindVerificationMethod(doc, url);

        if (RevocationReasons.IsHardRevocationReason(vm.RevocationReason))
        {
            throw new InvalidOperationException(
                $"verification method '{vm.Id}' revoked with hard reason '{vm.RevocationReason}'");
        }
        if (!string.IsNullOrEmpty(vm.Revoked))
        {
            var revoked = DateTimeOffset.Parse(vm.Revoked).UtcDateTime;
            throw new InvalidOperationException(
                $"verification method '{vm.Id}' was revoked at {revoked:yyyy-MM-ddTHH:mm:ssZ}");
        }
        EnsureVmAuthorizedForPurpose(doc, vm.Id, purpose);
        return new SigningVm { Vm = vm, Url = vm.Id };
    }

    public static VerificationMethodEntry SelectLatestActiveVmForPurpose(DidDocument doc, string purpose)
    {
        var purposeArr = PurposeArray(doc, purpose);
        if (purposeArr.Count == 0)
        {
            throw new InvalidOperationException($"no verification methods listed for purpose '{purpose}' on DID '{doc.Id}'");
        }
        VerificationMethodEntry? best = null;
        var bestN = -1;
        foreach (var vm in doc.VerificationMethod)
        {
            if (!string.IsNullOrEmpty(vm.Revoked)) continue;
            if (!IdInPurposeArray(vm.Id, doc.Id, purposeArr)) continue;
            var n = ParseSequentialFragment(vm.Id, doc.Id) ?? 0;
            if (n > bestN)
            {
                bestN = n;
                best = vm;
            }
        }
        if (best == null)
        {
            throw new InvalidOperationException($"no active verification method for purpose '{purpose}' on DID '{doc.Id}'");
        }
        return best;
    }

    public static VerificationMethodEntry SelectDefaultSigningVm(DidDocument doc, string purpose)
    {
        if (doc.VerificationMethod.Count == 1) return doc.VerificationMethod[0];
        return SelectLatestActiveVmForPurpose(doc, purpose);
    }

    public static void EnsureVmAuthorizedForPurpose(DidDocument doc, string vmId, string purpose)
    {
        var arr = PurposeArray(doc, purpose);
        if (!IdInPurposeArray(vmId, doc.Id, arr))
        {
            throw new InvalidOperationException(
                $"verification method '{vmId}' is not granted purpose '{purpose}' on DID '{doc.Id}'");
        }
    }

    private static List<string> PurposeArray(DidDocument doc, string purpose)
    {
        return purpose switch
        {
            "authentication" => doc.Authentication ?? [],
            "assertionMethod" => doc.AssertionMethod ?? [],
            _ => throw new InvalidOperationException($"unsupported purpose '{purpose}'")
        };
    }

    private static bool IdInPurposeArray(string vmId, string did, List<string> arr)
    {
        var frag = vmId.StartsWith(did + "#", StringComparison.Ordinal) ? vmId[did.Length..] : vmId;
        return arr.Any(r => r == vmId || r == frag);
    }

    private static int? ParseSequentialFragment(string vmId, string did)
    {
        var prefix = $"{did}#key-";
        if (!vmId.StartsWith(prefix, StringComparison.Ordinal)) return null;
        var tail = vmId[prefix.Length..];
        return int.TryParse(tail, out var n) && n.ToString() == tail ? n : null;
    }

    private static VerificationMethodEntry FindVerificationMethod(DidDocument doc, string vmUrl)
    {
        foreach (var vm in doc.VerificationMethod)
        {
            if (vm.Id == vmUrl) return vm;
        }
        throw new InvalidOperationException($"verification method '{vmUrl}' not found in DID '{doc.Id}' document");
    }

    private static string DidFromVmUrl(string url)
    {
        if (!url.StartsWith("did:", StringComparison.Ordinal)) return "";
        var i = url.IndexOf('#');
        return i > 0 ? url[..i] : url;
    }
}
