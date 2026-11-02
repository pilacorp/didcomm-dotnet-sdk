namespace Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

public static class RevocationReasons
{
    public const string KeyCompromise = "keyCompromise";

    public static bool IsHardRevocationReason(string? reason) =>
        KeyCompromise.Equals(reason, StringComparison.Ordinal);
}

public static class StrictPurposeCheck
{
    public static void Enforce(DidDocument doc, VerificationMethodEntry vm, string proofPurpose, string proofCreated)
    {
        if (RevocationReasons.IsHardRevocationReason(vm.RevocationReason))
        {
            throw new InvalidOperationException(
                $"verification method '{vm.Id}' revoked with hard reason '{vm.RevocationReason}'");
        }

        if (!string.IsNullOrEmpty(vm.Revoked))
        {
            var created = DateTime.Parse(proofCreated, null, System.Globalization.DateTimeStyles.RoundtripKind);
            var revoked = DateTime.Parse(vm.Revoked, null, System.Globalization.DateTimeStyles.RoundtripKind);
            if (created >= revoked)
            {
                throw new InvalidOperationException(
                    $"verification method '{vm.Id}' was revoked at {revoked:o}; proof.created {created:o} is not earlier");
            }
        }

        List<string>? arr = proofPurpose switch
        {
            "authentication" => doc.Authentication,
            "assertionMethod" => doc.AssertionMethod,
            _ => throw new InvalidOperationException($"unsupported proofPurpose '{proofPurpose}'")
        };

        if (!IdInArray(vm.Id, doc.Id, arr))
        {
            throw new InvalidOperationException(
                $"verification method '{vm.Id}' is not granted purpose '{proofPurpose}' on DID '{doc.Id}'");
        }
    }

    private static bool IdInArray(string vmId, string docId, List<string>? arr)
    {
        if (arr == null)
        {
            return false;
        }
        var frag = vmId.StartsWith(docId + "#", StringComparison.Ordinal)
            ? vmId[docId.Length..]
            : vmId;
        return arr.Any(refId => refId == vmId || refId == frag);
    }
}

public enum VerificationMethodKeyKind
{
    P256,
    Secp256k1,
    Unknown
}

public static class VerificationMethodKeyKindExtensions
{
    public static VerificationMethodKeyKind FromEntry(VerificationMethodEntry? vm)
    {
        if (vm == null)
        {
            return VerificationMethodKeyKind.Unknown;
        }
        if (vm.PublicKeyJwk != null)
        {
            if (vm.PublicKeyJwk.Crv == "P-256")
            {
                return VerificationMethodKeyKind.P256;
            }
            if (vm.PublicKeyJwk.Crv == "secp256k1")
            {
                return VerificationMethodKeyKind.Secp256k1;
            }
            return VerificationMethodKeyKind.Unknown;
        }
        if (!string.IsNullOrEmpty(vm.PublicKeyMultibase))
        {
            try
            {
                return Multikey.KindFromMultibase(vm.PublicKeyMultibase);
            }
            catch
            {
                return VerificationMethodKeyKind.Unknown;
            }
        }
        if (!string.IsNullOrEmpty(vm.PublicKeyHex))
        {
            if (!string.IsNullOrEmpty(vm.Type)
                && vm.Type != "EcdsaSecp256k1VerificationKey2019"
                && vm.Type != "EcdsaSecp256k1Signature2019")
            {
                return VerificationMethodKeyKind.Unknown;
            }
            return VerificationMethodKeyKind.Secp256k1;
        }
        return VerificationMethodKeyKind.Unknown;
    }
}
