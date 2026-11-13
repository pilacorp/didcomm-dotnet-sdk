using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.DidV2;

namespace Pila.CredentialSdk.DidComm.Credential.Did;

public static class DidDocuments
{
    public const string CidContext = "https://www.w3.org/ns/cid/v1";
    public const string Secp256k1VmType = "EcdsaSecp256k1VerificationKey2019";
    public const string MultikeyVmType = "Multikey";

    public static DidDocument BuildDidDocument(string publicKeyHex, string didIdentifier, string didType = "people")
    {
        var vm = new VerificationMethodEntry
        {
            Id = $"{didIdentifier}#key-1",
            Type = Secp256k1VmType,
            Controller = didIdentifier,
            PublicKeyHex = publicKeyHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? publicKeyHex.ToLowerInvariant() : "0x" + publicKeyHex.ToLowerInvariant()
        };
        return new DidDocument
        {
            Context = ["https://w3id.org/security/v1", "https://www.w3.org/ns/did/v1"],
            Id = didIdentifier,
            Controller = didIdentifier,
            VerificationMethod = [vm],
            Authentication = [vm.Id],
            AssertionMethod = [vm.Id],
            DidDocumentMetadata = new Dictionary<string, object> { ["type"] = didType, ["hash"] = "" }
        };
    }

    public static string CanonicalVmId(string did, string idOrFragment) =>
        idOrFragment.StartsWith('#') ? did + idOrFragment : idOrFragment;
}
