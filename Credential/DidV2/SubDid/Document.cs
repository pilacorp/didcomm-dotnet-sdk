using System.Text.RegularExpressions;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Did;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2.SubDid;

public static class SubDidDocument
{
    private static readonly Regex SubIdPattern = new("^[A-Za-z0-9_-]{8,64}$", RegexOptions.Compiled);
    private static readonly Regex DidPattern = new("^did:[a-z]{1,16}(:[a-z]{1,16}){0,2}:0x[0-9a-f]{40}$", RegexOptions.Compiled);
    private static readonly Regex CompressedKeyPattern = new("^0x0[23][0-9a-f]{64}$", RegexOptions.Compiled);

    public static string ParseSubId(string s)
    {
        if (!SubIdPattern.IsMatch(s)) throw new InvalidOperationException($"subdid: subId must match {SubIdPattern}");
        return s;
    }

    public static string SubDidFor(string rootDid, string publicKeyHex)
    {
        var bytes = Hex.ToBytes(publicKeyHex);
        if (!(bytes.Length == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03)))
        {
            throw new InvalidOperationException("subdid: public key must be a point on secp256k1");
        }
        CheckDid(rootDid);
        var addr = EthCrypto.AddressFromPublicKeyHex(publicKeyHex);
        return DidPrefix(rootDid) + addr;
    }

    public static void ValidateSubDid(DidDocument doc, string rootDid)
    {
        DidV2Document.ValidateDidDocument(doc);
        CheckDid(doc.Id);
        CheckDid(rootDid);
        if (DidPrefix(doc.Id) != DidPrefix(rootDid))
        {
            throw new InvalidOperationException($"subdid: {doc.Id} and root {rootDid} have different prefixes");
        }
        if (doc.Id == rootDid) throw new InvalidOperationException("subdid: a Sub-DID cannot be its own root");
        if (doc.Controller != rootDid)
        {
            throw new InvalidOperationException($"subdid: controller \"{doc.Controller}\" is not the root DID {rootDid}");
        }
        foreach (var vm in doc.VerificationMethod)
        {
            if (!vm.Id.StartsWith(doc.Id + "#", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"subdid: verification method id \"{vm.Id}\" must start with {doc.Id}#");
            }
        }
        CheckPrimaryKey(doc);
        if (doc.DidDocumentMetadata == null) throw new InvalidOperationException("subdid: didDocumentMetadata is missing");
    }

    public static void CheckDid(string s)
    {
        if (!DidPattern.IsMatch(s)) throw new InvalidOperationException($"\"{s}\" does not match {DidPattern}");
    }

    public static string DidPrefix(string s) => s[..(s.LastIndexOf(':') + 1)];
    public static string DidAddress(string s) => s[(s.LastIndexOf(':') + 1)..];

    public static string DocHash(DidDocument doc)
    {
        var h = DidV2Document.HashDidDocument(doc);
        if (!Regex.IsMatch(h, "^0x[0-9a-f]{64}$")) throw new InvalidOperationException($"subdid: document hash \"{h}\" is not 32 bytes");
        return h;
    }

    private static void CheckPrimaryKey(DidDocument doc)
    {
        var vm = VmOps.FindVerificationMethod(doc, "#key-1") ?? throw new InvalidOperationException("subdid: #key-1 is missing");
        if (vm.Type != DidDocuments.Secp256k1VmType)
        {
            throw new InvalidOperationException($"subdid: #key-1 has type \"{vm.Type}\", want {DidDocuments.Secp256k1VmType}");
        }
        if (string.IsNullOrEmpty(vm.PublicKeyHex) || !CompressedKeyPattern.IsMatch(vm.PublicKeyHex))
        {
            throw new InvalidOperationException("subdid: #key-1 publicKeyHex must be a lowercase compressed secp256k1 key");
        }
        var address = EthCrypto.AddressFromPublicKeyHex(vm.PublicKeyHex);
        if (address != DidAddress(doc.Id))
        {
            throw new InvalidOperationException($"subdid: #key-1 belongs to {address}, not to {doc.Id}");
        }
    }
}
