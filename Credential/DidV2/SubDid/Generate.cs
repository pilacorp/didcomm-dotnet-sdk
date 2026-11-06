using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2.SubDid;

public sealed class SubDidResult
{
    public string Did { get; set; } = "";
    public DidDocument Document { get; set; } = new();
    public string Type { get; set; } = "";
    public string Signature { get; set; } = "";
}

public static class SubDidGenerate
{
    public static SubDidResult GenerateSubDid(
        string rootDid,
        string subId,
        string subPublicKeyHex,
        byte didType,
        Dictionary<string, object>? metadata,
        IDidSigner rootSigner,
        IDidSigner subSigner,
        params VerificationMethodSpec[] extraVms)
    {
        if (DidTypes.ToName(didType) == "unknown") throw new InvalidOperationException($"subdid: unknown DID type {didType}");
        SubDidDocument.ParseSubId(subId);
        var pubBytes = Hex.ToBytes(subPublicKeyHex);
        if (pubBytes.Length != 33) throw new InvalidOperationException("subdid: Sub-DID public key: expected compressed secp256k1");
        var subDid = SubDidDocument.SubDidFor(rootDid, subPublicKeyHex);
        var consent = SubDidSignature.SignRootConsent(subDid, rootSigner);
        var docMetadata = metadata == null ? new Dictionary<string, object>() : new Dictionary<string, object>(metadata);
        docMetadata["subId"] = subId;
        var doc = DidV2Document.GenerateDidDocument(subPublicKeyHex, subDid, "", rootDid, didType, docMetadata, extraVms)
            ?? throw new InvalidOperationException("subdid: build document: invalid verification methods");
        SubDidSignature.SetRootConsent(doc, consent);
        SubDidDocument.ValidateSubDid(doc, rootDid);
        try { SubDidSignature.VerifyRootConsent(doc, rootDid); }
        catch (Exception e)
        {
            throw new InvalidOperationException($"subdid: the root signer does not hold the primary key of {rootDid}: {e.Message}");
        }
        var sig = SubDidSignature.SignDocument(doc, subSigner);
        try { SubDidSignature.VerifyDocumentSignature(doc, sig); }
        catch (Exception e)
        {
            throw new InvalidOperationException($"subdid: the Sub-DID signer does not hold the key of {subDid}: {e.Message}");
        }
        return new SubDidResult
        {
            Did = subDid,
            Document = doc,
            Type = DidTypes.ToName(didType),
            Signature = Hex.ToHex(sig)
        };
    }
}
