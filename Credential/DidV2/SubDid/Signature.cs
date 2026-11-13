using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1.Sec;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2.SubDid;

public static class SubDidSignature
{
    public const string RootConsentPrefix = "Sub-DID ";
    private const string RootConsentKey = "rootConsent";
    private static readonly Regex StoredSignaturePattern = new("^0x[0-9a-f]{130}$", RegexOptions.Compiled);

    public static byte[] NormalizeSignature(byte[] sig)
    {
        if (sig.Length != 65) throw new InvalidOperationException($"subdid: signature is {sig.Length} bytes, want 65");
        var output = (byte[])sig.Clone();
        output[64] = output[64] switch
        {
            0 or 1 => (byte)(output[64] + 27),
            27 or 28 => output[64],
            _ => throw new InvalidOperationException($"subdid: signature v = {output[64]}, want 0, 1, 27 or 28")
        };
        var n = SecNamedCurves.GetByName("secp256k1").N;
        var halfN = n.ShiftRight(1);
        var s = new Org.BouncyCastle.Math.BigInteger(1, output, 32, 32);
        if (s.CompareTo(halfN) > 0) throw new InvalidOperationException("subdid: signature s is above n/2");
        return output;
    }

    public static byte[] RootConsentDigest(string subDid) => EthCrypto.HashMessage(RootConsentPrefix + subDid);

    public static byte[] SignRootConsent(string subDid, IDidSigner root)
    {
        SubDidDocument.CheckDid(subDid);
        return NormalizeSignature(root.Sign(RootConsentDigest(subDid)));
    }

    public static void SetRootConsent(DidDocument doc, byte[] sig)
    {
        var normalized = NormalizeSignature(sig);
        var meta = doc.DidDocumentMetadata == null
            ? new Dictionary<string, object>()
            : new Dictionary<string, object>(doc.DidDocumentMetadata);
        meta[RootConsentKey] = Hex.ToHex(normalized);
        doc.DidDocumentMetadata = DidV2Document.SortObject(meta);
    }

    public static byte[] GetRootConsent(DidDocument doc)
    {
        if (doc.DidDocumentMetadata == null || !doc.DidDocumentMetadata.TryGetValue(RootConsentKey, out var value))
        {
            throw new InvalidOperationException("subdid: root consent invalid: rootConsent is missing");
        }
        if (value is not string s || !StoredSignaturePattern.IsMatch(s))
        {
            throw new InvalidOperationException("subdid: root consent invalid: rootConsent must be 0x followed by 130 lowercase hex characters");
        }
        var sig = Hex.ToBytes(s);
        if (sig[64] is not 27 and not 28)
        {
            throw new InvalidOperationException($"subdid: root consent invalid: rootConsent v = {sig[64]}, want 27 or 28");
        }
        NormalizeSignature(sig);
        return sig;
    }

    public static void VerifyRootConsent(DidDocument subDoc, string rootDid)
    {
        var sig = GetRootConsent(subDoc);
        try { SubDidDocument.CheckDid(rootDid); }
        catch (Exception e) { throw new InvalidOperationException($"subdid: root consent invalid: root DID: {e.Message}"); }
        try { SubDidDocument.CheckDid(subDoc.Id); }
        catch (Exception e) { throw new InvalidOperationException($"subdid: root consent invalid: Sub-DID: {e.Message}"); }
        try { CheckSigner(RootConsentDigest(subDoc.Id), sig, SubDidDocument.DidAddress(rootDid)); }
        catch (Exception e) { throw new InvalidOperationException($"subdid: root consent invalid: {e.Message}"); }
    }

    public static byte[] SignatureDigest(string documentHash) => EthCrypto.HashMessage(Hex.ToBytes(documentHash));

    public static byte[] SignDocument(DidDocument doc, IDidSigner sub)
    {
        var h = SubDidDocument.DocHash(doc);
        return NormalizeSignature(sub.Sign(SignatureDigest(h)));
    }

    public static void VerifyDocumentSignature(DidDocument doc, byte[] sig)
    {
        byte[] normalized;
        try { normalized = NormalizeSignature(sig); }
        catch (Exception e) { throw new InvalidOperationException($"subdid: sub-DID signature invalid: {e.Message}"); }
        string h;
        try { h = SubDidDocument.DocHash(doc); }
        catch (Exception e) { throw new InvalidOperationException($"subdid: sub-DID signature invalid: {e.Message}"); }
        try { CheckSigner(SignatureDigest(h), normalized, SubDidDocument.DidAddress(doc.Id)); }
        catch (Exception e) { throw new InvalidOperationException($"subdid: sub-DID signature invalid: {e.Message}"); }
    }

    private static void CheckSigner(byte[] digest, byte[] storedSig, string address)
    {
        var recovered = EthCrypto.RecoverAddress(digest, storedSig).ToLowerInvariant();
        if (recovered != address.ToLowerInvariant())
        {
            throw new InvalidOperationException($"signed by {recovered}, not by {address}");
        }
    }
}
