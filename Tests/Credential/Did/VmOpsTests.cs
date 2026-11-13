using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Did;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Did;

public class VmOpsTests
{
    private const string Did = "did:nda:0x0000000000000000000000000000000000000001";

    [Fact]
    public void AddRotateRevoke_CopiesPurposesAndKeepsRevokedVm()
    {
        var doc = DidDocuments.BuildDidDocument(SecpHex(1), Did);
        var id2 = VmOps.AddVerificationMethod(doc, new VerificationMethodEntry { PublicKeyHex = SecpHex(2) }, ["authentication"]);
        Assert.Equal($"{Did}#key-2", id2);
        Assert.Contains(id2, doc.Authentication!);

        var newId = VmOps.RotateVerificationMethod(doc, $"{Did}#key-1", new VerificationMethodEntry { PublicKeyHex = SecpHex(3) });
        Assert.Equal($"{Did}#key-3", newId);
        var old = doc.VerificationMethod.First(vm => vm.Id == $"{Did}#key-1");
        Assert.False(string.IsNullOrEmpty(old.Revoked));
        Assert.Equal("superseded", old.RevocationReason);
        Assert.Contains(newId, doc.Authentication!);
        Assert.Contains(newId, doc.AssertionMethod!);
        Assert.Contains(doc.VerificationMethod, vm => vm.Id == $"{Did}#key-1");
        Assert.Contains("https://www.w3.org/ns/cid/v1", doc.Context);
    }

    [Fact]
    public void RejectsDuplicateIdsSecondRevokeAndPurposesOnRevoked()
    {
        var doc = DidDocuments.BuildDidDocument(SecpHex(1), Did);
        Assert.Throws<InvalidOperationException>(() =>
            VmOps.AddVerificationMethod(doc, new VerificationMethodEntry { Id = "#key-1", PublicKeyHex = SecpHex(2) }));
        VmOps.RevokeVerificationMethod(doc, "#key-1", "compromised");
        var ex = Assert.Throws<InvalidOperationException>(() => VmOps.RevokeVerificationMethod(doc, "#key-1", "again"));
        Assert.Contains("already revoked", ex.Message);
        Assert.Throws<InvalidOperationException>(() =>
            VmOps.AddVerificationMethodPurposes(doc, "#key-1", ["authentication"]));
    }

    [Fact]
    public void DedupesPurposeRefsAndAddsCidContextForMultikey()
    {
        var doc = DidDocuments.BuildDidDocument(SecpHex(1), Did);
        VmOps.AddVerificationMethodPurposes(doc, "#key-1", ["authentication", "assertionMethod"]);
        Assert.Single(doc.Authentication!);

        var p256 = P256Uncompressed(2);
        var id = VmOps.AddVerificationMethod(doc, new VerificationMethodEntry
        {
            PublicKeyMultibase = Multikey.EncodeP256(P256Public(p256))
        }, ["assertionMethod"]);
        Assert.Equal($"{Did}#key-2", id);
        Assert.Contains("https://www.w3.org/ns/cid/v1", doc.Context);
        VmOps.RemoveVerificationMethodPurposes(doc, "#key-2", ["assertionMethod"]);
        Assert.DoesNotContain(id, doc.AssertionMethod ?? []);
    }

    private static string SecpHex(byte seed)
    {
        var priv = Enumerable.Repeat(seed, 32).ToArray();
        var curve = SecNamedCurves.GetByName("secp256k1");
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        var q = domain.G.Multiply(new BigInteger(1, priv)).Normalize();
        return "0x" + Convert.ToHexString(q.GetEncoded(true)).ToLowerInvariant();
    }

    private static byte[] P256Uncompressed(byte seed)
    {
        var priv = Enumerable.Repeat(seed, 32).ToArray();
        priv[0] = 0;
        var curve = SecNamedCurves.GetByName("secp256r1") ?? SecNamedCurves.GetByName("prime256v1");
        var domain = new ECDomainParameters(curve!.Curve, curve.G, curve.N, curve.H);
        var q = domain.G.Multiply(new BigInteger(1, priv)).Normalize();
        return q.GetEncoded(false);
    }

    private static ECPublicKeyParameters P256Public(byte[] uncompressed)
    {
        var curve = SecNamedCurves.GetByName("secp256r1") ?? SecNamedCurves.GetByName("prime256v1");
        var domain = new ECDomainParameters(curve!.Curve, curve.G, curve.N, curve.H);
        var point = curve.Curve.DecodePoint(uncompressed);
        return new ECPublicKeyParameters("EC", point, domain);
    }
}
