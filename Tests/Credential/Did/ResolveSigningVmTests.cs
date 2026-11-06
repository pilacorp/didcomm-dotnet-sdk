using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Did;

public class ResolveSigningVmTests
{
    private const string Did = "did:pila:abc123";

    [Theory]
    [InlineData("", "")]
    [InlineData("did:pila:abc123#key-1", "did:pila:abc123#key-1")]
    [InlineData("#key-1", "did:pila:abc123#key-1")]
    [InlineData("key-2", "did:pila:abc123#key-2")]
    public void NormalizeVerificationMethodUrl(string input, string want)
    {
        Assert.Equal(want, ResolveSigningVm.NormalizeVerificationMethodUrl(Did, input));
    }

    [Fact]
    public void RejectsPinnedRevokedKid()
    {
        var doc = SampleDoc(revokedKey1: true);
        var ex = Assert.Throws<InvalidOperationException>(() =>
            ResolveSigningVm.Resolve(Did, "assertionMethod", "key-1", new MemoryDidDocumentResolver(doc)));
        Assert.Contains("was revoked at 2026-01-01T00:00:00Z", ex.Message);
    }

    [Fact]
    public void RejectsHardRevocationReasonWithoutTimestamp()
    {
        var doc = SampleDoc(revokedKey1: false);
        doc.VerificationMethod =
        [
            new VerificationMethodEntry
            {
                Id = $"{Did}#key-1",
                Type = "EcdsaSecp256k1VerificationKey2019",
                Controller = Did,
                RevocationReason = RevocationReasons.KeyCompromise
            }
        ];
        doc.AssertionMethod = [$"{Did}#key-1"];
        var ex = Assert.Throws<InvalidOperationException>(() =>
            ResolveSigningVm.Resolve(Did, "assertionMethod", "key-1", new MemoryDidDocumentResolver(doc)));
        Assert.Contains("hard reason 'keyCompromise'", ex.Message);
    }

    [Fact]
    public void AcceptsPinnedActiveKid()
    {
        var doc = SampleDoc(revokedKey1: true);
        var resolved = ResolveSigningVm.Resolve(Did, "assertionMethod", "key-2", new MemoryDidDocumentResolver(doc));
        Assert.Equal($"{Did}#key-2", resolved.Url);
    }

    [Fact]
    public void RejectsKidNotGrantedPurpose()
    {
        var doc = SampleDoc(revokedKey1: false);
        doc.AssertionMethod = [$"{Did}#key-2"];
        var ex = Assert.Throws<InvalidOperationException>(() =>
            ResolveSigningVm.Resolve(Did, "assertionMethod", "key-1", new MemoryDidDocumentResolver(doc)));
        Assert.Contains("not granted purpose 'assertionMethod'", ex.Message);
    }

    [Fact]
    public void JsonAndJwtAddProof_RefuseRevokedExplicitKid()
    {
        var issuer = "did:example:issuer";
        var doc = new DidDocument
        {
            Id = issuer,
            VerificationMethod =
            [
                new VerificationMethodEntry
                {
                    Id = $"{issuer}#key-1",
                    Type = "EcdsaSecp256k1VerificationKey2019",
                    Controller = issuer,
                    PublicKeyHex = "0x02" + new string('1', 64),
                    Revoked = "2026-01-01T00:00:00Z"
                }
            ],
            Authentication = [$"{issuer}#key-1"],
            AssertionMethod = [$"{issuer}#key-1"]
        };
        var resolver = new MemoryDidDocumentResolver(doc);
        var contents = new CredentialContents
        {
            Context = ["https://www.w3.org/ns/credentials/v2"],
            Id = "urn:uuid:1",
            Issuer = issuer,
            Types = ["VerifiableCredential"],
            Subject = [new Subject { Id = "did:example:subject" }]
        };
        var json = JsonCredential.NewJsonCredential(contents, CredentialOpts.WithVerificationMethodKey("key-1"));
        Assert.Throws<InvalidOperationException>(() =>
            json.AddProof("11".PadRight(64, '1'), CredentialOpts.WithResolver(resolver), CredentialOpts.WithVerificationMethodKey("key-1")));

        var jwt = JwtCredential.NewJwtCredential(contents, CredentialOpts.WithVerificationMethodKey("key-1"));
        Assert.Throws<InvalidOperationException>(() =>
            jwt.AddProof("11".PadRight(64, '1'), CredentialOpts.WithResolver(resolver), CredentialOpts.WithVerificationMethodKey("key-1")));
    }

    private static DidDocument SampleDoc(bool revokedKey1)
    {
        return new DidDocument
        {
            Id = Did,
            VerificationMethod =
            [
                new VerificationMethodEntry
                {
                    Id = $"{Did}#key-1",
                    Type = "EcdsaSecp256k1VerificationKey2019",
                    Controller = Did,
                    Revoked = revokedKey1 ? "2026-01-01T00:00:00.000Z" : null
                },
                new VerificationMethodEntry
                {
                    Id = $"{Did}#key-2",
                    Type = "EcdsaSecp256k1VerificationKey2019",
                    Controller = Did
                }
            ],
            Authentication = [$"{Did}#key-1", $"{Did}#key-2"],
            AssertionMethod = [$"{Did}#key-1", $"{Did}#key-2"]
        };
    }
}
