using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.JsonMap;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using Pila.CredentialSdk.DidComm.Credential.Vp;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Vp;

/// <summary>
/// Verifiable Presentation subsystem: offline JSON-LD round-trip, challenge/domain
/// binding, expected* implying verification, embedded-VC validation, and JWT VP
/// holder binding. All offline via injected static resolvers. Mirrors Go
/// credential/vp.
/// </summary>
public class PresentationTests
{
    private const string HolderPriv = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    private const string HolderDid = "did:example:p256-holder";

    // --- resolver -----------------------------------------------------------

    private sealed class DictResolver : IDidDocumentResolver
    {
        private readonly Dictionary<string, DidDocument> _docs = new();
        public void Add(DidDocument doc) => _docs[doc.Id] = doc;
        public DidDocument ResolveDocument(string did) =>
            _docs.TryGetValue(did, out var d) ? d
            : throw new InvalidOperationException($"no document for {did}");
    }

    private static DidDocument P256Doc(string priv, string did, string fragment = "key-1")
    {
        var pub = P256Signer.PublicFromPrivate(priv);
        var mb = Multikey.EncodeP256(pub);
        var vmId = did + "#" + fragment;
        return new DidDocument
        {
            Id = did,
            VerificationMethod = new List<VerificationMethodEntry>
            {
                new() { Id = vmId, Type = "Multikey", Controller = did, PublicKeyMultibase = mb }
            },
            AssertionMethod = new List<string> { vmId },
            Authentication = new List<string> { vmId }
        };
    }

    private static IDidDocumentResolver HolderResolver()
    {
        var r = new DictResolver();
        r.Add(P256Doc(HolderPriv, HolderDid));
        return r;
    }

    private static PresentationContents BaseContents() => new()
    {
        Context = new List<object> { "https://www.w3.org/ns/credentials/v2" },
        Types = new List<string> { "VerifiablePresentation" },
        Holder = HolderDid
    };

    // --- JSON-LD round trip -------------------------------------------------

    [Fact]
    public void JsonVp_P256_Offline_RoundTrip_SignVerify()
    {
        var resolver = HolderResolver();
        var vp = JsonPresentation.NewJsonPresentation(BaseContents());

        var serialized = vp.AddProofByKey(HolderPriv,
            PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline());

        var map = (Dictionary<string, object>)serialized;
        var proof = JsonMap.ParseRawToProof(map["proof"])!;
        Assert.Equal("DataIntegrityProof", proof.Type);
        Assert.Equal("ecdsa-rdfc-2019", proof.Cryptosuite);
        Assert.Equal(HolderDid + "#key-1", proof.VerificationMethod);
        Assert.Equal("authentication", proof.ProofPurpose);

        // Offline verify through the same injected resolver.
        vp.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline());
    }

    [Fact]
    public void JsonVp_Verify_Offline_WithoutResolver_Throws()
    {
        var resolver = HolderResolver();
        var vp = JsonPresentation.NewJsonPresentation(BaseContents());
        vp.AddProofByKey(HolderPriv, PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline());

        Assert.Throws<InvalidOperationException>(() => vp.Verify(PresentationOpts.WithOffline()));
    }

    // --- challenge / domain -------------------------------------------------

    [Fact]
    public void JsonVp_ChallengeDomain_Match_Passes_And_Mismatch_Rejected()
    {
        var resolver = HolderResolver();
        var vp = JsonPresentation.NewJsonPresentation(BaseContents());
        vp.AddProofByKey(HolderPriv,
            PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline(),
            PresentationOpts.WithChallenge("nonce-123"), PresentationOpts.WithDomain("verifier.example"));

        // Match passes.
        vp.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline(),
            PresentationOpts.WithExpectedChallenge("nonce-123"),
            PresentationOpts.WithExpectedDomain("verifier.example"));

        // Challenge mismatch rejected.
        Assert.Throws<InvalidOperationException>(() =>
            vp.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline(),
                PresentationOpts.WithExpectedChallenge("wrong")));

        // Domain mismatch rejected.
        Assert.Throws<InvalidOperationException>(() =>
            vp.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline(),
                PresentationOpts.WithExpectedDomain("attacker.example")));
    }

    [Fact]
    public void ExpectedOptions_ImplyProofVerification()
    {
        Assert.True(Presentation.GetOptions(PresentationOpts.WithExpectedChallenge("c")).IsVerifyProof);
        Assert.True(Presentation.GetOptions(PresentationOpts.WithExpectedDomain("d")).IsVerifyProof);
        Assert.True(Presentation.GetOptions(PresentationOpts.WithRequireAudience()).IsVerifyProof);
    }

    [Fact]
    public void JsonVp_RequireAudience_WithoutExpectedDomain_Throws()
    {
        var resolver = HolderResolver();
        var vp = JsonPresentation.NewJsonPresentation(BaseContents());
        vp.AddProofByKey(HolderPriv, PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline(),
            PresentationOpts.WithDomain("verifier.example"));

        var ex = Assert.Throws<InvalidOperationException>(() =>
            vp.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline(),
                PresentationOpts.WithRequireAudience()));
        Assert.Contains("WithExpectedDomain", ex.Message);
    }

    // --- embedded VC validation --------------------------------------------

    private static object SignedVc(IDidDocumentResolver resolver)
    {
        var vc = JsonCredential.NewJsonCredential(new CredentialContents
        {
            Context = new List<object> { "https://www.w3.org/ns/credentials/v2" },
            Issuer = HolderDid,
            Types = new List<string> { "VerifiableCredential" },
            Subject = new List<Subject> { new() { Id = "did:example:subject" } }
        });
        return vc.AddProofByKey(HolderPriv,
            CredentialOpts.WithResolver(resolver), CredentialOpts.WithOffline());
    }

    [Fact]
    public void JsonVp_ValidEmbeddedVc_PassesWhenValidationOn()
    {
        var resolver = HolderResolver();
        var vcBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(SignedVc(resolver)));
        var cred = Pila.CredentialSdk.DidComm.Credential.Vc.Credential.ParseCredential(vcBytes);

        var contents = BaseContents();
        contents.VerifiableCredentials = new List<ICredential> { cred };
        var vp = JsonPresentation.NewJsonPresentation(contents);
        vp.AddProofByKey(HolderPriv, PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline());

        // Verifies VP proof AND each embedded VC, offline.
        vp.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline(),
            PresentationOpts.WithVCValidation());
    }

    [Fact]
    public void JsonVp_InvalidEmbeddedVc_FailsWhenValidationOn()
    {
        var resolver = HolderResolver();
        var signed = (Dictionary<string, object>)SignedVc(resolver);

        // Tamper the embedded credential's proofValue so its signature no longer
        // verifies, then re-parse it as the embedded credential.
        var proof = JsonMap.ParseRawToProof(signed["proof"])!;
        var pv = proof.ProofValue!;
        var flipped = pv[..^1] + (pv[^1] == 'a' ? 'b' : 'a');
        signed["proof"] = new Dictionary<string, object>
        {
            ["type"] = proof.Type,
            ["created"] = proof.Created,
            ["verificationMethod"] = proof.VerificationMethod,
            ["proofPurpose"] = proof.ProofPurpose,
            ["cryptosuite"] = proof.Cryptosuite!,
            ["proofValue"] = flipped
        };
        var badCred = Pila.CredentialSdk.DidComm.Credential.Vc.Credential.ParseCredential(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(signed)));

        var contents = BaseContents();
        contents.VerifiableCredentials = new List<ICredential> { badCred };
        var vp = JsonPresentation.NewJsonPresentation(contents);
        vp.AddProofByKey(HolderPriv, PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline());

        // VP's own proof is fine; the embedded VC fails when VC validation is on.
        var ex = Assert.Throws<InvalidOperationException>(() =>
            vp.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline(),
                PresentationOpts.WithVCValidation()));
        Assert.Contains("credential at index 0", ex.Message);
    }

    // --- JWT VP -------------------------------------------------------------

    [Fact]
    public void JwtVp_P256_Offline_RoundTrip_SignVerify()
    {
        var resolver = HolderResolver();
        var vp = JwtPresentation.NewJwtPresentation(BaseContents(),
            PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline());
        var token = (string)vp.AddProofByKey(HolderPriv,
            PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline());

        Assert.Equal(3, token.Split('.').Length);

        var parsed = Presentation.ParsePresentation(Encoding.UTF8.GetBytes(token));
        Assert.Equal("JWT", parsed.GetType());
        parsed.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline());
    }

    [Fact]
    public void JwtVp_HolderBinding_KidNamesNonHolder_Rejected()
    {
        // A vp+jwt whose header kid names a DID other than the holder. The verifier
        // resolves the holder's document (from the vp.holder / iss claim) and then
        // rejects a kid that does not belong to it.
        const string attackerDid = "did:example:attacker";
        string B64(object o) => Util.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(o)));

        var header = new Dictionary<string, object>
        {
            ["typ"] = "vp+jwt",
            ["alg"] = "ES256",
            ["kid"] = attackerDid + "#key-1"
        };
        var payload = new Dictionary<string, object>
        {
            ["vp"] = new Dictionary<string, object>
            {
                ["@context"] = new[] { "https://www.w3.org/ns/credentials/v2" },
                ["type"] = new[] { "VerifiablePresentation" },
                ["holder"] = HolderDid
            },
            ["iss"] = HolderDid
        };
        var signingInput = B64(header) + "." + B64(payload);
        // The signature is never reached: binding is checked first.
        var token = signingInput + "." + Util.Base64UrlEncode(new byte[64]);

        var resolver = HolderResolver();
        var parsed = Presentation.ParsePresentation(Encoding.UTF8.GetBytes(token));
        var ex = Assert.Throws<InvalidOperationException>(() =>
            parsed.Verify(PresentationOpts.WithResolver(resolver), PresentationOpts.WithOffline()));
        Assert.Contains("not found", ex.Message);
    }
}
