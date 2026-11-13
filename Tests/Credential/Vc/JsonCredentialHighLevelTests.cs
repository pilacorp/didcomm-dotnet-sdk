using System.Collections.Generic;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.JsonMap;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Vc;

/// <summary>
/// Exercises the high-level consumer API (JsonCredential.AddProofByKey + the
/// resolver/offline-aware Verify): the caller supplies only a private key and a
/// resolver, never a verification-method id, a proof purpose or a suite.
/// </summary>
public class JsonCredentialHighLevelTests
{
    private const string PrivHex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    private const string Did = "did:example:p256-highlevel-issuer";

    private static IDidDocumentResolver StaticP256Resolver(string privHex, string did, string fragment)
    {
        var pub = P256Signer.PublicFromPrivate(privHex);
        var mb = Multikey.EncodeP256(pub);
        var vmId = did + "#" + fragment;
        var doc = new DidDocument
        {
            Id = did,
            VerificationMethod = new List<VerificationMethodEntry>
            {
                new() { Id = vmId, Type = "Multikey", Controller = did, PublicKeyMultibase = mb }
            },
            AssertionMethod = new List<string> { vmId },
            Authentication = new List<string> { vmId }
        };
        return new MemoryDidDocumentResolver(doc);
    }

    [Fact]
    public void AddProofByKey_P256_Offline_ResolvesVmAndSuiteWithoutCallerInput()
    {
        var resolver = StaticP256Resolver(PrivHex, Did, "key-1");
        var contents = new CredentialContents
        {
            Context = new List<object> { "https://www.w3.org/ns/credentials/v2" },
            Issuer = Did,
            Types = new List<string> { "VerifiableCredential" }
        };
        var cred = JsonCredential.NewJsonCredential(contents);

        // Caller passes ONLY the key + resolver + offline. No VM id, no purpose, no suite.
        var serialized = cred.AddProofByKey(PrivHex,
            CredentialOpts.WithResolver(resolver), CredentialOpts.WithOffline());

        Assert.NotNull(serialized);
        var map = (Dictionary<string, object>)serialized;
        var proof = JsonMap.ParseRawToProof(map["proof"])!;

        // The suite and VM were derived from the resolved key, not supplied.
        Assert.Equal("DataIntegrityProof", proof.Type);
        Assert.Equal("ecdsa-rdfc-2019", proof.Cryptosuite);
        Assert.Equal(Did + "#key-1", proof.VerificationMethod);
        Assert.Equal("assertionMethod", proof.ProofPurpose);
        Assert.StartsWith("z", proof.ProofValue);

        // High-level offline verification through the same injected resolver.
        cred.Verify(CredentialOpts.WithResolver(resolver), CredentialOpts.WithOffline());
    }

    [Fact]
    public void AddProofByKey_Offline_WithoutResolver_Throws()
    {
        var contents = new CredentialContents
        {
            Context = new List<object> { "https://www.w3.org/ns/credentials/v2" },
            Issuer = Did,
            Types = new List<string> { "VerifiableCredential" }
        };
        var cred = JsonCredential.NewJsonCredential(contents);
        Assert.Throws<System.InvalidOperationException>(() =>
            cred.AddProofByKey(PrivHex, CredentialOpts.WithOffline()));
    }

    [Fact]
    public void Verify_Offline_WithoutResolver_Throws()
    {
        var resolver = StaticP256Resolver(PrivHex, Did, "key-1");
        var contents = new CredentialContents
        {
            Context = new List<object> { "https://www.w3.org/ns/credentials/v2" },
            Issuer = Did,
            Types = new List<string> { "VerifiableCredential" }
        };
        var cred = JsonCredential.NewJsonCredential(contents);
        cred.AddProofByKey(PrivHex, CredentialOpts.WithResolver(resolver), CredentialOpts.WithOffline());

        Assert.Throws<System.InvalidOperationException>(() =>
            cred.Verify(CredentialOpts.WithOffline()));
    }
}
