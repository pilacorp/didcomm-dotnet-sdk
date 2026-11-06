using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json.Linq;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.JsonMap;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Interop;

/// <summary>
/// Cross-SDK byte-level parity against fixtures emitted by the Go SDK
/// (credential/vc.NewJSONCredential + AddProofByProvider over a static P-256
/// resolver). Proves .NET and Go bind the same proof configuration and the same
/// signing input for the same inputs, and that .NET verifies the Go-signed
/// credential offline.
/// </summary>
public class CrossSdkByteFixturesTests
{
    private sealed class Fixture
    {
        public string PrivHex = "";
        public string Did = "";
        public string VmId = "";
        public string SignedCredentialRaw = "";
        public JsonElement Context;
        public string DocumentDigestHex = "";
        public string ProofConfigCanonical = "";
        public string ProofConfigHashHex = "";
        public string SigningInputHex = "";
    }

    private static Fixture Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Interop", "Fixtures", "p256_rdfc.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        var signed = root.GetProperty("signedCredential");
        return new Fixture
        {
            PrivHex = root.GetProperty("privHex").GetString()!,
            Did = root.GetProperty("did").GetString()!,
            VmId = root.GetProperty("vmId").GetString()!,
            SignedCredentialRaw = signed.GetRawText(),
            Context = signed.GetProperty("@context").Clone(),
            DocumentDigestHex = root.GetProperty("documentDigestHex").GetString()!,
            ProofConfigCanonical = root.GetProperty("proofConfigCanonical").GetString()!,
            ProofConfigHashHex = root.GetProperty("proofConfigHashHex").GetString()!,
            SigningInputHex = root.GetProperty("signingInputHex").GetString()!
        };
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static IDidDocumentResolver StaticResolver(Fixture fx)
    {
        // Rebuild the DID document from the same fixed key. key-1 is the signing
        // VM; key-2 maps to the same key so a flipped verificationMethod still
        // resolves (isolating the proof-config binding from a resolution error).
        var pub = P256Signer.PublicFromPrivate(fx.PrivHex);
        var mb = Multikey.EncodeP256(pub);
        var key1 = fx.Did + "#key-1";
        var key2 = fx.Did + "#key-2";
        var doc = new DidDocument
        {
            Id = fx.Did,
            VerificationMethod = new List<VerificationMethodEntry>
            {
                new() { Id = key1, Type = "Multikey", Controller = fx.Did, PublicKeyMultibase = mb },
                new() { Id = key2, Type = "Multikey", Controller = fx.Did, PublicKeyMultibase = mb }
            },
            AssertionMethod = new List<string> { key1, key2 },
            Authentication = new List<string> { key1, key2 }
        };
        return new MemoryDidDocumentResolver(doc);
    }

    [Fact]
    public void NetRebuildsSameDocumentDigestProofConfigAndSigningInput_AsGo()
    {
        var fx = Load();
        var map = JsonSerializer.Deserialize<JsonMap>(fx.SignedCredentialRaw)!;

        // (b) document digest (canonical body without proof).
        var docHash = map.GetDocumentDigest();
        Assert.Equal(fx.DocumentDigestHex, Hex(docHash));

        var proof = JsonMap.ParseRawToProof(map["proof"])!;

        // (a) proof configuration canonical N-Quads + hash, rebuilt from the same
        // proof fields (proofValue excluded) and the document @context.
        var cfg = new Dictionary<string, object?>
        {
            ["type"] = proof.Type,
            ["created"] = proof.Created,
            ["verificationMethod"] = proof.VerificationMethod,
            ["proofPurpose"] = proof.ProofPurpose,
            ["cryptosuite"] = proof.Cryptosuite!,
            ["@context"] = fx.Context
        };
        var cfgCanonical = Canonicalizer.CanonicalizeWithoutProof(cfg);
        Assert.Equal(fx.ProofConfigCanonical, Encoding.UTF8.GetString(cfgCanonical));
        Assert.Equal(fx.ProofConfigHashHex, Hex(Canonicalizer.ComputeDigest(cfgCanonical)));

        // (c) signing input (64-byte hashData) = proofConfigHash || docHash.
        var signingInput = map.CreateProofSigning(docHash, proof);
        Assert.Equal(fx.SigningInputHex, Hex(signingInput));
        Assert.Equal(fx.ProofConfigHashHex, Hex(signingInput[..32]));
    }

    [Fact]
    public void ProofValueIsExcludedFromProofConfiguration()
    {
        var fx = Load();
        var map = JsonSerializer.Deserialize<JsonMap>(fx.SignedCredentialRaw)!;
        var docHash = map.GetDocumentDigest();
        var proof = JsonMap.ParseRawToProof(map["proof"])!;

        var signingInput = map.CreateProofSigning(docHash, proof);

        // Mutating only proofValue must not change the signing input: it is not
        // part of the signed proof configuration.
        proof.ProofValue = "zTamperedButIgnoredBecauseExcludedFromConfig";
        var signingInput2 = map.CreateProofSigning(docHash, proof);
        Assert.Equal(Hex(signingInput), Hex(signingInput2));
        Assert.DoesNotContain("proofValue", fx.ProofConfigCanonical);
    }

    [Fact]
    public void NetVerifiesGoSignedCredential_Offline()
    {
        var fx = Load();
        var map = JsonSerializer.Deserialize<JsonMap>(fx.SignedCredentialRaw)!;
        var resolver = StaticResolver(fx);
        Assert.True(map.VerifyProof(resolver));
    }

    [Fact]
    public void SigningInputComputation_DoesNotMutateTheCredential()
    {
        var fx = Load();
        var map = JsonSerializer.Deserialize<JsonMap>(fx.SignedCredentialRaw)!;
        var proof = JsonMap.ParseRawToProof(map["proof"])!;

        var before = Encoding.UTF8.GetString(map.ToJSON());
        var docHash = map.GetDocumentDigest();
        _ = map.CreateProofSigning(docHash, proof);
        var after = Encoding.UTF8.GetString(map.ToJSON());

        Assert.Equal(before, after);
    }

    [Theory]
    [InlineData("claim")]
    [InlineData("created")]
    [InlineData("verificationMethod")]
    [InlineData("proofPurpose")]
    [InlineData("challenge")]
    [InlineData("domain")]
    public void FlippingAnySignedField_FailsVerification(string field)
    {
        var fx = Load();
        var obj = JObject.Parse(fx.SignedCredentialRaw);
        switch (field)
        {
            case "claim":
                obj["credentialSubject"]!["age"] = 31; // was 30
                break;
            case "created":
                obj["proof"]!["created"] = "2030-01-01T00:00:00Z";
                break;
            case "verificationMethod":
                obj["proof"]!["verificationMethod"] = fx.Did + "#key-2";
                break;
            case "proofPurpose":
                obj["proof"]!["proofPurpose"] = "authentication";
                break;
            case "challenge":
                obj["proof"]!["challenge"] = "injected-challenge";
                break;
            case "domain":
                obj["proof"]!["domain"] = "attacker.example";
                break;
        }

        var tampered = JsonSerializer.Deserialize<JsonMap>(obj.ToString())!;
        var resolver = StaticResolver(fx);
        Assert.False(VerificationSucceeds(tampered, resolver));
    }

    private static bool VerificationSucceeds(JsonMap map, IDidDocumentResolver resolver)
    {
        try
        {
            return map.VerifyProof(resolver);
        }
        catch
        {
            return false;
        }
    }
}
