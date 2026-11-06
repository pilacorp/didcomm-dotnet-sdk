using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.Jwt;
using Pila.CredentialSdk.DidComm.Credential.Common.SdJwt;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.SdJwtTests;

public class SdJwtTests
{
    // ---- VC fixture ---------------------------------------------------------

    private static Dictionary<string, object?> SampleVc() => new()
    {
        ["@context"] = new List<object?> { "https://www.w3.org/ns/credentials/v2" },
        ["type"] = new List<object?> { "VerifiableCredential" },
        ["issuer"] = "did:example:issuer",
        ["credentialSubject"] = new Dictionary<string, object?>
        {
            ["id"] = "did:example:subject",
            ["name"] = "Alice",
            ["email"] = "alice@example.com",
            ["age"] = "30",
        },
    };

    private static Dictionary<string, object?> SubjectOf(Dictionary<string, object?> vc) =>
        (Dictionary<string, object?>)vc["credentialSubject"]!;

    // ---- 1. full round-trip -------------------------------------------------

    [Fact]
    public void IssueSerializeParseReconstruct_RevealsAllClaims()
    {
        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = SampleVc(),
            SelectivePaths = new List<string> { "credentialSubject.name", "credentialSubject.email" },
        });

        // The selected claims were replaced by digests, not left in the clear.
        var procSubject = SubjectOf(res.ProcessedVc);
        Assert.False(procSubject.ContainsKey("name"));
        Assert.False(procSubject.ContainsKey("email"));
        Assert.True(procSubject.ContainsKey("_sd"));
        Assert.Equal(2, res.Disclosures.Count);

        var combined = SdJwt.BuildSdJwtPresentation("eyJhbGciOiJub25lIn0.eyJhIjoxfQ.sig", res.Disclosures);
        Assert.EndsWith("~", combined);

        var parsed = SdJwt.Parse(combined);
        Assert.Equal(2, parsed.Disclosures.Count);

        var reconstructed = SdJwt.Reconstruct(res.ProcessedVc, parsed.Disclosures, true);
        var subject = SubjectOf(reconstructed);
        Assert.Equal("Alice", subject["name"]);
        Assert.Equal("alice@example.com", subject["email"]);
        Assert.Equal("30", subject["age"]);
        Assert.False(subject.ContainsKey("_sd"));
        Assert.False(reconstructed.ContainsKey("_sd_alg"));
    }

    // ---- 2. selective presentation -----------------------------------------

    [Fact]
    public void SelectivePresentation_RevealsOnlyChosenSubset()
    {
        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = SampleVc(),
            SelectivePaths = new List<string> { "credentialSubject.name", "credentialSubject.email" },
        });

        var decoded = SdJwt.DecodeDisclosures(res.Disclosures);
        var nameDisclosure = decoded.First(d => d.FieldName == "name").Disclosure;

        // Present ONLY the name disclosure; email stays withheld.
        var reconstructed = SdJwt.Reconstruct(res.ProcessedVc, new[] { nameDisclosure }, true);
        var subject = SubjectOf(reconstructed);
        Assert.Equal("Alice", subject["name"]);
        Assert.False(subject.ContainsKey("email"));
    }

    // ---- 3. tampered disclosure (wrong digest) ------------------------------

    [Fact]
    public void TamperedDisclosure_IsRejected()
    {
        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = SampleVc(),
            SelectivePaths = new List<string> { "credentialSubject.name" },
        });

        // Re-encode the name disclosure with a changed value: same structure, but
        // its digest no longer matches the one the issuer put in _sd.
        var original = res.Disclosures[0];
        var arr = JsonSerializer.Deserialize<List<JsonElement>>(Util.Base64UrlDecode(original))!;
        var forged = new object?[] { arr[0].GetString(), "name", "Mallory" };
        var forgedStr = Util.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(forged)));

        var ex = Assert.ThrowsAny<Exception>(() =>
            SdJwt.Reconstruct(res.ProcessedVc, new[] { forgedStr }, true));
        Assert.Contains("matches nothing", ex.Message);
    }

    // ---- 4. disclosure not referenced by any _sd ----------------------------

    [Fact]
    public void UnreferencedDisclosure_IsRejected()
    {
        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = SampleVc(),
            SelectivePaths = new List<string> { "credentialSubject.name" },
        });

        // A brand-new disclosure the issuer never signed a digest for.
        var extra = new object?[] { "aaaaaaaaaaaaaaaaaaaaaa", "ssn", "123-45-6789" };
        var extraStr = Util.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(extra)));

        var all = new List<string>(res.Disclosures) { extraStr };
        var ex = Assert.ThrowsAny<Exception>(() =>
            SdJwt.Reconstruct(res.ProcessedVc, all, true));
        Assert.Contains("matches nothing", ex.Message);
    }

    [Fact]
    public void DuplicateDisclosure_IsRejected()
    {
        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = SampleVc(),
            SelectivePaths = new List<string> { "credentialSubject.name" },
        });
        var dup = new[] { res.Disclosures[0], res.Disclosures[0] };
        var ex = Assert.ThrowsAny<Exception>(() => SdJwt.Reconstruct(res.ProcessedVc, dup, true));
        Assert.Contains("more than once", ex.Message);
    }

    // ---- array-element selective disclosure ---------------------------------

    [Fact]
    public void ArrayElementDisclosure_RoundTrips()
    {
        var vc = new Dictionary<string, object?>
        {
            ["type"] = new List<object?> { "VerifiableCredential" },
            ["issuer"] = "did:example:issuer",
            ["credentialSubject"] = new Dictionary<string, object?>
            {
                ["skills"] = new List<object?> { "go", "dotnet", "rust" },
            },
        };
        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = vc,
            SelectivePaths = new List<string> { "credentialSubject.skills[1]" },
        });

        var subject = SubjectOf(res.ProcessedVc);
        var skills = (List<object?>)subject["skills"]!;
        // The disclosed element became a {"...": digest} placeholder.
        Assert.IsType<Dictionary<string, object?>>(skills[1]);

        var reconstructed = SdJwt.Reconstruct(res.ProcessedVc, res.Disclosures, true);
        var rebuilt = (List<object?>)SubjectOf(reconstructed)["skills"]!;
        Assert.Equal(new object?[] { "go", "dotnet", "rust" }, rebuilt);
    }

    // ---- decoys do not break reconstruct ------------------------------------

    [Fact]
    public void DecoysAreIgnoredOnReconstruct()
    {
        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = SampleVc(),
            SelectivePaths = new List<string> { "credentialSubject.name" },
            Decoys = new List<DecoyConfig> { new() { Path = "credentialSubject", Count = 3 } },
        });

        var sd = (List<object?>)SubjectOf(res.ProcessedVc)["_sd"]!;
        Assert.Equal(4, sd.Count); // 1 real + 3 decoys

        var reconstructed = SdJwt.Reconstruct(res.ProcessedVc, res.Disclosures, true);
        Assert.Equal("Alice", SubjectOf(reconstructed)["name"]);
    }

    // ---- 5. signer-binding verifier round-trip ------------------------------

    private const string IssuerPriv = "11112222333344445555666677778888999900001111222233334444555566aa";
    private const string IssuerDid = "did:nda:testnet:0xISSUER";

    private sealed class MapResolver : IDidDocumentResolver
    {
        private readonly Dictionary<string, DidDocument> _docs = new();
        public void Add(DidDocument doc) => _docs[doc.Id] = doc;
        public DidDocument ResolveDocument(string did) =>
            _docs.TryGetValue(did, out var d) ? d : throw new InvalidOperationException($"unknown DID {did}");
    }

    private static string PubHex(string priv)
    {
        var curve = SecNamedCurves.GetByName("secp256k1");
        var d = new BigInteger(1, Convert.FromHexString(priv));
        var q = curve.G.Multiply(d).Normalize();
        return Convert.ToHexString(q.GetEncoded(false)).ToLowerInvariant();
    }

    private static DidDocument IssuerDoc()
    {
        var vmId = IssuerDid + "#key-1";
        return new DidDocument
        {
            Id = IssuerDid,
            VerificationMethod = new List<VerificationMethodEntry>
            {
                new() { Id = vmId, Type = "EcdsaSecp256k1VerificationKey2019", Controller = IssuerDid, PublicKeyHex = PubHex(IssuerPriv) },
            },
            AssertionMethod = new List<string> { vmId },
        };
    }

    private static string B64(object o) =>
        Util.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(o)));

    private static string Sign(string signingInput, string priv)
    {
        var digest = Canonicalizer.ComputeDigest(Encoding.UTF8.GetBytes(signingInput));
        var sig = EcdsaSigner.Sign(digest, priv); // 65 bytes [r,s,v]
        return Util.Base64UrlEncode(sig[..64]);
    }

    [Fact]
    public void IssuerJwt_VerifiesViaSignerBinding_ThenReconstructs()
    {
        var vc = SampleVc();
        ((Dictionary<string, object?>)vc["credentialSubject"]!).Remove("age");
        vc["issuer"] = IssuerDid;

        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = vc,
            SelectivePaths = new List<string> { "credentialSubject.name", "credentialSubject.email" },
        });

        // The issuer signs the PROCESSED VC (digests, not cleartext claims) as a
        // vc+sd-jwt JWT. iss/issuer name the issuer; iat for the revocation check.
        var payload = res.ProcessedVc;
        payload["iss"] = IssuerDid;
        payload["iat"] = 1700000000L;

        var header = new Dictionary<string, object> { ["typ"] = "vc+sd-jwt", ["alg"] = "ES256K", ["kid"] = IssuerDid + "#key-1" };
        var signingInput = B64(header) + "." + B64(payload);
        var issuerJwt = signingInput + "." + Sign(signingInput, IssuerPriv);

        var combined = SdJwt.BuildSdJwtPresentation(issuerJwt, res.Disclosures);
        var parsed = SdJwt.Parse(combined);

        // 1) The signer-binding verifier accepts the issuer JWT.
        var resolver = new MapResolver();
        resolver.Add(IssuerDoc());
        JwtVerifier.Verify(parsed.BaseJwt, resolver); // must not throw

        // 2) Reconstruct the full claim set from the verified payload + disclosures.
        var payloadParts = parsed.BaseJwt.Split('.');
        using var doc = JsonDocument.Parse(Util.Base64UrlDecode(payloadParts[1]));
        var payloadMap = SdJwt.NormalizeObject(doc.RootElement);
        var reconstructed = SdJwt.Reconstruct(payloadMap, parsed.Disclosures, true);

        var subject = SubjectOf(reconstructed);
        Assert.Equal("Alice", subject["name"]);
        Assert.Equal("alice@example.com", subject["email"]);
    }

    // ---- cross-SDK: reconstruct a Go-produced SD-JWT ------------------------

    [Fact]
    public void CrossSdk_ReconstructsGoProducedSdJwt()
    {
        // Fixture produced by the Go SDK (credential/common/sdjwt.BuildDisclosures).
        // .NET hashes the exact disclosure strings Go shipped, so the digests Go
        // wrote into _sd must match byte-for-byte for reconstruction to succeed.
        var path = Path.Combine(AppContext.BaseDirectory, "Interop", "Fixtures", "go_sdjwt.json");
        using var fixture = JsonDocument.Parse(File.ReadAllText(path));
        var root = fixture.RootElement;

        var processedVc = SdJwt.NormalizeObject(root.GetProperty("processedVc"));
        var disclosures = root.GetProperty("disclosures").EnumerateArray().Select(e => e.GetString()!).ToList();

        var reconstructed = SdJwt.Reconstruct(processedVc, disclosures, true);
        var subject = SubjectOf(reconstructed);
        Assert.Equal("Alice", subject["name"]);
        Assert.Equal("alice@example.com", subject["email"]);
        var skills = (List<object?>)subject["skills"]!;
        Assert.Equal(new object?[] { "go", "dotnet", "rust" }, skills);
    }

    // ---- KB-JWT trailing slot is refused (Go parity) ------------------------

    [Fact]
    public void KeyBindingJwt_IsRefused()
    {
        var res = SdJwt.BuildDisclosures(new BuildDisclosuresInput
        {
            Vc = SampleVc(),
            SelectivePaths = new List<string> { "credentialSubject.name" },
        });
        var issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZSJ9.sig";
        var kbJwt = "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6IngifQ.kbsig";
        var combined = issuerJwt + "~" + res.Disclosures[0] + "~" + kbJwt;
        var ex = Assert.ThrowsAny<Exception>(() => SdJwt.Parse(combined));
        Assert.Contains("key binding JWT", ex.Message);
    }
}
