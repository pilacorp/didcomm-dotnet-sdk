using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;
using Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.EcdsaSd;

/// <summary>
/// ECDSA-SD (ecdsa-sd-2023) conformance against the W3C vc-di-ecdsa worked
/// example (vectors/ copied from the Java SDK, authored by W3C/digitalbazaar —
/// see vectors/SOURCE.md). Each byte-exact assertion reproduces a published
/// value; a green run means the .NET implementation matches the W3C example.
/// </summary>
public class EcdsaSdTests
{
    private static readonly string VectorsDir =
        Path.Combine(AppContext.BaseDirectory, "Credential", "Common", "EcdsaSd", "vectors");

    private static string Read(string name) => File.ReadAllText(Path.Combine(VectorsDir, name));
    private static JObject Cred() => JObject.Parse(Read("credential.json"));
    private static JObject Expected() => JObject.Parse(Read("expected.json"));
    private static JObject Keys() => JObject.Parse(Read("keys.json"));
    private static JObject Pointers() => JObject.Parse(Read("pointers.json"));

    private static string[] MandatoryPointers() =>
        Pointers()["mandatoryPointers"]!.Select(t => t.Value<string>()!).ToArray();

    private static string[] SelectivePointers() =>
        Pointers()["selectivePointers"]!.Select(t => t.Value<string>()!).ToArray();

    private static JObject ProofConfig(JObject exp, JToken? context)
    {
        var pc = (JObject)exp["proofConfig"]!.DeepClone();
        pc["@context"] = context?.DeepClone();
        return pc;
    }

    private static string IssuerPrivHex() =>
        global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .DecodeP256PrivMultibaseToHex(Keys()["baseKeyPair"]!["secretKeyMultibase"]!.Value<string>()!);

    private static Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters IssuerPub() =>
        global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .P256PubFromMultibase(Keys()["baseKeyPair"]!["publicKeyMultibase"]!.Value<string>()!);

    // ---- Phase 0: canonicalize with id map (Example 75) + HMAC labels (Example 76)

    [Fact]
    public void CanonicalizeWithIdMap_MatchesW3CCanonicalNQuads()
    {
        var (nquads, idMap) = SdJsonLd.CanonicalizeWithIdMap(Cred());
        Assert.Equal(Read("canonical.nq"), string.Concat(nquads));

        var hmacKey = Convert.FromHexString(Keys()["hmacKeyString"]!.Value<string>()!);
        var expLabels = (JObject)Expected()["hmacLabels"]!;
        var seen = new HashSet<string>();
        foreach (var c14n in idMap.Values)
        {
            if (!seen.Add(c14n))
            {
                continue;
            }
            using var mac = new HMACSHA256(hmacKey);
            var tag = mac.ComputeHash(Encoding.UTF8.GetBytes(c14n));
            var hmacLabel = "u" + Convert.ToBase64String(tag).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            Assert.Equal(expLabels[c14n]!.Value<string>(), hmacLabel);
        }
        Assert.Equal(expLabels.Count, seen.Count);
    }

    // ---- Phase 2: selective-disclosure document (Example 85), via DeriveProof

    [Fact]
    public void DeriveProof_RevealDoc_MatchesW3CRevealJson()
    {
        var exp = Expected();
        var (revealDoc, _) = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .DeriveProof(Cred(), exp["baseProofValue"]!.Value<string>()!, SelectivePointers());

        var want = JObject.Parse(Read("reveal.json"));
        Assert.True(JToken.DeepEquals(want, revealDoc),
            $"reveal doc mismatch:\n--- got ---\n{revealDoc}\n--- want ---\n{want}");
    }

    // ---- Phase 6: base proof value round-trip byte-exact, via byte-exact issuance.
    // CreateBaseProofDeterministic uses RFC 6979 (raw S) + the fixed hmac/ephemeral
    // keys to reproduce Example 82 exactly. This validates canonicalize, grouping,
    // proofHash, mandatoryHash, label map, skolemization and CBOR serialization.

    [Fact]
    public void CreateBaseProofDeterministic_ReproducesW3CBaseProofValue()
    {
        var exp = Expected();
        var keys = Keys();
        var hmacKey = Convert.FromHexString(keys["hmacKeyString"]!.Value<string>()!);
        var ephPriv = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .DecodeP256PrivMultibaseToHex(keys["proofKeyPair"]!["secretKeyMultibase"]!.Value<string>()!);
        var issuerPriv = IssuerPrivHex();

        var got = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .CreateBaseProofDeterministic(Cred(), ProofConfig(exp, Cred()["@context"]), MandatoryPointers(),
                hmacKey, ephPriv, issuerPriv);

        Assert.Equal(exp["baseProofValue"]!.Value<string>(), got);
    }

    // ---- Phase 7: derived proof value byte-exact (Appendix B)

    [Fact]
    public void DeriveProof_ReproducesW3CDerivedProofValue()
    {
        var exp = Expected();
        var (_, derivedPv) = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .DeriveProof(Cred(), exp["baseProofValue"]!.Value<string>()!, SelectivePointers());

        Assert.Equal(exp["derived"]!["derivedProofValue"]!.Value<string>(), derivedPv);
    }

    // ---- Verify the W3C base proof against the issuer key.

    [Fact]
    public void VerifyProof_W3CBaseProof_Succeeds()
    {
        var exp = Expected();
        global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .VerifyProof(Cred(), ProofConfig(exp, Cred()["@context"]), exp["baseProofValue"]!.Value<string>()!, IssuerPub());
    }

    // ---- Phase 8: verify the derived proof on the revealed document (W3C round trip).

    [Fact]
    public void VerifyProof_W3CDerivedProof_Succeeds()
    {
        var exp = Expected();
        var (revealDoc, derivedPv) = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .DeriveProof(Cred(), exp["baseProofValue"]!.Value<string>()!, SelectivePointers());

        global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .VerifyProof(revealDoc, ProofConfig(exp, revealDoc["@context"]), derivedPv, IssuerPub());
    }

    // ---- Full round trip with fresh randomness: create base -> derive -> verify.

    [Fact]
    public void RoundTrip_CreateBase_Derive_Verify_Succeeds()
    {
        var exp = Expected();
        var proofConfig = ProofConfig(exp, Cred()["@context"]);

        var baseProof = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .CreateBaseProof(Cred(), proofConfig, MandatoryPointers(), IssuerPrivHex());

        // Base proof verifies over the full document.
        global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .VerifyProof(Cred(), proofConfig, baseProof, IssuerPub());

        var (revealDoc, derivedPv) = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .DeriveProof(Cred(), baseProof, SelectivePointers());

        global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .VerifyProof(revealDoc, ProofConfig(exp, revealDoc["@context"]), derivedPv, IssuerPub());
    }

    // ---- Tamper negative: an altered revealed claim must fail verification.

    [Fact]
    public void VerifyProof_TamperedRevealedClaim_Fails()
    {
        var exp = Expected();
        var (revealDoc, derivedPv) = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .DeriveProof(Cred(), exp["baseProofValue"]!.Value<string>()!, SelectivePointers());

        ((JObject)revealDoc["credentialSubject"]!)["birthCountry"] = "Canada"; // was "Bahamas"

        Assert.ThrowsAny<Exception>(() =>
            global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
                .VerifyProof(revealDoc, ProofConfig(exp, revealDoc["@context"]), derivedPv, IssuerPub()));
    }

    // ---- Tamper negative: dropping a mandatory statement must fail verification.

    [Fact]
    public void VerifyProof_DroppedMandatoryStatement_Fails()
    {
        var exp = Expected();
        var (revealDoc, derivedPv) = global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
            .DeriveProof(Cred(), exp["baseProofValue"]!.Value<string>()!, SelectivePointers());

        // /issuer is mandatory; removing it drops mandatory statements.
        revealDoc.Remove("issuer");

        Assert.ThrowsAny<Exception>(() =>
            global::Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd.EcdsaSd
                .VerifyProof(revealDoc, ProofConfig(exp, revealDoc["@context"]), derivedPv, IssuerPub()));
    }
}
