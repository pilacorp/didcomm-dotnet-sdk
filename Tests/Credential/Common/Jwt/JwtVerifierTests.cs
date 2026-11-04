using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.Jwt;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.Jwt;

public class JwtVerifierTests
{
    // Two distinct secp256k1 keys: the victim issuer and an attacker.
    private const string VictimPriv = "11112222333344445555666677778888999900001111222233334444555566aa";
    private const string AttackerPriv = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb";

    private const string VictimDid = "did:nda:testnet:0xVICTIM";
    private const string AttackerDid = "did:nda:testnet:0xATTACKER";

    // A resolver that maps each DID to its own document (offline, no network).
    private sealed class MapResolver : IDidDocumentResolver
    {
        private readonly Dictionary<string, DidDocument> _docs = new();
        public void Add(DidDocument doc) => _docs[doc.Id] = doc;
        public DidDocument ResolveDocument(string did) =>
            _docs.TryGetValue(did, out var d)
                ? d
                : throw new InvalidOperationException($"unknown DID {did}");
    }

    private static string PubHex(string priv)
    {
        var curve = SecNamedCurves.GetByName("secp256k1");
        var d = new BigInteger(1, Convert.FromHexString(priv));
        var q = curve.G.Multiply(d).Normalize();
        return Convert.ToHexString(q.GetEncoded(false)).ToLowerInvariant();
    }

    private static DidDocument SecpDoc(string did, string priv, string purpose = "assertionMethod")
    {
        var vmId = did + "#key-1";
        var doc = new DidDocument
        {
            Id = did,
            VerificationMethod = new List<VerificationMethodEntry>
            {
                new()
                {
                    Id = vmId,
                    Type = "EcdsaSecp256k1VerificationKey2019",
                    Controller = did,
                    PublicKeyHex = PubHex(priv)
                }
            },
            AssertionMethod = purpose == "assertionMethod" ? new List<string> { vmId } : new List<string>(),
            Authentication = purpose == "authentication" ? new List<string> { vmId } : new List<string>()
        };
        return doc;
    }

    private static string Sign(string signingInput, string priv)
    {
        var digest = Canonicalizer.ComputeDigest(Encoding.UTF8.GetBytes(signingInput));
        var sig = EcdsaSigner.Sign(digest, priv); // 65 bytes [r,s,v]
        return Util.Base64UrlEncode(sig[..64]);
    }

    private static string B64(object o) =>
        Util.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(o)));

    // Builds a VC-JWT. signerPriv signs; the vc.issuer / iss claim name issuerClaim;
    // header carries kid + alg.
    private static string BuildVcJwt(string signerPriv, string kid, string issuerClaim,
        string alg = "ES256K", string? issOverride = null)
    {
        var header = new Dictionary<string, object> { ["typ"] = "vc+jwt", ["alg"] = alg, ["kid"] = kid };
        var vc = new Dictionary<string, object>
        {
            ["@context"] = new[] { "https://www.w3.org/ns/credentials/v2" },
            ["type"] = new[] { "VerifiableCredential" },
            ["issuer"] = issuerClaim,
            ["credentialSubject"] = new Dictionary<string, object> { ["id"] = "did:example:subject" }
        };
        var payload = new Dictionary<string, object>
        {
            ["vc"] = vc,
            ["iss"] = issOverride ?? issuerClaim,
            ["iat"] = 1700000000L
        };
        var signingInput = B64(header) + "." + B64(payload);
        return signingInput + "." + Sign(signingInput, signerPriv);
    }

    [Fact]
    public void ValidVcJwt_SignedByIssuer_Verifies()
    {
        var token = BuildVcJwt(VictimPriv, VictimDid + "#key-1", VictimDid);
        var resolver = new MapResolver();
        resolver.Add(SecpDoc(VictimDid, VictimPriv));
        JwtVerifier.Verify(token, resolver); // must not throw
    }

    [Fact]
    public void Forgery_AttackerKeyWithVictimIssuer_IsRejected()
    {
        // Attacker signs with its OWN key, claims issuer = victim, and points kid
        // at its own verification method. The old verifier resolved the kid's DID
        // and trusted VM[0]; the fixed one resolves the victim (issuer) and rejects
        // a kid that is not in the victim's document.
        var token = BuildVcJwt(AttackerPriv, AttackerDid + "#key-1", VictimDid);
        var resolver = new MapResolver();
        resolver.Add(SecpDoc(VictimDid, VictimPriv));
        resolver.Add(SecpDoc(AttackerDid, AttackerPriv));

        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, resolver));
        Assert.Contains("not found in DID", ex.Message);
    }

    [Fact]
    public void Forgery_VictimKidButAttackerSignature_IsRejected()
    {
        // Attacker uses the victim's real kid but cannot produce the victim's
        // signature; the crypto check must fail.
        var token = BuildVcJwt(AttackerPriv, VictimDid + "#key-1", VictimDid);
        var resolver = new MapResolver();
        resolver.Add(SecpDoc(VictimDid, VictimPriv));

        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, resolver));
        Assert.Contains("signature verification failed", ex.Message);
    }

    [Fact]
    public void IssMismatchWithIssuer_IsRejected()
    {
        var token = BuildVcJwt(VictimPriv, VictimDid + "#key-1", VictimDid, issOverride: AttackerDid);
        var resolver = new MapResolver();
        resolver.Add(SecpDoc(VictimDid, VictimPriv));
        resolver.Add(SecpDoc(AttackerDid, AttackerPriv));

        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, resolver));
        Assert.Contains("does not match", ex.Message);
    }

    [Fact]
    public void AlgNotMatchingKeyKind_IsRejected()
    {
        // Header claims ES256 (P-256) but the VM holds a secp256k1 key.
        var token = BuildVcJwt(VictimPriv, VictimDid + "#key-1", VictimDid, alg: "ES256");
        var resolver = new MapResolver();
        resolver.Add(SecpDoc(VictimDid, VictimPriv));

        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, resolver));
        Assert.Contains("does not match verification method", ex.Message);
    }

    [Fact]
    public void TamperedPayload_IsRejected()
    {
        var token = BuildVcJwt(VictimPriv, VictimDid + "#key-1", VictimDid);
        var parts = token.Split('.');
        // Flip one base64url char in the payload.
        var payload = parts[1];
        var tampered = payload[..^1] + (payload[^1] == 'A' ? 'B' : 'A');
        var mangled = $"{parts[0]}.{tampered}.{parts[2]}";
        var resolver = new MapResolver();
        resolver.Add(SecpDoc(VictimDid, VictimPriv));

        Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(mangled, resolver));
    }

    [Fact]
    public void PurposeNotGrantedOnDocument_IsRejected()
    {
        // VC-JWT demands assertionMethod, but the VM is only listed for authentication.
        var token = BuildVcJwt(VictimPriv, VictimDid + "#key-1", VictimDid);
        var resolver = new MapResolver();
        resolver.Add(SecpDoc(VictimDid, VictimPriv, purpose: "authentication"));

        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, resolver));
        Assert.Contains("not granted purpose", ex.Message);
    }

    [Fact]
    public void NullResolver_IsRejected()
    {
        var token = BuildVcJwt(VictimPriv, VictimDid + "#key-1", VictimDid);
        Assert.Throws<InvalidOperationException>(() => JwtVerifier.Verify(token, null!));
    }

    // --- extended negative matrix (#4) --------------------------------------

    private static string BuildRaw(Dictionary<string, object> header, Dictionary<string, object> payload, string priv)
    {
        var signingInput = B64(header) + "." + B64(payload);
        return signingInput + "." + Sign(signingInput, priv);
    }

    private static MapResolver VictimResolver()
    {
        var r = new MapResolver();
        r.Add(SecpDoc(VictimDid, VictimPriv));
        return r;
    }

    [Fact]
    public void UnsupportedAlg_IsRejected()
    {
        var token = BuildVcJwt(VictimPriv, VictimDid + "#key-1", VictimDid, alg: "RS256");
        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, VictimResolver()));
        Assert.Contains("unsupported algorithm", ex.Message);
    }

    [Fact]
    public void MissingKid_IsRejected()
    {
        var header = new Dictionary<string, object> { ["typ"] = "vc+jwt", ["alg"] = "ES256K" };
        var payload = new Dictionary<string, object>
        {
            ["vc"] = new Dictionary<string, object> { ["issuer"] = VictimDid, ["type"] = new[] { "VerifiableCredential" } },
            ["iss"] = VictimDid
        };
        var token = BuildRaw(header, payload, VictimPriv);
        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, VictimResolver()));
        Assert.Contains("kid not found", ex.Message);
    }

    [Fact]
    public void MalformedBase64Header_IsRejected()
    {
        var token = "@@@not-base64@@@.eyJ2YyI6e30=.AAAA";
        Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, VictimResolver()));
    }

    [Fact]
    public void AmbiguousVcAndVp_IsRejected()
    {
        var header = new Dictionary<string, object> { ["alg"] = "ES256K", ["kid"] = VictimDid + "#key-1" };
        var payload = new Dictionary<string, object>
        {
            ["vc"] = new Dictionary<string, object> { ["issuer"] = VictimDid },
            ["vp"] = new Dictionary<string, object> { ["holder"] = VictimDid },
            ["iss"] = VictimDid
        };
        var token = BuildRaw(header, payload, VictimPriv);
        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, VictimResolver()));
        Assert.Contains("both vc and vp", ex.Message);
    }

    [Fact]
    public void TypeArrayNamingBothKinds_IsRejected()
    {
        var header = new Dictionary<string, object> { ["alg"] = "ES256K", ["kid"] = VictimDid + "#key-1" };
        var payload = new Dictionary<string, object>
        {
            ["type"] = new[] { "VerifiableCredential", "VerifiablePresentation" },
            ["issuer"] = VictimDid,
            ["iss"] = VictimDid
        };
        var token = BuildRaw(header, payload, VictimPriv);
        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, VictimResolver()));
        Assert.Contains("both a credential and a presentation", ex.Message);
    }

    [Fact]
    public void CaseVariantIssuerKey_IsRejected()
    {
        // A "Issuer" sibling of "issuer" is how a case-insensitive downstream
        // consumer could be fed a signer this check never compares.
        var header = new Dictionary<string, object> { ["typ"] = "vc+jwt", ["alg"] = "ES256K", ["kid"] = VictimDid + "#key-1" };
        var payload = new Dictionary<string, object>
        {
            ["vc"] = new Dictionary<string, object>
            {
                ["issuer"] = VictimDid,
                ["Issuer"] = AttackerDid,
                ["type"] = new[] { "VerifiableCredential" }
            },
            ["iss"] = VictimDid
        };
        var token = BuildRaw(header, payload, VictimPriv);
        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, VictimResolver()));
        Assert.Contains("differs from issuer only by case", ex.Message);
    }

    [Fact]
    public void NoSigner_NeitherIssNorIssuer_IsRejected()
    {
        var header = new Dictionary<string, object> { ["typ"] = "vc+jwt", ["alg"] = "ES256K", ["kid"] = VictimDid + "#key-1" };
        var payload = new Dictionary<string, object>
        {
            ["vc"] = new Dictionary<string, object> { ["type"] = new[] { "VerifiableCredential" } }
        };
        var token = BuildRaw(header, payload, VictimPriv);
        var ex = Assert.ThrowsAny<Exception>(() => JwtVerifier.Verify(token, VictimResolver()));
        Assert.Contains("names no signer", ex.Message);
    }
}
