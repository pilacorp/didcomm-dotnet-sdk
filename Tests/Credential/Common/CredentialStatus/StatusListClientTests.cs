using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using Pila.CredentialSdk.DidComm.Credential.Common.CredentialStatus;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.DigitalCredential;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.CredentialStatus;

/// <summary>
/// Offline, end-to-end exercises of the BitstringStatusList subsystem: bit
/// decode/lookup, purpose check, proof-of-the-list verification, and the SSRF
/// guard on the default HTTP fetch path. All network access is stubbed via an
/// injected fetcher; the proof path reuses the offline resolver pattern from
/// JsonCredentialHighLevelTests.
/// </summary>
public class StatusListClientTests
{
    private const string PrivHex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    private const string Did = "did:example:statuslist-issuer";
    private const int RevokedIndex = 5;

    private static IDidDocumentResolver P256Resolver()
    {
        var pub = P256Signer.PublicFromPrivate(PrivHex);
        var mb = Multikey.EncodeP256(pub);
        var vmId = Did + "#key-1";
        var doc = new DidDocument
        {
            Id = Did,
            VerificationMethod = new List<VerificationMethodEntry>
            {
                new() { Id = vmId, Type = "Multikey", Controller = Did, PublicKeyMultibase = mb }
            },
            AssertionMethod = new List<string> { vmId },
            Authentication = new List<string> { vmId }
        };
        return new MemoryDidDocumentResolver(doc);
    }

    // A gzip+base64url bitstring with RevokedIndex set, built via the reused 1-bit primitive.
    private static string EncodedRevocationList()
    {
        var list = StatusList.New(128, 1);
        list.Set(RevokedIndex, 1);
        return StatusListClient.EncodeList(list.Bytes());
    }

    // Minimal, unsigned status-list response body (for bit/purpose/SSRF paths).
    private static string Body(string purpose, string encoded) =>
        "{\"data\":{\"credentialSubject\":{\"type\":\"BitstringStatusList\"," +
        $"\"statusPurpose\":\"{purpose}\",\"encodedList\":\"{encoded}\"}}}}}}";

    // A fully signed BitstringStatusListCredential wrapped as {"data": <vc>}.
    private static string SignedBody()
    {
        var resolver = P256Resolver();
        var contents = new CredentialContents
        {
            Context = new List<object> { "https://www.w3.org/ns/credentials/v2" },
            Issuer = Did,
            Types = new List<string> { "VerifiableCredential", "BitstringStatusListCredential" },
            Subject = new List<Subject>
            {
                new()
                {
                    Id = Did + "#list",
                    CustomFields = new Dictionary<string, object>
                    {
                        ["type"] = "BitstringStatusList",
                        ["statusPurpose"] = "revocation",
                        ["encodedList"] = EncodedRevocationList()
                    }
                }
            }
        };
        var cred = JsonCredential.NewJsonCredential(contents);
        cred.AddProofByKey(PrivHex, CredentialOpts.WithResolver(resolver), CredentialOpts.WithOffline());
        var vcJson = Encoding.UTF8.GetString(cred.GetContents());
        return "{\"data\":" + vcJson + "}";
    }

    [Fact]
    public void BitLookup_MatchesGoLsbFirstOrdering()
    {
        // 0x01 -> bit 0 set, LSB-first, like Go's TestIsRevoked.
        var subject = new StatusListCredentialSubject
        {
            StatusPurpose = "revocation",
            EncodedList = StatusListClient.EncodeList(new byte[] { 0x01 })
        };
        Assert.True(StatusListClient.IsRevoked(0, subject));
        Assert.False(StatusListClient.IsRevoked(1, subject));
    }

    [Fact]
    public void FetchAndCheck_BitSet_ReportsRevoked()
    {
        var client = new StatusListClient(_ => Body("revocation", EncodedRevocationList()));
        Assert.True(client.FetchAndCheckRevocation("https://issuer.example/status/1", RevokedIndex, "revocation"));
    }

    [Fact]
    public void FetchAndCheck_BitUnset_ReportsNotRevoked()
    {
        var client = new StatusListClient(_ => Body("revocation", EncodedRevocationList()));
        Assert.False(client.FetchAndCheckRevocation("https://issuer.example/status/1", RevokedIndex + 1, "revocation"));
    }

    [Fact]
    public void FetchAndCheck_PurposeMismatch_Throws()
    {
        var client = new StatusListClient(_ => Body("revocation", EncodedRevocationList()));
        var ex = Assert.Throws<System.InvalidOperationException>(() =>
            client.FetchAndCheckRevocation("https://issuer.example/status/1", RevokedIndex, "suspension"));
        Assert.Contains("purpose mismatch", ex.Message);
    }

    [Fact]
    public void FetchAndCheck_ValidListProof_Verifies()
    {
        var client = new StatusListClient(_ => SignedBody());
        Assert.True(client.FetchAndCheckRevocation(
            "https://issuer.example/status/1", RevokedIndex, "revocation", P256Resolver()));
    }

    [Fact]
    public void FetchAndCheck_TamperedListProof_Rejected()
    {
        // Mutate the signed content after signing: the list's own proof no longer matches.
        var node = JsonNode.Parse(SignedBody())!;
        node["data"]!["credentialSubject"]!["encodedList"] =
            StatusListClient.EncodeList(new byte[] { 0x02 });
        var tampered = node.ToJsonString();

        var client = new StatusListClient(_ => tampered);
        Assert.Throws<System.InvalidOperationException>(() =>
            client.FetchAndCheckRevocation(
                "https://issuer.example/status/1", RevokedIndex, "revocation", P256Resolver()));
    }

    [Theory]
    [InlineData("http://169.254.169.254/latest/meta-data/")] // cloud metadata
    [InlineData("http://127.0.0.1/status/1")]                 // loopback
    [InlineData("http://localhost/status/1")]                 // loopback by name
    public void FetchAndCheck_SsrfTarget_BlockedByGuard(string url)
    {
        // Default client => real HTTP fetch path => ResolverGuard rejects before any request.
        var client = new StatusListClient();
        Assert.Throws<System.InvalidOperationException>(() =>
            client.FetchAndCheckRevocation(url, 0, "revocation"));
    }
}
