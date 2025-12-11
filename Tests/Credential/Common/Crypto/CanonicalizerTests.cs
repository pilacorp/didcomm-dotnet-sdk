using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.Crypto;

public class CanonicalizerTests
{
    private const string CredentialJson = @"{
        ""validFrom"": ""2025-12-01T02:25:20Z"",
        ""id"": ""urn:uuid:f86b96e6-2e22-42d0-8d81-6849c80157b0"",
        ""validUntil"": ""2025-12-02T02:25:20Z"",
        ""@context"": [""https://www.w3.org/ns/credentials/v2""],
        ""type"": ""VerifiableCredential"",
        ""credentialSubject"": {
            ""issuer"": ""did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e"",
            ""citizenIdentify"": ""024537894514"",
            ""result"": ""matched"",
            ""id"": ""did:nda:testnet:0x86977f96a4f0973819d204541b1d9d48424302d9"",
            ""issuedBy"": ""Mobifone"",
            ""issuedDate"": ""2025-12-01"",
            ""phoneNumber"": ""0761804353""
        },
        ""proof"": {
            ""proofPurpose"": ""assertionMethod"",
            ""created"": ""2025-12-01T02:25:21Z"",
            ""proofValue"": ""a7a970560732bf2e2cb4a02b4a566e12adc658e57aac871f1399c2d4532f2d0037186ae3173990a3d98dec31e518e03efb1e7ea438d919babc9974356def26d000"",
            ""type"": ""DataIntegrityProof"",
            ""cryptosuite"": ""ecdsa-rdfc-2019"",
            ""verificationMethod"": ""did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e#key-1""
        },
        ""issuer"": ""did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e""
    }";

    [Fact]
    public void CanonicalizeWithoutProof_MatchesExpectedNQuads()
    {
        var document = JsonSerializer.Deserialize<Dictionary<string, object>>(CredentialJson)!;

        var canonicalized = Canonicalizer.CanonicalizeWithoutProof(document);
        var canonicalString = Encoding.UTF8.GetString(canonicalized);

        // CanonicalizeWithoutProof strips the proof; expect only credential body triples.
        const string expected = "<urn:uuid:f86b96e6-2e22-42d0-8d81-6849c80157b0> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n<urn:uuid:f86b96e6-2e22-42d0-8d81-6849c80157b0> <https://www.w3.org/2018/credentials#credentialSubject> <did:nda:testnet:0x86977f96a4f0973819d204541b1d9d48424302d9> .\n<urn:uuid:f86b96e6-2e22-42d0-8d81-6849c80157b0> <https://www.w3.org/2018/credentials#issuer> <did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e> .\n<urn:uuid:f86b96e6-2e22-42d0-8d81-6849c80157b0> <https://www.w3.org/2018/credentials#validFrom> \"2025-12-01T02:25:20Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n<urn:uuid:f86b96e6-2e22-42d0-8d81-6849c80157b0> <https://www.w3.org/2018/credentials#validUntil> \"2025-12-02T02:25:20Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n";

        static string Normalize(string s) => s.Replace("\r\n", "\n").Trim();

        Assert.Equal(Normalize(expected), Normalize(canonicalString));
    }
}
