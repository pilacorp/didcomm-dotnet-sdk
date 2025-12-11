using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using JwtCredential = Pila.CredentialSdk.DidComm.Credential.Vc.JwtCredential;
using JsonCredential = Pila.CredentialSdk.DidComm.Credential.Vc.JsonCredential;

namespace Pila.CredentialSdk.DidComm;

public class Program
{
    static void Main(string[] args)
    {
        CredentialConfig.Init("https://auth-dev.pila.vn/api/v1/did");
        Console.WriteLine("=== Verifiable Credential SDK Test ===");

        ParseJsonCredentialExample();
        ParseJwtCredentialExample();
        CreateJsonCredentialAndAddProofExample();
        CreateJwtCredentialAndAddProofExample();
    }

    // Example: parse and verify a JSON credential
    private static void ParseJsonCredentialExample()
    {
        Console.WriteLine("\n-- Parse JSON credential --");

        var rawCredential = @"{
            ""@context"": [
                ""https://www.w3.org/ns/credentials/v2"",
                ""https://www.w3.org/ns/credentials/examples/v2""
            ],
            ""credentialSchema"": {
                ""id"": ""https://auth-dev.pila.vn/api/v1/schemas/19cb4f2d-144d-4efd-a3f3-efa007b67d93"",
                ""type"": ""JsonSchema""
            },
            ""credentialStatus"": {
                ""id"": ""did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee/credentials/status/0#0"",
                ""statusListCredential"": ""https://auth-dev.pila.vn/api/v1/issuers/did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee/credentials/status/0"",
                ""statusListIndex"": ""0"",
                ""statusPurpose"": ""revocation"",
                ""type"": ""BitstringStatusListEntry""
            },
            ""credentialSubject"": {
                ""age"": 10,
                ""department"": ""Engineering"",
                ""id"": ""did:nda:testnet:0x9f57ad527eca94b2ab498549ff961f6bc67909c3"",
                ""name"": ""Test Create"",
                ""salary"": 50000
            },
            ""id"": ""did:nda:testnet:24a22351-daf2-41af-ac98-fa5cbe897e97"",
            ""issuer"": ""did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee"",
            ""proof"": {
                ""created"": ""2025-12-03T03:28:56Z"",
                ""cryptosuite"": ""ecdsa-rdfc-2019"",
                ""proofPurpose"": ""assertionMethod"",
                ""proofValue"": ""ffab9ce2a077a2be721b5999bdbff284bb672e8bafe9b98b87074f2110f6ce127703f6d9941e88b71c35e90fe7e0baf104dc8cba758d2988fa606d4a5761b78c"",
                ""type"": ""DataIntegrityProof"",
                ""verificationMethod"": ""did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee#key-1""
            },
            ""type"": ""VerifiableCredential"",
            ""validFrom"": ""2025-12-03T03:28:56Z"",
            ""validUntil"": ""2026-12-03T03:28:56Z""
        }";

        try
        {
            var credential = Pila.CredentialSdk.DidComm.Credential.Vc.Credential.ParseCredential(Encoding.UTF8.GetBytes(rawCredential));

            credential.Verify();
            Console.WriteLine("Verification: SUCCESS");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"JSON credential error: {ex.Message}");
        }
    }

    // Example: parse and verify a JWT VC (mirrors Java example)
    private static void ParseJwtCredentialExample()
    {
        Console.WriteLine("\n-- Parse JWT credential --");

        const string rawJwt = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHg3ZGJkOTkwMTI4MjJmNGNhNGE5YTc0Nzk0YzJhYTk4NTI0MTExYmFlI2tleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjE3OTYyNjk5MzksImlhdCI6MTc2NDczMzkzOSwiaXNzIjoiZGlkOm5kYTp0ZXN0bmV0OjB4N2RiZDk5MDEyODIyZjRjYTRhOWE3NDc5NGMyYWE5ODUyNDExMWJhZSIsImp0aSI6ImRpZDpuZGE6dGVzdG5ldDpmNjc4YTRlYy0yMDM3LTRiNTgtYjI4Yi04N2UzZTJjOWM2NjMiLCJuYmYiOjE3NjQ3MzM5MzksInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDBhMzRiM2E5YTgzNjZkMDczYTEyNzgzOTUxZDMzYzY2ODMzZTUxMTciLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXV0aC1kZXYucGlsYS52bi9hcGkvdjEvc2NoZW1hcy9mNGFmYjZiNC1kYjQxLTQ1YzEtOGI5OC02MWUwZjdhOWM3ZGMiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjB4N2RiZDk5MDEyODIyZjRjYTRhOWE3NDc5NGMyYWE5ODUyNDExMWJhZS9jcmVkZW50aWFscy9zdGF0dXMvMCMwIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2F1dGgtZGV2LnBpbGEudm4vYXBpL3YxL2lzc3VlcnMvZGlkOm5kYTp0ZXN0bmV0OjB4N2RiZDk5MDEyODIyZjRjYTRhOWE3NDc5NGMyYWE5ODUyNDExMWJhZS9jcmVkZW50aWFscy9zdGF0dXMvMCIsInN0YXR1c0xpc3RJbmRleCI6IjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiIsInR5cGUiOiJCaXRzdHJpbmdTdGF0dXNMaXN0RW50cnkifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiYWdlIjoxMCwiZGVwYXJ0bWVudCI6IkVuZ2luZWVyaW5nIiwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgwYTM0YjNhOWE4MzY2ZDA3M2ExMjc4Mzk1MWQzM2M2NjgzM2U1MTE3IiwibmFtZSI6IlRlc3QgQ3JlYXRlIiwic2FsYXJ5Ijo1MDAwMH0sImlkIjoiZGlkOm5kYTp0ZXN0bmV0OmY2NzhhNGVjLTIwMzctNGI1OC1iMjhiLTg3ZTNlMmM5YzY2MyIsImlzc3VlciI6ImRpZDpuZGE6dGVzdG5ldDoweDdkYmQ5OTAxMjgyMmY0Y2E0YTlhNzQ3OTRjMmFhOTg1MjQxMTFiYWUiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJ2YWxpZEZyb20iOiIyMDI1LTEyLTAzVDAzOjUyOjE5WiIsInZhbGlkVW50aWwiOiIyMDI2LTEyLTAzVDAzOjUyOjE5WiJ9fQ.i2tgKgnDfzC0weOsiY6f531nuxxvQrDmuHG7bBRkR8FgitolK_1L1dMB67FE05ozRi3CSBBpPceliBBQnJ_dcg";

        try
        {
            var credential = Pila.CredentialSdk.DidComm.Credential.Vc.Credential.ParseCredential(Encoding.UTF8.GetBytes(rawJwt));

            credential.Verify();
            Console.WriteLine("Verification: SUCCESS");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"JWT credential error: {ex.Message}");
        }
    }

    // private key hex
    private static string privateKeyHex = "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a";

    // issuer did
    private static string issuerDID = "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce";

    // create credential contents
    private static CredentialContents credentialContents = new CredentialContents
    {
        Context = new List<object> { "https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2" },
        Schemas = new List<Schema> { new Schema { Id = "https://auth-dev.pila.vn/api/v1/schemas/19cb4f2d-144d-4efd-a3f3-efa007b67d93", Type = "JsonSchema" } },
        CredentialStatus = new List<Status> { new Status { Id = "did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee/credentials/status/0#0", StatusListCredential = "https://auth-dev.pila.vn/api/v1/issuers/did:nda:testnet:0xf7da5bd53973184ee9f1bebedbd3ab1b0d0d60ee/credentials/status/0", StatusListIndex = "0", StatusPurpose = "revocation", Type = "BitstringStatusListEntry" } },
        Subject = new List<Subject>
        {
            new()
            {
                Id = "did:nda:testnet:0x9f57ad527eca94b2ab498549ff961f6bc67909c3",
                CustomFields = new Dictionary<string, object>
                {
                    ["name"] = "Test Create",
                    ["department"] = "Engineering",
                    ["age"] = 10,
                    ["salary"] = 50000
                }
            }
        },
        Id = "did:nda:testnet:24a22351-daf2-41af-ac98-fa5cbe897e97",
        Issuer = issuerDID,
        Types = new List<string> { "VerifiableCredential" },
        ValidFrom = DateTime.UtcNow,
        ValidUntil = DateTime.UtcNow.AddYears(1)
    };

    // Example: create a json credential and add a proof
    private static void CreateJsonCredentialAndAddProofExample()
    {
        Console.WriteLine("\n-- Create JSON credential and add proof --");

        try
        {
            var credential = JsonCredential.NewJsonCredential(credentialContents);
            credential.AddProof(privateKeyHex);
            credential.Verify();
            Console.WriteLine("Verification: SUCCESS");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"JSON verification failed: {ex.Message}");
        }
    }

    // Example: create a jwt credential and add a proof
    private static void CreateJwtCredentialAndAddProofExample()
    {
        Console.WriteLine("\n-- Create JWT credential and add proof --");

        try
        {
            var credential = JwtCredential.NewJwtCredential(credentialContents);
            credential.AddProof(privateKeyHex);
            credential.Verify();
            Console.WriteLine("Verification: SUCCESS");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"JWT verification failed: {ex.Message}");
        }
    }
}
