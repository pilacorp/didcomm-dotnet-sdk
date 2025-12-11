using System;
using System.Collections.Generic;
using System.Text;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using CredentialStatic = Pila.CredentialSdk.DidComm.Credential.Vc.Credential;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Vc;

public class CredentialTests
{
    private const string ValidJsonCredential = @"{
        ""@context"": [""https://www.w3.org/2018/credentials/v1""],
        ""id"": ""urn:uuid:1234"",
        ""type"": [""VerifiableCredential""],
        ""issuer"": ""did:example:issuer"",
        ""validFrom"": ""2025-08-05T10:00:00Z"",
        ""credentialSubject"": {""id"": ""did:example:subject1"", ""name"": ""John Doe""},
        ""credentialSchema"": {""id"": ""https://example.org/schema/1"", ""type"": ""JsonSchemaValidator2019""},
        ""credentialStatus"": {""id"": ""https://example.org/status/1"", ""type"": ""StatusList2021Entry""},
        ""proof"": {""type"": ""Ed25519Signature2020"", ""created"": ""2025-08-05T10:00:00Z"", ""proofValue"": ""signature""}
    }";

    // JWT lifted from Go tests; contains a vc claim with contexts/types/etc.
    private const string ValidJwtCredential = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHg4YjNiMWRlZThlMDBjYjk1ZjhiMmExZDFhOWE3Y2I4ZmU3ZDQ5MGNlI2tleS0xIiwidHlwIjoiSldUIn0.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5vcmcvc2NoZW1hcy9lZHVjYXRpb25hbC1jcmVkZW50aWFsLmpzb24iLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9leGFtcGxlLm9yZy9jcmVkZW50aWFscy9zdGF0dXMvMTIzIiwic3RhdHVzTGlzdEluZGV4IjoiMTIzIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24iLCJ0eXBlIjoiQml0c3RyaW5nU3RhdHVzTGlzdEVudHJ5In0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UiLCJncmFkdWF0aW9uWWVhciI6MjAyMywiaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnNFWXZkcmp4TWpRNHRwbmplOUJEQlR6dU5EUDNrbm42cUxaRXJ6ZDRiSjVnbzJDQ2hvUGpkNUdBSDN6cEZKUDVmdXdTazY2VTVQcTZFaEY0bktuSHpEbnpuRVA4Zlg5OW5aR2d3YkFoMW83R2oxWDUyVGRoZjdVNEtUazY2eHNBNXIiLCJuYW1lIjoiSm9obiBEb2UiLCJ1bml2ZXJzaXR5IjoiVGVzdCBVbml2ZXJzaXR5In0sImlkIjoidXJuOnV1aWQ6c2lnbmF0dXJlLXRlc3QtY3JlZGVudGlhbC0xMjM0NTY3OCIsImlzc3VlciI6ImRpZDpuZGE6dGVzdG5ldDoweDhiM2IxZGVlOGUwMGNiOTVmOGIyYTFkMWE5YTdjYjhmZTdkNDkwY2UiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRWR1Y2F0aW9uYWxDcmVkZW50aWFsIl0sInZhbGlkRnJvbSI6IjIwMjQtMDEtMDFUMDA6MDA6MDBaIiwidmFsaWRVbnRpbCI6IjIwMjUtMDEtMDFUMDA6MDA6MDBaIn19.aDZAa9pMUFaK5F0LE1S9B-ZL1814OwFaQNKvNr5G-HQTPLPNkIFB0ii9fTeDFMQXUiuEf09oBa7s0k0IHdrP0w";

    [Fact]
    public void NewJsonCredential_WithMinimalContents_BuildsCredential()
    {
        var contents = new CredentialContents
        {
            Context = new List<object> { "https://www.w3.org/2018/credentials/v1" },
            Id = "urn:uuid:1234",
            Issuer = "did:example:issuer",
            Types = new List<string> { "VerifiableCredential" },
            Subject = new List<Subject> { new() { Id = "did:example:subject1", CustomFields = new Dictionary<string, object> { ["name"] = "John Doe" } } },
            Schemas = new List<Schema>(),
            CredentialStatus = new List<Status>()
        };

        var credential = JsonCredential.NewJsonCredential(contents);

        Assert.NotNull(credential);
        Assert.Equal("JSON", credential.GetType());
        Assert.NotEmpty(credential.GetSigningInput());
        Assert.NotEmpty(credential.GetContents());
    }

    [Fact]
    public void ParseCredential_WithJsonInput_ReturnsJsonCredential()
    {
        var bytes = Encoding.UTF8.GetBytes(ValidJsonCredential);

        var credential = CredentialStatic.ParseCredential(bytes);

        Assert.IsType<JsonCredential>(credential);
        Assert.Equal("JSON", credential.GetType());
    }

    [Fact]
    public void ParseCredential_WithJwtInput_ReturnsJwtCredential()
    {
        var bytes = Encoding.UTF8.GetBytes(ValidJwtCredential);

        var credential = CredentialStatic.ParseCredential(bytes);

        Assert.IsType<JwtCredential>(credential);
        Assert.Equal("JWT", credential.GetType());
    }

    [Fact]
    public void ParseCredential_WithEmptyInput_Throws()
    {
        Assert.Throws<ArgumentException>(() => CredentialStatic.ParseCredential(Array.Empty<byte>()));
    }
}

