using System.Net;
using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.JsonMap;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Interop;

public class GoInteropFixturesTests : IDisposable
{
    private const string LegacyHexVc = """
        {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
          ],
          "credentialSubject": {
            "age": 30,
            "id": "did:example:legacy-subject",
            "name": "Alice"
          },
          "id": "urn:uuid:7f1e2c3d-legacy-vc",
          "issuer": "did:example:legacy-issuer",
          "proof": {
            "created": "2026-09-14T08:51:57Z",
            "cryptosuite": "ecdsa-rdfc-2019",
            "proofPurpose": "assertionMethod",
            "proofValue": "b95159fb2c2a5f9a5a04f23342eafb0aa66875a0c41b07c0d4f6bff3205a401f078c75299f88d6553cfdfce08050ca566736c23a47c6b575fef656e4f1ce768200",
            "type": "DataIntegrityProof",
            "verificationMethod": "did:example:legacy-issuer#key-1"
          },
          "type": [
            "VerifiableCredential",
            "ExampleDegreeCredential"
          ],
          "validFrom": "2025-01-01T00:00:00Z"
        }
        """;

    private const string LegacyPub =
        "04e962c45627a43f3bec0af18c6c780ddbacceb8275b5204d494bc2cc44dc96d9805e64ee5ffeb6d05ed37284636c7cf6bfbaaa0d131f950cecc43110ac5510cad";

    [Fact]
    public void LegacyHexRdfcCredential_VerifiesLikeGo()
    {
        var (port, _) = StartDidResolver("did:example:legacy-issuer", "did:example:legacy-issuer#key-1", LegacyPub);
        CredentialConfig.Init($"http://127.0.0.1:{port}");
        var map = JsonSerializer.Deserialize<JsonMap>(LegacyHexVc)!;
        Assert.True(map.VerifyProof(CredentialConfig.BaseUrl));
    }

    [Fact]
    public void GetSigningInput_Returns32ByteDigest()
    {
        var contents = new CredentialContents
        {
            Issuer = "did:example:issuer",
            Context = new List<object> { "https://www.w3.org/2018/credentials/v1" }
        };
        var cred = JsonCredential.NewJsonCredential(contents);
        Assert.Equal(32, cred.GetSigningInput().Length);
    }

    public void Dispose()
    {
    }

    private static (int port, HttpListener listener) StartDidResolver(string did, string vmId, string publicKeyHex)
    {
        var port = Random.Shared.Next(20000, 60000);
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();
        _ = Task.Run(async () =>
        {
            while (listener.IsListening)
            {
                var ctx = await listener.GetContextAsync();
                var body =
                    "{\"id\":\"" + did + "\",\"assertionMethod\":[\"" + vmId + "\"],\"authentication\":[\"" + vmId +
                    "\"],\"verificationMethod\":[{\"id\":\"" + vmId + "\",\"publicKeyHex\":\"" + publicKeyHex + "\"}]}";
                var bytes = Encoding.UTF8.GetBytes(body);
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
            }
        });
        return (port, listener);
    }
}
