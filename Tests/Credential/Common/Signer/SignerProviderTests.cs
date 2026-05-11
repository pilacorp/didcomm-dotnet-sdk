using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.Signer;

public class SignerProviderTests
{
    private const string PrivateKeyHex = "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a";

    private static string DeriveCompressedPublicKey(string privateKeyHex)
    {
        var priv = new BigInteger(privateKeyHex, 16);
        var curve = SecNamedCurves.GetByName("secp256k1");
        var q = curve.G.Multiply(priv);
        var compressed = q.GetEncoded(true);
        return Convert.ToHexString(compressed).ToLowerInvariant();
    }

    private sealed class LocalDidResolver : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly string _did;
        private readonly string _publicKeyHex;

        public string BaseUrl { get; }

        public LocalDidResolver(string did, string publicKeyHex)
        {
            _did = did;
            _publicKeyHex = publicKeyHex;

            var port = GetFreeTcpPort();
            BaseUrl = $"http://127.0.0.1:{port}";

            _listener = new HttpListener();
            _listener.Prefixes.Add($"{BaseUrl}/");
            _listener.Start();

            _ = ServeAsync();
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { }
            try { _listener.Close(); } catch { }
        }

        private async System.Threading.Tasks.Task ServeAsync()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch
                {
                    break;
                }

                try
                {
                    var path = ctx.Request.Url?.AbsolutePath ?? "/";
                    var requested = Uri.UnescapeDataString(path.TrimStart('/'));

                    if (!string.Equals(requested, _did, System.StringComparison.Ordinal))
                    {
                        ctx.Response.StatusCode = 404;
                        ctx.Response.Close();
                        continue;
                    }

                    var vmId = $"{_did}#key-1";
                    var body = $$"""
                    {
                      "@context": ["https://www.w3.org/ns/did/v1"],
                      "id": "{{_did}}",
                      "verificationMethod": [
                        {
                          "id": "{{vmId}}",
                          "type": "EcdsaSecp256k1VerificationKey2019",
                          "controller": "{{_did}}",
                          "publicKeyHex": "{{_publicKeyHex}}"
                        }
                      ]
                    }
                    """;

                    var bytes = Encoding.UTF8.GetBytes(body);
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
                    ctx.Response.Close();
                }
                catch
                {
                    try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
                }
            }
        }

        private static int GetFreeTcpPort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }
    }

    [Fact]
    public void JwtCredential_AddProofByProvider_NormalizesSignatureTo64Bytes()
    {
        const string did = "did:example:issuer";
        var publicKeyHex = DeriveCompressedPublicKey(PrivateKeyHex);
        using var resolver = new LocalDidResolver(did, publicKeyHex);

        var contents = new CredentialContents
        {
            Context = new List<object> { "https://www.w3.org/ns/credentials/v2" },
            Id = "urn:uuid:jwt-test",
            Issuer = did,
            Types = new List<string> { "VerifiableCredential" },
            Subject = new List<Subject> { new() { Id = "did:example:subject1" } }
        };

        var credential = JwtCredential.NewJwtCredential(contents);
        credential.AddProofByProvider(
            new Pila.CredentialSdk.DidComm.Credential.Common.Signer.DefaultSignerProvider(PrivateKeyHex),
            CredentialOpts.WithBaseUrl(resolver.BaseUrl)
        );

        var serialized = credential.Serialize();
        Assert.IsType<string>(serialized);

        var jwt = (string)serialized;
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        var decodedSig = Util.Base64UrlDecode(parts[2]);
        Assert.Equal(64, decodedSig.Length);
    }
}
