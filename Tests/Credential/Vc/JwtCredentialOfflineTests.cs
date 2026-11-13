using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Vc;

/// <summary>
/// Drives the public JwtCredential.Verify path with an injected resolver and the
/// explicit offline mode (follow-up #1), proving verification never needs HTTP.
/// </summary>
public class JwtCredentialOfflineTests
{
    private const string Priv = "11112222333344445555666677778888999900001111222233334444555566aa";
    private const string Did = "did:nda:testnet:0xOFFLINE";

    private static string PubHex(string priv)
    {
        var curve = SecNamedCurves.GetByName("secp256k1");
        var q = curve.G.Multiply(new BigInteger(1, Convert.FromHexString(priv))).Normalize();
        return Convert.ToHexString(q.GetEncoded(false)).ToLowerInvariant();
    }

    private static DidDocument Doc()
    {
        var vmId = Did + "#key-1";
        return new DidDocument
        {
            Id = Did,
            VerificationMethod = new List<VerificationMethodEntry>
            {
                new() { Id = vmId, Type = "EcdsaSecp256k1VerificationKey2019", Controller = Did, PublicKeyHex = PubHex(Priv) }
            },
            AssertionMethod = new List<string> { vmId }
        };
    }

    private static string Token()
    {
        string B64(object o) => Util.Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(o)));
        var header = new Dictionary<string, object> { ["typ"] = "vc+jwt", ["alg"] = "ES256K", ["kid"] = Did + "#key-1" };
        var payload = new Dictionary<string, object>
        {
            ["vc"] = new Dictionary<string, object>
            {
                ["@context"] = new[] { "https://www.w3.org/ns/credentials/v2" },
                ["type"] = new[] { "VerifiableCredential" },
                ["issuer"] = Did
            },
            ["iss"] = Did,
            ["iat"] = 1700000000L
        };
        var signingInput = B64(header) + "." + B64(payload);
        var digest = Canonicalizer.ComputeDigest(Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Util.Base64UrlEncode(EcdsaSigner.Sign(digest, Priv)[..64]);
    }

    [Fact]
    public void Verify_Offline_WithInjectedResolver_Passes()
    {
        var cred = JwtCredential.ParseJwtCredential(Token());
        cred.Verify(CredentialOpts.WithOffline(), CredentialOpts.WithResolver(new MapResolver(Doc())));
    }

    [Fact]
    public void Verify_Offline_WithoutResolver_Throws()
    {
        var cred = JwtCredential.ParseJwtCredential(Token());
        var ex = Assert.Throws<InvalidOperationException>(() => cred.Verify(CredentialOpts.WithOffline()));
        Assert.Contains("offline verification requires an injected resolver", ex.Message);
    }

    private sealed class MapResolver : IDidDocumentResolver
    {
        private readonly DidDocument _doc;
        public MapResolver(DidDocument doc) => _doc = doc;
        public DidDocument ResolveDocument(string did) => _doc;
    }
}
