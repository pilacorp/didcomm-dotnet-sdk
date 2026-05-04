using System;
using System.Collections.Generic;
using System.Text;
using Pila.CredentialSdk.DidComm.Credential.Common.Signer;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using Pila.CredentialSdk.DidComm.Credential.Vc;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.Signer;

public class SignerProviderTests
{
    private sealed class FixedSignatureProvider : ISignerProvider
    {
        private readonly byte[] _signature;

        public FixedSignatureProvider(byte[] signature)
        {
            _signature = signature;
        }

        public byte[] Sign(byte[] digest32)
        {
            Assert.NotNull(digest32);
            Assert.Equal(32, digest32.Length);
            return _signature;
        }
    }

    [Fact]
    public void JwtCredential_AddProofByProvider_NormalizesSignatureTo64Bytes()
    {
        var contents = new CredentialContents
        {
            Context = new List<object> { "https://www.w3.org/ns/credentials/v2" },
            Id = "urn:uuid:jwt-test",
            Issuer = "did:example:issuer",
            Types = new List<string> { "VerifiableCredential" },
            Subject = new List<Subject> { new() { Id = "did:example:subject1" } }
        };

        var credential = JwtCredential.NewJwtCredential(contents);

        var sig65 = new byte[65];
        for (var i = 0; i < sig65.Length; i++)
        {
            sig65[i] = (byte)(255 - i);
        }

        credential.AddProofByProvider(new FixedSignatureProvider(sig65));

        var serialized = credential.Serialize();
        Assert.IsType<string>(serialized);

        var jwt = (string)serialized;
        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);

        var decodedSig = Util.Base64UrlDecode(parts[2]);
        Assert.Equal(64, decodedSig.Length);
        Assert.Equal(sig65[..64], decodedSig);
    }
}
