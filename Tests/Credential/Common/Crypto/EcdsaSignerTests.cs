using System;
using System.Text;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Math;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.Common.Crypto;

public class EcdsaSignerTests
{
    private const string PrivateKeyHex = "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a";

    private static string DeriveCompressedPublicKey(string privateKeyHex)
    {
        var priv = new BigInteger(privateKeyHex, 16);
        var curve = SecNamedCurves.GetByName("secp256k1");
        var q = curve.G.Multiply(priv);
        // compressed = 33 bytes, prefix 02/03
        var compressed = q.GetEncoded(true);
        return Convert.ToHexString(compressed).ToLowerInvariant();
    }

    [Fact]
    public void SignAndVerify_RoundTrip_Succeeds()
    {
        var message = Encoding.UTF8.GetBytes("hello world");
        var signature = EcdsaSigner.Sign(message, PrivateKeyHex);
        var signatureHex = Convert.ToHexString(signature).ToLowerInvariant();
        var pubKeyHex = DeriveCompressedPublicKey(PrivateKeyHex);

        var ok = EcdsaVerifier.VerifySignature(pubKeyHex, signatureHex, message);

        Assert.True(ok);
    }

    [Fact]
    public void SignAndVerify_WithTamperedMessage_Fails()
    {
        var message = Encoding.UTF8.GetBytes("hello world");
        var signature = EcdsaSigner.Sign(message, PrivateKeyHex);
        var signatureHex = Convert.ToHexString(signature).ToLowerInvariant();
        var pubKeyHex = DeriveCompressedPublicKey(PrivateKeyHex);

        var tampered = (byte[])message.Clone();
        tampered[0] ^= 0xFF;

        var ok = EcdsaVerifier.VerifySignature(pubKeyHex, signatureHex, tampered);

        Assert.False(ok);
    }
}

