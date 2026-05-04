using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Signer;

/// <summary>
/// Default provider that signs using an in-memory hex private key.
///
/// Suitable for local/dev usage. For stronger key management, implement
/// <see cref="ISignerProvider"/> using Vault/HSM/remote signing services.
/// </summary>
public sealed class DefaultSignerProvider : ISignerProvider
{
    private readonly string _privateKeyHex;

    public DefaultSignerProvider(string privateKeyHex)
    {
        if (string.IsNullOrWhiteSpace(privateKeyHex))
        {
            throw new ArgumentException("privateKeyHex cannot be null or empty", nameof(privateKeyHex));
        }

        _privateKeyHex = privateKeyHex;
    }

    public byte[] Sign(byte[] digest32)
    {
        SignerProviderUtil.EnsureDigest32(digest32);

        var signature = EcdsaSigner.Sign(digest32, _privateKeyHex);
        SignerProviderUtil.EnsureSignatureLength(signature);
        return signature;
    }
}

