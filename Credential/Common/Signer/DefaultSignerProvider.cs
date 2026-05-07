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

    /// <summary>
    /// Creates a DefaultSignerProvider from a hex-encoded secp256k1 private key.
    /// </summary>
    /// <param name="privateKeyHex">
    /// Hex private key. The value may include or omit the <c>0x</c> prefix.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="privateKeyHex"/> is null or empty.</exception>
    public DefaultSignerProvider(string privateKeyHex)
    {
        if (string.IsNullOrWhiteSpace(privateKeyHex))
        {
            throw new ArgumentException("privateKeyHex cannot be null or empty", nameof(privateKeyHex));
        }

        _privateKeyHex = privateKeyHex;
    }

    /// <summary>
    /// Signs a 32-byte digest using the configured private key.
    /// </summary>
    /// <remarks>
    /// Returns either 64 or 65 bytes. See <see cref="ISignerProvider"/> contract for details.
    /// </remarks>
    public byte[] Sign(byte[] digest32)
    {
        SignerProviderUtil.EnsureDigest32(digest32);

        var signature = EcdsaSigner.Sign(digest32, _privateKeyHex);
        SignerProviderUtil.EnsureSignatureLength(signature);
        return signature;
    }
}
