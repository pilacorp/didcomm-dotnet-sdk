namespace Pila.CredentialSdk.DidComm.Credential.Common.Signer;

/// <summary>
/// Internal helpers enforcing the <see cref="ISignerProvider"/> contract.
/// </summary>
internal static class SignerProviderUtil
{
    /// <summary>
    /// Ensures the SDK digest is exactly 32 bytes.
    /// </summary>
    public static void EnsureDigest32(byte[] digest32)
    {
        if (digest32 == null)
        {
            throw new ArgumentNullException(nameof(digest32));
        }
        if (digest32.Length != 32)
        {
            throw new ArgumentException($"digest must be 32 bytes, got {digest32.Length}", nameof(digest32));
        }
    }

    /// <summary>
    /// Ensures a signature is either 64 bytes (R||S) or 65 bytes (R||S||V).
    /// </summary>
    public static void EnsureSignatureLength(byte[] signature)
    {
        if (signature == null)
        {
            throw new ArgumentNullException(nameof(signature));
        }

        if (signature.Length != 64 && signature.Length != 65)
        {
            throw new ArgumentException(
                $"signature length must be 64 or 65 bytes, got {signature.Length}",
                nameof(signature)
            );
        }
    }

    /// <summary>
    /// Normalizes a 65-byte signature (R||S||V) down to 64 bytes (R||S).
    /// </summary>
    /// <remarks>
    /// JWT proofs use the 64-byte R||S form. The SDK accepts 65-byte signatures
    /// from providers and will drop the trailing recovery byte when present.
    /// </remarks>
    public static byte[] NormalizeTo64(byte[] signature)
    {
        EnsureSignatureLength(signature);

        if (signature.Length == 64)
        {
            return signature;
        }

        // Drop trailing recovery ID (v) when present.
        return signature.Take(64).ToArray();
    }
}
