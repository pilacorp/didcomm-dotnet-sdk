namespace Pila.CredentialSdk.DidComm.Credential.Common.Signer;

internal static class SignerProviderUtil
{
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

