namespace Pila.CredentialSdk.DidComm.Credential.Common.Signer;

/// <summary>
/// SignerProvider signs digests produced by the SDK.
/// </summary>
/// <remarks>
/// Contract:
/// <list type="bullet">
/// <item>
/// The SDK always passes a 32-byte digest (already hashed). Implementations SHOULD
/// reject any input that is not exactly 32 bytes to avoid accidentally signing raw data.
/// </item>
/// <item>
/// Implementations may return either:
/// <list type="bullet">
/// <item>64 bytes: R(32) || S(32)</item>
/// <item>65 bytes: R(32) || S(32) || V(1)</item>
/// </list>
/// </item>
/// <item>
/// The SDK will accept both lengths; for JWT proofs it will normalize to 64 bytes (R||S).
/// </item>
/// </list>
/// </summary>
public interface ISignerProvider
{
    /// <summary>
    /// Sign signs a 32-byte digest produced by the SDK.
    /// </summary>
    /// <param name="digest32">A 32-byte digest computed by the SDK.</param>
    /// <returns>
    /// Signature bytes (64 or 65 bytes):
    /// R(32)||S(32) or R(32)||S(32)||V(1).
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="digest32"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="digest32"/> is not 32 bytes.</exception>
    byte[] Sign(byte[] digest32);
}
