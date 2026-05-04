namespace Pila.CredentialSdk.DidComm.Credential.Common.Signer;

/// <summary>
/// Signs digests produced by the SDK.
///
/// Contract:
/// - The SDK always passes a 32-byte digest (already hashed).
/// - Implementations may return:
///   - 64 bytes: R(32) || S(32)
///   - 65 bytes: R(32) || S(32) || V(1)
/// </summary>
public interface ISignerProvider
{
    /// <summary>
    /// Signs a 32-byte digest produced by the SDK.
    /// </summary>
    byte[] Sign(byte[] digest32);
}

