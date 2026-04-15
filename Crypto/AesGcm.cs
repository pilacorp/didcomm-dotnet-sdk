using System.Security.Cryptography;

namespace Pila.CredentialSdk.DidComm.Crypto;

public static class AesGcmHelper
{
    public static (byte[] nonce, byte[] ciphertext, byte[] tag) EncryptAesGcm(byte[] key, byte[] plaintext)
    {
        using var aes = new AesGcm(key, 16); // 16 bytes tag size
        var nonce = new byte[12]; // GCM nonce size
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16]; // GCM tag size

        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return (nonce, ciphertext, tag);
    }
}
