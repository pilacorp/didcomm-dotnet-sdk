using System.Security.Cryptography;

namespace Pila.CredentialSdk.DidComm.Crypto;

public static class AesGcmHelper
{
    public static (byte[] nonce, byte[] ciphertext) EncryptAesGcm(byte[] key, byte[] plaintext)
    {
        using var aes = new AesGcm(key, 16); // 16 bytes tag size
        var nonce = new byte[12]; // GCM nonce size
        RandomNumberGenerator.Fill(nonce);
        
        var ciphertext = new byte[plaintext.Length + 16]; // plaintext + tag
        var tag = new byte[16]; // GCM tag size
        
        aes.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length), tag);
        
        // Copy tag to end of ciphertext
        Array.Copy(tag, 0, ciphertext, plaintext.Length, tag.Length);
        
        return (nonce, ciphertext);
    }
}
