using System.Security.Cryptography;

namespace Pila.Credential.Sdk.DidComm.Crypto;

public static class AesGcmHelper
{
    public static (byte[] nonce, byte[] ciphertext) EncryptAesGcm(byte[] key, byte[] plaintext)
    {
        using var aes = new AesGcm(key, 16); // Specify tag size
        var nonce = new byte[12]; // GCM standard nonce size
        RandomNumberGenerator.Fill(nonce);
        
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16]; // GCM tag size
        
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        
        // Combine ciphertext and tag
        var result = new byte[ciphertext.Length + tag.Length];
        Array.Copy(ciphertext, 0, result, 0, ciphertext.Length);
        Array.Copy(tag, 0, result, ciphertext.Length, tag.Length);
        
        return (nonce, result);
    }
}

