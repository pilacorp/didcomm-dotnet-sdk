using System.Text;
using Pila.CredentialSdk.DidComm.Crypto;
using Pila.CredentialSdk.DidComm.Jwe;

namespace Pila.CredentialSdk.DidComm;

public static class Encryptor
{
    public static string Encrypt(byte[] key, string plaintext)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var (nonce, ciphertext) = AesGcmHelper.EncryptAesGcm(key, plaintextBytes);
        
        return JweBuilder.BuildJwe(key[..16], nonce, ciphertext);
    }
}
