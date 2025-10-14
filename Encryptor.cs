using Pila.Credential.Sdk.DidComm.Crypto;
using Pila.Credential.Sdk.DidComm.Jwe;

namespace Pila.Credential.Sdk.DidComm;

public static class Encryptor
{
    public static string Encrypt(byte[] key, string plaintext)
    {
        var (nonce, ciphertext) = AesGcmHelper.EncryptAesGcm(key, System.Text.Encoding.UTF8.GetBytes(plaintext));
        
        var jweOutput = JweBuilder.BuildJwe(key.Take(16).ToArray(), nonce, ciphertext);
        
        return jweOutput;
    }
}

