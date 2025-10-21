using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Pila.CredentialSdk.DidComm.Jwe;

namespace Pila.CredentialSdk.DidComm;

public static class Decryptor
{
    public static string DecryptJwe(string jweStr, byte[] sharedKey)
    {
        try
        {
            var jwe = JsonConvert.DeserializeObject<JweModel>(jweStr);
            if (jwe == null)
                throw new ArgumentException("Invalid JWE format");

            var iv = Base64UrlDecode(jwe.Iv);
            var ciphertext = Base64UrlDecode(jwe.Ciphertext);

            using var aes = new AesGcm(sharedKey, 16); // 16 bytes tag size
            var plaintext = new byte[ciphertext.Length - 16]; // Remove tag
            var tag = new byte[16];
            
            // Extract tag from end of ciphertext (like Go gcm.Open)
            Array.Copy(ciphertext, ciphertext.Length - 16, tag, 0, 16);
            var actualCiphertext = new byte[ciphertext.Length - 16];
            Array.Copy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);

            aes.Decrypt(iv, actualCiphertext, tag, plaintext);
            
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Decryption failed: {ex.Message}", ex);
        }
    }
    
    private static byte[] Base64UrlDecode(string input)
    {
        var base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}
