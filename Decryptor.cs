using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Pila.Credential.Sdk.DidComm.Jwe;

namespace Pila.Credential.Sdk.DidComm;

public static class Decryptor
{
    private static byte[] Base64UrlDecode(string input)
    {
        // Add padding if needed
        var padding = input.Length % 4;
        if (padding != 0)
        {
            input += new string('=', 4 - padding);
        }
        
        // Replace URL-safe characters
        input = input.Replace('-', '+').Replace('_', '/');
        
        return Convert.FromBase64String(input);
    }
    
    public static string DecryptJwe(string jweStr, byte[] sharedKey)
    {
        var jwe = JsonSerializer.Deserialize<Pila.Credential.Sdk.DidComm.Jwe.Jwe>(jweStr);
        if (jwe == null)
        {
            throw new ArgumentException("Invalid JWE format");
        }
        
        var iv = Base64UrlDecode(jwe.Iv);
        var ciphertext = Base64UrlDecode(jwe.Ciphertext);
        
        using var aes = new AesGcm(sharedKey, 16);
        
        // Split ciphertext and tag
        var tagLength = 16;
        var actualCiphertext = new byte[ciphertext.Length - tagLength];
        var tag = new byte[tagLength];
        
        Array.Copy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);
        Array.Copy(ciphertext, actualCiphertext.Length, tag, 0, tagLength);
        
        var plaintext = new byte[actualCiphertext.Length];
        aes.Decrypt(iv, actualCiphertext, tag, plaintext);
        
        return Encoding.UTF8.GetString(plaintext);
    }
}

