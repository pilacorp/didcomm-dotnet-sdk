using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Pila.CredentialSdk.DidComm;

public class JWE
{
    [JsonProperty("protected")]
    public string Protected { get; set; } = string.Empty;
    
    [JsonProperty("iv")]
    public string IV { get; set; } = string.Empty;
    
    [JsonProperty("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;
    
    [JsonProperty("tag")]
    public string Tag { get; set; } = string.Empty;
}

public static class Decryptor
{
    public static string DecryptJwe(string jweStr, byte[] sharedKey)
    {
        // Parse JWE JSON
        var jwe = JsonConvert.DeserializeObject<JWE>(jweStr);
        if (jwe == null)
            throw new ArgumentException("Invalid JWE format");

        // Decode base64url
        var iv = Base64UrlDecode(jwe.IV);
        var ciphertext = Base64UrlDecode(jwe.Ciphertext);
        var tag = Base64UrlDecode(jwe.Tag);

        // Try decrypt with tag from JWE field (new format with real tag)
        try
        {
            using var gcm = new AesGcm(sharedKey, 16);
            var plaintext = new byte[ciphertext.Length];
            gcm.Decrypt(iv, ciphertext, tag, plaintext);
            return Encoding.UTF8.GetString(plaintext);
        }
        catch
        {
            // Fallback: extract tag from end of ciphertext (old format with mock tag)
            return DecryptWithTagFromCiphertext(iv, ciphertext, sharedKey);
        }
    }

    private static string DecryptWithTagFromCiphertext(byte[] iv, byte[] ciphertext, byte[] sharedKey)
    {
        using var gcm = new AesGcm(sharedKey, 16);

        // Extract tag from end of ciphertext (old Go GCM format)
        var tag = new byte[16];
        Array.Copy(ciphertext, ciphertext.Length - 16, tag, 0, 16);
        var actualCiphertext = new byte[ciphertext.Length - 16];
        Array.Copy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);

        var plaintext = new byte[actualCiphertext.Length];
        gcm.Decrypt(iv, actualCiphertext, tag, plaintext);

        return Encoding.UTF8.GetString(plaintext);
    }
    
    private static byte[] Base64UrlDecode(string input)
    {
        // Same as Go base64.RawURLEncoding.DecodeString
        var base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}
