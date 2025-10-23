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
        try
        {
            // Parse JWE JSON - same as Go json.Unmarshal
            var jwe = JsonConvert.DeserializeObject<JWE>(jweStr);
            if (jwe == null)
                throw new ArgumentException("Invalid JWE format");

            // Decode base64url - same as Go base64urlDecode
            var iv = Base64UrlDecode(jwe.IV);
            var ciphertext = Base64UrlDecode(jwe.Ciphertext);

            // Debug output removed for cleaner output

            // Create GCM - same as Go cipher.NewGCM
            using var gcm = new AesGcm(sharedKey, 16); // 16 bytes tag size
            
            // Decrypt - same as Go gcm.Open(nil, iv, ciphertext, nil)
            // In Go, ciphertext already includes the tag at the end
            // JWE tag field is just mock (sharedKey[:16])
            var plaintext = new byte[ciphertext.Length - 16]; // Remove 16-byte tag
            var tag = new byte[16];
            
            // Extract tag from end of ciphertext (Go GCM stores tag at end)
            Array.Copy(ciphertext, ciphertext.Length - 16, tag, 0, 16);
            var actualCiphertext = new byte[ciphertext.Length - 16];
            Array.Copy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);

            // Debug output removed for cleaner output

            gcm.Decrypt(iv, actualCiphertext, tag, plaintext);
            
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Decryption failed: {ex.Message}", ex);
        }
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
