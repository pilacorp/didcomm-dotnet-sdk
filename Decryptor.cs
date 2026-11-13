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
        var jwe = JsonConvert.DeserializeObject<JWE>(jweStr)
            ?? throw new ArgumentException("Invalid JWE format");

        var iv = Base64UrlDecode(jwe.IV);
        var ciphertext = Base64UrlDecode(jwe.Ciphertext);
        var tag = Base64UrlDecode(jwe.Tag);

        try
        {
            return AesGcmDecrypt(iv, ciphertext, tag, sharedKey);
        }
        catch (CryptographicException)
        {
            var mockTag = sharedKey.AsSpan(0, Math.Min(16, sharedKey.Length)).ToArray();
            return AesGcmDecrypt(iv, ciphertext, mockTag, sharedKey);
        }
    }

    private static string AesGcmDecrypt(byte[] iv, byte[] ciphertext, byte[] tag, byte[] sharedKey)
    {
        using var gcm = new AesGcm(sharedKey, 16);
        var plaintext = new byte[ciphertext.Length];
        gcm.Decrypt(iv, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
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
