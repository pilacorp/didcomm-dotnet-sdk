using System;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json;

namespace Pila.CredentialSdk.DidComm.Jwe;

public static class JweBuilder
{
    public static string BuildJwe(byte[] iv, byte[] ciphertext, byte[] tag)
    {
        var header = new
        {
            alg = "ECDH-ES",
            enc = "A256GCM",
            crv = "secp256k1",
            typ = "application/didcomm-encrypted+json"
        };

        var headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header));

        var jwe = new JweModel
        {
            Protected = Base64UrlEncode(headerBytes),
            Iv = Base64UrlEncode(iv),
            Ciphertext = Base64UrlEncode(ciphertext),
            Tag = Base64UrlEncode(tag)
        };

        return JsonConvert.SerializeObject(jwe, Formatting.Indented);
    }
    
    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
