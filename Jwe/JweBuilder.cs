using System.Text.Json;

namespace Pila.Credential.Sdk.DidComm.Jwe;

public class Jwe
{
    public string Protected { get; set; } = string.Empty;
    public string Iv { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;
    public string Tag { get; set; } = string.Empty;
}

public static class JweBuilder
{
    public static string BuildJwe(byte[] sharedKey, byte[] iv, byte[] ciphertext)
    {
        var header = new Dictionary<string, string>
        {
            ["alg"] = "ECDH-ES",
            ["enc"] = "A256GCM",
            ["crv"] = "secp256k1",
            ["typ"] = "application/didcomm-encrypted+json"
        };
        
        var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);
        var jwe = new Jwe
        {
            Protected = Convert.ToBase64String(headerBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            Iv = Convert.ToBase64String(iv).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            Ciphertext = Convert.ToBase64String(ciphertext).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            Tag = Convert.ToBase64String(sharedKey.Take(16).ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        };
        
        return JsonSerializer.Serialize(jwe, new JsonSerializerOptions { WriteIndented = true });
    }
}

