using Newtonsoft.Json;

namespace Pila.CredentialSdk.DidComm.Jwe;

public class JweModel
{
    [JsonProperty("protected")]
    public string Protected { get; set; } = string.Empty;
    
    [JsonProperty("iv")]
    public string Iv { get; set; } = string.Empty;
    
    [JsonProperty("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;
    
    [JsonProperty("tag")]
    public string Tag { get; set; } = string.Empty;
}
