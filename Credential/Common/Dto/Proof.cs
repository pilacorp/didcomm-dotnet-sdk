using Newtonsoft.Json;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Dto;

/// <summary>
/// Represents a Linked Data Proof for a Verifiable Credential.
/// </summary>
public class Proof
{
    [JsonProperty("type")]
    public string Type { get; set; } = string.Empty;

    [JsonProperty("created")]
    public string Created { get; set; } = string.Empty;

    [JsonProperty("verificationMethod")]
    public string VerificationMethod { get; set; } = string.Empty;

    [JsonProperty("proofPurpose")]
    public string ProofPurpose { get; set; } = string.Empty;

    [JsonProperty("proofValue", NullValueHandling = NullValueHandling.Ignore)]
    public string? ProofValue { get; set; }

    [JsonProperty("jws", NullValueHandling = NullValueHandling.Ignore)]
    public string? Jws { get; set; }

    [JsonProperty("disclosures", NullValueHandling = NullValueHandling.Ignore)]
    public List<string>? Disclosures { get; set; }

    [JsonProperty("cryptosuite", NullValueHandling = NullValueHandling.Ignore)]
    public string? Cryptosuite { get; set; }

    [JsonProperty("challenge", NullValueHandling = NullValueHandling.Ignore)]
    public string? Challenge { get; set; }

    [JsonProperty("domain", NullValueHandling = NullValueHandling.Ignore)]
    public string? Domain { get; set; }

    [JsonIgnore]
    public byte[]? Signature { get; set; }
}

