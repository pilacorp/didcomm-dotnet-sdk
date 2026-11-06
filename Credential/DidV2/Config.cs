namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public static class DidV2Config
{
    public const string DefaultRpc = "https://rpc-new.pila.vn";
    public const long DefaultChainId = 704;
    public const string DefaultDidSmcAddress = "0x75e7b09a24bce5a921babe27b62ec7bfe2230d6a";
    public const string DefaultMethod = "did:nda";

    public static DidConfig Default() => new();
}

public sealed class DidConfig
{
    public string Rpc { get; set; } = DidV2Config.DefaultRpc;
    public long ChainId { get; set; } = DidV2Config.DefaultChainId;
    public string DidSmcAddr { get; set; } = DidV2Config.DefaultDidSmcAddress;
    public string Method { get; set; } = DidV2Config.DefaultMethod;
    public IDidSigner? IssuerSigner { get; set; }
    public IDidSigner? DidSigner { get; set; }
    public ulong Nonce { get; set; }
    public ulong Epoch { get; set; }
    public string CapId { get; set; } = "";
    public bool SyncEpoch { get; set; }
    public bool SyncNonce { get; set; }
    public List<VerificationMethodSpec> ExtraVms { get; set; } = [];
    public bool EnableP256Vm { get; set; }
}

public delegate void DidOption(DidConfig cfg);

public static class DidOptions
{
    public static DidOption WithRpc(string rpc) => c => c.Rpc = rpc;
    public static DidOption WithDidChainId(long chainId) => c => c.ChainId = chainId;
    public static DidOption WithDidAddressSmc(string addr) => c => c.DidSmcAddr = addr;
    public static DidOption WithMethod(string method) => c => c.Method = method;
    public static DidOption WithEpoch(ulong epoch) => c => c.Epoch = epoch;
    public static DidOption WithIssuerSigner(IDidSigner signer) => c => c.IssuerSigner = signer;
    public static DidOption WithDidSigner(IDidSigner signer) => c => c.DidSigner = signer;
    public static DidOption WithSyncEpoch(bool sync) => c => c.SyncEpoch = sync;
    public static DidOption WithSyncNonce(bool sync) => c => c.SyncNonce = sync;
    public static DidOption WithNonce(ulong nonce) => c => c.Nonce = nonce;
    public static DidOption WithCapId(string capId) => c => c.CapId = capId;
    public static DidOption WithP256VerificationMethod() => c => c.EnableP256Vm = true;
}
