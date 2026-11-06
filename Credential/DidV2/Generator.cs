using Pila.CredentialSdk.DidComm.Credential.DidV2.DidContract;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public sealed class DidGenerator
{
    private readonly DidConfig _base;
    private readonly DidRegistryContract _contract;

    public DidGenerator(params DidOption[] options)
    {
        _base = DidV2Config.Default();
        foreach (var opt in options) opt(_base);
        _contract = new DidRegistryContract(new DidContractConfig
        {
            RpcUrl = _base.Rpc,
            ContractAddress = string.IsNullOrEmpty(_base.DidSmcAddr) ? DidV2Config.DefaultDidSmcAddress : _base.DidSmcAddr,
            ChainId = _base.ChainId
        });
    }

    public DidTxResult GenerateDidTx(byte didType, string didPublicKeyHex, string hash, Dictionary<string, object>? metadata, params DidOption[] options)
    {
        var cfg = Resolve(options);
        if (cfg.IssuerSigner == null) throw new InvalidOperationException("issuer signer is required");
        var issuerAddr = cfg.IssuerSigner.GetAddress();
        var didAddr = EthCrypto.AddressFromPublicKeyHex(didPublicKeyHex);
        var issuerSig = GenerateIssuerSignature(didType, didAddr, issuerAddr, cfg);
        var issuerDid = DidIds.ToDid(cfg.Method, issuerAddr);
        var didIdentifier = DidIds.ToDid(cfg.Method, didAddr);
        var didDoc = DidV2Document.GenerateDidDocument(didPublicKeyHex, didIdentifier, hash, issuerDid, didType, metadata, cfg.ExtraVms.ToArray())
            ?? throw new InvalidOperationException("invalid DID document: build failed");
        DidV2Document.ValidateDidDocument(didDoc);
        var docHash = DidV2Document.HashDidDocument(didDoc);
        if (cfg.DidSigner == null) throw new InvalidOperationException("did signer is required");
        var tx = _contract.CreateDidTx(new CreateDidRequest
        {
            IssuerAddress = issuerAddr,
            IssuerSig = issuerSig,
            DocHash = docHash,
            CapId = cfg.CapId,
            DidType = didType,
            Nonce = cfg.Nonce
        }, cfg.DidSigner);
        return new DidTxResult { Did = didIdentifier, Document = didDoc, Transaction = tx };
    }

    public IssuerSignature GenerateIssuerSignature(byte didType, string didAddr, string issuerAddr, DidConfig cfg)
    {
        if (cfg.IssuerSigner == null) throw new InvalidOperationException("issuer signer is required");
        return Issuer.GenerateIssueDidSignature(new IssueDidPayload
        {
            ContractAddress = _base.DidSmcAddr,
            IssuerAddress = issuerAddr,
            DidAddress = didAddr,
            DidType = didType,
            Epoch = cfg.Epoch,
            CapId = cfg.CapId
        }, cfg.IssuerSigner);
    }

    private DidConfig Resolve(params DidOption[] options)
    {
        var cfg = new DidConfig
        {
            Rpc = _base.Rpc,
            ChainId = _base.ChainId,
            DidSmcAddr = _base.DidSmcAddr,
            Method = _base.Method,
            IssuerSigner = _base.IssuerSigner,
            DidSigner = _base.DidSigner,
            Nonce = _base.Nonce,
            Epoch = _base.Epoch,
            CapId = _base.CapId,
            SyncEpoch = _base.SyncEpoch,
            SyncNonce = _base.SyncNonce,
            ExtraVms = [.. _base.ExtraVms],
            EnableP256Vm = _base.EnableP256Vm
        };
        foreach (var opt in options) opt(cfg);
        if (string.IsNullOrEmpty(cfg.CapId)) cfg.CapId = Issuer.GenerateCapId();
        return cfg;
    }
}
