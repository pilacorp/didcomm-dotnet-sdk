using System.Numerics;
using System.Reflection;
using System.Text;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2.DidContract;

public sealed class DidContractConfig
{
    public string RpcUrl { get; set; } = "";
    public string ContractAddress { get; set; } = "";
    public long ChainId { get; set; }
    public BigInteger? GasPrice { get; set; }
    public ulong GasLimit { get; set; } = 200_000;
}

public sealed class CreateDidRequest
{
    public string IssuerAddress { get; set; } = "";
    public IssuerSignature IssuerSig { get; set; } = new();
    public string DocHash { get; set; } = "";
    public string CapId { get; set; } = "";
    public byte DidType { get; set; }
    public ulong Nonce { get; set; }
}

public sealed class SetDocumentHashRequest
{
    public string DidAddress { get; set; } = "";
    public string DocHash { get; set; } = "";
    public string CapId { get; set; } = "";
    public IssuerSignature IssuerSig { get; set; } = new();
    public ulong Nonce { get; set; }
}

public sealed class SetDocumentHashByIssuerRequest
{
    public string DidAddress { get; set; } = "";
    public string DocHash { get; set; } = "";
    public ulong Nonce { get; set; }
}

public sealed class WriterAnchor
{
    public string Writer { get; set; } = "";
    public string Did { get; set; } = "";
    public BigInteger TreeIndex { get; set; }
    public string Root { get; set; } = "";
}

public sealed class ReceiptLog
{
    public string Address { get; set; } = "";
    public List<string> Topics { get; set; } = [];
    public string Data { get; set; } = "";
    public int Index { get; set; }
}

public sealed class TransactionReceiptLike
{
    public long Status { get; set; }
    public List<ReceiptLog> Logs { get; set; } = [];
}

public static class DidRegistry
{
    public const ulong DefaultGasLimit = 200000;
    public static string SubtreeWriterRole => EthCrypto.Keccak256Hex(Encoding.UTF8.GetBytes("SUBTREE_WRITER_ROLE"));

    public static string WriterAnchorTopic0() =>
        EthCrypto.Keccak256Hex(Encoding.UTF8.GetBytes("BatchSubtreesAnchoredByWriter(address,address[],uint256[],bytes32[])"));

    public static string HasRoleSelector() => "0x" + AbiCodec.Selector("hasRole(bytes32,address)");
    public static string CreateDidSelector() => "0x" + AbiCodec.Selector("createDID(address,uint8,bytes32,bytes32,uint8,bytes32,bytes32)");

    public static byte[] LoadAbiJson()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().First(n => n.EndsWith("did_registry_smc_abi.json", StringComparison.Ordinal));
        using var stream = asm.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return Encoding.UTF8.GetBytes(reader.ReadToEnd());
    }

    public static ReceiptLog EncodeWriterAnchorLog(string emitter, string writer, string[] dids, BigInteger[] treeIndexes, string[] roots, int index = 0)
    {
        var data = AbiCodec.Encode(
            AbiValue.AddressArray(dids),
            AbiValue.UintArray(treeIndexes),
            AbiValue.Bytes32Array(roots));
        return new ReceiptLog
        {
            Address = emitter,
            Topics = [WriterAnchorTopic0(), Hex.ToHex(Hex.Pad32(Hex.ToBytes(Hex.ToAddress(writer))))],
            Data = Hex.ToHex(data),
            Index = index
        };
    }

    public static List<WriterAnchor> DecodeWriterAnchors(TransactionReceiptLike? receipt, string registry)
    {
        if (receipt == null) throw new InvalidOperationException("didcontract: receipt is nil");
        if (string.IsNullOrEmpty(registry) || Hex.ToAddress(registry) == "0x0000000000000000000000000000000000000000")
        {
            throw new InvalidOperationException("didcontract: registry address is zero");
        }
        var eventId = WriterAnchorTopic0();
        var registryAddr = Hex.ToAddress(registry);
        var anchors = new List<WriterAnchor>();
        foreach (var log in receipt.Logs)
        {
            if (Hex.ToAddress(log.Address) != registryAddr) continue;
            if (log.Topics.Count == 0 || !string.Equals(log.Topics[0], eventId, StringComparison.OrdinalIgnoreCase)) continue;
            if (log.Topics.Count != 2) throw new InvalidOperationException($"BatchSubtreesAnchoredByWriter has {log.Topics.Count} topics, want 2");
            var (dids, indexes, roots) = AbiCodec.DecodeWriterData(Hex.ToBytes(log.Data));
            if (dids.Count != indexes.Count || dids.Count != roots.Count)
            {
                throw new InvalidOperationException($"BatchSubtreesAnchoredByWriter arrays have lengths {dids.Count}, {indexes.Count} and {roots.Count}");
            }
            var writer = Hex.ToAddress(log.Topics[1]);
            for (var i = 0; i < dids.Count; i++)
            {
                anchors.Add(new WriterAnchor
                {
                    Writer = writer,
                    Did = dids[i],
                    TreeIndex = indexes[i],
                    Root = roots[i].ToLowerInvariant()
                });
            }
        }
        return anchors;
    }

    public static byte[] EncodeCreateDid(CreateDidRequest req)
    {
        if (!Hex.IsAddress(req.IssuerAddress)) throw new InvalidOperationException($"invalid issuer address: {req.IssuerAddress}");
        if (Hex.Normalize(req.DocHash).Length != 64) throw new InvalidOperationException($"invalid docHash length: expected 64 hex chars (32 bytes), got {Hex.Normalize(req.DocHash).Length}");
        if (Hex.Normalize(req.CapId).Length != 64) throw new InvalidOperationException($"invalid capID length: expected 64 hex chars (32 bytes), got {Hex.Normalize(req.CapId).Length}");
        return AbiCodec.EncodeFunction("createDID(address,uint8,bytes32,bytes32,uint8,bytes32,bytes32)",
            AbiValue.Address(req.IssuerAddress),
            AbiValue.Uint8(req.DidType),
            AbiValue.Bytes32(Hex.ToBytes(req.DocHash)),
            AbiValue.Bytes32(Hex.ToBytes(req.CapId)),
            AbiValue.Uint8((byte)req.IssuerSig.V),
            AbiValue.Bytes32(Hex.Pad32(req.IssuerSig.R)),
            AbiValue.Bytes32(Hex.Pad32(req.IssuerSig.S)));
    }

    public static byte[] EncodeSetDocumentHash(SetDocumentHashRequest req) =>
        AbiCodec.EncodeFunction("setDocumentHash(address,bytes32,bytes32,uint8,bytes32,bytes32)",
            AbiValue.Address(req.DidAddress),
            AbiValue.Bytes32(Hex.ToBytes(req.DocHash)),
            AbiValue.Bytes32(Hex.ToBytes(req.CapId)),
            AbiValue.Uint8((byte)req.IssuerSig.V),
            AbiValue.Bytes32(Hex.Pad32(req.IssuerSig.R)),
            AbiValue.Bytes32(Hex.Pad32(req.IssuerSig.S)));

    public static byte[] EncodeSetDocumentHashByIssuer(SetDocumentHashByIssuerRequest req) =>
        AbiCodec.EncodeFunction("setDocumentHashByIssuer(address,bytes32)",
            AbiValue.Address(req.DidAddress),
            AbiValue.Bytes32(Hex.ToBytes(req.DocHash)));
}

public sealed class DidRegistryContract
{
    private readonly DidContractConfig _cfg;

    public DidRegistryContract(DidContractConfig cfg)
    {
        if (!Hex.IsAddress(cfg.ContractAddress)) throw new InvalidOperationException("contract address is required");
        if (cfg.ChainId <= 0) throw new InvalidOperationException("chain ID must be greater than 0, it's required");
        if (cfg.GasLimit == 0) cfg.GasLimit = DidRegistry.DefaultGasLimit;
        _cfg = cfg;
    }

    public SignedTransaction CreateDidTx(CreateDidRequest req, IDidSigner txSigner) =>
        SignLegacy(DidRegistry.EncodeCreateDid(req), req.Nonce, txSigner);

    public SignedTransaction SetDocumentHashTx(SetDocumentHashRequest req, IDidSigner txSigner) =>
        SignLegacy(DidRegistry.EncodeSetDocumentHash(req), req.Nonce, txSigner);

    public SignedTransaction SetDocumentHashByIssuerTx(SetDocumentHashByIssuerRequest req, IDidSigner txSigner) =>
        SignLegacy(DidRegistry.EncodeSetDocumentHashByIssuer(req), req.Nonce, txSigner);

    private SignedTransaction SignLegacy(byte[] data, ulong nonce, IDidSigner signer)
    {
        var (txHex, txHash) = LegacyTx.Sign(
            Hex.ToAddress(_cfg.ContractAddress),
            nonce,
            _cfg.GasPrice ?? 0,
            _cfg.GasLimit,
            data,
            _cfg.ChainId,
            signer);
        return new SignedTransaction { TxHex = txHex, TxHash = txHash };
    }
}
