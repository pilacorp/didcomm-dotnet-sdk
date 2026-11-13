using Pila.CredentialSdk.DidComm.Credential.DidV2;
using Pila.CredentialSdk.DidComm.Credential.DidV2.DidContract;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.DidV2;

public class ContractTests
{
    [Fact]
    public void AbiTopic0AndRole()
    {
        Assert.Equal("0x39edf358809bd8ab55bfce6add00fc1843a5c6e38ca5257fe7fb98b8bb145469", DidRegistry.WriterAnchorTopic0());
        Assert.Equal(EthCrypto.Keccak256Hex(System.Text.Encoding.UTF8.GetBytes("SUBTREE_WRITER_ROLE")), DidRegistry.SubtreeWriterRole);
        Assert.Equal("0x91d14854", DidRegistry.HasRoleSelector());
    }

    [Fact]
    public void CreateDidRawTxEncodesCapabilityArgs()
    {
        var issuer = new DefaultDidSigner(string.Concat(Enumerable.Repeat("11", 32)));
        var did = new DefaultDidSigner(string.Concat(Enumerable.Repeat("22", 32)));
        var capId = "0x" + string.Concat(Enumerable.Repeat("cd", 32));
        var docHash = "0x" + string.Concat(Enumerable.Repeat("11", 32));
        var sig = Issuer.GenerateIssueDidSignature(new IssueDidPayload
        {
            ContractAddress = DidV2Config.DefaultDidSmcAddress,
            IssuerAddress = issuer.GetAddress(),
            DidAddress = did.GetAddress(),
            DidType = DidTypes.People,
            Epoch = 0,
            CapId = capId
        }, issuer);
        var contract = new DidRegistryContract(new DidContractConfig
        {
            RpcUrl = "http://127.0.0.1:1",
            ContractAddress = DidV2Config.DefaultDidSmcAddress,
            ChainId = DidV2Config.DefaultChainId
        });
        var tx = contract.CreateDidTx(new CreateDidRequest
        {
            IssuerAddress = issuer.GetAddress(),
            IssuerSig = sig,
            DocHash = docHash,
            CapId = capId,
            DidType = DidTypes.People,
            Nonce = 0
        }, did);
        Assert.Matches("^[0-9a-f]+$", tx.TxHex);
        Assert.Matches("^0x[0-9a-f]{64}$", tx.TxHash);
        var decoded = LegacyTx.Decode(Hex.ToBytes(tx.TxHex));
        Assert.Equal(DidV2Config.DefaultDidSmcAddress, decoded.To);
        Assert.StartsWith(DidRegistry.CreateDidSelector()[2..], Hex.ToHex(decoded.Data, prefix: false), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DecodeWriterAnchorsKeepsRegistryBatchOrder()
    {
        var registry = DidV2Config.DefaultDidSmcAddress;
        var writer = "0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3";
        const int n = 8;
        var dids = Enumerable.Range(0, n).Select(i => "0x" + (1000 + i).ToString("x").PadLeft(40, '0')).ToArray();
        var treeIndexes = Enumerable.Range(0, n).Select(i => (System.Numerics.BigInteger)i).ToArray();
        var roots = Enumerable.Range(0, n).Select(i => EthCrypto.Keccak256Hex([(byte)i])).ToArray();
        var other = "0x0000000000000000000000000000000000000bad";
        var receipt = new TransactionReceiptLike
        {
            Status = 1,
            Logs =
            [
                DidRegistry.EncodeWriterAnchorLog(other, writer, dids[..1], treeIndexes[..1], roots[..1], 3),
                DidRegistry.EncodeWriterAnchorLog(registry, writer, dids, treeIndexes, roots, 7)
            ]
        };
        var anchors = DidRegistry.DecodeWriterAnchors(receipt, registry);
        Assert.Equal(n, anchors.Count);
        Assert.Equal(writer.ToLowerInvariant(), anchors[0].Writer);
        Assert.Equal(3, anchors[3].TreeIndex);
    }
}
