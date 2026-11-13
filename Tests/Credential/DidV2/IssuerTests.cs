using Pila.CredentialSdk.DidComm.Credential.DidV2;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.DidV2;

public class IssuerTests
{
    [Fact]
    public void CapIdIs32Bytes()
    {
        Assert.Matches("^0x[0-9a-f]{64}$", Issuer.GenerateCapId());
    }

    [Fact]
    public void Eip191PayloadRecoversIssuer()
    {
        var issuer = new DefaultDidSigner(string.Concat(Enumerable.Repeat("11", 32)));
        var capId = "0x" + string.Concat(Enumerable.Repeat("ab", 32));
        var payload = new IssueDidPayload
        {
            ContractAddress = DidV2Config.DefaultDidSmcAddress,
            IssuerAddress = issuer.GetAddress(),
            DidAddress = "0x86b2efd244acb31eb238a65ca05476ab42558071",
            DidType = DidTypes.People,
            Epoch = 7,
            CapId = capId
        };
        var packed = Issuer.BuildIssueDidPayload(payload);
        var sig = Issuer.GenerateIssueDidSignature(payload, issuer);
        var compact = new byte[65];
        Buffer.BlockCopy(Hex.Pad32(sig.R), 0, compact, 0, 32);
        Buffer.BlockCopy(Hex.Pad32(sig.S), 0, compact, 32, 32);
        compact[64] = (byte)sig.V;
        var recovered = EthCrypto.RecoverAddress(EthCrypto.Keccak256(packed), compact);
        Assert.Equal(issuer.GetAddress(), recovered.ToLowerInvariant());
    }
}
