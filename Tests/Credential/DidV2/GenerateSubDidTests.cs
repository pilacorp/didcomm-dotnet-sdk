using Pila.CredentialSdk.DidComm.Credential.DidV2;
using Pila.CredentialSdk.DidComm.Credential.DidV2.SubDid;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.DidV2;

public class GenerateSubDidTests
{
    private const string CreateSignature =
        "0x73ffc216c50a9cbdf28d8eac72954f337974e390e83427abe79d3ed5bea8ee7e602b23159cf8ce401bf7e5fc2de553568e9c3a9359267fc393e5033f7fa59ce61b";
    private const string Row1PrivateKeyHex = "46c9a6cf35b07f7d3f5d37f75bf671cc1251d9399a2db28e35b0942765cde8e8";
    private const string RootR1PrivateKeyHex = "1111111111111111111111111111111111111111111111111111111111111111";

    [Fact]
    public void DocumentAndSignatureVectors()
    {
        var res = SubDidGenerate.GenerateSubDid(
            DocumentTests.RootR1,
            DocumentTests.SubIdS1,
            DocumentTests.Row1PublicKeyHex,
            DidTypes.People,
            null,
            new DefaultDidSigner(RootR1PrivateKeyHex),
            new DefaultDidSigner(Row1PrivateKeyHex));
        Assert.Equal(DocumentTests.CreateSubDidJson, DidV2Document.ToJson(res.Document));
        Assert.Equal(CreateSignature, res.Signature);
        Assert.Equal(DocumentTests.Row1SubDid, res.Did);
        Assert.Equal("people", res.Type);
    }

    [Fact]
    public void RefusesMismatchedSigners()
    {
        Assert.Throws<InvalidOperationException>(() =>
            SubDidGenerate.GenerateSubDid(
                DocumentTests.RootR1,
                DocumentTests.SubIdS1,
                DocumentTests.Row1PublicKeyHex,
                DidTypes.People,
                null,
                new DefaultDidSigner(Row1PrivateKeyHex),
                new DefaultDidSigner(Row1PrivateKeyHex)));
        Assert.Throws<InvalidOperationException>(() =>
            SubDidGenerate.GenerateSubDid(
                DocumentTests.RootR1,
                DocumentTests.SubIdS1,
                DocumentTests.Row1PublicKeyHex,
                DidTypes.People,
                null,
                new DefaultDidSigner(RootR1PrivateKeyHex),
                new DefaultDidSigner(RootR1PrivateKeyHex)));
    }
}
