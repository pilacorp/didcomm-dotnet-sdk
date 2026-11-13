using Pila.CredentialSdk.DidComm.Credential.DidV2.SubDid;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.DidV2;

public class MerkleTests
{
    [Theory]
    [InlineData(1, "0x0101010101010101010101010101010101010101010101010101010101010101")]
    [InlineData(2, "0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0")]
    [InlineData(3, "0x1d614fa3c8de62938b0948972494f9a3858575db69ce1d34c77926f30732c981")]
    [InlineData(5, "0x55d458ff264cc10cb4ef71d27a18db86f587999b2355cfa5eb5fccf8c973bced")]
    public void RootVectors(int n, string root)
    {
        Assert.Equal(root, Merkle.Root(FixtureLeaves(n)));
    }

    [Fact]
    public void ProofVectors()
    {
        Assert.Equal(
            ["0x0b242b9a6559f2d9f8563485a0697b746ec58ce879e0e5ac94d4c8a250723121"],
            Merkle.Proof(FixtureLeaves(5), 4));
        Assert.Equal(
            [
                "0x0404040404040404040404040404040404040404040404040404040404040404",
                "0x346d8c96a2454213fcc0daff3c96ad0398148181b9fa6488f7ae2c0af5b20aa0",
                "0x0505050505050505050505050505050505050505050505050505050505050505"
            ],
            Merkle.Proof(FixtureLeaves(5), 2));
        var leaves = FixtureLeaves(5);
        Assert.True(Merkle.VerifyProof(leaves[2], Merkle.Proof(leaves, 2), Merkle.Root(leaves)));
    }

    [Fact]
    public void RevokedLeafVectors()
    {
        Assert.Equal(
            "0x83c91d2020210e4924defde940dcb4e63ec3f20bbad4229da6019faba05cc206",
            Merkle.RevokedLeaf("0x86b2efd244acb31eb238a65ca05476ab42558071"));
        Assert.Equal(
            "0xa0fed93a6a92b69bcbc4e8f5983d5ede26eef742274c3700b5e400a4c8856c3d",
            Merkle.RevokedLeaf("0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3"));
        var leaves = FixtureLeaves(3);
        leaves[2] = Merkle.RevokedLeaf("0x86b2efd244acb31eb238a65ca05476ab42558071");
        Assert.Equal("0x934b02ce8ddedb479ffc1fad0eaf40f0cd0d75e853f9d28e9b1273fd49004993", Merkle.Root(leaves));
    }

    private static string[] FixtureLeaves(int n) =>
        Enumerable.Range(0, n).Select(i => "0x" + Convert.ToHexString(Enumerable.Repeat((byte)(i + 1), 32).ToArray()).ToLowerInvariant()).ToArray();
}
