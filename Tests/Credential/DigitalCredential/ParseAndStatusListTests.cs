using Pila.CredentialSdk.DidComm.Credential.DigitalCredential;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.DigitalCredential;

public class ParseAndStatusListTests
{
    [Fact]
    public void ParseRejectsBareJwtWithoutTilde()
    {
        var ex = Assert.Throws<DigitalCredentialException>(() => DcCredential.Parse("not-a-jwt"));
        Assert.Equal(DigitalCredentialCode.Malformed, ex.Code);
        Assert.Contains("~", ex.Message);
    }

    [Fact]
    public void ParseAcceptsSdJwtAndHashesIssuerJwt()
    {
        var compact = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2kifQ.sig~disclosure~";
        var cred = DcCredential.Parse(compact);
        Assert.Equal(compact, cred.Serialize());
        Assert.Matches("^[0-9a-f]{64}$", cred.Hash());
    }

    [Fact]
    public void StatusListDraftExampleAndSet917()
    {
        var list = StatusList.Decode("eNrbuRgAAhcBXQ", 1);
        Assert.Equal(new byte[] { 0xb9, 0xa3 }, list.Bytes());
        var want = new[] { 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1 };
        for (var i = 0; i < want.Length; i++)
        {
            Assert.Equal(want[i], list.Get(i));
        }

        var round = StatusList.FromBytes([0xb9, 0xa3], 1);
        Assert.Equal(new byte[] { 0xb9, 0xa3 }, StatusList.Decode(round.Encode(), 1).Bytes());

        var big = StatusList.New(1000, 1);
        big.Set(917, 1);
        Assert.Equal(0b0010_0000, big.Bytes()[114]);
        Assert.Equal(1, big.Get(917));
    }
}
