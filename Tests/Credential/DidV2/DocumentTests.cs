using Pila.CredentialSdk.DidComm.Credential.DidV2;
using Pila.CredentialSdk.DidComm.Credential.DidV2.SubDid;
using Xunit;

namespace Pila.CredentialSdk.DidComm.Tests.Credential.DidV2;

public class DocumentTests
{
    public const string RootR1 = "did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
    public const string RootR2 = "did:nda:0x681248d5c48008ce14e5aebab76ce15476ad2509";
    public const string SubIdS1 = "0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5";
    public const string Row1PublicKeyHex = "0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7";
    public const string Row1SubDid = "did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071";
    public const string Row2PublicKeyHex = "0x03eea1acf8f417b7825a00be2bf446ef87da146f58e664f36f85f91e74d4f79dc1";
    public const string Row2SubDid = "did:nda:0x97c19e066bdaa1bc4788e3c2e6c35c7e7bfc73af";
    public const string RootConsentR1 =
        "0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c";
    public const string CreateSubDidJson =
        """{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/v1"],"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","controller":"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a","verificationMethod":[{"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","publicKeyHex":"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"}],"authentication":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"assertionMethod":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"didDocumentMetadata":{"rootConsent":"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c","subId":"0b8e6f3c-5a1d-4c27-9f40-3e2a7d91c6b5","type":"people"}}""";
    public const string CreateSubDidDocHash = "0xd40e8cdf47ef809607d4be35edfc75aa9cbc3bda443ab93c706956ecdba3d8a8";
    public const string RegisterSubDidJson =
        """{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/v1"],"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","controller":"did:nda:0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a","verificationMethod":[{"id":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1","type":"EcdsaSecp256k1VerificationKey2019","controller":"did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071","publicKeyHex":"0x03354b9ae48c3cecaf6636ba88e321847edbf450a2777a012240d6d51705de73d7"}],"authentication":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"assertionMethod":["did:nda:0x86b2efd244acb31eb238a65ca05476ab42558071#key-1"],"didDocumentMetadata":{"rootConsent":"0x45b815352a92764deec8dd6bd5f8842332f3e5548f75f803602ec99086537fb63bfa08f1ed32a03d3d33e7f455d4d78cb00877f4c8689c28f41b69dca8a5fa511c","type":"people"}}""";
    public const string RegisterSubDidDocHash = "0x0d19356dd2d8688182a95aa166b7eb0b1f5516821f06b147d50c70e3bd743eec";

    [Fact]
    public void SubDidFor_KdfRows()
    {
        Assert.Equal(Row1SubDid, SubDidDocument.SubDidFor(RootR1, Row1PublicKeyHex));
        Assert.Equal(Row2SubDid, SubDidDocument.SubDidFor(RootR1, Row2PublicKeyHex));
    }

    [Fact]
    public void ParseSubId_Refuses()
    {
        foreach (var bad in new[] { "NV-0012", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-a", "NV 00123", "NV.00123", "" })
        {
            Assert.Throws<InvalidOperationException>(() => SubDidDocument.ParseSubId(bad));
        }
    }

    [Fact]
    public void ValidateSubDid()
    {
        var ok = DidV2Document.GenerateDidDocument(Row1PublicKeyHex, Row1SubDid, "", RootR1, DidTypes.People, new Dictionary<string, object> { ["subId"] = SubIdS1 })!;
        SubDidDocument.ValidateSubDid(ok, RootR1);
        var second = DidV2Document.GenerateDidDocument(Row1PublicKeyHex, Row1SubDid, "", RootR1, DidTypes.People, null,
            DidV2Document.NewSpec(DidV2Document.NewSecp256k1Vm(Row1SubDid, "#key-2", Row2PublicKeyHex)))!;
        SubDidDocument.ValidateSubDid(second, RootR1);
        var wrong = DidV2Document.GenerateDidDocument(Row1PublicKeyHex, Row1SubDid, "", RootR1, DidTypes.People, null)!;
        wrong.Controller = RootR2;
        Assert.Throws<InvalidOperationException>(() => SubDidDocument.ValidateSubDid(wrong, RootR1));
    }

    [Fact]
    public void DocHashVectors()
    {
        Assert.Equal(CreateSubDidDocHash, SubDidDocument.DocHash(DidV2Document.ParseDidDocumentJson(CreateSubDidJson)));
        Assert.Equal(RegisterSubDidDocHash, SubDidDocument.DocHash(DidV2Document.ParseDidDocumentJson(RegisterSubDidJson)));
    }
}
