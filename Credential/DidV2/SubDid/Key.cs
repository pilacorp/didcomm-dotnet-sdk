using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Pila.CredentialSdk.DidComm.Credential.DidV2;
using BcBigInt = Org.BouncyCastle.Math.BigInteger;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2.SubDid;

public static class SubDidKey
{
    private const string KdfSalt = "subdid-keygen-v1";
    private const string KdfInfoPrefix = "subdid-key-v1";
    private const int KdfLength = 48;

    public static DidKeyPair DeriveSubDidKey(string rootPrivateKeyHex, string subId)
    {
        var root = Hex.ToBytes(rootPrivateKeyHex);
        if (root.Length != 32) throw new InvalidOperationException("subdid: root private key must be 32 bytes of hex");
        var rootScalar = new BcBigInt(1, root);
        var secpN = SecNamedCurves.GetByName("secp256k1").N;
        if (rootScalar.SignValue == 0 || rootScalar.CompareTo(secpN) >= 0)
        {
            throw new InvalidOperationException("subdid: root private key is out of range");
        }
        var id = SubDidDocument.ParseSubId(subId);
        var okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, root, KdfLength, Encoding.UTF8.GetBytes(KdfSalt), Encoding.UTF8.GetBytes(KdfInfoPrefix + id));
        var child = ReduceToP256Scalar(okm);
        var secpCurve = SecNamedCurves.GetByName("secp256k1");
        var secpDomain = new ECDomainParameters(secpCurve.Curve, secpCurve.G, secpCurve.N, secpCurve.H);
        var secpPub = secpDomain.G.Multiply(new BcBigInt(1, child)).Normalize().GetEncoded(true);
        var p256Curve = SecNamedCurves.GetByName("secp256r1") ?? SecNamedCurves.GetByName("prime256v1");
        var p256Domain = new ECDomainParameters(p256Curve!.Curve, p256Curve.G, p256Curve.N, p256Curve.H);
        var p256Pub = p256Domain.G.Multiply(new BcBigInt(1, child)).Normalize().GetEncoded(false);
        var pubHex = Hex.ToHex(secpPub);
        return new DidKeyPair
        {
            PrivateKeyHex = Hex.ToHex(child),
            PublicKeyHex = pubHex,
            Address = EthCrypto.AddressFromPublicKeyHex(pubHex),
            P256PublicKeyXy = new P256Xy
            {
                X = Convert.ToHexString(p256Pub.AsSpan(1, 32).ToArray()).ToLowerInvariant(),
                Y = Convert.ToHexString(p256Pub.AsSpan(33, 32).ToArray()).ToLowerInvariant()
            }
        };
    }

    private static byte[] ReduceToP256Scalar(byte[] okm)
    {
        var n = (SecNamedCurves.GetByName("secp256r1") ?? SecNamedCurves.GetByName("prime256v1"))!.N;
        var nMinusOne = n.Subtract(BcBigInt.One);
        var k = new BcBigInt(1, okm).Mod(nMinusOne).Add(BcBigInt.One);
        return Hex.Pad32(Hex.ToBytes(k.ToString(16)));
    }
}
