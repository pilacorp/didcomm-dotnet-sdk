using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using System.Text;
using BcBigInt = Org.BouncyCastle.Math.BigInteger;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public static class EthCrypto
{
    public static byte[] Keccak256(byte[] data)
    {
        var digest = new KeccakDigest(256);
        digest.BlockUpdate(data, 0, data.Length);
        var hash = new byte[32];
        digest.DoFinal(hash, 0);
        return hash;
    }

    public static byte[] Keccak256(params byte[][] parts)
    {
        var digest = new KeccakDigest(256);
        foreach (var part in parts)
        {
            digest.BlockUpdate(part, 0, part.Length);
        }
        var hash = new byte[32];
        digest.DoFinal(hash, 0);
        return hash;
    }

    public static string Keccak256Hex(byte[] data) => Hex.ToHex(Keccak256(data));

    public static byte[] HashMessage(byte[] message)
    {
        var prefix = Encoding.UTF8.GetBytes("\u0019Ethereum Signed Message:\n" + message.Length);
        return Keccak256(Concat(prefix, message));
    }

    public static byte[] HashMessage(string message) => HashMessage(Encoding.UTF8.GetBytes(message));

    public static string AddressFromPublicKeyHex(string publicKeyHex)
    {
        var uncompressed = DecompressSecp256k1(Hex.ToBytes(publicKeyHex));
        var hash = Keccak256(uncompressed[1..]);
        return Hex.ToAddress(Hex.ToHex(hash[12..]));
    }

    public static byte[] DecompressSecp256k1(byte[] bytes)
    {
        var curve = SecNamedCurves.GetByName("secp256k1");
        if (bytes.Length == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03))
        {
            return curve.Curve.DecodePoint(bytes).GetEncoded(false);
        }
        if (bytes.Length == 65 && bytes[0] == 0x04)
        {
            return bytes;
        }
        throw new InvalidOperationException(
            $"unsupported public key format: expected 33 bytes (compressed) or 65 bytes (uncompressed), got {bytes.Length} bytes");
    }

    public static byte[] CompressSecp256k1(byte[] bytes)
    {
        var curve = SecNamedCurves.GetByName("secp256k1");
        return curve.Curve.DecodePoint(bytes).GetEncoded(true);
    }

    public static string AddressFromPrivateKey(byte[] privateKey)
    {
        var curve = SecNamedCurves.GetByName("secp256k1");
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        var q = domain.G.Multiply(new BcBigInt(1, privateKey)).Normalize().GetEncoded(false);
        return AddressFromPublicKeyHex(Hex.ToHex(q));
    }

    public static byte[] SignDigest(byte[] digest32, byte[] privateKey)
    {
        if (digest32.Length != 32)
        {
            throw new InvalidOperationException("failed to sign payload: digest must be 32 bytes");
        }
        var curve = SecNamedCurves.GetByName("secp256k1");
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        var key = new ECPrivateKeyParameters(new BcBigInt(1, privateKey), domain);
        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        signer.Init(true, key);
        var sig = signer.GenerateSignature(digest32);
        var r = sig[0];
        var s = sig[1];
        var halfN = curve.N.ShiftRight(1);
        var recId = 0;
        if (s.CompareTo(halfN) > 0)
        {
            s = curve.N.Subtract(s);
            recId ^= 1;
        }
        var rBytes = Hex.Pad32(Hex.ToBytes(r.ToString(16)));
        var sBytes = Hex.Pad32(Hex.ToBytes(s.ToString(16)));
        var pub = AddressFromPrivateKey(privateKey);
        var compact = new byte[65];
        Buffer.BlockCopy(rBytes, 0, compact, 0, 32);
        Buffer.BlockCopy(sBytes, 0, compact, 32, 32);
        for (var i = 0; i < 2; i++)
        {
            compact[64] = (byte)(27 + ((recId ^ i) & 1));
            try
            {
                if (RecoverAddress(digest32, compact) == pub)
                {
                    return compact;
                }
            }
            catch
            {
                // try the other recovery id
            }
        }
        compact[64] = (byte)(27 + (recId & 1));
        return compact;
    }

    public static string RecoverAddress(byte[] digest32, byte[] signature65)
    {
        var recId = signature65[64] >= 27 ? signature65[64] - 27 : signature65[64];
        var curve = SecNamedCurves.GetByName("secp256k1");
        var r = new BcBigInt(1, signature65, 0, 32);
        var s = new BcBigInt(1, signature65, 32, 32);
        var compressed = new byte[33];
        compressed[0] = (byte)(recId % 2 == 0 ? 0x02 : 0x03);
        var rRaw = r.ToByteArrayUnsigned();
        Buffer.BlockCopy(rRaw, 0, compressed, 33 - rRaw.Length, rRaw.Length);
        var R = curve.Curve.DecodePoint(compressed);
        var e = new BcBigInt(1, digest32);
        var rInv = r.ModInverse(curve.N);
        var sR = R.Multiply(s);
        var eG = curve.G.Multiply(e);
        var Q = sR.Subtract(eG).Multiply(rInv).Normalize();
        return AddressFromPublicKeyHex(Hex.ToHex(Q.GetEncoded(false)));
    }

    public static byte[] Packed(params byte[][] parts) => Concat(parts);

    public static byte[] Concat(params byte[][] parts)
    {
        var dest = new byte[parts.Sum(p => p.Length)];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, dest, o, p.Length);
            o += p.Length;
        }
        return dest;
    }
}
