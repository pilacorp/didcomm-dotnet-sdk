using System.Numerics;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2.DidContract;

public static class LegacyTx
{
    public static (string TxHex, string TxHash) Sign(
        string to,
        ulong nonce,
        BigInteger gasPrice,
        ulong gasLimit,
        byte[] data,
        long chainId,
        IDidSigner signer)
    {
        var toBytes = Hex.ToBytes(Hex.ToAddress(to));
        var unsigned = Rlp.EncodeList(
            Rlp.EncodeInteger(nonce),
            Rlp.EncodeInteger(gasPrice),
            Rlp.EncodeInteger(gasLimit),
            Rlp.EncodeBytes(toBytes),
            Rlp.EncodeInteger(0),
            Rlp.EncodeBytes(data),
            Rlp.EncodeInteger(chainId),
            Rlp.EncodeBytes([]),
            Rlp.EncodeBytes([]));
        var digest = EthCrypto.Keccak256(unsigned);
        var sig = signer.Sign(digest);
        var recId = sig[64] >= 27 ? sig[64] - 27 : sig[64];
        var v = (int)(chainId * 2 + 35 + recId);
        var signed = Rlp.EncodeList(
            Rlp.EncodeInteger(nonce),
            Rlp.EncodeInteger(gasPrice),
            Rlp.EncodeInteger(gasLimit),
            Rlp.EncodeBytes(toBytes),
            Rlp.EncodeInteger(0),
            Rlp.EncodeBytes(data),
            Rlp.EncodeInteger(v),
            Rlp.EncodeBytes(TrimLeadingZeros(sig[..32])),
            Rlp.EncodeBytes(TrimLeadingZeros(sig[32..64])));
        return (Hex.ToHex(signed, prefix: false), Hex.ToHex(EthCrypto.Keccak256(signed)));
    }

    public static (string To, byte[] Data) Decode(byte[] rlp)
    {
        var items = Rlp.DecodeList(rlp);
        return (Hex.ToAddress(Hex.ToHex(items[3])), items[5]);
    }

    private static byte[] TrimLeadingZeros(byte[] b)
    {
        var i = 0;
        while (i < b.Length - 1 && b[i] == 0) i++;
        return b[i..];
    }
}

public static class Rlp
{
    public static byte[] EncodeBytes(byte[] data)
    {
        if (data.Length == 1 && data[0] < 0x80) return data;
        if (data.Length <= 55) return new[] { (byte)(0x80 + data.Length) }.Concat(data).ToArray();
        var len = EncodeLength(data.Length);
        return new[] { (byte)(0xb7 + len.Length) }.Concat(len).Concat(data).ToArray();
    }

    public static byte[] EncodeInteger(BigInteger value)
    {
        if (value == 0) return [0x80];
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        return EncodeBytes(bytes);
    }

    public static byte[] EncodeInteger(ulong value) => EncodeInteger(new BigInteger(value));
    public static byte[] EncodeInteger(long value) => EncodeInteger(new BigInteger(value));

    public static byte[] EncodeList(params byte[][] items)
    {
        var payload = EthCrypto.Concat(items);
        if (payload.Length <= 55) return new[] { (byte)(0xc0 + payload.Length) }.Concat(payload).ToArray();
        var len = EncodeLength(payload.Length);
        return new[] { (byte)(0xf7 + len.Length) }.Concat(len).Concat(payload).ToArray();
    }

    public static List<byte[]> DecodeList(byte[] input)
    {
        var (items, _) = Decode(input, 0);
        return items;
    }

    private static (List<byte[]> Items, int Next) Decode(byte[] input, int offset)
    {
        var prefix = input[offset];
        if (prefix < 0xc0) throw new InvalidOperationException("not a list");
        int len, payload;
        if (prefix <= 0xf7)
        {
            len = prefix - 0xc0;
            payload = offset + 1;
        }
        else
        {
            var lenOfLen = prefix - 0xf7;
            len = (int)new BigInteger(input.AsSpan(offset + 1, lenOfLen).ToArray(), isUnsigned: true, isBigEndian: true);
            payload = offset + 1 + lenOfLen;
        }
        var end = payload + len;
        var items = new List<byte[]>();
        var i = payload;
        while (i < end)
        {
            var (item, next) = DecodeItem(input, i);
            items.Add(item);
            i = next;
        }
        return (items, end);
    }

    private static (byte[] Item, int Next) DecodeItem(byte[] input, int offset)
    {
        var prefix = input[offset];
        if (prefix < 0x80) return ([prefix], offset + 1);
        if (prefix <= 0xb7)
        {
            var len = prefix - 0x80;
            return (input[(offset + 1)..(offset + 1 + len)], offset + 1 + len);
        }
        if (prefix < 0xc0)
        {
            var lenOfLen = prefix - 0xb7;
            var len = (int)new BigInteger(input.AsSpan(offset + 1, lenOfLen).ToArray(), isUnsigned: true, isBigEndian: true);
            var start = offset + 1 + lenOfLen;
            return (input[start..(start + len)], start + len);
        }
        var (list, next) = Decode(input, offset);
        return (input[offset..next], next);
    }

    private static byte[] EncodeLength(int len)
    {
        var bytes = new BigInteger(len).ToByteArray(isUnsigned: true, isBigEndian: true);
        return bytes;
    }
}
