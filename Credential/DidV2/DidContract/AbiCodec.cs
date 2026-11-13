using System.Numerics;
using System.Text;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2.DidContract;

public static class AbiCodec
{
    public static string Selector(string signature) =>
        Hex.ToHex(EthCrypto.Keccak256(Encoding.UTF8.GetBytes(signature)), prefix: false)[..8];

    public static byte[] Encode(params AbiValue[] values)
    {
        var heads = new List<byte[]>();
        var tails = new List<byte[]>();
        var dynamicCount = values.Count(v => v.Dynamic);
        var headSize = values.Length * 32;
        var tailOffset = headSize;
        foreach (var v in values)
        {
            if (!v.Dynamic)
            {
                heads.Add(v.Encoded);
                continue;
            }
            heads.Add(PadUint((ulong)tailOffset));
            tails.Add(v.Encoded);
            tailOffset += v.Encoded.Length;
        }
        return EthCrypto.Concat(heads.Concat(tails).ToArray());
    }

    public static byte[] EncodeFunction(string signature, params AbiValue[] values) =>
        EthCrypto.Concat(Hex.ToBytes(Selector(signature)), Encode(values));

    public static byte[] PadUint(BigInteger value) => Hex.Pad32(ToBe(value));
    public static byte[] PadUint(ulong value) => PadUint(new BigInteger(value));
    public static byte[] PadAddress(string addr) => Hex.Pad32(Hex.ToBytes(Hex.ToAddress(addr)));
    public static byte[] PadBytes32(byte[] value) => Hex.Pad32(value);

    public static byte[] EncodeArray(string elem, IEnumerable<string> items)
    {
        var list = items.ToList();
        var parts = new List<byte[]> { PadUint((ulong)list.Count) };
        foreach (var item in list)
        {
            parts.Add(elem switch
            {
                "address" => PadAddress(item),
                "bytes32" => PadBytes32(Hex.ToBytes(item)),
                "uint256" => PadUint(BigInteger.Parse(item)),
                _ => throw new InvalidOperationException(elem)
            });
        }
        return EthCrypto.Concat(parts.ToArray());
    }

    public static byte[] EncodeUintArray(IEnumerable<BigInteger> items)
    {
        var list = items.ToList();
        var parts = new List<byte[]> { PadUint((ulong)list.Count) };
        parts.AddRange(list.Select(PadUint));
        return EthCrypto.Concat(parts.ToArray());
    }

    public static (List<string> Dids, List<BigInteger> Indexes, List<string> Roots) DecodeWriterData(byte[] data)
    {
        if (data.Length < 96) throw new InvalidOperationException("event data too short");
        var off0 = (int)ReadUint(data, 0);
        var off1 = (int)ReadUint(data, 32);
        var off2 = (int)ReadUint(data, 64);
        var dids = ReadAddressArray(data, off0);
        var indexes = ReadUintArray(data, off1);
        var roots = ReadBytes32Array(data, off2);
        return (dids, indexes, roots);
    }

    private static BigInteger ReadUint(byte[] data, int offset) =>
        new(data.AsSpan(offset, 32).ToArray(), isUnsigned: true, isBigEndian: true);

    private static List<string> ReadAddressArray(byte[] data, int offset)
    {
        var n = (int)ReadUint(data, offset);
        var list = new List<string>(n);
        for (var i = 0; i < n; i++)
        {
            list.Add(Hex.ToAddress(Hex.ToHex(data.AsSpan(offset + 32 + i * 32, 32).ToArray())));
        }
        return list;
    }

    private static List<BigInteger> ReadUintArray(byte[] data, int offset)
    {
        var n = (int)ReadUint(data, offset);
        var list = new List<BigInteger>(n);
        for (var i = 0; i < n; i++) list.Add(ReadUint(data, offset + 32 + i * 32));
        return list;
    }

    private static List<string> ReadBytes32Array(byte[] data, int offset)
    {
        var n = (int)ReadUint(data, offset);
        var list = new List<string>(n);
        for (var i = 0; i < n; i++)
        {
            list.Add(Hex.ToHex(data.AsSpan(offset + 32 + i * 32, 32).ToArray()));
        }
        return list;
    }

    private static byte[] ToBe(BigInteger value)
    {
        if (value.Sign < 0) throw new InvalidOperationException("negative");
        var raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        return raw.Length == 0 ? [0] : raw;
    }
}

public sealed class AbiValue
{
    public bool Dynamic { get; }
    public byte[] Encoded { get; }
    public AbiValue(bool dynamic, byte[] encoded)
    {
        Dynamic = dynamic;
        Encoded = encoded;
    }

    public static AbiValue Address(string a) => new(false, AbiCodec.PadAddress(a));
    public static AbiValue Uint8(byte v) => new(false, AbiCodec.PadUint(v));
    public static AbiValue Bytes32(byte[] v) => new(false, AbiCodec.PadBytes32(v));
    public static AbiValue AddressArray(IEnumerable<string> items) => new(true, AbiCodec.EncodeArray("address", items));
    public static AbiValue UintArray(IEnumerable<BigInteger> items) => new(true, AbiCodec.EncodeUintArray(items));
    public static AbiValue Bytes32Array(IEnumerable<string> items) => new(true, AbiCodec.EncodeArray("bytes32", items));
}
