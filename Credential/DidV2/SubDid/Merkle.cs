using System.Numerics;
using Pila.CredentialSdk.DidComm.Credential.DidV2;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2.SubDid;

public static class Merkle
{
    public const int MaxLeaves = 8192;
    private const int MaxProofLen = 13;
    private const string RevokedLeafTag = "revoked";

    public static string Root(IReadOnlyList<string> leaves)
    {
        CheckLeafCount(leaves.Count);
        var level = leaves.Select(Norm32).ToList();
        while (level.Count > 1) level = NextLevel(level);
        return level[0];
    }

    public static List<string> Proof(IReadOnlyList<string> leaves, int index)
    {
        CheckLeafCount(leaves.Count);
        if (index < 0 || index >= leaves.Count)
        {
            throw new InvalidOperationException($"subdid: leaf index {index} out of range [0, {leaves.Count})");
        }
        var proof = new List<string>();
        var level = leaves.Select(Norm32).ToList();
        var i = index;
        while (level.Count > 1)
        {
            var sibling = i ^ 1;
            if (sibling < level.Count) proof.Add(level[sibling]);
            level = NextLevel(level);
            i /= 2;
        }
        return proof;
    }

    public static bool VerifyProof(string leaf, IReadOnlyList<string> path, string root)
    {
        if (path.Count > MaxProofLen) return false;
        var h = Norm32(leaf);
        foreach (var sibling in path) h = HashPair(h, sibling);
        return h == Norm32(root);
    }

    public static string RevokedLeaf(string addr)
    {
        var a = Hex.ToBytes(Hex.ToAddress(addr));
        return Hex.ToHex(EthCrypto.Keccak256(System.Text.Encoding.UTF8.GetBytes(RevokedLeafTag), a));
    }

    private static void CheckLeafCount(int n)
    {
        if (n == 0) throw new InvalidOperationException("subdid: a tree needs at least one leaf");
        if (n > MaxLeaves) throw new InvalidOperationException($"subdid: {n} leaves exceed the maximum of {MaxLeaves}");
    }

    private static List<string> NextLevel(List<string> level)
    {
        var next = new List<string>();
        for (var i = 0; i + 1 < level.Count; i += 2) next.Add(HashPair(level[i], level[i + 1]));
        if (level.Count % 2 == 1) next.Add(level[^1]);
        return next;
    }

    private static string HashPair(string a, string b)
    {
        var left = Hex.ToBytes(a);
        var right = Hex.ToBytes(b);
        if (left.AsSpan().SequenceCompareTo(right) > 0) (left, right) = (right, left);
        return Hex.ToHex(EthCrypto.Keccak256(left, right));
    }

    private static string Norm32(string h)
    {
        var hex = h.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? h : "0x" + h;
        if (hex.Length != 66) throw new InvalidOperationException($"hash is not 32 bytes: {h}");
        return hex.ToLowerInvariant();
    }
}
