using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using U = Pila.CredentialSdk.DidComm.Credential.Common.Util.Util;

namespace Pila.CredentialSdk.DidComm.Credential.Common.SdJwt;

// Port of Go credential/common/sdjwt (types.go, disclosure.go, helper.go,
// reconstruct.go). Mirrors its behaviour: salted [salt,key,value] / [salt,value]
// disclosures, base64url-encoded, _sd digest arrays + _sd_alg, and the combined
// <jwt>~<d1>~...~<dN>~ format. Hashing is sha256/384/512 over the disclosure
// STRING, so a digest is self-consistent across SDKs that ship the same string.
//
// The in-memory JSON model is Dictionary&lt;string, object?&gt; (object) and
// List&lt;object?&gt; (array), matching Go's map[string]interface{} / []interface{}.

/// <summary>Kind of a resolved disclosure target.</summary>
public enum TargetKind
{
    ObjectField,
    ArrayContainer,
    ArrayElem,
}

/// <summary>A decoded disclosure, for Holders inspecting what they may reveal.</summary>
public sealed class DecodedDisclosure
{
    public string Disclosure { get; init; } = "";
    public string Salt { get; init; } = "";
    public string FieldName { get; init; } = "";
    public object? Value { get; init; }
    public bool IsArrayElem { get; init; }
}

/// <summary>A parsed SD-JWT at the string level.</summary>
public sealed class ParsedSdJwt
{
    public string BaseJwt { get; init; } = "";
    public List<string> Disclosures { get; init; } = new();
    public List<DecodedDisclosure> DecodedDisclosures { get; init; } = new();
}

/// <summary>Where and how many decoy digests to add.</summary>
public sealed class DecoyConfig
{
    public string Path { get; init; } = "";
    public int Count { get; init; }
}

/// <summary>Input for <see cref="SdJwt.BuildDisclosures"/>.</summary>
public sealed class BuildDisclosuresInput
{
    public Dictionary<string, object?> Vc { get; init; } = new();
    public List<string> SelectivePaths { get; init; } = new();
    public string? HashAlgorithm { get; init; }
    public bool Shuffle { get; init; }
    public List<DecoyConfig> Decoys { get; init; } = new();
}

/// <summary>Result of <see cref="SdJwt.BuildDisclosures"/>.</summary>
public sealed class SdJwtResult
{
    public Dictionary<string, object?> ProcessedVc { get; init; } = new();
    public List<string> Disclosures { get; init; } = new();
}

public static class SdJwt
{
    public const string AlgSha256 = "sha-256";
    public const string AlgSha384 = "sha-384";
    public const string AlgSha512 = "sha-512";
    public const string DefaultHashAlgorithm = AlgSha256;

    private const string SdKey = "_sd";
    private const string SdAlgKey = "_sd_alg";

    private static readonly HashSet<string> SupportedHashAlgorithms = new()
    {
        AlgSha256, AlgSha384, AlgSha512,
    };

    // ---- internal metadata --------------------------------------------------

    private sealed class DisclosureInfo
    {
        public string Salt = "";
        public string ObjectField = "";
        public object? Value;
        public bool IsArrayElem;
    }

    private sealed class ResolvedTarget
    {
        public object? Parent;          // parent container (Dictionary or List)
        public TargetKind Kind;
        public string FieldName = "";   // for object fields / array containers
        public int Index;               // for array elements
        public object? Value;           // value at this location
    }

    private readonly struct PathSegment
    {
        public readonly string Key;
        public readonly int? Index;
        public PathSegment(string key, int? index)
        {
            Key = key;
            Index = index;
        }
    }

    // =========================================================================
    // Issue: BuildDisclosures
    // =========================================================================

    public static SdJwtResult BuildDisclosures(BuildDisclosuresInput input)
    {
        var (sdAlg, shuffle) = ValidateAndGetDefaults(input);

        var processedVc = DeepCopyMap(input.Vc);

        // Decoys require _sd_alg even with no selective paths.
        if (input.Decoys.Count > 0)
        {
            processedVc[SdAlgKey] = sdAlg;
        }

        if (input.SelectivePaths.Count == 0 && input.Decoys.Count == 0)
        {
            return new SdJwtResult { ProcessedVc = processedVc, Disclosures = new List<string>() };
        }

        if (input.SelectivePaths.Count > 0)
        {
            processedVc[SdAlgKey] = sdAlg;
        }

        var disclosures = ProcessSelectivePaths(processedVc, input.SelectivePaths, sdAlg);
        ProcessDecoys(processedVc, input.Decoys, sdAlg);

        if (shuffle)
        {
            ShuffleSdArrays(processedVc);
        }

        return new SdJwtResult { ProcessedVc = processedVc, Disclosures = disclosures };
    }

    private static (string sdAlg, bool shuffle) ValidateAndGetDefaults(BuildDisclosuresInput input)
    {
        var sdAlg = string.IsNullOrEmpty(input.HashAlgorithm) ? DefaultHashAlgorithm : input.HashAlgorithm!;
        if (!SupportedHashAlgorithms.Contains(sdAlg))
        {
            throw new InvalidOperationException($"unsupported hash algorithm \"{sdAlg}\"");
        }
        return (sdAlg, input.Shuffle);
    }

    private static List<string> ProcessSelectivePaths(Dictionary<string, object?> vc, List<string> paths, string sdAlg)
    {
        var disclosures = new List<string>();
        foreach (var raw in paths)
        {
            var path = raw.Trim();
            if (path.Length == 0)
            {
                throw new InvalidOperationException("empty path");
            }
            disclosures.Add(ProcessSinglePath(vc, path, sdAlg));
        }
        return disclosures;
    }

    private static string ProcessSinglePath(Dictionary<string, object?> vc, string path, string sdAlg)
    {
        var resolved = ResolvePath(vc, path);
        if (resolved == null)
        {
            throw new InvalidOperationException($"path \"{path}\" not found");
        }
        return BuildAndApplyDisclosure(resolved, sdAlg);
    }

    private static string BuildAndApplyDisclosure(ResolvedTarget resolved, string sdAlg)
    {
        var salt = RandomSalt();
        var disclosureArr = BuildDisclosureArray(resolved, salt);
        var disclosureJson = JsonSerializer.Serialize(disclosureArr);
        var encoded = U.Base64UrlEncode(Encoding.UTF8.GetBytes(disclosureJson));
        var digest = HashDisclosure(sdAlg, encoded);
        ApplyDisclosureToVc(resolved, digest);
        return encoded;
    }

    private static List<object?> BuildDisclosureArray(ResolvedTarget resolved, string salt) => resolved.Kind switch
    {
        TargetKind.ObjectField or TargetKind.ArrayContainer => new List<object?> { salt, resolved.FieldName, resolved.Value },
        TargetKind.ArrayElem => new List<object?> { salt, resolved.Value },
        _ => new List<object?>(),
    };

    private static void ApplyDisclosureToVc(ResolvedTarget resolved, string digest)
    {
        switch (resolved.Kind)
        {
            case TargetKind.ObjectField:
            case TargetKind.ArrayContainer:
                if (resolved.Parent is not Dictionary<string, object?> m)
                {
                    throw new InvalidOperationException("parent is not a map");
                }
                AppendSd(m, digest);
                m.Remove(resolved.FieldName);
                break;
            case TargetKind.ArrayElem:
                if (resolved.Parent is not List<object?> arr)
                {
                    throw new InvalidOperationException("parent is not an array");
                }
                arr[resolved.Index] = new Dictionary<string, object?> { ["..."] = digest };
                break;
            default:
                throw new InvalidOperationException($"unexpected kind {resolved.Kind}");
        }
    }

    private static void AppendSd(Dictionary<string, object?> m, string digest)
    {
        if (m.TryGetValue(SdKey, out var existing) && existing is List<object?> list)
        {
            list.Add(digest);
        }
        else
        {
            m[SdKey] = new List<object?> { digest };
        }
    }

    // ---- decoys -------------------------------------------------------------

    private static void ProcessDecoys(Dictionary<string, object?> vc, List<DecoyConfig> decoys, string sdAlg)
    {
        foreach (var decoy in decoys)
        {
            if (decoy.Count <= 0)
            {
                continue;
            }
            var hashes = GenerateDecoyHashes(sdAlg, decoy.Count);
            ApplyDecoyToVc(vc, decoy.Path, hashes);
        }
    }

    private static void ApplyDecoyToVc(Dictionary<string, object?> vc, string path, List<string> hashes)
    {
        var resolved = ResolvePath(vc, path);
        if (resolved == null)
        {
            return;
        }
        switch (resolved.Kind)
        {
            case TargetKind.ObjectField:
            {
                var target = resolved.Value as Dictionary<string, object?>
                             ?? resolved.Parent as Dictionary<string, object?>
                             ?? throw new InvalidOperationException("decoy target is not an object");
                foreach (var h in hashes)
                {
                    AppendSd(target, h);
                }
                break;
            }
            case TargetKind.ArrayContainer:
            {
                if (resolved.Value is not List<object?> arr)
                {
                    throw new InvalidOperationException("decoy target value is not an array");
                }
                foreach (var h in hashes)
                {
                    arr.Add(new Dictionary<string, object?> { ["..."] = h });
                }
                break;
            }
            case TargetKind.ArrayElem:
            {
                if (resolved.Parent is not List<object?> arr)
                {
                    throw new InvalidOperationException("decoy target parent is not an array");
                }
                foreach (var h in hashes)
                {
                    arr.Add(new Dictionary<string, object?> { ["..."] = h });
                }
                break;
            }
        }
    }

    private static List<string> GenerateDecoyHashes(string sdAlg, int count)
    {
        var hashes = new List<string>(count);
        for (var i = 0; i < count; i++)
        {
            hashes.Add(HashDisclosure(sdAlg, RandomSalt()));
        }
        return hashes;
    }

    private static void ShuffleSdArrays(object? node)
    {
        switch (node)
        {
            case Dictionary<string, object?> v:
                if (v.TryGetValue(SdKey, out var sd) && sd is List<object?> sdList)
                {
                    for (var i = sdList.Count - 1; i > 0; i--)
                    {
                        var j = RandomNumberGenerator.GetInt32(i + 1);
                        (sdList[i], sdList[j]) = (sdList[j], sdList[i]);
                    }
                }
                foreach (var val in v.Values)
                {
                    ShuffleSdArrays(val);
                }
                break;
            case List<object?> arr:
                foreach (var elem in arr)
                {
                    ShuffleSdArrays(elem);
                }
                break;
        }
    }

    // =========================================================================
    // Path resolution
    // =========================================================================

    private static ResolvedTarget? ResolvePath(Dictionary<string, object?> root, string path)
    {
        if (path.Length == 0)
        {
            return new ResolvedTarget { Parent = root, Kind = TargetKind.ObjectField };
        }

        var segs = ParsePath(path);
        if (segs.Count == 0)
        {
            return new ResolvedTarget { Parent = root, Kind = TargetKind.ObjectField };
        }

        object? current = root;
        for (var i = 0; i < segs.Count; i++)
        {
            var seg = segs[i];
            var last = i == segs.Count - 1;

            if (seg.Index == null)
            {
                if (current is not Dictionary<string, object?> m)
                {
                    throw new InvalidOperationException($"segment \"{seg.Key}\" expects object");
                }
                if (!m.TryGetValue(seg.Key, out var val))
                {
                    return null;
                }
                if (last)
                {
                    if (val is List<object?> listVal)
                    {
                        return new ResolvedTarget { Parent = m, Kind = TargetKind.ArrayContainer, FieldName = seg.Key, Value = listVal };
                    }
                    return new ResolvedTarget { Parent = m, Kind = TargetKind.ObjectField, FieldName = seg.Key, Value = val };
                }
                current = val;
                continue;
            }

            var arr = ResolveArray(current, seg);
            if (arr == null)
            {
                return null;
            }
            var idx = seg.Index.Value;
            if (idx < 0 || idx >= arr.Count)
            {
                throw new InvalidOperationException($"index {idx} out of range (len {arr.Count}) for path \"{path}\"");
            }
            if (last)
            {
                return new ResolvedTarget { Parent = arr, Kind = TargetKind.ArrayElem, Index = idx, Value = arr[idx] };
            }
            current = arr[idx];
        }

        return null;
    }

    private static List<object?>? ResolveArray(object? current, PathSegment seg)
    {
        if (seg.Key.Length != 0)
        {
            if (current is not Dictionary<string, object?> m)
            {
                throw new InvalidOperationException($"segment \"{seg.Key}\" expects object");
            }
            if (!m.TryGetValue(seg.Key, out var raw))
            {
                return null;
            }
            if (raw is not List<object?> arr)
            {
                throw new InvalidOperationException($"segment \"{seg.Key}\" expects array");
            }
            return arr;
        }
        if (current is not List<object?> list)
        {
            throw new InvalidOperationException($"segment [{seg.Index}] expects array");
        }
        return list;
    }

    private static List<PathSegment> ParsePath(string path)
    {
        var segs = new List<PathSegment>();
        foreach (var rawPart in path.Split('.'))
        {
            var p = rawPart.Trim();
            if (p.Length == 0)
            {
                continue;
            }
            var bracketIdx = p.IndexOf('[');
            if (bracketIdx == -1)
            {
                segs.Add(new PathSegment(p, null));
                continue;
            }
            var key = p[..bracketIdx];
            var rest = p[bracketIdx..];
            if (!rest.EndsWith("]"))
            {
                throw new InvalidOperationException($"invalid array segment \"{p}\" in path \"{path}\"");
            }
            var idxStr = rest[1..^1];
            if (idxStr.Length == 0)
            {
                throw new InvalidOperationException($"empty index in path \"{path}\"");
            }
            if (idxStr == "*")
            {
                throw new InvalidOperationException($"wildcard index '*' is not supported in path \"{path}\"");
            }
            if (!int.TryParse(idxStr, out var idx))
            {
                throw new InvalidOperationException($"invalid index \"{idxStr}\" in path \"{path}\"");
            }
            segs.Add(new PathSegment(key, idx));
        }
        return segs;
    }

    // =========================================================================
    // Parse / serialize combined format
    // =========================================================================

    public static bool IsSdJwt(string raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return false;
        }
        var s = raw.Trim().Trim('"');
        if (!s.Contains('~'))
        {
            return false;
        }
        var idx = s.IndexOf('~');
        return IsJwt(s[..idx]);
    }

    public static ParsedSdJwt Parse(string raw)
    {
        if (!IsSdJwt(raw))
        {
            throw new InvalidOperationException("invalid SD-JWT format");
        }
        var s = raw.Trim().Trim('"');
        var parts = s.Split('~');
        if (parts.Length < 2)
        {
            throw new InvalidOperationException("invalid SD-JWT: missing disclosures or terminator");
        }

        var issuer = parts[0];
        var disclosures = new List<string>();
        for (var i = 1; i < parts.Length; i++)
        {
            var seg = parts[i].Trim();
            if (seg.Length == 0)
            {
                continue;
            }
            // A trailing JWT in the last slot (after ≥1 disclosure) is a key-binding
            // JWT. Go refuses it until verified rather than silently skipping; so do we.
            if (i == parts.Length - 1 && IsJwt(seg) && i > 1)
            {
                throw new InvalidOperationException(
                    "SD-JWT carries a key binding JWT, which this SDK does not verify yet; present the credential without it");
            }
            disclosures.Add(seg);
        }

        var decoded = ParseDisclosures(disclosures);
        return new ParsedSdJwt { BaseJwt = issuer, Disclosures = disclosures, DecodedDisclosures = decoded };
    }

    public static string BuildSdJwtPresentation(string issuerSignedJwt, IEnumerable<string> selectedDisclosures)
    {
        var sb = new StringBuilder(issuerSignedJwt);
        foreach (var sel in selectedDisclosures)
        {
            if (string.IsNullOrEmpty(sel))
            {
                continue;
            }
            sb.Append('~').Append(sel);
        }
        sb.Append('~'); // trailing ~ terminates the combined format (draft §4)
        return sb.ToString();
    }

    public static List<DecodedDisclosure> DecodeDisclosures(IEnumerable<string> disclosures) =>
        ParseDisclosures(disclosures);

    private static List<DecodedDisclosure> ParseDisclosures(IEnumerable<string> disclosures)
    {
        var result = new List<DecodedDisclosure>();
        foreach (var disc in disclosures)
        {
            if (string.IsNullOrEmpty(disc))
            {
                continue;
            }
            var info = ParseDisclosure(disc);
            result.Add(new DecodedDisclosure
            {
                Disclosure = disc,
                Salt = info.Salt,
                FieldName = info.ObjectField,
                Value = info.Value,
                IsArrayElem = info.IsArrayElem,
            });
        }
        return result;
    }

    private static DisclosureInfo ParseDisclosure(string disc)
    {
        byte[] decoded;
        try
        {
            decoded = U.Base64UrlDecode(disc);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"failed to decode disclosure \"{disc}\": {ex.Message}");
        }

        object? parsed;
        try
        {
            using var doc = JsonDocument.Parse(decoded);
            parsed = Normalize(doc.RootElement);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"failed to unmarshal disclosure: {ex.Message}");
        }

        if (parsed is not List<object?> arr || (arr.Count != 2 && arr.Count != 3))
        {
            var n = parsed is List<object?> l ? l.Count : -1;
            throw new InvalidOperationException($"invalid disclosure structure: expected 2 or 3 elements, got {n}");
        }

        if (arr[0] is not string salt)
        {
            throw new InvalidOperationException("disclosure salt must be a string");
        }

        if (arr.Count == 3)
        {
            if (arr[1] is not string name)
            {
                throw new InvalidOperationException("disclosure field name must be a string");
            }
            return new DisclosureInfo { Salt = salt, ObjectField = name, Value = arr[2], IsArrayElem = false };
        }
        return new DisclosureInfo { Salt = salt, Value = arr[1], IsArrayElem = true };
    }

    // =========================================================================
    // Reconstruct (security-critical)
    // =========================================================================

    public static Dictionary<string, object?> Reconstruct(
        Dictionary<string, object?> vcMap, IEnumerable<string> disclosures, bool validateAlg)
    {
        var sdAlg = ValidateAndGetAlgorithm(vcMap, validateAlg);
        var disclosureMap = BuildDisclosureMap(disclosures, sdAlg);

        var rootCopy = DeepCopyMap(vcMap);
        var used = new HashSet<string>();
        var processed = ProcessNode(rootCopy, disclosureMap, used);

        // §7.1 step 5: every disclosure must be referenced by a digest in the payload.
        foreach (var digest in disclosureMap.Keys)
        {
            if (!used.Contains(digest))
            {
                throw new InvalidOperationException(
                    $"disclosure for digest \"{digest}\" matches nothing in the payload; it was not part of what the issuer signed");
            }
        }

        if (processed is not Dictionary<string, object?> result)
        {
            throw new InvalidOperationException("processed payload is not an object");
        }
        result.Remove(SdAlgKey);
        return result;
    }

    private static string ValidateAndGetAlgorithm(Dictionary<string, object?> vcMap, bool validateAlg)
    {
        var sdAlg = DefaultHashAlgorithm;
        if (vcMap.TryGetValue(SdAlgKey, out var v) && v is string s && s.Length != 0)
        {
            sdAlg = s;
        }
        if (validateAlg && !SupportedHashAlgorithms.Contains(sdAlg))
        {
            throw new InvalidOperationException($"unsupported _sd_alg: \"{sdAlg}\"");
        }
        return sdAlg;
    }

    private static Dictionary<string, DisclosureInfo> BuildDisclosureMap(IEnumerable<string> disclosures, string sdAlg)
    {
        var map = new Dictionary<string, DisclosureInfo>();
        foreach (var disc in disclosures)
        {
            if (string.IsNullOrEmpty(disc))
            {
                continue;
            }
            var h = HashDisclosure(sdAlg, disc);
            var info = ParseDisclosure(disc);
            // §7.1 step 4: a digest encountered more than once is rejected.
            if (map.ContainsKey(h))
            {
                throw new InvalidOperationException($"disclosure for digest \"{h}\" was sent more than once");
            }
            map[h] = info;
        }
        return map;
    }

    private static object? ProcessNode(object? node, Dictionary<string, DisclosureInfo> disclosureMap, HashSet<string> used)
    {
        switch (node)
        {
            case Dictionary<string, object?> v:
            {
                // Process issuer-written fields first (snapshot keys: we reassign
                // existing keys here and only add new keys via _sd afterwards).
                foreach (var key in v.Keys.ToList())
                {
                    if (key == SdKey)
                    {
                        continue;
                    }
                    v[key] = ProcessNode(v[key], disclosureMap, used);
                }

                if (v.TryGetValue(SdKey, out var rawSd))
                {
                    if (rawSd is not List<object?> sdList)
                    {
                        throw new InvalidOperationException($"_sd must be an array of digests, got {rawSd?.GetType().Name ?? "null"}");
                    }
                    var hashes = new List<string>(sdList.Count);
                    foreach (var item in sdList)
                    {
                        if (item is string sh)
                        {
                            hashes.Add(sh);
                        }
                    }
                    ApplySdHashes(hashes, v, disclosureMap, new HashSet<string>(), used);
                    v.Remove(SdKey);
                }
                return v;
            }
            case List<object?> arr:
            {
                var outList = new List<object?>();
                var arrayDigests = new HashSet<string>();
                foreach (var elem in arr)
                {
                    if (elem is Dictionary<string, object?> m && m.Count == 1 && m.TryGetValue("...", out var rawHash))
                    {
                        if (rawHash is string h)
                        {
                            if (!arrayDigests.Add(h))
                            {
                                throw new InvalidOperationException($"duplicate digest \"{h}\" found in array");
                            }
                            // Payload-wide §7.1 step 4 count (before the lookup).
                            if (!used.Add(h))
                            {
                                throw new InvalidOperationException($"digest \"{h}\" is referenced more than once in the payload");
                            }
                            if (!disclosureMap.TryGetValue(h, out var info))
                            {
                                // Placeholder without disclosure: keep to preserve structure.
                                outList.Add(new Dictionary<string, object?> { ["..."] = h });
                                continue;
                            }
                            if (!info.IsArrayElem)
                            {
                                throw new InvalidOperationException("object field disclosure used in array context");
                            }
                            outList.Add(ProcessNode(info.Value, disclosureMap, used));
                            continue;
                        }
                    }
                    outList.Add(ProcessNode(elem, disclosureMap, used));
                }
                return outList;
            }
            default:
                return node;
        }
    }

    private static void ApplySdHashes(
        List<string> hashes, Dictionary<string, object?> v,
        Dictionary<string, DisclosureInfo> disclosureMap, HashSet<string> objectDigests, HashSet<string> used)
    {
        foreach (var h in hashes)
        {
            if (!objectDigests.Add(h))
            {
                throw new InvalidOperationException($"duplicate digest \"{h}\" found in _sd array");
            }
            // §7.1 step 4: counted across the whole payload, before the lookup.
            if (!used.Add(h))
            {
                throw new InvalidOperationException($"digest \"{h}\" is referenced more than once in the payload");
            }
            if (!disclosureMap.TryGetValue(h, out var info))
            {
                // Unrevealed digest or decoy.
                continue;
            }
            if (info.IsArrayElem || info.ObjectField.Length == 0)
            {
                throw new InvalidOperationException("array element disclosure used in object context");
            }
            if (v.ContainsKey(info.ObjectField))
            {
                throw new InvalidOperationException($"duplicate field \"{info.ObjectField}\" when reconstructing SD-JWT object");
            }
            v[info.ObjectField] = ProcessNode(info.Value, disclosureMap, used);
        }
    }

    // =========================================================================
    // helpers: hashing, salt, deep copy, normalization, isJWT
    // =========================================================================

    private static string HashDisclosure(string sdAlg, string disclosure)
    {
        var bytes = Encoding.UTF8.GetBytes(disclosure);
        byte[] sum = sdAlg switch
        {
            AlgSha256 => SHA256.HashData(bytes),
            AlgSha384 => SHA384.HashData(bytes),
            AlgSha512 => SHA512.HashData(bytes),
            _ => throw new InvalidOperationException($"unsupported sd_alg \"{sdAlg}\""),
        };
        return U.Base64UrlEncode(sum);
    }

    private static string RandomSalt()
    {
        var buf = new byte[16];
        RandomNumberGenerator.Fill(buf);
        return U.Base64UrlEncode(buf);
    }

    private static Dictionary<string, object?> DeepCopyMap(Dictionary<string, object?> src)
    {
        var dst = new Dictionary<string, object?>(src.Count);
        foreach (var kvp in src)
        {
            dst[kvp.Key] = DeepCopyValue(kvp.Value);
        }
        return dst;
    }

    private static object? DeepCopyValue(object? v) => v switch
    {
        Dictionary<string, object?> m => DeepCopyMap(m),
        List<object?> list => list.Select(DeepCopyValue).ToList(),
        _ => v,
    };

    // JsonElement -> Dictionary/List/string/long/double/bool/null, matching Go's
    // json.Unmarshal shapes so ProcessNode's type switches work.
    private static object? Normalize(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.Object => el.EnumerateObject().ToDictionary(p => p.Name, p => Normalize(p.Value)),
        JsonValueKind.Array => el.EnumerateArray().Select(Normalize).ToList(),
        JsonValueKind.String => el.GetString(),
        JsonValueKind.Number => el.TryGetInt64(out var l) ? l : el.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null,
    };

    private static bool IsJwt(string s)
    {
        s = s.Trim().TrimEnd('.');
        var parts = s.Split('.');
        if (parts.Length is < 2 or > 3)
        {
            return false;
        }
        foreach (var part in parts)
        {
            if (part.Length == 0 || !part.All(c =>
                    c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
            {
                return false;
            }
        }
        return true;
    }

    // Normalizes an arbitrary parsed JSON object into the Dictionary/List model.
    public static Dictionary<string, object?> NormalizeObject(JsonElement obj)
    {
        if (Normalize(obj) is Dictionary<string, object?> d)
        {
            return d;
        }
        throw new InvalidOperationException("expected a JSON object");
    }
}
