using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Pila.CredentialSdk.DidComm.Credential.Common.EcdsaSd;

/// <summary>
/// ECDSA-SD (ecdsa-sd-2023) selective-disclosure Data Integrity cryptosuite.
/// Faithful port of the Go credential/common/ecdsasd package (base proof
/// creation, derive/disclosure, verify) validated byte-for-byte against the
/// W3C vc-di-ecdsa worked example.
///
/// Documents are represented as Newtonsoft <see cref="JObject"/>. Issuer keys
/// are P-256 (base signature); per-statement ephemeral keys are always P-256.
/// </summary>
public static class EcdsaSd
{
    public const string Cryptosuite = "ecdsa-sd-2023";

    private static readonly byte[] BaseProofHeader = { 0xd9, 0x5d, 0x00 };
    private static readonly byte[] DerivedProofHeader = { 0xd9, 0x5d, 0x01 };
    private static readonly byte[] P256PubMulticodec = { 0x80, 0x24 }; // p256-pub 0x1200
    private static readonly byte[] P256PrivMulticodec = { 0x86, 0x26 }; // p256-priv 0x1306

    private static readonly Regex UrnBnidRe = new(@"<urn:bnid:([^>]+)>", RegexOptions.Compiled);
    private static readonly Regex BnodeRe = new(@"_:([^\s]+)", RegexOptions.Compiled);

    // ---------------------------------------------------------------- public API

    /// <summary>
    /// Produces an ecdsa-sd-2023 base proof value over <paramref name="document"/>.
    /// <paramref name="proofConfig"/> holds the proof options (type/cryptosuite/
    /// created/verificationMethod/proofPurpose) plus the securing document's
    /// @context, without proofValue. <paramref name="mandatoryPointers"/> are JSON
    /// Pointers the issuer forces to always be disclosed. Signs with the issuer's
    /// P-256 private key (raw 32-byte scalar hex). Uses fresh randomness.
    /// </summary>
    public static string CreateBaseProof(JObject document, JObject proofConfig, string[] mandatoryPointers, string issuerPrivHex)
    {
        var hmacKey = RandomNumberGenerator.GetBytes(32);
        var eph = GenerateP256();
        var ephPub = PubToMultikeyBytes(eph.Pub);
        return BuildBaseProof(document, proofConfig, mandatoryPointers, hmacKey, ephPub,
            nq => SignEphemeral(eph, nq, deterministic: false),
            digest => P256Signer.Sign(digest, issuerPrivHex));
    }

    /// <summary>
    /// Deterministic (RFC 6979, raw S) variant used to reproduce a base proof
    /// value byte-for-byte from fixed randomness (W3C conformance). Production
    /// issuance uses <see cref="CreateBaseProof"/>.
    /// </summary>
    public static string CreateBaseProofDeterministic(JObject document, JObject proofConfig, string[] mandatoryPointers,
        byte[] hmacKey, string ephemeralPrivHex, string issuerPrivHex)
    {
        var eph = P256FromPrivHex(ephemeralPrivHex);
        var ephPub = PubToMultikeyBytes(eph.Pub);
        return BuildBaseProof(document, proofConfig, mandatoryPointers, hmacKey, ephPub,
            nq => SignEphemeral(eph, nq, deterministic: true),
            digest => SignDeterministic(issuerPrivHex, digest));
    }

    /// <summary>
    /// Produces a revealed document plus a derived (disclosure) proof value,
    /// revealing the mandatory statements plus those addressed by
    /// <paramref name="selectivePointers"/>. The base credential is not modified.
    /// </summary>
    public static (JObject RevealDoc, string ProofValue) DeriveProof(JObject document, string baseProofValue, string[] selectivePointers)
    {
        var dd = CreateDisclosureData(document, baseProofValue, selectivePointers);
        var proofValue = SerializeDisclosureProofValue(dd.BaseSignature, dd.PublicKey, dd.Signatures, dd.LabelMap, dd.MandatoryIndexes);
        return (dd.RevealDoc, proofValue);
    }

    /// <summary>
    /// Verifies an ecdsa-sd-2023 proof against the issuer's P-256 public key,
    /// routing on the proof value header: base proof (0xd95d00) over the full
    /// document, or derived proof (0xd95d01) over a revealed document. Throws on
    /// failure.
    /// </summary>
    public static void VerifyProof(JObject document, JObject proofConfig, string proofValue, ECPublicKeyParameters issuerPub)
    {
        if (TryDecodeProofValue(proofValue, BaseProofHeader, out _))
        {
            VerifyBaseProof(document, proofConfig, proofValue, issuerPub);
            return;
        }
        if (TryDecodeProofValue(proofValue, DerivedProofHeader, out _))
        {
            VerifyDerivedProof(document, proofConfig, proofValue, issuerPub);
            return;
        }
        throw new InvalidOperationException("ecdsasd: unrecognized proof value header");
    }

    // ------------------------------------------------------------- base producer

    private static string BuildBaseProof(JObject document, JObject proofConfig, string[] mandatoryPointers,
        byte[] hmacKey, byte[] ephPubMultikey, Func<string, byte[]> signStatement, Func<byte[], byte[]> issuerSign)
    {
        var proofHash = HashProofConfig(proofConfig);
        var grouped = CanonicalizeAndGroup(document, hmacKey, new() { ["mandatory"] = mandatoryPointers });
        var mg = grouped.Groups["mandatory"];
        var nonMandatory = OrderedValues(mg.NonMatching);
        var mandatoryHash = HashMandatory(mg.Matching);

        var signatures = nonMandatory.Select(signStatement).ToList();

        var toSign = Concat(proofHash, ephPubMultikey, mandatoryHash);
        var baseSig = issuerSign(Sha256(toSign));

        return SerializeBaseProofValue(baseSig, ephPubMultikey, hmacKey, signatures, mandatoryPointers);
    }

    // ------------------------------------------------------------ derive/disclose

    private sealed class DisclosureData
    {
        public byte[] BaseSignature = Array.Empty<byte>();
        public byte[] PublicKey = Array.Empty<byte>();
        public List<byte[]> Signatures = new();
        public Dictionary<string, string> LabelMap = new();
        public List<int> MandatoryIndexes = new();
        public JObject RevealDoc = new();
    }

    private static DisclosureData CreateDisclosureData(JObject document, string baseProofValue, string[] selectivePointers)
    {
        var bp = ParseBaseProofValue(baseProofValue);

        var combined = bp.MandatoryPointers.Concat(selectivePointers).ToArray();
        var grouped = CanonicalizeAndGroup(document, bp.HMACKey, new()
        {
            ["mandatory"] = bp.MandatoryPointers,
            ["selective"] = selectivePointers,
            ["combined"] = combined
        });
        var mandatoryGroup = grouped.Groups["mandatory"];
        var selectiveGroup = grouped.Groups["selective"];
        var combinedGroup = grouped.Groups["combined"];

        // Convert absolute mandatory indexes to relative indexes within combined.
        var mandatoryIndexes = new List<int>();
        var combinedSorted = SortedIndexes(combinedGroup.Matching);
        for (int rel = 0; rel < combinedSorted.Count; rel++)
        {
            if (mandatoryGroup.Matching.ContainsKey(combinedSorted[rel]))
            {
                mandatoryIndexes.Add(rel);
            }
        }

        // Filter base signatures to non-mandatory quads that are selectively disclosed.
        var filtered = new List<byte[]>();
        int index = 0;
        foreach (var sig in bp.Signatures)
        {
            while (mandatoryGroup.Matching.ContainsKey(index))
            {
                index++;
            }
            if (selectiveGroup.Matching.ContainsKey(index))
            {
                filtered.Add(sig);
            }
            index++;
        }

        var revealDoc = SelectJsonLd(document, combined)
            ?? throw new InvalidOperationException("ecdsasd: no statements to reveal; provide mandatory or selective pointers");

        // Canonicalize the combined group's deskolemized N-Quads to the labels the
        // verifier will see, then map verifier canonical labels -> HMAC labels.
        var (_, rawIdMap) = SdJsonLd.CanonicalizeNQuadsWithIdMap(combinedGroup.DeskolemizedNQuads);
        var verifierLabelMap = new Dictionary<string, string>();
        foreach (var kv in rawIdMap)
        {
            // kv.Key = input label (skolem label), kv.Value = verifier canonical label.
            verifierLabelMap[kv.Value] = grouped.LabelMap[kv.Key];
        }

        return new DisclosureData
        {
            BaseSignature = bp.BaseSignature,
            PublicKey = bp.PublicKey,
            Signatures = filtered,
            LabelMap = verifierLabelMap,
            MandatoryIndexes = mandatoryIndexes,
            RevealDoc = revealDoc
        };
    }

    // --------------------------------------------------------------------- verify

    private static void VerifyBaseProof(JObject document, JObject proofConfig, string baseProofValue, ECPublicKeyParameters issuerPub)
    {
        var bp = ParseBaseProofValue(baseProofValue);
        var ephPub = EcPubFromMultikeyBytes(bp.PublicKey);

        var grouped = CanonicalizeAndGroup(document, bp.HMACKey, new() { ["mandatory"] = bp.MandatoryPointers });
        var mg = grouped.Groups["mandatory"];
        var nonMandatory = OrderedValues(mg.NonMatching);
        var mandatoryHash = HashMandatory(mg.Matching);

        var proofHash = HashProofConfig(proofConfig);
        var signData = Concat(proofHash, bp.PublicKey, mandatoryHash);
        if (!EcdsaRawVerifier.Verify(issuerPub, Sha256(signData), bp.BaseSignature))
        {
            throw new InvalidOperationException("ecdsasd: issuer base signature invalid");
        }

        if (bp.Signatures.Count != nonMandatory.Count)
        {
            throw new InvalidOperationException(
                $"ecdsasd: signature count {bp.Signatures.Count} != non-mandatory quads {nonMandatory.Count}");
        }
        for (int i = 0; i < nonMandatory.Count; i++)
        {
            if (!EcdsaRawVerifier.Verify(ephPub, Sha256(Encoding.UTF8.GetBytes(nonMandatory[i])), bp.Signatures[i]))
            {
                throw new InvalidOperationException($"ecdsasd: non-mandatory statement signature invalid: {nonMandatory[i]}");
            }
        }
    }

    private static void VerifyDerivedProof(JObject revealDoc, JObject proofConfig, string derivedProofValue, ECPublicKeyParameters issuerPub)
    {
        var dp = ParseDisclosureProofValue(derivedProofValue);
        var ephPub = EcPubFromMultikeyBytes(dp.PublicKey);

        var (canonicalNQuads, _) = SdJsonLd.CanonicalizeWithIdMap(revealDoc);
        var relabeled = RelabelBlankNodes(canonicalNQuads, dp.LabelMap);
        relabeled.Sort(StringComparer.Ordinal);

        var mandatorySet = new HashSet<int>(dp.MandatoryIndexes);
        var mandatory = new List<string>();
        var nonMandatory = new List<string>();
        for (int i = 0; i < relabeled.Count; i++)
        {
            if (mandatorySet.Contains(i))
            {
                mandatory.Add(relabeled[i]);
            }
            else
            {
                nonMandatory.Add(relabeled[i]);
            }
        }

        var proofHash = HashProofConfig(proofConfig);
        var mandatoryHash = Sha256(Encoding.UTF8.GetBytes(string.Concat(mandatory)));

        var signData = Concat(proofHash, dp.PublicKey, mandatoryHash);
        if (!EcdsaRawVerifier.Verify(issuerPub, Sha256(signData), dp.BaseSignature))
        {
            throw new InvalidOperationException("ecdsasd: issuer base signature invalid");
        }

        if (dp.Signatures.Count != nonMandatory.Count)
        {
            throw new InvalidOperationException(
                $"ecdsasd: signature count {dp.Signatures.Count} != non-mandatory quads {nonMandatory.Count}");
        }
        for (int i = 0; i < nonMandatory.Count; i++)
        {
            if (!EcdsaRawVerifier.Verify(ephPub, Sha256(Encoding.UTF8.GetBytes(nonMandatory[i])), dp.Signatures[i]))
            {
                throw new InvalidOperationException($"ecdsasd: non-mandatory statement signature invalid: {nonMandatory[i]}");
            }
        }
    }

    // ------------------------------------------------------- canonicalize & group

    private sealed class GroupIndexes
    {
        public Dictionary<int, string> Matching = new();
        public Dictionary<int, string> NonMatching = new();
        public List<string> DeskolemizedNQuads = new();
    }

    private sealed class GroupedCanon
    {
        public List<string> HmacNQuads = new();
        public Dictionary<string, string> LabelMap = new();
        public JObject SkolemizedCompact = new();
        public Dictionary<string, GroupIndexes> Groups = new();
    }

    private static GroupedCanon CanonicalizeAndGroup(JObject document, byte[] hmacKey, Dictionary<string, string[]> groups)
    {
        var (expanded, compact) = SkolemizeCompactJsonLd(document);
        var deskolemized = ToDeskolemizedNQuads(expanded);
        var (hmacNQuads, labelMap) = LabelReplacementCanonicalizeNQuads(deskolemized, hmacKey);

        var result = new GroupedCanon
        {
            HmacNQuads = hmacNQuads,
            LabelMap = labelMap,
            SkolemizedCompact = compact
        };

        foreach (var (name, pointers) in groups)
        {
            var (deskolemizedSel, selNQuads) = SelectCanonicalNQuads(compact, pointers, labelMap);
            var selSet = new HashSet<string>(selNQuads);
            var gi = new GroupIndexes { DeskolemizedNQuads = deskolemizedSel };
            for (int idx = 0; idx < hmacNQuads.Count; idx++)
            {
                if (selSet.Contains(hmacNQuads[idx]))
                {
                    gi.Matching[idx] = hmacNQuads[idx];
                }
                else
                {
                    gi.NonMatching[idx] = hmacNQuads[idx];
                }
            }
            result.Groups[name] = gi;
        }
        return result;
    }

    // ------------------------------------------------- skolemize / label plumbing

    private sealed class SkolemLabeler
    {
        public string Prefix = "urn:bnid:";
        public string Random = "";
        public int Count;
    }

    private static (JArray Expanded, JObject Compact) SkolemizeCompactJsonLd(JObject document)
    {
        var expanded = SdJsonLd.ExpandJsonLd(document);
        var labeler = new SkolemLabeler { Random = RandomHex(16) };
        var skolemized = SkolemizeExpanded(expanded, labeler);
        var compact = SdJsonLd.CompactJsonLd(skolemized, document["@context"]);
        return (skolemized, compact);
    }

    private static JArray SkolemizeExpanded(JArray expanded, SkolemLabeler l)
    {
        var outArr = new JArray();
        foreach (var element in expanded)
        {
            if (element is not JObject m)
            {
                outArr.Add(element.DeepClone());
                continue;
            }
            if (m["@value"] != null)
            {
                outArr.Add(m.DeepClone());
                continue;
            }
            var node = new JObject();
            foreach (var prop in m.Properties())
            {
                if (prop.Value is JArray arr)
                {
                    node[prop.Name] = SkolemizeExpanded(arr, l);
                }
                else
                {
                    node[prop.Name] = SkolemizeExpanded(new JArray(prop.Value.DeepClone()), l)[0];
                }
            }
            var idTok = node["@id"];
            if (idTok is not JValue || idTok.Type != JTokenType.String)
            {
                node["@id"] = $"{l.Prefix}_{l.Random}_{l.Count}";
                l.Count++;
            }
            else
            {
                var id = idTok.Value<string>()!;
                if (id.StartsWith("_:"))
                {
                    node["@id"] = l.Prefix + id.Substring(2);
                }
            }
            outArr.Add(node);
        }
        return outArr;
    }

    private static List<string> DeskolemizeNQuads(List<string> nquads)
    {
        var outList = new List<string>(nquads.Count);
        foreach (var nq in nquads)
        {
            outList.Add(nq.Contains("<urn:bnid:") ? UrnBnidRe.Replace(nq, "_:$1") : nq);
        }
        return outList;
    }

    private static List<string> ToDeskolemizedNQuads(JToken document) => DeskolemizeNQuads(SdJsonLd.ToRdfNQuads(document));

    private static List<string> RelabelBlankNodes(List<string> nquads, Dictionary<string, string> labelMap)
    {
        var outList = new List<string>(nquads.Count);
        foreach (var nq in nquads)
        {
            outList.Add(BnodeRe.Replace(nq, match =>
            {
                var label = match.Value.Substring(2);
                return labelMap.TryGetValue(label, out var nl) ? "_:" + nl : match.Value;
            }));
        }
        return outList;
    }

    private static Dictionary<string, string> CreateHmacLabelMap(Dictionary<string, string> canonicalIdMap, byte[] hmacKey)
    {
        var outMap = new Dictionary<string, string>(canonicalIdMap.Count);
        foreach (var kv in canonicalIdMap)
        {
            using var mac = new HMACSHA256(hmacKey);
            var tag = mac.ComputeHash(Encoding.UTF8.GetBytes(kv.Value));
            outMap[kv.Key] = "u" + Base64UrlNoPad(tag);
        }
        return outMap;
    }

    private static (List<string> NQuads, Dictionary<string, string> LabelMap) LabelReplacementCanonicalizeNQuads(List<string> nquads, byte[] hmacKey)
    {
        var (canonicalNQuads, rawIdMap) = SdJsonLd.CanonicalizeNQuadsWithIdMap(nquads);
        // rawIdMap is already bare input-label -> bare canonical-label.
        var labelMap = CreateHmacLabelMap(rawIdMap, hmacKey);

        var c14nToNew = new Dictionary<string, string>(labelMap.Count);
        foreach (var kv in labelMap)
        {
            c14nToNew[rawIdMap[kv.Key]] = kv.Value;
        }
        var outList = RelabelBlankNodes(canonicalNQuads, c14nToNew);
        outList.Sort(StringComparer.Ordinal);
        return (outList, labelMap);
    }

    private static (List<string> Deskolemized, List<string> Relabeled) SelectCanonicalNQuads(JObject compact, string[] pointers, Dictionary<string, string> labelMap)
    {
        var selection = SelectJsonLd(compact, pointers);
        if (selection == null)
        {
            return (new List<string>(), new List<string>());
        }
        var deskolemized = ToDeskolemizedNQuads(selection);
        return (deskolemized, RelabelBlankNodes(deskolemized, labelMap));
    }

    // ----------------------------------------------------------- JSON pointer sel

    private static List<object> ParsePointer(string pointer)
    {
        var parts = pointer.Split('/');
        var parsed = new List<object>();
        for (int i = 1; i < parts.Length; i++)
        {
            var part = parts[i];
            if (!part.Contains('~'))
            {
                if (int.TryParse(part, out var n))
                {
                    parsed.Add(n);
                }
                else
                {
                    parsed.Add(part);
                }
                continue;
            }
            parsed.Add(part.Replace("~1", "/").Replace("~0", "~"));
        }
        return parsed;
    }

    private static JObject? SelectJsonLd(JObject document, string[] pointers)
    {
        if (pointers.Length == 0)
        {
            return null;
        }
        var sel = new JObject();
        if (document["@context"] != null)
        {
            sel["@context"] = document["@context"]!.DeepClone();
        }
        InitSelection(sel, document);

        foreach (var pointer in pointers)
        {
            var paths = ParsePointer(pointer);
            if (paths.Count == 0)
            {
                return (JObject)document.DeepClone();
            }
            SelectInto(document, paths, sel);
        }
        DensifyArrays(sel);
        return sel;
    }

    private static void SelectInto(JToken source, List<object> paths, JToken sel)
    {
        var path = paths[0];
        var childSource = GetChild(source, path)
            ?? throw new InvalidOperationException("JSON pointer does not match document");

        if (paths.Count == 1)
        {
            SetChild(sel, path, childSource.DeepClone());
            return;
        }

        var childSel = GetChild(sel, path);
        if (childSel == null)
        {
            childSel = childSource is JArray ? new JArray() : InitSelection(new JObject(), childSource);
            SetChild(sel, path, childSel);
        }
        SelectInto(childSource, paths.GetRange(1, paths.Count - 1), childSel);
    }

    private static JObject InitSelection(JObject sel, JToken source)
    {
        if (source is not JObject m)
        {
            return sel;
        }
        if (m["id"] is JValue { Type: JTokenType.String } idVal)
        {
            var id = idVal.Value<string>()!;
            if (!id.StartsWith("_:"))
            {
                sel["id"] = id;
            }
        }
        if (m["type"] != null)
        {
            sel["type"] = m["type"]!.DeepClone();
        }
        return sel;
    }

    private static JToken? GetChild(JToken parent, object path)
    {
        switch (parent)
        {
            case JObject o when path is string key:
                return o[key];
            case JArray a when path is int idx && idx >= 0 && idx < a.Count:
                return a[idx];
            default:
                return null;
        }
    }

    private static void SetChild(JToken parent, object path, JToken val)
    {
        switch (parent)
        {
            case JObject o when path is string key:
                if (!ReferenceEquals(o[key], val))
                {
                    o[key] = val;
                }
                break;
            case JArray a when path is int idx:
                while (a.Count <= idx)
                {
                    a.Add(JValue.CreateNull());
                }
                if (!ReferenceEquals(a[idx], val))
                {
                    a[idx] = val;
                }
                break;
        }
    }

    private static void DensifyArrays(JToken v)
    {
        switch (v)
        {
            case JObject o:
                foreach (var prop in o.Properties().ToList())
                {
                    DensifyArrays(prop.Value);
                }
                break;
            case JArray a:
                for (int i = a.Count - 1; i >= 0; i--)
                {
                    if (a[i].Type == JTokenType.Null)
                    {
                        a.RemoveAt(i);
                    }
                    else
                    {
                        DensifyArrays(a[i]);
                    }
                }
                break;
        }
    }

    // ----------------------------------------------------------------- hashes

    private static byte[] HashProofConfig(JObject proofConfig) => Sha256(SdJsonLd.Canonicalize(proofConfig));

    private static byte[] HashMandatory(Dictionary<int, string> matching)
    {
        var sb = new StringBuilder();
        foreach (var i in SortedIndexes(matching))
        {
            sb.Append(matching[i]);
        }
        return Sha256(Encoding.UTF8.GetBytes(sb.ToString()));
    }

    // ----------------------------------------------------------- proof value CBOR

    private sealed class BaseProof
    {
        public byte[] BaseSignature = Array.Empty<byte>();
        public byte[] PublicKey = Array.Empty<byte>();
        public byte[] HMACKey = Array.Empty<byte>();
        public List<byte[]> Signatures = new();
        public string[] MandatoryPointers = Array.Empty<string>();
    }

    private sealed class DerivedProof
    {
        public byte[] BaseSignature = Array.Empty<byte>();
        public byte[] PublicKey = Array.Empty<byte>();
        public List<byte[]> Signatures = new();
        public Dictionary<string, string> LabelMap = new();
        public List<int> MandatoryIndexes = new();
    }

    private static string SerializeBaseProofValue(byte[] baseSig, byte[] publicKey, byte[] hmacKey, List<byte[]> signatures, string[] mandatoryPointers)
    {
        var w = new CborWriter(CborConformanceMode.Canonical);
        w.WriteStartArray(5);
        w.WriteByteString(baseSig);
        w.WriteByteString(publicKey);
        w.WriteByteString(hmacKey);
        w.WriteStartArray(signatures.Count);
        foreach (var s in signatures)
        {
            w.WriteByteString(s);
        }
        w.WriteEndArray();
        w.WriteStartArray(mandatoryPointers.Length);
        foreach (var p in mandatoryPointers)
        {
            w.WriteTextString(p);
        }
        w.WriteEndArray();
        w.WriteEndArray();
        return MultibaseProofValue(BaseProofHeader, w.Encode());
    }

    private static BaseProof ParseBaseProofValue(string proofValue)
    {
        if (!TryDecodeProofValue(proofValue, BaseProofHeader, out var cbor))
        {
            throw new InvalidOperationException("ecdsasd: proof value has wrong header (expected base proof)");
        }
        var r = new CborReader(cbor, CborConformanceMode.Lax);
        var n = r.ReadStartArray();
        if (n != 5)
        {
            throw new InvalidOperationException($"ecdsasd: base proof value: want 5 elements, got {n}");
        }
        var bp = new BaseProof
        {
            BaseSignature = r.ReadByteString(),
            PublicKey = r.ReadByteString(),
            HMACKey = r.ReadByteString()
        };
        var sigN = r.ReadStartArray();
        var sigs = new List<byte[]>();
        for (int i = 0; i < sigN; i++)
        {
            sigs.Add(r.ReadByteString());
        }
        r.ReadEndArray();
        bp.Signatures = sigs;
        var pN = r.ReadStartArray();
        var ptrs = new List<string>();
        for (int i = 0; i < pN; i++)
        {
            ptrs.Add(r.ReadTextString());
        }
        r.ReadEndArray();
        bp.MandatoryPointers = ptrs.ToArray();
        r.ReadEndArray();
        return bp;
    }

    private static string SerializeDisclosureProofValue(byte[] baseSig, byte[] publicKey, List<byte[]> signatures, Dictionary<string, string> labelMap, List<int> mandatoryIndexes)
    {
        var compressed = CompressLabelMap(labelMap); // sorted by numeric key
        var w = new CborWriter(CborConformanceMode.Canonical);
        w.WriteStartArray(5);
        w.WriteByteString(baseSig);
        w.WriteByteString(publicKey);
        w.WriteStartArray(signatures.Count);
        foreach (var s in signatures)
        {
            w.WriteByteString(s);
        }
        w.WriteEndArray();
        w.WriteStartMap(compressed.Count);
        foreach (var kv in compressed)
        {
            w.WriteUInt64(kv.Key);
            w.WriteByteString(kv.Value);
        }
        w.WriteEndMap();
        w.WriteStartArray(mandatoryIndexes.Count);
        foreach (var i in mandatoryIndexes)
        {
            w.WriteUInt64((ulong)i);
        }
        w.WriteEndArray();
        w.WriteEndArray();
        return MultibaseProofValue(DerivedProofHeader, w.Encode());
    }

    private static DerivedProof ParseDisclosureProofValue(string proofValue)
    {
        if (!TryDecodeProofValue(proofValue, DerivedProofHeader, out var cbor))
        {
            throw new InvalidOperationException("ecdsasd: proof value has wrong header (expected derived proof)");
        }
        var r = new CborReader(cbor, CborConformanceMode.Lax);
        var n = r.ReadStartArray();
        if (n != 5)
        {
            throw new InvalidOperationException($"ecdsasd: derived proof value: want 5 elements, got {n}");
        }
        var dp = new DerivedProof
        {
            BaseSignature = r.ReadByteString(),
            PublicKey = r.ReadByteString()
        };
        var sigN = r.ReadStartArray();
        var sigs = new List<byte[]>();
        for (int i = 0; i < sigN; i++)
        {
            sigs.Add(r.ReadByteString());
        }
        r.ReadEndArray();
        dp.Signatures = sigs;

        var mapN = r.ReadStartMap();
        var compressed = new Dictionary<ulong, byte[]>();
        for (int i = 0; i < mapN; i++)
        {
            var k = r.ReadUInt64();
            compressed[k] = r.ReadByteString();
        }
        r.ReadEndMap();
        dp.LabelMap = DecompressLabelMap(compressed);

        var mIdxN = r.ReadStartArray();
        var mIdx = new List<int>();
        for (int i = 0; i < mIdxN; i++)
        {
            mIdx.Add((int)r.ReadUInt64());
        }
        r.ReadEndArray();
        dp.MandatoryIndexes = mIdx;
        r.ReadEndArray();
        return dp;
    }

    private static SortedDictionary<ulong, byte[]> CompressLabelMap(Dictionary<string, string> labelMap)
    {
        var outMap = new SortedDictionary<ulong, byte[]>();
        foreach (var kv in labelMap)
        {
            var num = ulong.Parse(kv.Key.StartsWith("c14n") ? kv.Key.Substring(4) : kv.Key);
            outMap[num] = Base64UrlDecode(kv.Value.StartsWith("u") ? kv.Value.Substring(1) : kv.Value);
        }
        return outMap;
    }

    private static Dictionary<string, string> DecompressLabelMap(Dictionary<ulong, byte[]> compressed)
    {
        var outMap = new Dictionary<string, string>();
        foreach (var kv in compressed)
        {
            outMap[$"c14n{kv.Key}"] = "u" + Base64UrlNoPad(kv.Value);
        }
        return outMap;
    }

    private static string MultibaseProofValue(byte[] header, byte[] payload)
    {
        var buf = Concat(header, payload);
        return "u" + Base64UrlNoPad(buf);
    }

    private static bool TryDecodeProofValue(string proofValue, byte[] header, out byte[] payload)
    {
        payload = Array.Empty<byte>();
        if (string.IsNullOrEmpty(proofValue) || proofValue[0] != 'u')
        {
            return false;
        }
        byte[] raw;
        try
        {
            raw = Base64UrlDecode(proofValue.Substring(1));
        }
        catch
        {
            return false;
        }
        if (raw.Length < header.Length)
        {
            return false;
        }
        for (int i = 0; i < header.Length; i++)
        {
            if (raw[i] != header[i])
            {
                return false;
            }
        }
        payload = raw[header.Length..];
        return true;
    }

    // ------------------------------------------------------------------- keys

    /// <summary>p256-pub Multikey raw bytes: 0x80 0x24 || compressed point (35 bytes).</summary>
    private static byte[] PubToMultikeyBytes(ECPublicKeyParameters pub)
    {
        var compressed = pub.Q.GetEncoded(true);
        return Concat(P256PubMulticodec, compressed);
    }

    private static ECPublicKeyParameters EcPubFromMultikeyBytes(byte[] raw)
    {
        if (raw.Length < 3 || raw[0] != P256PubMulticodec[0] || raw[1] != P256PubMulticodec[1])
        {
            throw new InvalidOperationException("ecdsasd: not a p256-pub multikey");
        }
        var curve = Curve();
        var point = curve.Curve.DecodePoint(raw[2..]);
        return new ECPublicKeyParameters("EC", point, Domain());
    }

    /// <summary>Decodes a p256-priv secretKeyMultibase (z42t...) to its 32-byte scalar hex.</summary>
    public static string DecodeP256PrivMultibaseToHex(string secretKeyMultibase)
    {
        var raw = Multibase.DecodeBase58Btc(secretKeyMultibase);
        if (raw.Length < 3 || raw[0] != P256PrivMulticodec[0] || raw[1] != P256PrivMulticodec[1])
        {
            throw new InvalidOperationException("ecdsasd: not a p256-priv multikey");
        }
        return Convert.ToHexString(raw[2..]).ToLowerInvariant();
    }

    /// <summary>Public key (for verification) from a p256 publicKeyMultibase.</summary>
    public static ECPublicKeyParameters P256PubFromMultibase(string publicKeyMultibase) =>
        VerificationMethod.Multikey.PublicKeyFromMultibase(publicKeyMultibase);

    private static (ECPrivateKeyParameters Priv, ECPublicKeyParameters Pub) GenerateP256()
    {
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(Domain(), new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        return ((ECPrivateKeyParameters)kp.Private, (ECPublicKeyParameters)kp.Public);
    }

    private static (ECPrivateKeyParameters Priv, ECPublicKeyParameters Pub) P256FromPrivHex(string privHex)
    {
        var hex = privHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? privHex[2..] : privHex;
        var d = new BcBigInteger(1, Convert.FromHexString(hex));
        var priv = new ECPrivateKeyParameters("EC", d, Domain());
        var curve = Curve();
        var q = curve.G.Multiply(d).Normalize();
        var pub = new ECPublicKeyParameters("EC", q, Domain());
        return (priv, pub);
    }

    private static byte[] SignEphemeral((ECPrivateKeyParameters Priv, ECPublicKeyParameters Pub) eph, string statement, bool deterministic)
    {
        var digest = Sha256(Encoding.UTF8.GetBytes(statement));
        var signer = deterministic
            ? new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()))
            : new ECDsaSigner();
        signer.Init(true, eph.Priv);
        var rs = signer.GenerateSignature(digest);
        var r = rs[0];
        var s = rs[1];
        if (!deterministic)
        {
            s = NormalizeLowS(s);
        }
        return EncodeRs(r, s);
    }

    private static byte[] SignDeterministic(string privHex, byte[] digest32)
    {
        var (priv, _) = P256FromPrivHex(privHex);
        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        signer.Init(true, priv);
        var rs = signer.GenerateSignature(digest32);
        return EncodeRs(rs[0], rs[1]); // raw S (no low-S), matching the reference
    }

    private static BcBigInteger NormalizeLowS(BcBigInteger s)
    {
        var n = Curve().N;
        var halfN = n.ShiftRight(1);
        return s.CompareTo(halfN) > 0 ? n.Subtract(s) : s;
    }

    private static byte[] EncodeRs(BcBigInteger r, BcBigInteger s)
    {
        var outBytes = new byte[64];
        var rb = r.ToByteArrayUnsigned();
        var sb = s.ToByteArrayUnsigned();
        Buffer.BlockCopy(rb, 0, outBytes, 32 - rb.Length, rb.Length);
        Buffer.BlockCopy(sb, 0, outBytes, 64 - sb.Length, sb.Length);
        return outBytes;
    }

    private static X9ECParameters Curve() => SecNamedCurves.GetByName("secp256r1");

    private static ECDomainParameters Domain()
    {
        var c = Curve();
        return new ECDomainParameters(c.Curve, c.G, c.N, c.H);
    }

    // ------------------------------------------------------------------- helpers

    private static List<string> OrderedValues(Dictionary<int, string> m) => SortedIndexes(m).Select(k => m[k]).ToList();

    private static List<int> SortedIndexes(Dictionary<int, string> m)
    {
        var keys = m.Keys.ToList();
        keys.Sort();
        return keys;
    }

    private static byte[] Sha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var outBytes = new byte[total];
        int off = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, outBytes, off, p.Length);
            off += p.Length;
        }
        return outBytes;
    }

    private static string RandomHex(int n) => Convert.ToHexString(RandomNumberGenerator.GetBytes(n)).ToLowerInvariant();

    private static string Base64UrlNoPad(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        var b64 = s.Replace('-', '+').Replace('_', '/');
        switch (b64.Length % 4)
        {
            case 2: b64 += "=="; break;
            case 3: b64 += "="; break;
        }
        return Convert.FromBase64String(b64);
    }
}
