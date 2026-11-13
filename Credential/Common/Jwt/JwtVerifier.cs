using System.Globalization;
using System.Text;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Crypto;
using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Jwt;

/// <summary>
/// Verifies ES256K / ES256 JWTs (vc+jwt / vp+jwt) with go-credential-sdk parity.
///
/// The verifier binds the header <c>kid</c> to the signer the payload names
/// (issuer for a credential, holder for a presentation): the document is
/// resolved by that signer DID, and the <c>kid</c> must name a verification
/// method inside THAT document. The header algorithm must match the key the
/// method holds, and the proof-purpose / revocation checks run after the
/// cryptographic check. See Go credential/common/jwt/verifier.go.
/// </summary>
public static class JwtVerifier
{
    public const string AlgES256K = "ES256K";
    public const string AlgES256 = "ES256";

    /// <summary>
    /// Verifies a JWT token, binding the signing key to the payload's signer.
    /// Throws when verification fails.
    /// </summary>
    public static void Verify(string tokenString, IDidDocumentResolver resolver)
    {
        if (resolver == null)
        {
            throw new InvalidOperationException("document resolver is not configured");
        }

        var token = tokenString.Trim().Trim('"');
        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            throw new InvalidOperationException("invalid JWT format");
        }

        var header = DecodeJson(parts[0], "header");
        var alg = GetString(header, "alg");
        if (alg != AlgES256K && alg != AlgES256)
        {
            throw new InvalidOperationException($"unsupported algorithm: {alg}");
        }

        var kid = GetString(header, "kid");
        if (string.IsNullOrEmpty(kid))
        {
            throw new InvalidOperationException("kid not found in header");
        }

        // Which property names the signer depends on the kind: a credential is
        // signed by its issuer, a presentation by its holder. Purpose and signer
        // come from the payload, never from the attacker-chosen kid.
        var body = DecodeJson(parts[1], "payload");
        var purpose = JwtProofPurpose(header, body);
        var signer = JwtSigner(body, purpose);

        // Resolve the document for the signer the body names; FindVerificationMethod
        // then rejects a kid that does not belong to that signer's document.
        var doc = resolver.ResolveDocument(signer)
            ?? throw new InvalidOperationException($"failed to resolve DID document for '{signer}'");
        var vm = FindVerificationMethod(doc, kid);

        // The header must not claim an algorithm the method's key cannot produce.
        var kind = VerificationMethodKeyKindExtensions.FromEntry(vm);
        var wantAlg = AlgForKeyKind(kind)
            ?? throw new InvalidOperationException(
                $"verification method '{vm.Id}' has an unsupported key type for JWT");
        if (alg != wantAlg)
        {
            throw new InvalidOperationException(
                $"JWT alg \"{alg}\" does not match verification method '{vm.Id}', which holds a {kind} key");
        }

        var publicKey = VerificationMethodMaterial.EcPublicKeyFromEntry(vm);

        var signingString = parts[0] + "." + parts[1];
        var signature = Base64UrlDecode(parts[2]);
        if (signature.Length == 65)
        {
            signature = signature[..64];
        }
        if (signature.Length != 64)
        {
            throw new InvalidOperationException(
                $"invalid signature length: got {signature.Length}, want 64 or 65");
        }

        // alg was matched to the key kind above; ES256K (secp256k1) and ES256
        // (P-256) share the same raw ECDSA check over SHA-256(signingString).
        var digest = Canonicalizer.ComputeDigest(Encoding.UTF8.GetBytes(signingString));
        if (!EcdsaRawVerifier.Verify(publicKey, digest, signature))
        {
            throw new InvalidOperationException("JWT signature verification failed");
        }

        var issuedAt = JwtIssuedAt(body);
        // JWTs carry no proof.created; the soft-revocation comparison uses iat.
        var softRevoked = !string.IsNullOrEmpty(vm.Revoked);
        if (softRevoked && issuedAt == null
            && !RevocationReasons.IsHardRevocationReason(vm.RevocationReason))
        {
            throw new InvalidOperationException(
                $"verification method '{vm.Id}' was revoked at {vm.Revoked} (missing iat for time-based revocation check)");
        }
        StrictPurposeCheck.Enforce(doc, vm, purpose, issuedAt ?? "");
    }

    private static string? AlgForKeyKind(VerificationMethodKeyKind kind) => kind switch
    {
        VerificationMethodKeyKind.P256 => AlgES256,
        VerificationMethodKeyKind.Secp256k1 => AlgES256K,
        _ => null
    };

    private static VerificationMethodEntry FindVerificationMethod(DidDocument doc, string kid)
    {
        var want = ResolveSigningVm.NormalizeVerificationMethodUrl(doc.Id, kid);
        foreach (var vm in doc.VerificationMethod)
        {
            if (vm.Id == want)
            {
                return vm;
            }
        }
        throw new InvalidOperationException(
            $"verification method '{kid}' not found in DID '{doc.Id}' document");
    }

    // --- proof purpose -------------------------------------------------------

    private static string JwtProofPurpose(Dictionary<string, JsonElement> header, Dictionary<string, JsonElement> body)
    {
        var carried = PurposeFromBody(body);
        var declared = PurposeFromTyp(header);
        if (carried.Length != 0 && declared.Length != 0 && carried != declared)
        {
            throw new InvalidOperationException(
                $"JWT typ {GetString(header, "typ")} implies proofPurpose {declared} but its payload is a {DocumentKind(carried)}");
        }
        if (carried.Length != 0)
        {
            return carried;
        }
        if (declared.Length != 0)
        {
            return declared;
        }
        throw new InvalidOperationException(
            "JWT has neither vc/vp claims nor vc+jwt/vp+jwt typ; cannot determine proofPurpose");
    }

    private static string PurposeFromTyp(Dictionary<string, JsonElement> header) => GetString(header, "typ") switch
    {
        "vc+jwt" or "application/vc+jwt" or "vc+sd-jwt" or "application/vc+sd-jwt" => "assertionMethod",
        "vp+jwt" or "application/vp+jwt" => "authentication",
        _ => ""
    };

    private static string PurposeFromBody(Dictionary<string, JsonElement> body)
    {
        var hasVc = body.ContainsKey("vc");
        var hasVp = body.ContainsKey("vp");
        if (hasVc && hasVp)
        {
            throw new InvalidOperationException("JWT carries both vc and vp claims; its kind is ambiguous");
        }
        if (hasVc)
        {
            return "assertionMethod";
        }
        if (hasVp)
        {
            return "authentication";
        }
        if (body.TryGetValue("type", out var type))
        {
            if (type.ValueKind == JsonValueKind.Array)
            {
                var found = "";
                foreach (var v in type.EnumerateArray())
                {
                    var p = PurposeFromType(v.ValueKind == JsonValueKind.String ? v.GetString()! : "");
                    if (p.Length == 0)
                    {
                        continue;
                    }
                    if (found.Length != 0 && found != p)
                    {
                        throw new InvalidOperationException(
                            "JWT type names both a credential and a presentation; its kind is ambiguous");
                    }
                    found = p;
                }
                return found;
            }
            if (type.ValueKind == JsonValueKind.String)
            {
                return PurposeFromType(type.GetString()!);
            }
        }
        return "";
    }

    private static string PurposeFromType(string t) => t switch
    {
        "VerifiableCredential" => "assertionMethod",
        "VerifiablePresentation" => "authentication",
        _ => ""
    };

    private static string DocumentKind(string purpose) =>
        purpose == "assertionMethod" ? "credential" : "presentation";

    // --- signer --------------------------------------------------------------

    private static string JwtSigner(Dictionary<string, JsonElement> body, string purpose)
    {
        var field = purpose == "assertionMethod" ? "issuer" : "holder";

        // VC 1.1 nests the document under a vc/vp claim; read the property there
        // when present so a nested issuer cannot disagree with iss unnoticed.
        var doc = body;
        if (body.TryGetValue("vc", out var vc) && vc.ValueKind == JsonValueKind.Object)
        {
            doc = ToDict(vc);
        }
        else if (body.TryGetValue("vp", out var vp) && vp.ValueKind == JsonValueKind.Object)
        {
            doc = ToDict(vp);
        }

        // Guard against a case-variant duplicate key: a downstream consumer that
        // matches the field case-insensitively would read a value this lookup
        // never sees, letting a signer name the victim under an unchecked key.
        foreach (var k in doc.Keys)
        {
            if (!k.Equals(field, StringComparison.Ordinal)
                && k.Equals(field, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"JWT carries \"{k}\", which differs from {field} only by case");
            }
        }

        var present = doc.TryGetValue(field, out var fieldVal);
        var claimed = present ? DidFromClaim(fieldVal) : "";
        if (present && claimed.Length == 0)
        {
            throw new InvalidOperationException(
                $"JWT {field} must be a string or an object with a string id");
        }

        var iss = GetString(body, "iss");
        if (iss.Length != 0 && claimed.Length != 0 && iss != claimed)
        {
            throw new InvalidOperationException($"JWT iss \"{iss}\" does not match {field} \"{claimed}\"");
        }
        if (iss.Length != 0)
        {
            return iss;
        }
        if (claimed.Length != 0)
        {
            return claimed;
        }
        throw new InvalidOperationException($"JWT names no signer: both iss and {field} are absent");
    }

    private static string DidFromClaim(JsonElement v)
    {
        if (v.ValueKind == JsonValueKind.String)
        {
            return v.GetString() ?? "";
        }
        if (v.ValueKind == JsonValueKind.Object
            && v.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String)
        {
            return id.GetString() ?? "";
        }
        return "";
    }

    // --- misc ---------------------------------------------------------------

    private static string? JwtIssuedAt(Dictionary<string, JsonElement> body)
    {
        if (!body.TryGetValue("iat", out var iat))
        {
            return null;
        }
        long sec;
        if (iat.ValueKind == JsonValueKind.Number && iat.TryGetInt64(out var n))
        {
            sec = n;
        }
        else if (iat.ValueKind == JsonValueKind.String
                 && long.TryParse(iat.GetString(), out var parsed))
        {
            sec = parsed;
        }
        else
        {
            return null;
        }
        return DateTimeOffset.FromUnixTimeSeconds(sec).UtcDateTime
            .ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
    }

    private static Dictionary<string, JsonElement> DecodeJson(string b64, string what)
    {
        try
        {
            var bytes = Base64UrlDecode(b64);
            return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(bytes)
                ?? throw new InvalidOperationException($"invalid {what}: empty JSON");
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            throw new InvalidOperationException($"invalid {what}: {ex.Message}");
        }
    }

    private static Dictionary<string, JsonElement> ToDict(JsonElement obj)
    {
        var d = new Dictionary<string, JsonElement>();
        foreach (var p in obj.EnumerateObject())
        {
            d[p.Name] = p.Value;
        }
        return d;
    }

    private static string GetString(Dictionary<string, JsonElement> d, string key) =>
        d.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static byte[] Base64UrlDecode(string input)
    {
        var base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}
