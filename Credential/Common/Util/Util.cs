using System.Text.Json;

namespace Pila.CredentialSdk.DidComm.Credential.Common.Util;

/// <summary>
/// Utility functions for JSON and credential operations.
/// </summary>
public static class Util
{
    /// <summary>
    /// Serializes types to JSON-LD compatible format.
    /// </summary>
    public static object SerializeTypes(List<string> types)
    {
        if (types.Count == 0)
        {
            return null!;
        }
        if (types.Count == 1)
        {
            return types[0];
        }
        return MapSlice(types, t => (object)t);
    }

    /// <summary>
    /// Transforms a slice of type T to a slice of type U using a mapping function.
    /// </summary>
    public static List<U> MapSlice<T, U>(List<T> slice, Func<T, U> mapFn)
    {
        var result = new List<U>(slice.Count);
        foreach (var v in slice)
        {
            result.Add(mapFn(v));
        }
        return result;
    }

    /// <summary>
    /// Validates and converts a slice of JSON-LD context entries.
    /// </summary>
    public static List<object> SerializeContexts(List<object> contexts)
    {
        var validated = new List<object>(contexts.Count);
        for (int i = 0; i < contexts.Count; i++)
        {
            var ctx = contexts[i];
            if (ctx == null)
            {
                throw new ArgumentException($"Failed to validate context: context entry at index {i} is nil");
            }

            switch (ctx)
            {
                case string str:
                    if (string.IsNullOrEmpty(str))
                    {
                        throw new ArgumentException($"Failed to validate context: context string at index {i} is empty");
                    }
                    validated.Add(str);
                    break;
                case Dictionary<string, object> ctxMap:
                    if (ctxMap.ContainsKey("@context"))
                    {
                        throw new ArgumentException($"Failed to validate context: context object at index {i} must not contain nested @context");
                    }
                    foreach (var kvp in ctxMap)
                    {
                        if (string.IsNullOrEmpty(kvp.Key))
                        {
                            throw new ArgumentException($"Failed to validate context: context object at index {i} has empty key");
                        }
                        if (kvp.Value is string strValue && string.IsNullOrEmpty(strValue))
                        {
                            throw new ArgumentException($"Failed to validate context: context object at index {i} has empty string value for key \"{kvp.Key}\"");
                        }
                    }
                    validated.Add(ctxMap);
                    break;
                default:
                    throw new ArgumentException($"Failed to validate context: invalid context entry at index {i}: must be string or map, got {ctx.GetType()}");
            }
        }
        return validated;
    }

    /// <summary>
    /// Splits JSON object into provided fields and rest.
    /// </summary>
    public static (Dictionary<string, object> fields, Dictionary<string, object> rest) SplitJsonObj(
        Dictionary<string, object> json, params string[] fields)
    {
        var fieldsMap = new Dictionary<string, object>();
        var rest = new Dictionary<string, object>();

        foreach (var kvp in json)
        {
            if (fields.Contains(kvp.Key))
            {
                fieldsMap[kvp.Key] = kvp.Value;
            }
            else
            {
                rest[kvp.Key] = kvp.Value;
            }
        }

        return (fieldsMap, rest);
    }

    /// <summary>
    /// Creates a shallow copy of a JSON object.
    /// </summary>
    public static Dictionary<string, object> ShallowCopyObj(Dictionary<string, object> json)
    {
        var result = new Dictionary<string, object>();
        foreach (var kvp in json)
        {
            result[kvp.Key] = kvp.Value;
        }
        return result;
    }

    /// <summary>
    /// Copies all fields except fields with given names.
    /// </summary>
    public static Dictionary<string, object> CopyExcept(Dictionary<string, object> json, params string[] fields)
    {
        var newJson = ShallowCopyObj(json);
        foreach (var field in fields)
        {
            newJson.Remove(field);
        }
        return newJson;
    }

    /// <summary>
    /// Selects only fields with given names.
    /// </summary>
    public static Dictionary<string, object> Select(Dictionary<string, object> json, params string[] fields)
    {
        var newJson = new Dictionary<string, object>();
        foreach (var field in fields)
        {
            if (json.TryGetValue(field, out var value))
            {
                newJson[field] = value;
            }
        }
        return newJson;
    }

    /// <summary>
    /// Converts object, string or bytes to JSON object represented by map.
    /// </summary>
    public static Dictionary<string, object> ToMap(object v)
    {
        byte[] b;
        
        switch (v)
        {
            case byte[] bytes:
                b = bytes;
                break;
            case string str:
                b = System.Text.Encoding.UTF8.GetBytes(str);
                break;
            default:
                var json = JsonSerializer.Serialize(v);
                b = System.Text.Encoding.UTF8.GetBytes(json);
                break;
        }

        var jsonStr = System.Text.Encoding.UTF8.GetString(b);
        var m = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonStr);
        
        if (m == null)
        {
            throw new InvalidOperationException("Failed to deserialize to map");
        }

        return m;
    }

    /// <summary>
    /// Encodes bytes to base64url string.
    /// </summary>
    public static string Base64UrlEncode(byte[] input)
    {
        var base64 = Convert.ToBase64String(input);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>
    /// Decodes base64url string to bytes.
    /// </summary>
    public static byte[] Base64UrlDecode(string input)
    {
        var base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }

    /// <summary>
    /// Removes the "0x" prefix from a hex string if present, but preserves leading zeros in the actual key.
    /// </summary>
    public static string RemoveHexPrefix(string hex)
    {
        if (string.IsNullOrEmpty(hex))
        {
            return hex;
        }

        // Only remove "0x" prefix, not leading zeros
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return hex.Substring(2);
        }

        return hex;
    }
}

