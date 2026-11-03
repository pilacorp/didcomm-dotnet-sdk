using System.Globalization;
using System.Text;
using Newtonsoft.Json.Linq;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public static class Rfc8785
{
    public static byte[] Transform(string json)
    {
        var token = JToken.Parse(json);
        return Encoding.UTF8.GetBytes(Serialize(token));
    }

    private static string Serialize(JToken token)
    {
        return token.Type switch
        {
            JTokenType.Null => "null",
            JTokenType.Boolean => token.Value<bool>() ? "true" : "false",
            JTokenType.Integer or JTokenType.Float => NumberToJson(token),
            JTokenType.String => DecorateString(token.Value<string>() ?? ""),
            JTokenType.Array => "[" + string.Join(",", token.Children().Select(Serialize)) + "]",
            JTokenType.Object => SerializeObject((JObject)token),
            _ => throw new InvalidOperationException($"canonicalizer: unsupported value type {token.Type}")
        };
    }

    private static string SerializeObject(JObject obj)
    {
        var props = obj.Properties().OrderBy(p => p.Name, StringComparer.Ordinal).ToList();
        return "{" + string.Join(",", props.Select(p => DecorateString(p.Name) + ":" + Serialize(p.Value))) + "}";
    }

    private static string NumberToJson(JToken token)
    {
        if (token.Type == JTokenType.Integer)
        {
            return token.Value<long>().ToString(CultureInfo.InvariantCulture);
        }
        var n = token.Value<double>();
        if (double.IsNaN(n) || double.IsInfinity(n))
        {
            throw new InvalidOperationException("Invalid JSON number");
        }
        if (n == 0)
        {
            return "0";
        }
        var sign = n < 0 ? "-" : "";
        n = Math.Abs(n);
        var format = n < 1e21 && n >= 1e-6 ? "G17" : "E16";
        var formatted = n.ToString(format, CultureInfo.InvariantCulture);
        if (formatted.Contains('E'))
        {
            formatted = formatted.Replace("E", "e").Replace("e+", "e+").Replace("e+0", "e+");
            formatted = formatted.Replace("e-0", "e-");
            while (formatted.Contains("e+0"))
            {
                formatted = formatted.Replace("e+0", "e+");
            }
            while (formatted.Contains("e-0") && !formatted.Contains("e-0e"))
            {
                var idx = formatted.IndexOf("e-0", StringComparison.Ordinal);
                if (idx < 0) break;
                if (idx + 3 < formatted.Length && char.IsDigit(formatted[idx + 3]))
                {
                    formatted = formatted.Remove(idx + 2, 1);
                }
                else break;
            }
        }
        return sign + formatted;
    }

    private static string DecorateString(string value)
    {
        var sb = new StringBuilder("\"");
        foreach (var ch in value)
        {
            switch (ch)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (ch < 0x20)
                    {
                        sb.Append("\\u");
                        sb.Append(((int)ch).ToString("x4"));
                    }
                    else
                    {
                        sb.Append(ch);
                    }
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }
}
