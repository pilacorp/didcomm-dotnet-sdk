using System.Globalization;
using System.Text.Json;
using Pila.CredentialSdk.DidComm.Credential.Common.Util;

namespace Pila.CredentialSdk.DidComm.Credential.Vc;

/// <summary>
/// Helper functions for credential serialization and parsing.
/// </summary>
internal static class CredentialHelper
{
    /// <summary>
    /// Serializes CredentialContents into a CredentialData.
    /// </summary>
    public static CredentialData SerializeCredentialContents(CredentialContents vcc)
    {
        if (vcc == null)
        {
            throw new ArgumentNullException(nameof(vcc));
        }

        // Validate that at least one essential field is present
        if (vcc.Context.Count == 0 && string.IsNullOrEmpty(vcc.Id) && string.IsNullOrEmpty(vcc.Issuer))
        {
            throw new ArgumentException("Credential contents must have at least one of: context, ID, or issuer");
        }

        var vcJson = new CredentialData();
        
        if (vcc.Context.Count > 0)
        {
            var validatedContext = Util.SerializeContexts(vcc.Context);
            vcJson["@context"] = validatedContext;
        }

        if (!string.IsNullOrEmpty(vcc.Id))
        {
            vcJson["id"] = vcc.Id;
        }

        if (vcc.Types.Count > 0)
        {
            vcJson["type"] = Util.SerializeTypes(vcc.Types);
        }

        if (vcc.Subject.Count > 0)
        {
            vcJson["credentialSubject"] = SerializeSubjects(vcc.Subject);
        }

        if (!string.IsNullOrEmpty(vcc.Issuer))
        {
            vcJson["issuer"] = vcc.Issuer;
        }

        if (vcc.Schemas.Count > 0)
        {
            // TODO: Validate credential schema against provided Schema URIs/types before serialization
            vcJson["credentialSchema"] = SerializeSchemas(vcc.Schemas);
        }

        if (vcc.CredentialStatus.Count > 0)
        {
            vcJson["credentialStatus"] = SerializeStatuses(vcc.CredentialStatus);
        }

        if (vcc.ValidFrom != default(DateTime))
        {
            vcJson["validFrom"] = vcc.ValidFrom.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        }

        if (vcc.ValidUntil != default(DateTime))
        {
            vcJson["validUntil"] = vcc.ValidUntil.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        }

        return vcJson;
    }

    /// <summary>
    /// Serializes subjects to JSON-LD compatible format.
    /// </summary>
    private static object SerializeSubjects(List<Subject> subjects)
    {
        if (subjects.Count == 0)
        {
            return null!;
        }

        if (subjects.Count == 1)
        {
            return SerializeSubject(subjects[0]);
        }

        return Util.MapSlice(subjects, SerializeSubject);
    }

    /// <summary>
    /// Serializes a single subject to JSON object.
    /// </summary>
    private static CredentialData SerializeSubject(Subject subject)
    {
        var jsonObj = Util.ShallowCopyObj(subject.CustomFields);
        if (!string.IsNullOrEmpty(subject.Id))
        {
            jsonObj["id"] = subject.Id;
        }

        var result = new CredentialData();
        foreach (var kvp in jsonObj)
        {
            result[kvp.Key] = kvp.Value;
        }
        return result;
    }

    /// <summary>
    /// Serializes schemas to JSON-LD compatible format.
    /// </summary>
    private static object SerializeSchemas(List<Schema> schemas)
    {
        if (schemas.Count == 0)
        {
            return null!;
        }

        if (schemas.Count == 1)
        {
            return SerializeSchema(schemas[0]);
        }

        return Util.MapSlice(schemas, SerializeSchema);
    }

    /// <summary>
    /// Serializes a single schema to JSON object.
    /// </summary>
    private static CredentialData SerializeSchema(Schema schema)
    {
        return new CredentialData
        {
            ["id"] = schema.Id,
            ["type"] = schema.Type
        };
    }

    /// <summary>
    /// Serializes statuses to JSON-LD compatible format.
    /// </summary>
    private static object SerializeStatuses(List<Status> statuses)
    {
        if (statuses.Count == 0)
        {
            return null!;
        }

        if (statuses.Count == 1)
        {
            return SerializeStatus(statuses[0]);
        }

        return Util.MapSlice(statuses, SerializeStatus);
    }

    /// <summary>
    /// Serializes a single status to JSON object.
    /// </summary>
    private static CredentialData SerializeStatus(Status status)
    {
        var result = new CredentialData();

        if (!string.IsNullOrEmpty(status.Id))
        {
            result["id"] = status.Id;
        }

        if (!string.IsNullOrEmpty(status.Type))
        {
            result["type"] = status.Type;
        }

        if (!string.IsNullOrEmpty(status.StatusPurpose))
        {
            result["statusPurpose"] = status.StatusPurpose;
        }

        if (!string.IsNullOrEmpty(status.StatusListIndex))
        {
            result["statusListIndex"] = status.StatusListIndex;
        }

        if (!string.IsNullOrEmpty(status.StatusListCredential))
        {
            result["statusListCredential"] = status.StatusListCredential;
        }

        return result;
    }

    /// <summary>
    /// Parses context from CredentialData.
    /// </summary>
    public static void ParseContext(CredentialData c, CredentialContents contents)
    {
        if (c.TryGetValue("@context", out var contextObj) && contextObj is List<object> contextList)
        {
            foreach (var ctx in contextList)
            {
                if (ctx is string || ctx is Dictionary<string, object>)
                {
                    contents.Context.Add(ctx);
                }
                else
                {
                    throw new ArgumentException($"Unsupported context type: {ctx.GetType()}");
                }
            }
        }
    }

    /// <summary>
    /// Parses ID from CredentialData.
    /// </summary>
    public static void ParseId(CredentialData c, CredentialContents contents)
    {
        if (c.TryGetValue("id", out var idObj) && idObj is string id)
        {
            contents.Id = id;
        }
    }

    /// <summary>
    /// Standardizes a dictionary into JSON-LD compatible format.
    /// Recursively processes all nested values.
    /// </summary>
    public static Dictionary<string, object?> StandardizeToJsonLd(Dictionary<string, object?> input)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));

        var result = new Dictionary<string, object?>(input.Count);

        foreach (var kvp in input)
        {
            result[kvp.Key] = ConvertToJsonLdCompatible(kvp.Value);
        }

        return result;
    }

    /// <summary>
    /// Recursively converts values so they are JSON-LD friendly.
    /// Fully preserves numbers, booleans, and strings.
    /// Arrays and dictionaries are recursively processed.
    /// Any JsonElement is expanded to CLR types before recursion.
    /// If an exception occurs, the original value is returned unchanged.
    /// </summary>
    public static object? ConvertToJsonLdCompatible(object? value)
    {
        if (value is JsonElement je)
        {
            value = FromJsonElement(je);
        }

        switch (value)
        {
            case string:
                return value;

            // IDictionary<string, object>
            case Dictionary<string, object?> dict:
                {
                    var result = new Dictionary<string, object?>(dict.Count);
                    foreach (var kv in dict)
                        result[kv.Key] = ConvertToJsonLdCompatible(kv.Value);
                    return result;
                }

            // Generic array / List<object>
            case List<object?> list:
                {
                    var result = new List<object?>(list.Count);
                    foreach (var item in list)
                        result.Add(ConvertToJsonLdCompatible(item));
                    return result;
                }

            case null:
                return null;

            default:
                return value?.ToString();
        }
    }

    private static object? FromJsonElement(JsonElement je)
    {
        switch (je.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var dict = new Dictionary<string, object?>();
                foreach (var prop in je.EnumerateObject())
                {
                    dict[prop.Name] = FromJsonElement(prop.Value);
                }
                return dict;
            }

            case JsonValueKind.Array:
            {
                var list = new List<object?>();
                foreach (var item in je.EnumerateArray())
                {
                    list.Add(FromJsonElement(item));
                }
                return list;
            }

            case JsonValueKind.String:
                return je.GetString();

            case JsonValueKind.Number:
                if (je.TryGetInt64(out var l))
                    return l;
                if (je.TryGetDouble(out var d))
                    return d;
                return je.GetRawText(); // fallback

            case JsonValueKind.True:
            case JsonValueKind.False:
                return je.GetBoolean();

            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
            default:
                return null;
        }
    }

    /// <summary>
    /// Parses types from CredentialData.
    /// </summary>
    public static void ParseTypes(CredentialData c, CredentialContents contents)
    {
        if (c.TryGetValue("type", out var typeObj))
        {
            if (typeObj is string typeStr)
            {
                contents.Types.Add(typeStr);
            }
            else if (typeObj is List<object> typeList)
            {
                foreach (var t in typeList)
                {
                    if (t is string typeString)
                    {
                        contents.Types.Add(typeString);
                    }
                }
            }
            else
            {
                throw new ArgumentException($"Unsupported type field: {typeObj.GetType()}");
            }
        }
    }

    /// <summary>
    /// Parses issuer from CredentialData.
    /// </summary>
    public static void ParseIssuer(CredentialData c, CredentialContents contents)
    {
        if (c.TryGetValue("issuer", out var issuerObj) && issuerObj is string issuer)
        {
            contents.Issuer = issuer;
        }
    }

    /// <summary>
    /// Parses dates from CredentialData.
    /// </summary>
    public static void ParseDates(CredentialData c, CredentialContents contents)
    {
        if (c.TryGetValue("validFrom", out var validFromObj) && validFromObj is string validFromStr)
        {
            if (DateTime.TryParse(validFromStr, out var validFrom))
            {
                contents.ValidFrom = validFrom.ToUniversalTime();
            }
        }

        if (c.TryGetValue("validUntil", out var validUntilObj) && validUntilObj is string validUntilStr)
        {
            if (DateTime.TryParse(validUntilStr, out var validUntil))
            {
                contents.ValidUntil = validUntil.ToUniversalTime();
            }
        }
    }

    /// <summary>
    /// Parses subject from CredentialData.
    /// </summary>
    public static void ParseSubject(CredentialData c, CredentialContents contents)
    {
        if (!c.TryGetValue("credentialSubject", out var subjectRaw) || subjectRaw == null)
        {
            return;
        }

        if (subjectRaw is string subjectId)
        {
            contents.Subject.Add(new Subject { Id = subjectId });
        }
        else if (subjectRaw is Dictionary<string, object> subjectDict)
        {
            var parsed = SubjectFromJson(subjectDict);
            contents.Subject.Add(parsed);
        }
        else if (subjectRaw is List<object> subjectList)
        {
            foreach (var raw in subjectList)
            {
                if (raw is Dictionary<string, object> subDict)
                {
                    var parsed = SubjectFromJson(subDict);
                    contents.Subject.Add(parsed);
                }
                else
                {
                    throw new ArgumentException($"Unsupported subject format: {raw.GetType()}");
                }
            }
        }
        else
        {
            throw new ArgumentException($"Unsupported subject format: {subjectRaw.GetType()}");
        }
    }

    /// <summary>
    /// Creates a credential subject from a JSON object.
    /// </summary>
    public static Subject SubjectFromJson(Dictionary<string, object> subjectObj)
    {
        var (flds, rest) = Util.SplitJsonObj(subjectObj, "id");

        var id = flds.TryGetValue("id", out var idObj) && idObj is string idStr ? idStr : "";

        return new Subject { Id = id, CustomFields = rest };
    }

    /// <summary>
    /// Parses schema from CredentialData.
    /// </summary>
    public static void ParseSchema(CredentialData c, CredentialContents contents)
    {
        if (!c.TryGetValue("credentialSchema", out var schemaRaw) || schemaRaw == null)
        {
            return;
        }

        if (schemaRaw is Dictionary<string, object> schemaDict)
        {
            var parsed = ParseSchemaId(schemaDict);
            contents.Schemas.Add(parsed);
        }
        else if (schemaRaw is List<object> schemaList)
        {
            foreach (var raw in schemaList)
            {
                var parsed = ParseSchemaId(raw);
                contents.Schemas.Add(parsed);
            }
        }
        else
        {
            throw new ArgumentException($"Unsupported schema format: {schemaRaw.GetType()}");
        }
    }

    /// <summary>
    /// Parses a Schema from a value.
    /// </summary>
    private static Schema ParseSchemaId(object value)
    {
        var schema = new Schema();
        
        switch (value)
        {
            case string schemaId:
                schema.Id = schemaId;
                break;
            case Dictionary<string, object> schemaDict:
                if (schemaDict.TryGetValue("id", out var idObj) && idObj is string id)
                {
                    schema.Id = id;
                }
                if (schemaDict.TryGetValue("type", out var typeObj) && typeObj is string type)
                {
                    schema.Type = type;
                }
                break;
            default:
                throw new ArgumentException($"Invalid schema format: {value.GetType()}");
        }

        return schema;
    }

    /// <summary>
    /// Parses status from CredentialData.
    /// </summary>
    public static void ParseStatus(CredentialData c, CredentialContents contents)
    {
        if (!c.TryGetValue("credentialStatus", out var statusRaw) || statusRaw == null)
        {
            return;
        }

        if (statusRaw is Dictionary<string, object> statusDict)
        {
            var parsed = ParseStatusEntry(statusDict);
            contents.CredentialStatus.Add(parsed);
        }
        else if (statusRaw is List<object> statusList)
        {
            foreach (var raw in statusList)
            {
                if (raw is Dictionary<string, object> statusMap)
                {
                    var parsed = ParseStatusEntry(statusMap);
                    contents.CredentialStatus.Add(parsed);
                }
                else
                {
                    throw new ArgumentException($"Unsupported status format: {raw.GetType()}");
                }
            }
        }
        else
        {
            throw new ArgumentException($"Unsupported status format: {statusRaw.GetType()}");
        }
    }

    /// <summary>
    /// Parses a single status entry from a JSON object.
    /// </summary>
    private static Status ParseStatusEntry(Dictionary<string, object> status)
    {
        var s = new Status();

        if (status.TryGetValue("id", out var idObj) && idObj is string id)
        {
            s.Id = id;
        }

        if (status.TryGetValue("type", out var typeObj) && typeObj is string type)
        {
            s.Type = type;
        }

        if (status.TryGetValue("statusPurpose", out var purposeObj) && purposeObj is string purpose)
        {
            s.StatusPurpose = purpose;
        }

        if (status.TryGetValue("statusListIndex", out var indexObj) && indexObj is string index)
        {
            s.StatusListIndex = index;
        }

        if (status.TryGetValue("statusListCredential", out var credObj) && credObj is string cred)
        {
            s.StatusListCredential = cred;
        }

        return s;
    }

    /// <summary>
    /// Parses a string field from a JSON object.
    /// </summary>
    public static string ParseStringField(Dictionary<string, object> obj, string fieldName)
    {
        if (obj.TryGetValue(fieldName, out var value))
        {
            if (value is string str)
            {
                return str;
            }
            throw new ArgumentException($"Field {fieldName} must be a string, got {value.GetType()}");
        }

        return "";
    }

    /// <summary>
    /// Validates a credential against its schema.
    /// </summary>
    public static void ValidateCredential(CredentialData m)
    {
        var copyMap = Util.ShallowCopyObj(m);

        var requiredKeys = new[] { "type", "credentialSchema", "credentialSubject" };
        var schemaList = new List<object>();

        foreach (var key in requiredKeys)
        {
            if (!copyMap.ContainsKey(key))
            {
                throw new ArgumentException($"{key} is required");
            }
            if (key == "credentialSchema")
            {
                schemaList = ConvertToArray(copyMap[key]);
            }
        }

        // TODO: Implement schema validation using JSON schema validator
        // For now, just validate that schema IDs are present
        foreach (var schema in schemaList)
        {
            var schemaJson = JsonSerializer.Serialize(schema);
            var schemaMap = JsonSerializer.Deserialize<Dictionary<string, object>>(schemaJson);

            if (schemaMap == null || !schemaMap.ContainsKey("id"))
            {
                throw new ArgumentException("credentialSchema.id is required");
            }

            if (schemaMap["id"] is not string schemaId || string.IsNullOrEmpty(schemaId))
            {
                throw new ArgumentException("credentialSchema.id must be a non-empty string");
            }

            // TODO: Validate against schema using JSON schema validator
        }
    }

    /// <summary>
    /// Converts a value to an array.
    /// </summary>
    private static List<object> ConvertToArray(object? value)
    {
        if (value == null)
        {
            return new List<object>();
        }
        if (value is List<object> arr)
        {
            return arr;
        }
        return new List<object> { value };
    }
}

