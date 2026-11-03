using Pila.CredentialSdk.DidComm.Credential.Common.VerificationMethod;

namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public static class DidTypes
{
    public const byte People = 0;
    public const byte Item = 1;
    public const byte Location = 2;
    public const byte Activity = 3;

    public static string ToName(byte didType) => didType switch
    {
        Item => "item",
        People => "people",
        Location => "location",
        Activity => "activity",
        _ => "unknown"
    };
}

public static class VerificationPurposes
{
    public const string Authentication = "authentication";
    public const string AssertionMethod = "assertionMethod";
}

public sealed class VerificationMethodSpec
{
    public VerificationMethodEntry Vm { get; set; } = new();
    public List<string> Purposes { get; set; } = [];
}

public sealed class DidKeyPair
{
    public string PrivateKeyHex { get; set; } = "";
    public string PublicKeyHex { get; set; } = "";
    public string Address { get; set; } = "";
    public P256Xy? P256PublicKeyXy { get; set; }
}

public sealed class P256Xy
{
    public string X { get; set; } = "";
    public string Y { get; set; } = "";
}

public sealed class DidTxResult
{
    public string Did { get; set; } = "";
    public DidDocument Document { get; set; } = new();
    public SignedTransaction Transaction { get; set; } = new();
    public string? PrivateKeyHex { get; set; }
}

public sealed class SignedTransaction
{
    public string TxHex { get; set; } = "";
    public string TxHash { get; set; } = "";
}

public static class DidIds
{
    public static string ToDid(string method, string address) => $"{method}:{address}".ToLowerInvariant();
}
