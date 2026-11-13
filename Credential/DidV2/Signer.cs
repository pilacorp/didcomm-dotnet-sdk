namespace Pila.CredentialSdk.DidComm.Credential.DidV2;

public interface IDidSigner
{
    byte[] Sign(byte[] digest32);
    string GetAddress();
}

public sealed class DefaultDidSigner : IDidSigner
{
    internal readonly byte[] PrivateKeyBytes;

    public DefaultDidSigner(string privateKeyHex)
    {
        PrivateKeyBytes = Hex.ToBytes(privateKeyHex);
        if (PrivateKeyBytes.Length != 32)
        {
            throw new ArgumentException("private key must be 32 bytes");
        }
    }

    public byte[] Sign(byte[] digest32) => EthCrypto.SignDigest(digest32, PrivateKeyBytes);

    public string GetAddress() => EthCrypto.AddressFromPrivateKey(PrivateKeyBytes);
}
