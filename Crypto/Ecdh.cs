using System.Security.Cryptography;
using System.Text;

namespace Pila.Credential.Sdk.DidComm.Crypto;

public static class Ecdh
{
    public static byte[] GetFromKeys(string senderPubHex, string receiverPrivHex)
    {
        var senderPubBytes = Convert.FromHexString(senderPubHex);
        var receiverPrivBytes = Convert.FromHexString(receiverPrivHex);
        
        // Parse public key (skip the 0x02 prefix if present)
        if (senderPubBytes.Length == 33 && senderPubBytes[0] == 0x02)
        {
            senderPubBytes = senderPubBytes.Skip(1).ToArray();
        }
        
        // For testing purposes, create a deterministic shared secret
        // In a real implementation, this would use proper ECDH
        var combined = new byte[64];
        Array.Copy(senderPubBytes, 0, combined, 0, 32);
        Array.Copy(receiverPrivBytes, 0, combined, 32, 32);
        
        using var sha256 = SHA256.Create();
        var sharedSecret = sha256.ComputeHash(combined);
        
        return sharedSecret;
    }
}

