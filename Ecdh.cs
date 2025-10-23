using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Pila.CredentialSdk.DidComm;

public static class Ecdh
{
    public static byte[] GetFromKeys(string senderPubHex, string receiverPrivHex)
    {
        try
        {
            var senderPubBytes = Convert.FromHexString(senderPubHex);
            var receiverPrivBytes = Convert.FromHexString(receiverPrivHex);
            
            // Create secp256k1 curve parameters
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            
            // Parse sender public key
            var senderPubKey = new ECPublicKeyParameters("EC", 
                curve.Curve.DecodePoint(senderPubBytes), domainParams);
            
            // Parse receiver private key
            var receiverPrivKey = new ECPrivateKeyParameters("EC", 
                new Org.BouncyCastle.Math.BigInteger(1, receiverPrivBytes), domainParams);
            
            // Perform ECDH key agreement
            var agreement = new ECDHBasicAgreement();
            agreement.Init(receiverPrivKey);
            var sharedSecret = agreement.CalculateAgreement(senderPubKey);
            
            // Convert to byte array
            var sharedSecretBytes = sharedSecret.ToByteArray();
            if (sharedSecretBytes.Length > 32)
            {
                // Take last 32 bytes if longer
                var result = new byte[32];
                Array.Copy(sharedSecretBytes, sharedSecretBytes.Length - 32, result, 0, 32);
                return result;
            }
            else if (sharedSecretBytes.Length < 32)
            {
                // Pad with zeros if shorter
                var result = new byte[32];
                Array.Copy(sharedSecretBytes, 0, result, 32 - sharedSecretBytes.Length, sharedSecretBytes.Length);
                return result;
            }
            
            return sharedSecretBytes;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"ECDH key derivation failed: {ex.Message}", ex);
        }
    }
}