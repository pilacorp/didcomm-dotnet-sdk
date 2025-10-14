# Pila Credential SDK - DIDComm .NET

Thư viện .NET Core để mã hóa và giải mã DIDComm messages.

## Cài đặt

```bash
dotnet add package Pila.Credential.Sdk.DidComm
```

## Sử dụng

### Mã hóa

```csharp
using Pila.Credential.Sdk.DidComm;

// Tạo shared key từ ECDH
var sharedKey = Ecdh.GetFromKeys(senderPublicKeyHex, receiverPrivateKeyHex);

// Mã hóa message
var encryptedMessage = Encryptor.Encrypt(sharedKey, "Hello World");
```

### Giải mã

```csharp
using Pila.Credential.Sdk.DidComm;

// Giải mã JWE
var decryptedMessage = Decryptor.DecryptJwe(encryptedMessage, sharedKey);
```

## Dependencies

- .NET 8.0
- Nethereum.Secp256k1
- Newtonsoft.Json

