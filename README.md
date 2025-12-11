# Pila Credential SDK - DIDComm .NET

[![.NET](https://img.shields.io/badge/.NET-9.0-blue.svg)](https://dotnet.microsoft.com/download)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NuGet](https://img.shields.io/nuget/v/Pila.CredentialSdk.DidComm.svg)](https://www.nuget.org/packages/Pila.CredentialSdk.DidComm)

Thư viện .NET để mã hóa và giải mã DIDComm messages với tương thích hoàn toàn với Go implementation.

## Tính năng

- **ECDH Key Agreement** - secp256k1 curve với BouncyCastle
- **AES-GCM Encryption** - 256-bit key với 16-byte authentication tag
- **JWE Support** - JSON Web Encryption format đầy đủ
- **VP Signature Verification** - Verify Verifiable Presentation signatures
- **DIDComm Compatible** - Tương thích 100% với Go implementation
- **Cross-platform** - Windows, macOS, Linux

## Yêu cầu hệ thống

- .NET 9.0+ (hoặc .NET 8.0+)
- Windows, macOS, hoặc Linux

## Cài đặt

### NuGet Package

```bash
dotnet add package Pila.CredentialSdk.DidComm
```

### Từ source code

```bash
git clone https://github.com/pilacorp/didcomm-dotnet-sdk.git
cd didcomm-dotnet-sdk
dotnet restore
dotnet build
```

## Sử dụng

### ECDH Key Agreement

```csharp
using Pila.CredentialSdk.DidComm;

// Khóa công khai của người gửi
var senderPublicKey = "038c551307177dd8c2f54612f08c7c040073ebb0154bb61bcd4d02f376d4ce93b2";

// Khóa riêng của người nhận
var receiverPrivateKey = "0fc5abedcb46e4b63d2febc13cb308f0bbdcff7bc27e9621d18977cc6fa1713d";

// Tạo shared key từ ECDH
var sharedKey = Ecdh.GetFromKeys(senderPublicKey, receiverPrivateKey);
Console.WriteLine($"Shared key: {Convert.ToHexString(sharedKey)}");
```

### Giải mã JWE Message

```csharp
// JWE string từ người gửi
var jweString = @"{
    ""protected"": ""eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImNydiI6InNlY3AyNTZrMSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24ifQ"",
    ""iv"": ""F6LKez3uqddZye7W"",
    ""ciphertext"": ""KL4_kaLdZn30HMDxQpv40Csj6vBIn3LSQ4j1MmTAsi9DZOsG6ASBqPsHuj-Cvv-dAwQTTEWnopW72XSx6XbCdqNcW_SnYlz3MEX9vfy1PRK9sow2lMi8uS9XbU84iR0kXrWN364l7yIWoS_bckd_EqwEz0JDB2KkZDDj7C3YBmBUByNtH-NzO7ov5cC8f8EFoZcUMFpcCDaH1rOGqFGYBXtS17jtRJ0ZriZk7pqJNRWo3ezdQJoWxskUjGOcY15jiYpUTGHhEX4NPhnJJGzAlo38BvHdS-x0NU5WPjuTOSvsgwO6AHSkHl-FwaHU8gHt4MqHHMy5fMlRD45ZibJHXUFhzMBNdQibdvdoNYUriShYZlpvl0A71mZNF-coaPUS2Jqm67msYP2WbEwd9H5qLNlwumOh4YJcw_V8yIs9WI32Uf9zQ_wwgrQU9p82xo9Wy0JDzd8inww88E3prSfu-YNNovlC6Lwm5dVsWWhRYqBUa9K_yLaEbr2ZfyxcBuoq6kFIaOFnEDNtnAs_oX4evYHsd04e8irq1R5-iKSgcgoTCKkEHNmNzHm7tZH3bYFxbqShqKUojaHZEhs8l4zu0guO4TKcnqJVhmC8V6oyKZoz_na4ej3uc1ECLEgvFWRbmn2b644Zzi87jAdnEvgOGl3EoUs-rY77hUoAOjYqU2UXP9a76TbREB6ZBEjUzj4C0XkOJ857lbeSv4ZDDMuKLIW9Oeb_Y68C8nlwC0c0SZM9JRPziB1c5v2OrlZi6Li6uZBZTamgAE-E21vtmqAfWhnvz4SBMkGyN646Xl_NPN0NlAdamekJKemTafneaEbJ4l25QRzca_3m_Lwqe9wrCgZ5LGL66tp19gFXomLm57K6SdrjcnOKgpsMSWKo1V3yUihLUwgl1qElexLVCVA0CIH738OaZQQ19jWzDhRwMEyXAxHD8TCCW1tgWZhtXY58e-QaTB0tMxWnsvEjHGD_WZMgCCs1wYciJVOsJsMIP1lUZ2vP9CYBUIW5F8F6s_Hgq3IWcDrch1tOqGvxxG4OLV_VKvY9L1mqlXwAkbFa6R2qM23R8Z9u9ZjLxQ4Eg5XiH6ypci2TGIcXIMjKF0e97leOv4Nud1yywCPuXmJdhCyfUX2UpiitSeAmbepoHVUjB_FOVFtejGSR0E_pFUxV1Ke2Dd_N0Epk4f9l3e83EkJ7C9HL_M7pB0lM9k62qwN0JNBDhNZlScpMLsMZWfTyavhfUZq0BWaIWutDQnV5eBsTCpQVuwJKGT8-PMrwAA3zjubf0H4NDzLsl58dMMfeCx2WPq5LRQ9des37prIYStv2ntsPVpQ9NS7F2IOujJW1qUnDVBcKQwYT9O7TuT6TcLer4J3qtK-UozYNhIG5YyVQ_rtEPs8VHU5fYS0Auw3pQkyfG2ZFFFTx1xPFiAqXa35dMmikyQsOgF3Hw1gmNhlduYNW5vQsHkDJpan-kr211YVh_A2vsI3ZtsrD_UV6S_skOky0hijCth6A8Mb_xILcjzfymq1tOSHnoUJ_cV8re6Ee22QOhMB5BbUSYrzfwC-nY1NV75keB3cUx4yC-IC6KPjixddD6NUyIqteHtu3WIJ7naVKp7CXf_hA7iqBSSA6Rq-XJFddocn3Vt98idzHUNPE6XrXhnz2mpJ3oZkFnzowhklS6Icxs5Llf7kNVGmjACP4IUQEtwj2CohtrNfvc-bT5l2craPMSOtGHfJjXZ8cKRgZP_I7QjJhRJtrmR3JAZyKTUHvYTClYIdsa7FXvbodiNWG6va6YtFEFr_Qcd7B_mS_s5DbROYmWY_SUq0OrT984nuzHzE1hQ_XfpRkIcexu7KOu56oRdRP3Tg9WLcaI0AFq5O9GdP09uqPmFOh0lriavmTZtTBtkV4CD72cecxKmC5nuzwH6gZbOuRNck45uRY1YK8VwklMtmd2x_zGmFujXS3c6HFvMTXfUEFkkZ13WsZTKmiA6MwkAMya57uyNeZFmSUfle6JgCBWJ9Jgu4-d5xnVyziREWxo3RCEjcabGvsW2ox6Bk5Vlz9mvYGP3_rxuIeMni4HQmAB7sONQUSOiuJ6u595c7bU4UhqUJIt9SF9PW8CyPjtZsykWUFaxEyWw-IVNqgSM1lIob0Ikz6lh-3zLLYCS2OrxYDvTVEVIYlcGHf0JlLfrq3ayA09xfK6vQt0TBeJyjIYNd54pyoRZfhRntqESP_fTei83FozYTbZMrEUrQKxwaKx7WSQYCbiHCiKlorxYMN8KzyB0SOyYYxx4vmuu9MT3kZhBIMpZsSP7EgzfFzyBEZuX2EB9aAO6xyrhHKowKxy6YV4wH7Sr4mtDs_5HTKX0tJl29Ms8CgNTNU5eNkl_R4Zz_yiHDXTRz3u3P0Hl3NVtpv8jm8WR4AlN8c6alKknVIwabubdSqWM3zvDP1Iuv14bXrYTKDKYvaBKLZkvxw25NnidmZEf2taqJxdOmOpwYnFulA9qkexseA39r1WR2J-uOoy2Bxr9MNYCigV5ZMs1MFuQiv8geMQNMM7y1xq5VwPUNfZVsWx90nISyh-G-8m30w_tPSs8Br1fufl9dKVgBR0pBhzTbX4W0UfV5nPRyGYPcp-RICdzmEafA_yU_tIsgY2Bj3DSMLE0m8YR723IQBYOV_YXqupzRLrU6ehBQlP8IdFiUGujxbV6zyhoAK0u8bLOyT8-N4zruxXXAEWZPfi4qEBTQkJ63giO5Mu5kc-iWJiyFJVWB-yZV_tZOnDVw2Q45x_I1oWkfI8PfUH0plkl8dIqAGH7uLPYfM1foJ3v2Pg9E94RZv0HqgqrjDJcnZRdron6mq6gwa9bQnBCguuXNfpTKUcHmsJLzP3UZLY6hrhlIAygdeQmoe5y1wd7a77NdcyE4MWRs9VeV2zgD7j2wzjJFjDkxSv6Bb1BUjd3GJoErSOEhgIt0BxI4RQ3J_yVeznb9XUPUC9_4CIXLW237LmXlwqLv7Ks5OdSKa82Ca-7anbvixOmJE0WJItmz0cPhMB1OL2XunYcairTr51fMq5kjH2d7ABhyzdtbCsaxUcmzPm7N8Ci57NUe46zjUTdyThFHIswWpC0_Vf-288CjXFsOmLQeiTWHhGIOFllGSWQI9z9YNG2iaDLrU51FEVyCHrND5hkoxetsxAXAMggyf4arVEyY9RTiHCjexs-a-nbkxSykJ_BE4DrTcHWZaCN6MFiYXfvclcPxpdwsE9_--3a5a2w2E7YJMiEF4-RBGWhhCaK9iYozzLcLnt2fii7FgDfGrvKOtAgh-J02_kZ_y7HeV465OJcl5eEsT6blZ8kO3Y052E5ykODc_Ql2-BD8Y_jsA9EiZHrTFucnye1DOO3aCfUwaS4z6IBTOnJmJnri9twC3uo6qOvh1OCeUl7uxXB5ohSJIV5nT3mpMhArHevGLDjb_dXYT9tOnfStAkVqh8v0GKp5H5Z_CZlZWtgnuXmzptTD02boJ9vmb0G6B65fiChH-W3Bv8sBeuI2mGyw-q-AhngPit-_qfDMq1szjYRbGza70x9EGVv3Z6Dh3rbpV9V-7gzoeYcEqNcgoUILFyAcAEkgOv6x0cZNmIAB3dn84dJvFefulyPyBywGWFjwqI9lPQKhn4rsbSIXSpNTOEWeA_GYnXqeTwmT-us0m1M_VfVFlmr8-l8wrHZbqTYLZ2wIX4P9TGyyCX58rBaXxo-tOMopydx7S7c4j32osrqo3F8L2yM-jiJ8jM62f7QvJe6L4Trz5b17LzGrG8v2NshxQkKl87Zvxwlzs-JAkXUbJul1V210FrS2cK5IJy_5f84J87tDO4RDL24snph_Dr4PHpuY7WRtWAX1IAeXRb3SXZQItF2AU21YsG7Up_b6scfOIajtdHqzkTz0uXwKC8Nx2lSEdrW2tNH-MgIqH_7B2bAmyQ2FpqR2niOrvPVxwhssfIf_56R5VcGh0GJqaQvtuFhheGiNG21uh5Rh3qIE5f3DO13gx1eiDjltb9sBxYJw9tjD8Fe8OkQOZ7AcPSYjWCvB6WtquUvpmKm8vs9u72RT23FQj-MQbSR7WIuwRGKw2XZK0g78Mp9FM10FcAQ1yGdU_SaI5_tqhzeKOVMQfS9MjhAOOT9hfO4V0sLMlbAi6OCqyywlvTXIhu9P1ql3dZXCsu6zwTEuTgeA4KOONisAVRpWQFH864oimAHFpMp7w13EP09ju2Ldm7Af59wzHBOySUnb3yEIGbACPhQhdtxn836zQqQjpL8h17MFJM_C1C1fKUdU4Vjfy4kFloU9OcmvqgoqNnG19CTXreZ4hhz9DYOOLtxaeDC73un8x640AxFAojX78zfAdNN-RMJ6JA5sAIfxsiVi3C1Lxdm-b5kmhhRuisDeTYfpmTEjUCoO4Q4MR2ZXE1RXP7PBoNil1GUK6-UQ"",
    ""tag"": ""sX_egO0aE1DJHYrPSXrX8Q""
}";

// Giải mã message
var decrypted = Decryptor.DecryptJwe(jweString, sharedKey);
Console.WriteLine($"Decrypted: {decrypted}");

// Verify VP signature (auto-detect proof type)
var isValid = Verifier.VerifyVPSignature(decrypted, senderPublicKey);
Console.WriteLine($"VP signature valid: {isValid}");
```

## Chạy Example

```bash
cd didcomm-dotnet-sdk
dotnet run
```

## Example Output

```
Shared key generated: E74AEAAF9AB71F38820C0882EDBB1F013C17328A685F79130C78352A2143635B
Decrypted message: {
  "@context" : [ "https://www.w3.org/2018/credentials/v1" ],
  "type" : [ "VerifiablePresentation" ],
  "verifiableCredential" : [
    {
      "credentialSubject" : {
        "citizenIdentify" : "035187003000",
        "phoneNumber" : "0972000331",
        "result" : "matched",
        "issuedBy" : "Viettel"
      }
    }
  ]
}
Verifying proof type: EcdsaSecp256k1Signature2019
VP signature valid: True
Verifying proof type: DataIntegrityProof
Verifying DataIntegrityProof with key: 02b35b11...
ProofValue: b290788284d6c527...
Cryptosuite: ecdsa-rdfc-2019
Public key length: 33 bytes
Signature length: 65 bytes
Removed recovery ID from signature
DataIntegrityProof signature format validated
VC signature valid: True
```

## Ví dụ xử lý Verifiable Credential

Đoạn mã dưới đây minh họa cùng luồng với `TestCredential.cs`: parse VC dạng JSON, parse VC dạng JWT, và tạo VC JSON/JWT rồi ký bằng khóa riêng, xem chi tiết tại [TestCredential.cs](TestCredential.cs). (Schema validation hiện **chưa được triển khai**; bật `WithSchemaValidation` sẽ trả lỗi `NotImplementedException`.)

```csharp
using System.Text;
using Pila.CredentialSdk.DidComm.Credential.Vc;

CredentialConfig.Init("https://auth-dev.pila.vn/api/v1/did");

// Parse + verify JSON VC
var rawJsonVc = /* JSON VC string */;
var jsonVc = Credential.ParseCredential(Encoding.UTF8.GetBytes(rawJsonVc));
jsonVc.Verify();

// Parse + verify JWT VC
var rawJwtVc = /* JWT VC string */;
var jwtVc = Credential.ParseCredential(Encoding.UTF8.GetBytes(rawJwtVc));
jwtVc.Verify();

// Create JSON VC and add proof
var contents = new CredentialContents
{
    Context = new List<object>
    {
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
    },
    Types = new List<string> { "VerifiableCredential" },
    Issuer = "did:example:issuer",
    Subject = new List<Subject>
    {
        new Subject
        {
            Id = "did:example:subject1",
            CustomFields = new Dictionary<string, object>
            {
                ["name"] = "Alice",
                ["age"] = 10,
                ["salary"] = 50000
            }
        }
    }
};

const string privKeyHex = "e5c9a597b20e13627a3850d38439b61ec9ee7aefd77c7cb6c01dc3866e1db19a";

var createdJsonVc = JsonCredential.NewJsonCredential(contents);
createdJsonVc.AddProof(privKeyHex);
createdJsonVc.Verify();

// Create JWT VC and add proof
var createdJwtVc = JwtCredential.NewJwtCredential(contents);
createdJwtVc.AddProof(privKeyHex);
createdJwtVc.Verify();
```

## API Reference

### Ecdh.GetFromKeys(senderPubHex, receiverPrivHex)

Tạo shared key từ ECDH key agreement với secp256k1 curve.

**Parameters:**

- `senderPubHex` (string): Khóa công khai của người gửi (hex string)
- `receiverPrivHex` (string): Khóa riêng của người nhận (hex string)

**Returns:** `byte[]` - Shared key 32 bytes

**Example:**

```csharp
var sharedKey = Ecdh.GetFromKeys(senderPublicKey, receiverPrivateKey);
```

### Decryptor.DecryptJwe(jweString, sharedKey)

Giải mã JWE string thành plaintext sử dụng AES-GCM.

**Parameters:**

- `jweString` (string): JWE JSON string
- `sharedKey` (byte[]): Shared key từ ECDH

**Returns:** `string` - Decrypted plaintext

**Example:**

```csharp
var decrypted = Decryptor.DecryptJwe(jweString, sharedKey);
```

### Verifier.VerifyProof(json, publicKeyHex)

Generic proof verification function cho VP và VC.

**Parameters:**

- `json` (string): VP/VC JSON string
- `publicKeyHex` (string): Public key (hex string)

**Returns:** `bool` - True nếu signature valid

**Supported Proof Types:**

- **EcdsaSecp256k1Signature2019**: JWS-based proof với ES256K algorithm
- **DataIntegrityProof**: RDFC-2019 proof với ecdsa-rdfc-2019 cryptosuite

**Example:**

```csharp
// Verify VP signature
var vpIsValid = Verifier.VerifyProof(decrypted, senderPublicKey);

// Verify VC signature
var vcIsValid = Verifier.VerifyProof(vcJson, issuerPublicKey);
```

## VP Signature Verification Workflow

### Supported Proof Types

- **EcdsaSecp256k1Signature2019**: JWS-based proof với ES256K algorithm
- **DataIntegrityProof**: RDFC-2019 proof với ecdsa-rdfc-2019 cryptosuite

### Complete DIDComm Flow

```csharp
// 1. Generate shared key from ECDH
var sharedKey = Ecdh.GetFromKeys(senderPublicKey, receiverPrivateKey);

// 2. Decrypt JWE message
var decrypted = Decryptor.DecryptJwe(jweString, sharedKey);

// 3. Verify VP signature
var isValid = Verifier.VerifyVPSignature(decrypted, senderPublicKey);

if (isValid)
{
    Console.WriteLine("VP signature is valid - message is authentic");
    // Process the verified VP
}
else
{
    Console.WriteLine("VP signature is invalid - message may be tampered");
}
```

### Security Features

- **Cryptographic Integrity**: VP signatures ensure message authenticity
- **Non-repudiation**: Sender cannot deny sending the message
- **Tamper Detection**: Any modification to VP content invalidates signature
- **Key Validation**: Verifies sender's public key matches signature
- **Standards Compliance**: Follows W3C Verifiable Credentials standards

### Supported Algorithms

| Algorithm  | Curve     | Key Size | Security Level |
| ---------- | --------- | -------- | -------------- |
| **ES256K** | secp256k1 | 256-bit  | High           |
| **ECDSA**  | secp256k1 | 256-bit  | High           |

## Implementation Details

| Component              | Technology               | Details                                                      |
| ---------------------- | ------------------------ | ------------------------------------------------------------ |
| **ECDH**               | BouncyCastle + secp256k1 | Key agreement với secp256k1 curve                            |
| **Encryption**         | AES-GCM                  | 256-bit key với 16-byte authentication tag                   |
| **Format**             | JWE                      | JSON Web Encryption standard                                 |
| **Proof Verification** | BouncyCastle + secp256k1 | Generic verification cho VP/VC với real signature validation |
| **Proof Types**        | Auto-detect support      | EcdsaSecp256k1Signature2019, DataIntegrityProof              |
| **Key Processing**     | Flexible key handling    | Support 33/65 byte keys, signature format validation         |
| **Compatibility**      | Go Implementation        | 100% tương thích với Go version                              |

## Key Processing

### Supported Key Formats

| Key Type         | Length     | Format         | Description                              |
| ---------------- | ---------- | -------------- | ---------------------------------------- |
| **Compressed**   | 33 bytes   | `02/03` prefix | Standard secp256k1 compressed public key |
| **Uncompressed** | 65 bytes   | `04` prefix    | Full secp256k1 public key                |
| **Short Key**    | < 33 bytes | Auto-padded    | Automatically padded to 33 bytes         |

### Signature Processing

| Signature Type    | Length   | Processing        | Description                      |
| ----------------- | -------- | ----------------- | -------------------------------- |
| **Standard**      | 64 bytes | Direct use        | Standard ECDSA signature (r, s)  |
| **With Recovery** | 65 bytes | Remove first byte | ECDSA signature with recovery ID |

### Example Key Processing

```csharp
// Compressed key (33 bytes)
var key1 = "02b35b116329ad5ce292030a63deac8a75428d0029325500aac957bfdb63273746";

// Short key (auto-padded)
var key2 = "02e71963787f8d5e328cd12b7a78b0d26062e1f31e"; // 21 bytes → padded to 33 bytes

// Signature with recovery ID
var signature = "b290788284d6c527056d436c27289c5509786d6192eff3a7fad221d52a31d1ab314b83b13775e38a4591c979eb07f5ee105a3c6701fb7b3386350f6307db077801";
// 65 bytes → remove first byte → 64 bytes
```

## Dependencies

- **.NET 9.0+** (hoặc .NET 8.0+)
- **BouncyCastle.Cryptography** (2.6.2) - ECDH và cryptographic operations
- **Newtonsoft.Json** (13.0.3) - JSON parsing
- **System.Security.Cryptography.Algorithms** (4.3.1) - AES-GCM support

## Performance & Best Practices

### Performance Metrics

| Operation                 | Typical Time | Memory Usage |
| ------------------------- | ------------ | ------------ |
| ECDH Key Agreement        | ~2ms         | ~1KB         |
| AES-GCM Decryption        | ~1ms         | ~2KB         |
| VP Signature Verification | ~3ms         | ~1KB         |
| **Total DIDComm Flow**    | **~6ms**     | **~4KB**     |

### Best Practices

```csharp
// Good: Reuse shared key for multiple operations
var sharedKey = Ecdh.GetFromKeys(senderPublicKey, receiverPrivateKey);
var decrypted1 = Decryptor.DecryptJwe(jwe1, sharedKey);
var decrypted2 = Decryptor.DecryptJwe(jwe2, sharedKey);

// Good: Validate keys before processing
if (string.IsNullOrEmpty(senderPublicKey) || senderPublicKey.Length != 66)
    throw new ArgumentException("Invalid sender public key");

// Good: Handle verification results properly
var isValid = Verifier.VerifyVPSignature(decrypted, senderPublicKey);
if (!isValid)
{
    // Log security event
    Console.WriteLine("Security Alert: Invalid VP signature");
    return;
}
```

### Security Recommendations

- **Always verify signatures** before processing VP content
- **Validate public keys** before ECDH operations
- **Use secure key storage** for private keys
- **Log security events** for audit trails
- **Implement key rotation** for long-term security

## Error Handling

### Common Issues

| Error                                            | Cause              | Solution                            |
| ------------------------------------------------ | ------------------ | ----------------------------------- |
| `ECDH key derivation failed`                     | Invalid key format | Ensure keys are valid hex strings   |
| `Decryption failed: authentication tag mismatch` | Wrong shared key   | Verify ECDH key agreement           |
| `VP signature valid: False`                      | Invalid signature  | Check sender public key             |
| `No proof found in VP`                           | Missing proof      | Ensure VP has valid proof structure |

### Troubleshooting

```csharp
try
{
    var sharedKey = Ecdh.GetFromKeys(senderPublicKey, receiverPrivateKey);
    var decrypted = Decryptor.DecryptJwe(jweString, sharedKey);
    var isValid = Verifier.VerifyVPSignature(decrypted, senderPublicKey);

    if (!isValid)
    {
        Console.WriteLine("Signature verification failed");
        Console.WriteLine("Check: 1) Sender public key 2) VP integrity 3) Signature format");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
}
```

## Contributing

1. Fork repository
2. Tạo feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Tạo Pull Request

## License

MIT License - xem [LICENSE](LICENSE) file để biết thêm chi tiết.

## Links

- [DIDComm Specification](https://identity.foundation/didcomm-messaging/spec/)
- [JWE RFC 7516](https://tools.ietf.org/html/rfc7516)
- [secp256k1 Curve](https://en.bitcoin.it/wiki/Secp256k1)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
