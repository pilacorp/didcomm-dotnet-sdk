using Pila.CredentialSdk.DidComm;

namespace Pila.CredentialSdk.DidComm.Example;

public class Program
{
    public static void Main(string[] args)
    {
        // Example usage
        var senderPublicKey = "03951a8f2673371c1ad37e6b0e00dcd4800a777cfce53857115cb2ab3dbedbda22";
        var receiverPrivateKey = "3756330b933a117066e4509ef87b2d82ce10829208ecdd52c9754ddaa1abe746";
        
        try
        {
            // Generate shared key using proper ECDH
            var sharedKey = Ecdh.GetFromKeys(senderPublicKey, receiverPrivateKey);
            Console.WriteLine($"Shared key generated: {Convert.ToHexString(sharedKey)}");
            
            // Encrypt message
            var encrypted = @"{
                    ""protected"": ""eyJjcnYiOiJzZWNwMjU2azEiLCJ0eXAiOiJhcHBsaWNhdGlvblwvZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImFsZyI6IkVDREgtRVMiLCJlbmMiOiJBMjU2R0NNIn0"",
                    ""iv"": ""WIeBYfTuEA4kMeFa"",
                    ""ciphertext"": ""UmSpMp2Pb0ZCwN5OEpx7c7j4HHVYxKq6Rc0GgqAHLG9zTtu1RcrdoP31r-liAjPZu_uGNjOih4XK9tq7tASiLe4RvcJKlGg3nttJReoOOVpbZDkJAKr-N6r8I7ubCdBG3mXmg-rpU6wODXwar0nD1wfO1MTrKD7ENM0SY15r_Qvy15UZmOOuU63T6ZIgLHCMvtaOks5nefdf2hhacU8nqQyxKdouwvvX1tA_MxbhlGMf7rv9UpYl7VRX74QriAcAX0BR6NijuicBsVV-IfYTPRjfDtTr3I5aa_9hGt-I8ngaKxdYubDpmxcuyxK1kvoGtpChttAgfDIKJ0Q7yYdokndPUUvutWFZe-W3qpTzZWMzxtzkT7mN9XW31-4twSZ6Tw53PJ8U_w7_WfDIsQOZvsZNCfE8hLXS4DMDd29FZWNF-rJgu5hWBpPxu4cKfGj0j51mNqQQRlcCxsc51HG98qP-3naxH01l9-VcgsnY6Lapcqxd5gvsDK7_5CHoBp6oZIcZ5cIErTfDm7lHW-joClmfA03upp_4rtTa1AVhfaKHUb6uNkBBl5aag7PeNKAWQ-cgMNygZ43nejEOCGzRbho8fQ88WgKFLStit6IR4tXXRlEJ4--4lw1l37bJW3hlaZSOgph25aWYExSWxXRw8PRtfFy3F81Es0YiWMhNXB33TjHZsEI-zYqS6oIMrNc8rpgIcBakQn4Z0Bgbi_NfV9_wlQkqxntiEEJWXRcDUxWx3coGz5AklQgrrGugN0-3NdWqgFDM4f7Gc2aAgMB2P76EK-C7ISu5fdRYqR8BVUpyPmoNOAGaYeGodDDPndnuos4m601EIvpnStxsPQhuoB_A5W1sHciLLbhH2UlZNNpz7Z3Pf_0uY5MDOHhm_1D-8AY-FmfQP9a9wNgiflq6KdLmrY2aWxTbOPLbEFdNNIAupznUiKUA8IkQ3Vs-5TstxmQx_oYk5LzDDYE_vtIY6AEEv90re-SKocRlOEc1w8Kur-3qRNL5FKW6-O9kk5UIEQqJX7rofqmid18zQxTUIWw64SjO8UYqtjFKmbRqTWs1zUhXrhfjyE4fGjkdpIIt5I_4N5Uy5rbi7lQS_tIQxZXmqFpp_jZu_wbyBcOfqM3Dkv6kftnyC1Xyo57YIKYqv4NGG13IZv7E9rromsD66SeGNU6hXhvMCf-PZ2oHwZECnx2O1pWH64JwEGmYCH1qS0pcMMA0si_Yfd7wN7nzqdUGZ4hl1H0k41J6aB-1VggtNx779IZY3c1lzomgbreUEcZtESxUBquolOPon1_JOmeO2LQQXQ4rqi0w7g_TrcTHetM48t8K1-Dhr-_reNROLpoR-YvdB3Ez318sRNFUG3r6DFZQDd198bdS0SndNiv90X_UweuAsRUdAp6_z1ExNsa7wAZlgxlEXMlcTBOmgKkuHy_tZ3khGPYVMuqOAzk9ettAlgLqnes_ypk0K0Ba_it-hA5XdmchZgh4I4HWBGMUbLoBGsuK9cJILe2eTxPc6euuTBCUaRKmhdMUqPqVt7UxIYrWbUNWQKWhDQV6kQlEKOAvDbOPqwAcqDtuchOc83uOncZNqbxW76O5lDmMtVtAOVCi88R8NRcCo3edmr2iXKMLOigHq6x-3pT5t-K-egeGa_CCknQsAeAjU35mQON7pRktFsTVkiDTgw8HBz-s7y0DPifk3v3sdxtrKLN-48M97dwyYJl22dHkpH76s-W9BHaeqzP3IeT-61pYTuY4II3n1YsjyStQM8gBsoCPEHIifMr-J1UZFIrd1FRVPGTqovEj6DwBV6q3Ne9w7yGKvoAP40sPe2cCSkHhI3mYOE1FaCzBrqOo6o8NmxDiKro3GUrMaYSBuSqJn7yzg2PhQmVzgLCWGEWRXdoTkxB9oY5ukOClXE5dk6bXDlJDTJWSqtJS4gvZ7Lxlj5HoZeihmQAtRKxazy-QRJ0cfTxkySICFcEBhafMxZ2HToGS7Gg9C5QGbcGHuLukHdejTryOWDOfuD0_YvqcQnwZ-c3nlwSibyOhO1G9xReN9TbQOaYG6HYxYmbn5BjowXjVrE5t_lpDtRB1X2iXdMg6jUBecC0CwiUT167WPeUxcWotlHzaNCZjj6IbhF45ifMgPY8Tb9U_oh8BDIHoN0RWSxKDIgJSxb-5_xfVF5t0pshjf-ElIozYGWC67o9OqFiIty4eiljfq8AsUibAmfRUVcYBPv-HMZGzRROhe90vfC85E8wLIJVU9eWTrA8jzDfhYZfKedVZwmZfNaT4UpVLjfkgOkEUldm45xUK7POc3nvhTFxWBud2W2ePsmhSz6WCUsjF6IyTCmEyhksYnrdv4gvF9j2NmrICYqSl3DJs4ALFSyQQgjchjI92knZV7sge9iOzCH-TdFg_Ya1HIVV5riiNSY9P25wF6M1UFVUGs4K9T-isCi578gakslCxjZBOIgRaxdQYbf-vOPUjOPE7Bjlf6qIv-GOK7N6eWfjSz3BVt47RBs6TioZyOPRYAL9EH3foBisoRu_yyM8xvdPgumOuSLeReqDUlf8TN-RVQblnw4MUjS2dgWfcUk3KS7syn2gePlWRUYZbmoQI9Bok5WX2H5C3Ck-2vJ4OQUg2RBJX91sCaMBy4V3UDu-OnrtlyM7zdUOr8pjcWBw5o7qaDKU-uMtAlDruMu6dMiNe8sX-h5xptS6cPh1njmpWE87J5jGTgOGsUXSKMwBr6vhN35sksZu49HfZPJjHQHvUkM5exxn2XUZK_sBwpQ6tbIlO9o82UUurnGy06RbYZ3e17ZWEZ0X4ijLMLPojJ6KjH54-SA1yNhTW2bhj3QD5doRhEuQE4p40XVGMrdjhvfnlM4P1I-UX5EqZzF_pDTwppssDxEBbLXKzIrNFerrAX3QlfevWet7dXpDk2h-dvQFl8-HjNFtSN7-jhaDCV9bbqgN3m6JXfpfQEURkCLzoOhNrHR1sCSelPmHUchhHR17TtR7HOkge9Kvr_DE3UNOSX02ZV7R5qq3zbw3m93nD4J2l6tHiYR4xb08ywSPj5Q29gDs-DnasX41TNmQ1x5cfLqDZO2nbTlq4Cz8ijVJkoOlgd6_xRf_KnQ4aVyLvPuzbeBiXcY9aClld2NT7DwNFb7_mzd04_jqaEOpRg7CUTaUtCsKCS2KM0Q_h44IUhwjKBYKKZ7BLsLlxMqfAYknrIOGfO0UAHpwnhQ7nzPKWUWNWozmnPcuiBtY5GjzNlrbxVVwIjmXvMfu2NPlcde3eonX9a7F3S8VjI1CYp6ldW576AJNYigzWMgd7-xSSq_8wK6LKBF-RcYsfI4_gh2CZvImk0-NEgmMuRhW7QPw0e8Vsd5RCY7K7RP2lWCjUyTC5yI5Gh7YB1EvTehwHC_MD_N_lF7hP8Gs-GYl4UeZH7ByQBX06Pda-yVF34F969ARJiLZPDNep-XWLj-UA2VrkyStFv65e7knDRgmjlKoumWsCXVHlOSorsY9s8cbQn3LSTaXtto2at6ORXC3EBdyr7JHveCUx5kN8ZD41FAZcb3MrCiqPcgkh8QQCup-t_ARXsGvCvcPbCtOYuDe6ePB6Ih2khBaSSjV9dnpovHlD_QrzyUi9Esyfv1aTtjukd7OnjUqaDUwOeNspZtXXBFtaXaC07cu4RqomHD42oPGsRcqc7r7YLGzXoVgG7C-IyKkgDmxDWyeeRctJ0lJJhA6057O-vyHlsEdMLsZMzMTQH4Wo6CwqmP9EhN-MSl9r4qe1ZcQlWZfTlw4oMA4hcZujPsE2T5XapfSgDwmtzYBYJRfJP6RucJ66swvvktVSz68PKDFXBebzryvAQHQAlkma2oHjfPw90NcWk1C1Aqj5ButbpaCtH579Fdj8jdDecDuWM4viYmDyHagtK-OU5Mk-MOuc2vkVUwOQg3IeeT94CJS1kKAv1XxxFJ9Af05RYRlTz4sMN4mPqOEYVee-Qf225Sm71cOm_NlIPuE_UKgsYH2rRq9LNB4jdCaQkE4z5RST1j_X3jtcCrXW6c1TxkPfGTsK7rs0MGpaIlzetlkTGbTehT8AwwfVsgjyWw1qLR1pAClf-t8Qo5M_yHlJLJL3K2yF28mE2x02AFTiXpmA3D9_XKwmf3GiGgxwpo5CQZWJ8Zu90gYK3TraYeOCVqTtZ3E5p-cgqlgGh54Au2xtRJlHO79qt4yyp_D9OP9mqo5yvW_j-dXaLEe20het7bNsBD9nHoCpUHyyOZhgPPQqwVxzwUdvPcadRUoXGBZDifbCPkJMopvsGpe-T3gfmUXcjxT03Ir1onXBImRpdr3UQDrmDE3Z_RI-cO99CORZ_Kisy038pT6Shh2fkySZSVVerjwqUFOPPrreun2HUfVybJpjYy1odc8PJfsX3n3T_ivA0Hp-cimQVAqgxs-n8M1_Uq72dzMDqGn_nInFO7bWLlOe9VoUvSbwggEZkMAeCSj-MysiY242AzdGR9wst2MMreK3BkwpsP_Xe8nGvt59ND0oq1p1huJBa-zwXkfIcWHlOKffxd-cVheuxX4"",
                    ""tag"": ""4L72ufhEUaVHSVyITsaowg""
                }";
            // var encrypted = Encryptor.Encrypt(sharedKey, message);
            // Console.WriteLine($"Encrypted message: {encrypted}");
            
            // Decrypt message
            var decrypted = Decryptor.DecryptJwe(encrypted, sharedKey);
            Console.WriteLine($"Decrypted message: {decrypted}");
            
            // Verify VP signature
            var vpIsValid = Verifier.VerifyProof(decrypted, senderPublicKey);
            Console.WriteLine($"VP signature valid: {vpIsValid}");
            
            // Extract and verify VC signature
            var vp = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(decrypted);
            if (vp.TryGetProperty("verifiableCredential", out var vcArray) && vcArray.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var vc in vcArray.EnumerateArray())
                {
                    var vcJson = vc.GetRawText();
                    var issuerPublicKey = "02b35b116329ad5ce292030a63deac8a75428d0029325500aac957bfdb63273746"; 
                    var vcIsValid = Verifier.VerifyProof(vcJson, issuerPublicKey);
                    Console.WriteLine($"VC signature valid: {vcIsValid}");
                    
                    if (vcIsValid)
                    {
                        Console.WriteLine("🎉 VC Proof verification successful!");
                    }
                    else
                    {
                        Console.WriteLine("❌ VC Proof verification failed!");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
        
        // Test specific VC verification
        Console.WriteLine("\n=== Testing Specific VC Verification ===");
        TestSpecificVCVerification();
    }
    
    private static void TestSpecificVCVerification()
    {
        var vcJson = @"{
            ""id"" : ""urn:uuid:78cdaacd-eabd-4253-bf30-535635425642"",
            ""type"" : ""VerifiableCredential"",
            ""validUntil"" : ""2026-10-23T08:23:20Z"",
            ""issuer"" : ""did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e"",
            ""proof"" : {
                ""proofPurpose"" : ""assertionMethod"",
                ""created"" : ""2025-10-23T08:23:20Z"",
                ""proofValue"" : ""b290788284d6c527056d436c27289c5509786d6192eff3a7fad221d52a31d1ab314b83b13775e38a4591c979eb07f5ee105a3c6701fb7b3386350f6307db077801"",
                ""type"" : ""DataIntegrityProof"",
                ""cryptosuite"" : ""ecdsa-rdfc-2019"",
                ""verificationMethod"" : ""did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e#key-1""
            },
            ""@context"" : [
                ""https://www.w3.org/ns/credentials/v2""
            ],
            ""validFrom"" : ""2025-10-23T08:23:20Z"",
            ""credentialSubject"" : {
                ""issuer"" : ""did:nda:testnet:0xe71963787f8d5e328cd12b7a78b0d26062e1f31e"",
                ""citizenIdentify"" : ""035187003000"",
                ""result"" : ""matched"",
                ""id"" : ""did:nda:testnet:0x3b5a8585b78628410530014c094abb86f6b33cdd"",
                ""issuedBy"" : ""Viettel"",
                ""issuedDate"" : ""2025-10-23"",
                ""phoneNumber"" : ""0972000331""
            }
        }";
        
        var publicKey = "02b35b116329ad5ce292030a63deac8a75428d0029325500aac957bfdb63273746";
        
        try
        {
            Console.WriteLine($"VC JSON: {vcJson}");
            Console.WriteLine($"Public Key: {publicKey}");
            
            var vcIsValid = Verifier.VerifyProof(vcJson, publicKey);
            Console.WriteLine($"\n✅ VC signature valid: {vcIsValid}");
            
            if (vcIsValid)
            {
                Console.WriteLine("🎉 VC Proof verification successful!");
            }
            else
            {
                Console.WriteLine("❌ VC Proof verification failed!");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error verifying VC: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
    }
}
