using Pila.CredentialSdk.DidComm;

namespace Pila.CredentialSdk.DidComm.Example;

public class Program
{
    public static void Main(string[] args)
    {
        // Example usage
        var senderPublicKey = "032c9d922daa04d446612b168180c649752316456944a6d36e0dbcf4dc7c299aa5";
        var receiverPrivateKey = "3756330b933a117066e4509ef87b2d82ce10829208ecdd52c9754ddaa1abe746";
        
        try
        {
            // Generate shared key using proper ECDH
            var sharedKey = Ecdh.GetFromKeys(senderPublicKey, receiverPrivateKey);
            Console.WriteLine($"Shared key generated: {Convert.ToHexString(sharedKey)}");
            
            // Encrypt message
            var encrypted = @"{
                    ""protected"": ""eyJhbGciOiJFQ0RILUVTIiwiY3J2Ijoic2VjcDI1NmsxIiwidHlwIjoiYXBwbGljYXRpb25cL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJBMjU2R0NNIn0"",
                    ""iv"": ""vwHAsvPxoSQt6qo8"",
                    ""ciphertext"": ""PdN29Gsp2Uquh2sjZPMi1IAvU39ZEgkuM1wI0iWwRqkzg_TQhBJhBRWQD8wHCxxNvQ4QyoeZU3tAOzN3b-dv8ZOq1iWZ1NVF4rcHpWrS-RBv4MmOIPXXNthatc7yH1x9lzbjNhdYThwY2fojeJtbK5EikWb2Cxfjg5nQ31ZkJDuKK3tyMZNmPNKX1THK0vp9R9haYkOjK3o9EyezRvuCTUXDJWd-aEw8n7Bm8JNueUw8Yw-jDcrXVC5QfO2-c3BnE6c57DrSkrHtg-K657fCrJ3sj1mOSw6scGs1-NG9WMB0VyT5LGQ31JpXv_24XrqKX67qFALXAiwu3uEaufFfMSDIw7tQsSY1kU5ZdXUWGzQgptkf37PGjhpWhDY6SieWuYmsfYMO5ZR_SyYJfBj2jOnEqQO53N8hpbEe6ZVUiwxQkd4N6YIi_6k57AneeRlBrnP5AlWnPIkZpvTBk_Gjogpy38IiDt4ZtAuvz5R327FbXpdwxokhaD6kA_OXQFkPr63MUdwUNnqO6FDx20izrW9_B5CoT1GYPW00ENxSSoMC0fXdTmS2I8a9wTHXzaUtlRSQ6XHqeclavsZTPgeWWtGdQ4DpeTvygNHmpzIIGvaRzGGd3ZrJsWzGRUSdGE0PoccY_Jcuo5lJ3G162wdnPIJiVhEEos1cPTzg24ox-v5qA6ibtfxwGSElLd_DUbwwk2I_4u-vLcSTJgS7eQgOKtrVnhNk0YTVlrhnDnIN_oWKATDjf1mxUoNo0fOkOsxWQ6jSbBOOrM-ROAevJfEq4bIYIdb10LCQ2uVOybJ3BbuJfJJFREry0MYJ75R_MXNJlZXFfaCGqWrySZ_PtEkb4hsrR6-v6kkiHWJYVncSY0VWHaU2sLmkN0ILDX2-sriLcySXXuRcqUvkNPp5tej4BOS_VwyDlYJ6RAoyvItiWqrqhUD3AX0iEA6XyJLMT6xjF5cZ46dlgPY8FVx6ulfD3ljMjK87dflNvW7ueWDtDt5PDRKoiYCbRNva-bjSamP8h9I9BoMysuWHVGkBMln0_ww2dniyDtPRzodHANlal66kfzAmx5seE_97cZrF2zY3JwjzVeUNUD3E0NrwQY3GXCnv-M3Rwz2OdYJYkVSOJmfDLmnIZHiN7pgRBIOJ89KS6TNweOhqXx-XwjDXBbzsLCQ6O3zIscZJ60EuZOjND_jw69uVRiLmdAryv2rqt2pBBVplS4fh3AbEEwiAX-01pztu5EwAChNxsAsjQnbsX5dAKypasKdIHmsRPsPU0k_cTJddZQRSZFuAjluA0yV-NJaej3XoJPzLUQ7DCbTR-6eTROgrBzCe9MXi-0WIIme28dCUe7TBqiSNG9q8zqnhTBp5OHCIzhojX1wX1v8cnHTWxYlii-KWHX9YMdEukQwnVT5hi_ipFUu6KRoDzOgYAhUZE2ZYLxOw8WnwbU5p9aIlslvDm8acQ9BOBSde0qRinv_Ss4seBc5FqQI1AB50d25CNMwk1PbjUxDuEn8ZrXI2lRy3tRdYC8KGqn2Sx3Xz7AGHm0h4q7ZepYjvAAQNpZnfgfQlY-pCjb0qVFq71LLEaNQ_V-Rph8Mi7OaI8_pDPoHDHCApkym-hr35qs3e7aDPuduTe0y5n15Oe1hzOST3a1-7TL9g9u77fUXHVCLcQEQQNrWuhLhn6TGn7oKo8zFyJTHIQFBHNgjebujmzZEWzKAqwvfqCCUMMicqI0Evxfs96D7aR-S2rnlmXa4q3qluaCGiO1fzaGKzEAx-P-kqkU2_YNrFX195GPip7oFA0RBnKRWBgFJlCAGyRvs_q4g6OiJNH8_hjxR_m02dFT-sqYtiSK423aSU4lK1VrB38EpYlzDvUsvmVcg3EYv7EK-6jYMFk8x9pBrcf9dOP4HALWMs4SwFInFmxOW-X0WKNkoXvDkDy7c6ENX0TlNHKjSx64vVgX8ZXUqrYAs02r1B0Y9vG3j2G_jTERGlhWvLyvXcvjabYrpUdSRTru81rRvk2nBaz7tc_HvgC8esPQJzQEv4eV8IuPHFngRvJGNsCAfwyG4LN7al-5egTI4Chn4NghrIvzASELmv7WrEt-QkaQO7uku1lapYV8FL1PvygZwfQLBQLE5ADye08rA8jpeMkBKVKVLhHUiLNSltMROkByRWqaC_iUJByJFbyS4xr7aFVssnXNlQ6YTTRyONV36hHlY6FyKV4MDxFv7BdOyPUI4v1hGEVC47IdKgPZ958O0wCYiVqGRCU-ngprm5MG343CPyqKy4NSTByu_FAKDzTqGlrWQIi2ziJ4FFPYPfsRUy_Ow1BxmIUKYT-pKR-QMe68nurYyvzFXPF5e5O9RR-qJ_-9gtl4byVHYgAOHoXPlrgdxSempf2t_YzrOlaZmhIe_jbODb8lIdeGVI2fED2DC_T_6PBaKIwAVFdyqLK2tpwrjBLuE5gg1DFz95VdvWzllxrgNwQXPgLnTCHD82xn8sogh3cYwKqaYwCaQDq4Qwjw8VVl_NsLwSeW5pBo_dIA5mwPmB-omAICRgmPig-CIc-WI1CJ-sEZs9vpbyOv11UNvCd05zj-uLKxJRc-7l60v-VVqSl6ZR8ufMZSZYYLCsb9Rtq4O1b0d0nnbj3dT551iqzCFP7XrPqxYp_ny3oCS-DIwuE2_BRf9n0Obaul45hwfJMELpma6Tiumw0GMzHbUBjj2_5pv0dMKTtpRo6byuS5ZygoxdRk7JMP3kIuDyi2LkXR5_RpgBmSZz2LIlnkCqS6KMg90vR5huaJUrfvMmzmIQ5kZ4ALkt6DAVI8XbyGpdwuACvA_GXnPsdhwegxQKYWg_j-xhFJY7tT5w5RBSMd7vEGQih11_JPGz1aZMf_E8fyqsC_mM_kx_J3xYD6lDBwTLANKbJ2LhM6eO_4dK-x680HA0OCSj1rZz1woOQK5RceieS_AtcfsYJbZBUsz8yv158EfPiGYmCVzpYtAdgBMb4vd0LGJd5CViOeBWKFshEhvVUzISY55jJvodg6CnfU3xiARPf98MF6RfxC5T8tVJc6psGxwq5gWu0rTMQvUn41zTLjzfLfprKw-huazRk-LYqEDPyCAaeZYUgIOZn7zR6kYVairN0bmF6KJtWhUYNuPJ7ouDavudbC6sF_nsTqiVaBkhhCno5fd996tQUnoM03jt1bcD52tAzgpI7uuSeScutWj4PWlceNo4ab1UHFmK0ZqnFuGtXFDGvLNKMvfPHsJuvXPfBDbbEMOWbOtCLHAsvxW1EGgqFMv5E4ULuOBZ3zdMZSW88K4kEAddagVZXvs-pOvd-N5QCs958rHXyTIHlMUPh0IYMJySwzVia2vFJSH82rwuQ4N2OWtmhPaZbCtr1Jil7PszT25xRhjLiMr8Kv-_lnz5HWQ-zhrB7JiFwXRxW-wOr6rh2OXGpPnRPplef5dXoDKfQsbAwJwuSQvXkkVY5un66fRTLXpwHkfnxObFr33WF_qORx4oMOcbLXDrdcznI2ODIykTWh4fcaH4QCXk7pMlYoVJLJ1zXJ8ABNRjvLnvUmw0TmyS6sQlqfS-hF8wQmpqLowzWH71b-GIRUvqSw3mVCbiG2sZ_39WI7JXIbUnjao7SS66p5yUnYPV6A7IR_7RKQs43XoeYeC4AP_ese4pGDD9OPGzRbpi0Nid9CClYhgd8Do7_coDoDOZPctR5jxRtjahCY791eUI6GZ_Lh1DyvyJGu0hnvv-UOOPGcdlUU7NuVwx5BXu5BJBKtxsMoXd6cB5aAKW7cGwszMqUWOH8QCFv326KbxCdny1XKBpFp4XomiQWF73Pvmwp4OmhJwFp8di7mJpbSVMbSIYr8w5_S4gMpIKu0wNi7q1XnFVmyg0kOgLCXeUzrceCzRkLAzowgRjx-OB3WSCyMpP3oPqOETO4uLObNGI5e-zPEfjfvwhPIs-IrnN-IszQDfpAzcO6hNNIJqqNrFaulGbWz8Fdlt3gwpmMeP-SIkXbc1SSHhmEiKvEOXdC2QRI6g9mnq8Yi380-KwzPUIsF-_3dVvLS1Anx44WgF6sQ7hNt5TNJCob_ihpr6u0LJMAw4vXyyZIsx4S8lZ-gefqFP_fBAsUBHHxGDnsYgOeclikoJ9a0Dzc79VfX6m7yEs9et2DnKSjFXURrTYLZIK1nMIrI9GhcP1Ei8DB2PL7yrFhtkNSWeQWlK-eeyR6vmWFzN7LvPNGmxaPRcSdK2yfeG3Wr2hhWBBx_74pClnCQubl3x-5BwjWq0Q23Uv5oowwZvzIkxkrLtBpzUD51w8QnsYpU8HK2tazO6iUy_2bHtdAnLmcSvtDEDT2mXo6jq5ocIGFX_4O5PS2MkrDuVFq1Q0uiFMEm1w1C7LPOY4kFDtIHyDdS6O7qJ4vyh9EXs0FCRRpOp5sgrzcPP0JbxMHhTxSzjyNcksuYXNWiLis7o1iya0ELfXG4chYllLwDrkjkHFmtPBfRYqaqPmCOA-OkBRQovYB0GmPUON6cpl758ZHlrONb25y5ienmya9t_FIcKE4tpEiiskcJKfcQ"",
                    ""tag"": ""50rqr5q3HziCDAiC7bsfAQ""
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
                    var issuerPublicKey = "02b35b116329ad5ce292030a63deac8a75428d0029325500aac957bfdb63273746"; // Issuer public key
                    var vcIsValid = Verifier.VerifyProof(vcJson, issuerPublicKey);
                    Console.WriteLine($"VC signature valid: {vcIsValid}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
