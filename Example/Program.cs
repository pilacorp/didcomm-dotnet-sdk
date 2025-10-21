using Pila.CredentialSdk.DidComm;

namespace Pila.CredentialSdk.DidComm.Example;

public class Program
{
    public static void Main(string[] args)
    {
        // Example usage
        var senderPublicKey = "038c551307177dd8c2f54612f08c7c040073ebb0154bb61bcd4d02f376d4ce93b2";
        var receiverPrivateKey = "0fc5abedcb46e4b63d2febc13cb308f0bbdcff7bc27e9621d18977cc6fa1713d";
        
        try
        {
            // Generate shared key using proper ECDH
            var sharedKey = Ecdh.GetFromKeys(senderPublicKey, receiverPrivateKey);
            Console.WriteLine($"Shared key generated: {Convert.ToHexString(sharedKey)}");
            
            // Encrypt message
            var encrypted = @"{
                    ""protected"": ""eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImNydiI6InNlY3AyNTZrMSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24ifQ"",
                    ""iv"": ""F6LKez3uqddZye7W"",
                    ""ciphertext"": ""KL4_kaLdZn30HMDxQpv40Csj6vBIn3LSQ4j1MmTAsi9DZOsG6ASBqPsHuj-Cvv-dAwQTTEWnopW72XSx6XbCdqNcW_SnYlz3MEX9vfy1PRK9sow2lMi8uS9XbU84iR0kXrWN364l7yIWoS_bckd_EqwEz0JDB2KkZDDj7C3YBmBUByNtH-NzO7ov5cC8f8EFoZcUMFpcCDaH1rOGqFGYBXtS17jtRJ0ZriZk7pqJNRWo3ezdQJoWxskUjGOcY15jiYpUTGHhEX4NPhnJJGzAlo38BvHdS-x0NU5WPjuTOSvsgwO6AHSkHl-FwaHU8gHt4MqHHMy5fMlRD45ZibJHXUFhzMBNdQibdvdoNYUriShYZlpvl0A71mZNF-coaPUS2Jqm67msYP2WbEwd9H5qLNlwumOh4YJcw_V8yIs9WI32Uf9zQ_wwgrQU9p82xo9Wy0JDzd8inww88E3prSfu-YNNovlC6Lwm5dVsWWhRYqBUa9K_yLaEbr2ZfyxcBuoq6kFIaOFnEDNtnAs_oX4evYHsd04e8irq1R5-iKSgcgoTCKkEHNmNzHm7tZH3bYFxbqShqKUojaHZEhs8l4zu0guO4TKcnqJVhmC8V6oyKZoz_na4ej3uc1ECLEgvFWRbmn2b644Zzi87jAdnEvgOGl3EoUs-rY77hUoAOjYqU2UXP9a76TbREB6ZBEjUzj4C0XkOJ857lbeSv4ZDDMuKLIW9Oeb_Y68C8nlwC0c0SZM9JRPziB1c5v2OrlZi6Li6uZBZTamgAE-E21vtmqAfWhnvz4SBMkGyN646Xl_NPN0NlAdamekJKemTafneaEbJ4l25QRzca_3m_Lwqe9wrCgZ5LGL66tp19gFXomLm57K6SdrjcnOKgpsMSWKo1V3yUihLUwgl1qElexLVCVA0CIH738OaZQQ19jWzDhRwMEyXAxHD8TCCW1tgWZhtXY58e-QaTB0tMxWnsvEjHGD_WZMgCCs1wYciJVOsJsMIP1lUZ2vP9CYBUIW5F8F6s_Hgq3IWcDrch1tOqGvxxG4OLV_VKvY9L1mqlXwAkbFa6R2qM23R8Z9u9ZjLxQ4Eg5XiH6ypci2TGIcXIMjKF0e97leOv4Nud1yywCPuXmJdhCyfUX2UpiitSeAmbepoHVUjB_FOVFtejGSR0E_pFUxV1Ke2Dd_N0Epk4f9l3e83EkJ7C9HL_M7pB0lM9k62qwN0JNBDhNZlScpMLsMZWfTyavhfUZq0BWaIWutDQnV5eBsTCpQVuwJKGT8-PMrwAA3zjubf0H4NDzLsl58dMMfeCx2WPq5LRQ9des37prIYStv2ntsPVpQ9NS7F2IOujJW1qUnDVBcKQwYT9O7TuT6TcLer4J3qtK-UozYNhIG5YyVQ_rtEPs8VHU5fYS0Auw3pQkyfG2ZFFFTx1xPFiAqXa35dMmikyQsOgF3Hw1gmNhlduYNW5vQsHkDJpan-kr211YVh_A2vsI3ZtsrD_UV6S_skOky0hijCth6A8Mb_xILcjzfymq1tOSHnoUJ_cV8re6Ee22QOhMB5BbUSYrzfwC-nY1NV75keB3cUx4yC-IC6KPjixddD6NUyIqteHtu3WIJ7naVKp7CXf_hA7iqBSSA6Rq-XJFddocn3Vt98idzHUNPE6XrXhnz2mpJ3oZkFnzowhklS6Icxs5Llf7kNVGmjACP4IUQEtwj2CohtrNfvc-bT5l2craPMSOtGHfJjXZ8cKRgZP_I7QjJhRJtrmR3JAZyKTUHvYTClYIdsa7FXvbodiNWG6va6YtFEFr_Qcd7B_mS_s5DbROYmWY_SUq0OrT984nuzHzE1hQ_XfpRkIcexu7KOu56oRdRP3Tg9WLcaI0AFq5O9GdP09uqPmFOh0lriavmTZtTBtkV4CD72cecxKmC5nuzwH6gZbOuRNck45uRY1YK8VwklMtmd2x_zGmFujXS3c6HFvMTXfUEFkkZ13WsZTKmiA6MwkAMya57uyNeZFmSUfle6JgCBWJ9Jgu4-d5xnVyziREWxo3RCEjcabGvsW2ox6Bk5Vlz9mvYGP3_rxuIeMni4HQmAB7sONQUSOiuJ6u595c7bU4UhqUJIt9SF9PW8CyPjtZsykWUFaxEyWw-IVNqgSM1lIob0Ikz6lh-3zLLYCS2OrxYDvTVEVIYlcGHf0JlLfrq3ayA09xfK6vQt0TBeJyjIYNd54pyoRZfhRntqESP_fTei83FozYTbZMrEUrQKxwaKx7WSQYCbiHCiKlorxYMN8KzyB0SOyYYxx4vmuu9MT3kZhBIMpZsSP7EgzfFzyBEZuX2EB9aAO6xyrhHKowKxy6YV4wH7Sr4mtDs_5HTKX0tJl29Ms8CgNTNU5eNkl_R4Zz_yiHDXTRz3u3P0Hl3NVtpv8jm8WR4AlN8c6alKknVIwabubdSqWM3zvDP1Iuv14bXrYTKDKYvaBKLZkvxw25NnidmZEf2taqJxdOmOpwYnFulA9qkexseA39r1WR2J-uOoy2Bxr9MNYCigV5ZMs1MFuQiv8geMQNMM7y1xq5VwPUNfZVsWx90nISyh-G-8m30w_tPSs8Br1fufl9dKVgBR0pBhzTbX4W0UfV5nPRyGYPcp-RICdzmEafA_yU_tIsgY2Bj3DSMLE0m8YR723IQBYOV_YXqupzRLrU6ehBQlP8IdFiUGujxbV6zyhoAK0u8bLOyT8-N4zruxXXAEWZPfi4qEBTQkJ63giO5Mu5kc-iWJiyFJVWB-yZV_tZOnDVw2Q45x_I1oWkfI8PfUH0plkl8dIqAGH7uLPYfM1foJ3v2Pg9E94RZv0HqgqrjDJcnZRdron6mq6gwa9bQnBCguuXNfpTKUcHmsJLzP3UZLY6hrhlIAygdeQmoe5y1wd7a77NdcyE4MWRs9VeV2zgD7j2wzjJFjDkxSv6Bb1BUjd3GJoErSOEhgIt0BxI4RQ3J_yVeznb9XUPUC9_4CIXLW237LmXlwqLv7Ks5OdSKa82Ca-7anbvixOmJE0WJItmz0cPhMB1OL2XunYcairTr51fMq5kjH2d7ABhyzdtbCsaxUcmzPm7N8Ci57NUe46zjUTdyThFHIswWpC0_Vf-288CjXFsOmLQeiTWHhGIOFllGSWQI9z9YNG2iaDLrU51FEVyCHrND5hkoxetsxAXAMggyf4arVEyY9RTiHCjexs-a-nbkxSykJ_BE4DrTcHWZaCN6MFiYXfvclcPxpdwsE9_--3a5a2w2E7YJMiEF4-RBGWhhCaK9iYozzLcLnt2fii7FgDfGrvKOtAgh-J02_kZ_y7HeV465OJcl5eEsT6blZ8kO3Y052E5ykODc_Ql2-BD8Y_jsA9EiZHrTFucnye1DOO3aCfUwaS4z6IBTOnJmJnri9twC3uo6qOvh1OCeUl7uxXB5ohSJIV5nT3mpMhArHevGLDjb_dXYT9tOnfStAkVqh8v0GKp5H5Z_CZlZWtgnuXmzptTD02boJ9vmb0G6B65fiChH-W3Bv8sBeuI2mGyw-q-AhngPit-_qfDMq1szjYRbGza70x9EGVv3Z6Dh3rbpV9V-7gzoeYcEqNcgoUILFyAcAEkgOv6x0cZNmIAB3dn84dJvFefulyPyBywGWFjwqI9lPQKhn4rsbSIXSpNTOEWeA_GYnXqeTwmT-us0m1M_VfVFlmr8-l8wrHZbqTYLZ2wIX4P9TGyyCX58rBaXxo-tOMopydx7S7c4j32osrqo3F8L2yM-jiJ8jM62f7QvJe6L4Trz5b17LzGrG8v2NshxQkKl87Zvxwlzs-JAkXUbJul1V210FrS2cK5IJy_5f84J87tDO4RDL24snph_Dr4PHpuY7WRtWAX1IAeXRb3SXZQItF2AU21YsG7Up_b6scfOIajtdHqzkTz0uXwKC8Nx2lSEdrW2tNH-MgIqH_7B2bAmyQ2FpqR2niOrvPVxwhssfIf_56R5VcGh0GJqaQvtuFhheGiNG21uh5Rh3qIE5f3DO13gx1eiDjltb9sBxYJw9tjD8Fe8OkQOZ7AcPSYjWCvB6WtquUvpmKm8vs9u72RT23FQj-MQbSR7WIuwRGKw2XZK0g78Mp9FM10FcAQ1yGdU_SaI5_tqhzeKOVMQfS9MjhAOOT9hfO4V0sLMlbAi6OCqyywlvTXIhu9P1ql3dZXCsu6zwTEuTgeA4KOONisAVRpWQFH864oimAHFpMp7w13EP09ju2Ldm7Af59wzHBOySUnb3yEIGbACPhQhdtxn836zQqQjpL8h17MFJM_C1C1fKUdU4Vjfy4kFloU9OcmvqgoqNnG19CTXreZ4hhz9DYOOLtxaeDC73un8x640AxFAojX78zfAdNN-RMJ6JA5sAIfxsiVi3C1Lxdm-b5kmhhRuisDeTYfpmTEjUCoO4Q4MR2ZXE1RXP7PBoNil1GUK6-UQ"",
                    ""tag"": ""sX_egO0aE1DJHYrPSXrX8Q""
                }";
            // var encrypted = Encryptor.Encrypt(sharedKey, message);
            // Console.WriteLine($"Encrypted message: {encrypted}");
            
            // Decrypt message
            var decrypted = Decryptor.DecryptJwe(encrypted, sharedKey);
            Console.WriteLine($"Decrypted message: {decrypted}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
