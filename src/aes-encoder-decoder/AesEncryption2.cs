using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Use this for URL encrypted secrets
public class AesEncryption2
{
    private static readonly byte[] _salt = Encoding.ASCII.GetBytes("This is the salt for AES encryption");

    public static string Encrypt(string plainText, string password)
    {
        byte[] encryptedBytes;
        byte[] saltBytes = _salt;

        using (MemoryStream ms = new MemoryStream())
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(password, saltBytes, 1000, HashAlgorithmName.SHA256);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);

                aes.Mode = CipherMode.CBC;

                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                    cs.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cs.Close();
                }

                encryptedBytes = ms.ToArray();
            }
        }

        // Convert the encrypted bytes to Base64Url string
        string base64UrlString = Base64UrlEncode(encryptedBytes);
        return base64UrlString;
    }

    public static string Decrypt(string encryptedText, string password)
    {
        // Convert the Base64Url string to encrypted bytes
        byte[] cipherTextBytes = Base64UrlDecode(encryptedText);
        byte[] saltBytes = _salt;
        string decryptedText = null;

        using (MemoryStream ms = new MemoryStream(cipherTextBytes))
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(password, saltBytes, 1000, HashAlgorithmName.SHA256);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);

                aes.Mode = CipherMode.CBC;

                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cs))
                    {
                        decryptedText = reader.ReadToEnd();
                    }
                }
            }
        }

        return decryptedText;
    }

    // Helper method to perform Base64Url encoding
    private static string Base64UrlEncode(byte[] input)
    {
        string base64 = Convert.ToBase64String(input);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    // Helper method to perform Base64Url decoding
    private static byte[] Base64UrlDecode(string input)
    {
        string base64 = input.Replace('-', '+').Replace('_', '/');
        while (base64.Length % 4 != 0)
        {
            base64 += '=';
        }
        return Convert.FromBase64String(base64);
    }
}
