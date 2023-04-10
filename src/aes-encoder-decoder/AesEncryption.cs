using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class AesEncryption
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

        return Convert.ToBase64String(encryptedBytes);
    }

    public static string Decrypt(string encryptedText, string password)
    {
        byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
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
}
