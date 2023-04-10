using Xunit;

public class AesEncryptionTests
{
    [Fact]
    public void TestAesEncryptionAndDecryption()
    {
        // Arrange
        string plainText = "Hello, World!";
        string password = "MyPassword123";

        // Act
        string encryptedText = AesEncryption2.Encrypt(plainText, password);
        string decryptedText = AesEncryption2.Decrypt(encryptedText, password);

        // Assert
        Assert.Equal(plainText, decryptedText);
    }

    [Fact]
    public void TestAesEncryptionWithInvalidPassword()
    {
        // Arrange
        string plainText = "Hello, World!";
        string password = "MyPassword123";
        string invalidPassword = "InvalidPassword123";

        // Act
        string encryptedText = AesEncryption2.Encrypt(plainText, password);
        string decryptedText = AesEncryption2.Decrypt(encryptedText, invalidPassword);

        // Assert
        Assert.NotEqual(plainText, decryptedText);
    }
}
