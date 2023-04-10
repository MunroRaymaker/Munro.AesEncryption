// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

var e = AesEncryption2.Encrypt("This is &= plaintext secret!", "password123");
var d = AesEncryption2.Decrypt(e, "password123");

System.Console.WriteLine("Encrypted: " + e);
System.Console.WriteLine("Decrypted " + d);

string plainText = "Hello, World!";
string password = "MyPassword123";
string invalidPassword = "InvalidPassword123";

// Act
string encryptedText = AesEncryption2.Encrypt(plainText, password);
string decryptedText = AesEncryption2.Decrypt(encryptedText, invalidPassword);