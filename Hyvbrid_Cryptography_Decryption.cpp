#include <iostream>
#include <string>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// AES Decryption Function
std::string aesDecrypt(const std::string& encryptedData, const std::string& key) {
    AES_KEY aesKey;
    unsigned char decryptedData[encryptedData.length()];
    memset(decryptedData, 0, sizeof(decryptedData));

    AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &aesKey);
    AES_decrypt(reinterpret_cast<const unsigned char*>(encryptedData.c_str()), decryptedData, &aesKey);

    return std::string(reinterpret_cast<char*>(decryptedData), encryptedData.length());
}

// RSA Decryption Function
std::string rsaDecrypt(const std::string& encryptedData, RSA* privateKey) {
    int decryptedDataLength = RSA_size(privateKey);
    unsigned char decryptedData[decryptedDataLength];
    memset(decryptedData, 0, sizeof(decryptedData));

    RSA_private_decrypt(encryptedData.length(), reinterpret_cast<const unsigned char*>(encryptedData.c_str()),
                        decryptedData, privateKey, RSA_PKCS1_PADDING);

    return std::string(reinterpret_cast<char*>(decryptedData), decryptedDataLength);
}

// Hybrid Decryption Function
std::string hybridDecrypt(const std::string& encryptedData, const std::string& symmetricKey, RSA* privateKey) {
    // Step 1: Separate the encrypted message and encrypted symmetric key
    std::string encryptedMessage = encryptedData.substr(0, encryptedData.length() - RSA_size(privateKey));
    std::string encryptedSymmetricKey = encryptedData.substr(encryptedData.length() - RSA_size(privateKey));

    // Step 2: Decrypt the symmetric key using RSA and the recipient's private key
    std::string decryptedSymmetricKey = rsaDecrypt(encryptedSymmetricKey, privateKey);

    // Step 3: Decrypt the message using AES and the decrypted symmetric key
    std::string decryptedMessage = aesDecrypt(encryptedMessage, decryptedSymmetricKey);

    return decryptedMessage;
}

int main() {
    // Assume we have the encrypted data, the symmetric key, and the recipient's private key
    std::string encryptedData = "encrypted_data_here";
    std::string symmetricKey = "mysecretkey";
    std::string recipientPrivateKeyFile = "private_key.pem";

    // Load recipient's private key from file
    FILE* privateKeyFile = fopen(recipientPrivateKeyFile.c_str(), "rb");
    RSA* privateKey = PEM_read_RSAPrivateKey(privateKeyFile, nullptr, nullptr, nullptr);
    fclose(privateKeyFile);

    // Decrypt the encrypted data using hybrid decryption
    std::string decryptedData = hybridDecrypt(encryptedData, symmetricKey, privateKey);

    // Display the decrypted data
    std::cout << "Decrypted Data: " << decryptedData << std::endl;

    // Clean up the RSA key
    RSA_free(privateKey);

    return 0;
}

//Note that you need to replace "encrypted_data_here" with the actual encrypted data 
//you want to decrypt, and "private_key.pem" with the file name or path to the recipient's private key file.

//Make sure you have the OpenSSL library installed and linked correctly when compiling the code.