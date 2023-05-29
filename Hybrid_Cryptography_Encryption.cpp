#include <iostream>
#include <string>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// AES Encryption Function
std::string aesEncrypt(const std::string& message, const std::string& key) {
    AES_KEY aesKey;
    unsigned char encryptedData[message.length()];
    memset(encryptedData, 0, sizeof(encryptedData));

    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &aesKey);
    AES_encrypt(reinterpret_cast<const unsigned char*>(message.c_str()), encryptedData, &aesKey);

    return std::string(reinterpret_cast<char*>(encryptedData), message.length());
}

// RSA Encryption Function
std::string rsaEncrypt(const std::string& message, RSA* publicKey) {
    int encryptedDataLength = RSA_size(publicKey);
    unsigned char encryptedData[encryptedDataLength];
    memset(encryptedData, 0, sizeof(encryptedData));

    RSA_public_encrypt(message.length(), reinterpret_cast<const unsigned char*>(message.c_str()),
                       encryptedData, publicKey, RSA_PKCS1_PADDING);

    return std::string(reinterpret_cast<char*>(encryptedData), encryptedDataLength);
}

// Hybrid Encryption Function
std::string hybridEncrypt(const std::string& message, const std::string& symmetricKey, RSA* publicKey) {
    // Step 1: Generate a random symmetric encryption key for AES
    // Assuming symmetricKey is already generated securely

    // Step 2: Encrypt the message using AES and the symmetric key
    std::string encryptedMessage = aesEncrypt(message, symmetricKey);

    // Step 3: Encrypt the symmetric key using RSA and the recipient's public key
    std::string encryptedSymmetricKey = rsaEncrypt(symmetricKey, publicKey);

    // Step 4: Combine the encrypted message and encrypted symmetric key
    std::string combinedData = encryptedMessage + encryptedSymmetricKey;

    return combinedData;
}

int main() {
    // Assume we have a message, a symmetric key, and a recipient's public key
    std::string message = "Hello, world!";
    std::string symmetricKey = "mysecretkey";
    std::string recipientPublicKeyFile = "public_key.pem";

    // Load recipient's public key from file
    FILE* publicKeyFile = fopen(recipientPublicKeyFile.c_str(), "rb");
    RSA* publicKey = PEM_read_RSA_PUBKEY(publicKeyFile, nullptr, nullptr, nullptr);
    fclose(publicKeyFile);

    // Encrypt the message using hybrid encryption
    std::string encryptedData = hybridEncrypt(message, symmetricKey, publicKey);

    // Display the encrypted data
    std::cout << "Encrypted Data: " << encryptedData << std::endl;

    // Clean up the RSA key
    RSA_free(publicKey);

    return 0;
}
