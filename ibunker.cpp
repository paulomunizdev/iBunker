/*
 * Title: iBunker
 * Version: 2.0
 * Author: Paulo Muniz
 * GitHub: https://github.com/paulomunizdev
 * Description: This program encrypts or decrypts files.
 */

#include <iostream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <string>

// Function to encrypt using AES
std::string EncryptAES(const std::string& plaintext, const std::string& key) {
    std::string ciphertext;

    // AES encryption setup
    CryptoPP::AES::Encryption aesEncryption((CryptoPP::byte*)key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (CryptoPP::byte*)key.c_str());

    // Encryption process
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::StreamTransformationFilter(cbcEncryption,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    return ciphertext;
}

// Function to decrypt using AES
std::string DecryptAES(const std::string& ciphertext, const std::string& key) {
    std::string decryptedtext;

    // AES decryption setup
    CryptoPP::AES::Decryption aesDecryption((CryptoPP::byte*)key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte*)key.c_str());

    // Decryption process
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(cbcDecryption,
            new CryptoPP::StringSink(decryptedtext)
        )
    );

    return decryptedtext;
}

int main(int argc, char* argv[]) {
    // Check if correct number of arguments provided
    if (argc != 5 && argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <encrypt/decrypt> <input_file> <output_file> <key_file>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string keyFile = argv[4];
    std::string key;

    if (mode == "encrypt") {
        // Read key from specified file
        std::ifstream keyInput(keyFile);
        if (!keyInput) {
            std::cerr << "Error opening key file.\n";
            return 1;
        }
        std::getline(keyInput, key);
        keyInput.close();
    } else if (mode == "decrypt") {
        // Check if all parameters were provided
        if (argc != 5) {
            std::cerr << "Usage: " << argv[0] << " decrypt <input_file> <output_file> <key_file>\n";
            return 1;
        }

        // Read key from specified file
        std::ifstream keyInput(keyFile);
        if (!keyInput) {
            std::cerr << "Error opening key file.\n";
            return 1;
        }
        std::getline(keyInput, key);
        keyInput.close();
    } else {
        std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'.\n";
        return 1;
    }

    // Read data from input file
    std::ifstream input(inputFile, std::ios::binary);
    if (!input) {
        std::cerr << "Error opening input file.\n";
        return 1;
    }

    std::string plaintext((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();

    std::string result;
    if (mode == "encrypt") {
        result = EncryptAES(plaintext, key);
    } else if (mode == "decrypt") {
        result = DecryptAES(plaintext, key);
    }

    // Save result to output file
    std::ofstream output(outputFile, std::ios::binary);
    if (!output) {
        std::cerr << "Error opening output file.\n";
        return 1;
    }

    output << result;
    output.close();

    std::cout << "Result successfully saved to file '" << outputFile << "'.\n";

    return 0;
}
