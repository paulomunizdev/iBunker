/*
 * Title:       iBunker
 * Version:     0.2.1
 * Author:      Paulo Muniz
 * GitHub:      https://github.com/paulomunizdev/iBunker
 * Description: This program encrypts or decrypts files.
 */

#include <iostream>
#include <fstream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <sstream>

// Function to generate a strong AES key
/*
 * @brief                  Function to generate a strong AES key.
 * @return std::string     The generated AES key in hexadecimal format.
 */
std::string GenerateAESKey() {
    const int keyLength = 32; // Key size and bytes (256 bits)
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock key(keyLength);
    rng.GenerateBlock(key, key.size());

    // Convert the key to a hexadecimal string
    std::string hexKey;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexKey));
    encoder.Put(key, key.size());
    encoder.MessageEnd();

    return hexKey;
}

// Function to encrypt using AES
/*
 * @brief                  Function to encrypt a plaintext using AES.
 * @param plaintext        The plaintext to be encrypted.
 * @param key              The AES key used for encryption.
 * @return std::string     The resulting ciphertext.
 */
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
/*
 * @brief                  Function to decrypt a ciphertext using AES.
 * @param ciphertext       The ciphertext to be decrypted.
 * @param key              The AES key usesed for decryption.
 * @return std::string     The resulting decrypted plaintext.
 */
std::string DecryptAES(const std::string& ciphertext, const std::string& key) {
    std::string decryptedtext;

    // AES decryption setup
    CryptoPP::AES::Decryption aesDecryption((CryptoPP::byte*)key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte*)key.c_str());

    try {
        // Decryption process
        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::StreamTransformationFilter(cbcDecryption,
                new CryptoPP::StringSink(decryptedtext)
            )
        );
    } catch (const CryptoPP::InvalidCiphertext& e) {
        // Handle invalid ciphertext (e.g., incorrect key)
        std::cerr << "Decryption failed (invalid key)\n";
        decryptedtext = "Decryption failed (invalid key)";
    }

    return decryptedtext;
}

// Function to display the help message
/*
 * @brief                  Function to display the help message.
 */
void DisplayHelp() {
    std::cout << "Usage: ./ibunker <encrypt/decrypt> <input_file> <output_file> <key_file>\n";
    std::cout << "Available commands:\n";
    std::cout << "  encrypt: Encrypts the input file and saves the key to the specified file.\n";
    std::cout << "  decrypt: Decrypts the input file using the key from the specified file.\n";
    std::cout << "\n";
    std::cout << "iBunker\n";
    std::cout << "Version: 0.2.1\n";
    std::cout << "Author: Paulo Muniz\n";
    std::cout << "GitHub: https://github.com/paulomunizdev/iBunker\n";
    std::cout << "Description: This program provides AES-256 encryption and decryption for files.\n";
}

/**
 * @brief Main             function to handle program execution.
 *
 * @param argc             Number of command-line arguments.
 * @param argv             Array of command-line arguments.
 * @return int             Exit code.
 */
int main(int argc, char* argv[]) {

	if (argc != 5 && argc != 6) {
        DisplayHelp();
        return 1;
    }

    std::string mode = argv[1]; // Get operation mode (encrypt/decrypt)
    std::string inputFile = argv[2]; // Get input file name
    std::string outputFile = argv[3]; // Get output file name
    std::string keyFile = argv[4]; // Get key file name
    std::string key; // Variable to store AES key

    // Read data from input file
    std::ifstream input(inputFile, std::ios::binary);
    if (!input) {
      std::cerr << "Error opening input file.\n";
      return 1;
    }

    // Read plaintext from input file
    std::string plaintext((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();

    std::string result;
    if (mode == "encrypt") {
        // Encrypt plaintext using AES
        result = EncryptAES(plaintext, key);
    } else if (mode == "decrypt") {
        // Decrypt ciphertext using AES
        result = DecryptAES(plaintext, key);
    }

    // Write result to output file
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
