/*
 * Title: iBunker
 * Version: 1.0
 * Author: Paulo Muniz
 * GitHub: https://github.com/paulomunizdev
 * Description: This program encrypts or decrypts files using a provided key.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime> // To use time()
#include <cstdlib> // To use srand() and rand()

using namespace std;

// Function to generate a strong key
string generateStrongKey() {
    const int keyLength = 32; // Set the length of the key (32 characters for a 128-bit key)
    const string charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    srand(time(nullptr)); // Initialize the random number generator seed

    string key;
    for (int i = 0; i < keyLength; ++i) {
        key += charset[rand() % charset.length()]; // Add a random character to the key
    }
    return key;
}

// Function to convert the key from letters to numeric values
vector<int> convertKey(const string& key) {
    vector<int> numericKey;
    for (char character : key) {
        numericKey.push_back(static_cast<int>(character)); // Convert each character of the key to its ASCII value and add it to the vector
    }
    return numericKey; // Return the vector with the decimal values corresponding to the key
}

// Function to encrypt the text with a key
void encryptText(ifstream& input, ofstream& output, const vector<int>& numericKey) {
    char character;
    int keyIndex = 0;
    while (input.get(character)) { // Read each character from the input file
        // Calculate the encrypted value of the character using the key
        int encryptedValue = static_cast<int>(character) + numericKey[keyIndex];
        // Write the encrypted value to the output file
        output << static_cast<char>(encryptedValue);
        // Update the key index to move to the next character of the key
        keyIndex = (keyIndex + 1) % numericKey.size();
    }
}

// Function to decrypt the text with a key
void decryptText(ifstream& input, ofstream& output, const vector<int>& numericKey) {
    char character;
    int keyIndex = 0;
    while (input.get(character)) { // Read each character from the input file
        // Calculate the decrypted value of the character using the key
        int decryptedValue = static_cast<int>(character) - numericKey[keyIndex];
        // Check if the decrypted value is less than 0
        if (decryptedValue < 0) {
            // If yes, add 256 to bring it back to the valid ASCII characters range
            decryptedValue += 256;
        }
        // Write the decrypted value to the output file
        output << static_cast<char>(decryptedValue);
        // Update the key index to move to the next character of the key
        keyIndex = (keyIndex + 1) % numericKey.size();
    }
}

// Function to open and check if files were opened correctly
bool openFiles(const string& inputFile, const string& outputFile, ifstream& input, ofstream& output) {
    // Open the input and output files
    input.open(inputFile);
    output.open(outputFile);

    // Check if the files were opened correctly
    if (!input.is_open()) {
        cerr << "Error opening the input file." << endl;
        return false;
    }

    if (!output.is_open()) {
        cerr << "Error opening the output file." << endl;
        return false;
    }

    return true;
}

// Function to perform the encryption or decryption operation on the text
void performOperation(const string& option, const string& inputFile, const string& outputFile, const string& keyOrPassword) {
    ifstream input;
    ofstream output;

    // Open the input and output files
    if (!openFiles(inputFile, outputFile, input, output)) {
        return;
    }

    string key; // Key to be used

    // Generate a strong key for encryption
    if (option == "encrypt") {
        key = generateStrongKey();
        cout << "Generated strong key: " << key << endl;
    }
    // Use the provided password for decryption
    else if (option == "decrypt") {
        key = keyOrPassword; // Password provided by the user
    }

    // Convert the key from letters to numeric values
    vector<int> numericKey = convertKey(key);

    // Decide whether to encrypt or decrypt the text
    if (option == "encrypt")
        encryptText(input, output, numericKey);
    else if (option == "decrypt")
        decryptText(input, output, numericKey);

    // Close the input and output files
    input.close();
    output.close();

    cout << "Operation completed." << endl;
}

int main(int argc, char* argv[]) {
    if (argc != 4 && argc != 5) {
        cerr << "Usage: " << argv[0] << " <encrypt/decrypt> <input_file> <output_file> [password]" << endl;
        return 1;
    }

    // Get the command-line arguments
    string option = argv[1];
    string inputFile = argv[2];
    string outputFile = argv[3];

    // If the operation is decryption, get the password from the command line
    string password;
    if (argc == 5) {
        password = argv[4];
    }

    // Perform the chosen operation
    performOperation(option, inputFile, outputFile, password);

    return 0;
}
