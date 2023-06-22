#include <iostream>
#include <chrono>
#include "openfhe.h"

#include "openfhe.h"

using namespace lbcrypto;

int main() {
    // Set CryptoContext
    std::cout << "Setting Context..." << std::endl;
    int amountOperations = 20;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(amountOperations);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Key Generation
    std::cout << "Generating keys..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    auto stop = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << "Keys generated in " << duration.count() << " microseconds" << std::endl;
    // Encryption

    // First plaintext vector is encoded
    std::vector<int64_t> vectorOfInt1 = {1};
    std::vector<int64_t> vectorOfInt2 = {1};
    std::vector<int64_t> vectorOfInt3 = {2};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInt1);
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInt2);
    Plaintext plaintext3              = cryptoContext->MakePackedPlaintext(vectorOfInt3);
    // The encoded vectors are encrypted
    std::cout << "Encrypting numbers..." << std::endl;
    start = std::chrono::high_resolution_clock::now();
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
    auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
    stop = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << "Encrypted in " << duration.count() << " microseconds" << std::endl;
    // Evaluation
    // additions, adding 1 each time
    std::cout << "Adding numbers..." << std::endl;
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        ciphertext1 = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        std::cout << "Added in " << duration.count() << " microseconds" << std::endl;
    }
    // multiplications, multiplying by 2
    std::cout << "Multiplying numbers..." << std::endl;
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        ciphertext2 = cryptoContext->EvalMult(ciphertext2, ciphertext3);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        std::cout << "Took product in " << duration.count() << " microseconds" << std::endl;

    }

    // Decryption

    // Decrypt the result of additions
    std::cout << "Decrypting results..." << std::endl;
    start = std::chrono::high_resolution_clock::now();
    Plaintext plaintextAddResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextAddResult);

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintextMultResult);

    stop = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << "Decrypted in " << duration.count() << " microseconds" << std::endl;

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "Addition: " << plaintextAddResult << std::endl;
    std::cout << "Multiplication: " << plaintextMultResult << std::endl;

    return 0;
}
