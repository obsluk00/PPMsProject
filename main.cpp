#include <iostream>
#include <fstream>
#include <chrono>
#include "openfhe.h"

using namespace lbcrypto;

int main() {
    std::ofstream myfile;
    // Set CryptoContext
    std::cout << "Setting Context..." << std::endl;
    int amountOperations = 100;
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetStatisticalSecurity(72);
    parameters.SetMultiplicativeDepth(10);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Key Generation
    std::cout << "Generating keys..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;
    myfile.open("Results/BGVResults/KeyGenerationDepth10.csv");
    myfile << "Microseconds\n";
    // Generate a public/private key pair
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        std::cout << "Key generated in " << duration.count() << " microseconds" << std::endl;
        myfile << duration.count() << "\n";
    }
    myfile.close();

    // Generate additional keys for other operations relinearization key

    // Encryption
    std::vector<int64_t> vectorOfSize1 = {1};
    std::vector<int64_t> vectorOfSize5 = {1, 2, 3, 4, 5};
    std::vector<int64_t> vectorOfSize10 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfSize1);
    Plaintext plaintext5 = cryptoContext->MakePackedPlaintext(vectorOfSize5);
    Plaintext plaintext10 = cryptoContext->MakePackedPlaintext(vectorOfSize10);
    // The encoded vectors are encrypted
    std::cout << "Encrypting and decrypting numbers..." << std::endl;
    myfile.open("Results/BGVResults/EncryptionDecryption.csv");
    myfile << "Encrypt Size 1, Encrypt Size 5, Encrypt Size 10, Decrypt Size 1, Decrypt Size 5, Decrypt Size 10\n";
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext5);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext10);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        Plaintext plaintextDecrypt;
        start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDecrypt);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintextDecrypt);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext3, &plaintextDecrypt);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();
    // Evaluation
    // additions, adding self each time
    myfile.open("Results/BGVResults/Addition.csv");
    myfile << "Size 1, Size 5, Size 10\n";
    std::cout << "Adding homomorphically..." << std::endl;
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext5);
    auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext10);
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        ciphertext1 = cryptoContext->EvalAdd(ciphertext1, ciphertext1);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        start = std::chrono::high_resolution_clock::now();
        ciphertext2 = cryptoContext->EvalAdd(ciphertext2, ciphertext2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        start = std::chrono::high_resolution_clock::now();
        ciphertext3 = cryptoContext->EvalAdd(ciphertext3, ciphertext3);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();
    // multiplications, multiplying by 2
    std::vector<int64_t> factorVec = {2};
    Plaintext factorPlain = cryptoContext->MakePackedPlaintext(factorVec);
    auto ciphertextFactor = cryptoContext->Encrypt(keyPair.publicKey, factorPlain);

    std::cout << "Multiplying, Dividing, Relinearizing numbers..." << std::endl;
    myfile.open("Results/BGVesults/ScalarMultDivRelin.csv");
    myfile << "Multiplication,Division,Relinearization\n";
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        ciphertext1 = cryptoContext->EvalMult(ciphertext1, ciphertextFactor);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        std::cout << "Took product in " << duration.count() << " microseconds" << std::endl;

    }
    myfile.close();

    return 0;
}
