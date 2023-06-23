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
    int multiplicativeDepth = 10;
    int statisticalSecurity = 72;
    std::string pathPrefix = "Results/BGVResults/";
    std::string fileSuffix = "Depth" + std::to_string(multiplicativeDepth) + "Security" + std::to_string(statisticalSecurity) + ".csv";
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetStatisticalSecurity(statisticalSecurity);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);

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
    myfile.open(pathPrefix + "KeyGeneration" + fileSuffix);
    myfile << "Microseconds\n";
    // Generate a public/private key pair
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
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

    auto ciphertext1Const = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2Const = cryptoContext->Encrypt(keyPair.publicKey, plaintext5);
    auto ciphertext3Const = cryptoContext->Encrypt(keyPair.publicKey, plaintext10);

    // The encoded vectors are encrypted
    std::cout << "Encrypting and decrypting numbers..." << std::endl;
    myfile.open(pathPrefix + "EncryptionDecryption" + fileSuffix);
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
    myfile.open(pathPrefix + "Addition" + fileSuffix);
    myfile << "Size 1, Size 5, Size 10\n";
    std::cout << "Adding homomorphically..." << std::endl;
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext5);
    auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext10);
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        ciphertext1 = cryptoContext->EvalAdd(ciphertext1, ciphertext1Const);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        ciphertext2 = cryptoContext->EvalAdd(ciphertext2, ciphertext2Const);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        ciphertext3 = cryptoContext->EvalAdd(ciphertext3, ciphertext3Const);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    Plaintext plaintextDecryptAdd1;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDecryptAdd1);
    std::cout << "result of add)" << plaintextDecryptAdd1 << std::endl;
    Plaintext plaintextDecryptAdd5;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintextDecryptAdd5);
    std::cout << "result of add" << plaintextDecryptAdd5 << std::endl;
    Plaintext plaintextDecryptAdd10;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext3, &plaintextDecryptAdd10);
    std::cout << "result of add" << plaintextDecryptAdd10 << std::endl;

    // multiplications, multiplying by 2
    std::vector<int64_t> factorVec = {2};
    Plaintext factorPlain = cryptoContext->MakePackedPlaintext(factorVec);
    auto ciphertextFactor = cryptoContext->Encrypt(keyPair.publicKey, factorPlain);
    ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    std::cout << "Multiplying, Dividing, Relinearizing numbers..." << std::endl;
    myfile.open(pathPrefix + "ScalarMultDivRelin" + fileSuffix);
    myfile << "Multiplication times two,Division by two,Relinearization\n";
    int innerCount = floor(multiplicativeDepth);
    int outerCount = floor(amountOperations / innerCount);
    for (int i = 0; i < outerCount; i++) {
        for (int j = 0; j < innerCount; j++) {
            ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
            start = std::chrono::high_resolution_clock::now();
            ciphertext1 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertextFactor);
            stop = std::chrono::high_resolution_clock::now();
            duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
            myfile << duration.count() << ",";
            start = std::chrono::high_resolution_clock::now();
            //ciphertext1 = cryptoContext->EvalMultNoRelin(ciphertext1, cryptoContext->EvalDivide(ciphertextFactor, 0, 1, 129));
            stop = std::chrono::high_resolution_clock::now();
            duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
            myfile << ",";
            if (j != innerCount - 1)
                myfile << "-\n";
        }
        start = std::chrono::high_resolution_clock::now();
        ciphertext1 = cryptoContext->Relinearize(ciphertext1);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    Plaintext plaintextDecryptMult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDecryptMult);
    std::cout << "result of mult (should be 2)" << plaintextDecryptMult << std::endl;

    return 0;
}
