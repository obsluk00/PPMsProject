#include <iostream>
#include <fstream>
#include <chrono>
#include "openfhe.h"

using namespace lbcrypto;

int main() {
    int amountOperations = 10;
    uint32_t multDepth = 1;
    uint32_t security = 72;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 8;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetBatchSize(72);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    std::ofstream myfile;
    std::string pathPrefix = "Results/CKKSResults/";
    std::string fileSuffix = "Depth" + std::to_string(multDepth) + "Security" + std::to_string(security) +
                             "RingDimenstion" + std::to_string(cc->GetRingDimension()) + "Batchsize" + std::to_string(batchSize) + ".csv";

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;


    std::cout << "Generating keys..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    KeyPair<DCRTPoly> keyPair;
    myfile.open(pathPrefix + "KeyGeneration" + fileSuffix);
    myfile << "Microseconds\n";
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Inputs
    std::vector<double> x1 = {0.25};
    std::vector<double> x4 = {0.25, 0.5, 4.0, 5.0};
    std::vector<double> x8 = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};

    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1);
    Plaintext ptxt4 = cc->MakeCKKSPackedPlaintext(x4);
    Plaintext ptxt8 = cc->MakeCKKSPackedPlaintext(x8);

    std::cout << "Encrypting and decrypting numbers..." << std::endl;
    myfile.open(pathPrefix + "EncryptionDecryption" + fileSuffix);
    myfile << "Encrypt Size 1, Encrypt Size 4, Encrypt Size 8, Decrypt Size 1, Decrypt Size 4, Decrypt Size 8\n";

    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        auto ciphertext1 = cc->Encrypt(keyPair.publicKey, ptxt1);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ciphertext2 = cc->Encrypt(keyPair.publicKey, ptxt4);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ciphertext3 = cc->Encrypt(keyPair.publicKey, ptxt8);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        Plaintext plaintextDecrypt;
        start = std::chrono::high_resolution_clock::now();
        cc->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDecrypt);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        cc->Decrypt(keyPair.secretKey, ciphertext2, &plaintextDecrypt);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        cc->Decrypt(keyPair.secretKey, ciphertext3, &plaintextDecrypt);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto c2 = cc->Encrypt(keys.publicKey, ptxt4);
    auto c3 = cc->Encrypt(keys.publicKey, ptxt8);


    auto ciphertext1Const = cc->Encrypt(keyPair.publicKey, ptxt1);
    auto ciphertext2Const = cc->Encrypt(keyPair.publicKey, ptxt8);
    auto ciphertext3Const = cc->Encrypt(keyPair.publicKey, ptxt8);

    myfile.open(pathPrefix + "Addition" + fileSuffix);
    myfile << "Size 1, Size 4, Size 8\n";
    std::cout << "Adding homomorphically..." << std::endl;
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        c1 = cc->EvalAdd(c1, ciphertext1Const);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        c2 = cc->EvalAdd(c2, ciphertext2Const);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        c3 = cc->EvalAdd(c3, ciphertext3Const);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    Plaintext plaintextDecryptAdd1;
    cc->Decrypt(keyPair.secretKey, c1, &plaintextDecryptAdd1);
    plaintextDecryptAdd1->SetLength(batchSize);
    std::cout << "result of add)" << plaintextDecryptAdd1 << std::endl;
    Plaintext plaintextDecryptAdd5;
    cc->Decrypt(keyPair.secretKey, c2, &plaintextDecryptAdd5);
    plaintextDecryptAdd5->SetLength(batchSize);
    std::cout << "result of add" << plaintextDecryptAdd5 << std::endl;
    Plaintext plaintextDecryptAdd10;
    cc->Decrypt(keyPair.secretKey, c3, &plaintextDecryptAdd10);
    plaintextDecryptAdd10->SetLength(batchSize);
    std::cout << "result of add" << plaintextDecryptAdd10 << std::endl;

    std::cout << "Multiplying, Dividing, Relinearizing numbers..." << std::endl;
    myfile.open(pathPrefix + "ScalarMultDivRelin" + fileSuffix);
    myfile << "Multiplication times two,Division by two,Relinearization\n";
    std::vector<double> factorVec = {2.0};
    Plaintext factorPlain = cc->MakeCKKSPackedPlaintext(factorVec);
    auto ciphertextFactor = cc->Encrypt(keyPair.publicKey, factorPlain);
    int innerCount = floor(multDepth);
    int outerCount = floor(amountOperations / innerCount);
    for (int i = 0; i < outerCount; i++) {
        for (int j = 0; j < innerCount; j++) {
            start = std::chrono::high_resolution_clock::now();
            c1 = cc->EvalMultNoRelin(c1, ciphertextFactor);
            stop = std::chrono::high_resolution_clock::now();
            duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
            myfile << duration.count() << ",";
            start = std::chrono::high_resolution_clock::now();
            c1 = cc->EvalMultNoRelin(c1, cc->EvalDivide(ciphertextFactor, 0, 1, 129));
            stop = std::chrono::high_resolution_clock::now();
            duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
            myfile << ",";
            if (j != innerCount - 1)
                myfile << "-\n";
        }
        start = std::chrono::high_resolution_clock::now();
        c1 = cc->Relinearize(c1);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    // Step 5: Decryption and output
    Plaintext result;
    // We set the cout precision to 8 decimal digits for a nicer output.
    // If you want to see the error/noise introduced by CKKS, bump it up
    // to 15 and it should become visible.
    std::cout.precision(8);

    // Decrypt the result of multiplication
    cc->Decrypt(keys.secretKey, c1, &result);
    result->SetLength(batchSize);
    std::cout << "mult results (should be 0.25): " << result;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;


    return 0;
}