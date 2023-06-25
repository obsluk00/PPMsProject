#include <iostream>
#include <fstream>
#include <chrono>
#include "binfhecontext.h"

using namespace lbcrypto;

std::pair<std::shared_ptr<LWECiphertextImpl>, std::shared_ptr<LWECiphertextImpl>> fullAdder(
        BinFHEContext cc,
        std::shared_ptr<LWECiphertextImpl> c1,
        std::shared_ptr<LWECiphertextImpl> c2,
        std::shared_ptr<LWECiphertextImpl> cCarry) {
    std::shared_ptr<LWECiphertextImpl> sum;
    std::shared_ptr<LWECiphertextImpl> carry;
    auto aXORb= cc.EvalBinGate(XOR, c1, c2);
    sum = cc.EvalBinGate(XOR, aXORb, cCarry);
    auto aANDb = cc.EvalBinGate(AND, c1, c2);
    auto aXORbANDCarry = cc.EvalBinGate(AND, aXORb, cCarry);
    carry = cc.EvalBinGate(OR, aANDb, aXORbANDCarry);
    std::pair<std::shared_ptr<LWECiphertextImpl>,std::shared_ptr<LWECiphertextImpl>> res (sum, carry);
    return res;
}



int main() {
    std::ofstream myfile;
    std::string pathPrefix = "Results/CGGIResults/";
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    // GINX is CGGI, AP is DM scheme
    cc.GenerateBinFHEContext(STD128, GINX);
    int amountOperations = 100;
    std::string fileSuffix = "SecuritySTD128.csv";

    // Key Generation
    std::cout << "Generating keys..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    // Initialize Public Key Containers
    myfile.open(pathPrefix + "KeyGeneration" + fileSuffix);
    myfile << "Microseconds\n";
    // Generate a public/private key pair
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        auto cc1 = BinFHEContext();
        cc1.GenerateBinFHEContext(STD128, GINX);
        auto sk = cc1.KeyGen();
        cc1.BTKeyGen(sk);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    std::cout << "Encrypting and decrypting numbers..." << std::endl;
    myfile.open(pathPrefix + "EncryptionDecryption" + fileSuffix);
    myfile << "Encrypt, Decrypt\n";
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        auto ct1 = cc.Encrypt(sk, 1);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        LWEPlaintext result;
        start = std::chrono::high_resolution_clock::now();
        cc.Decrypt(sk, ct1, &result);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    auto ct1 = cc.Encrypt(sk, 1);
    auto ct2 = cc.Encrypt(sk, 1);

    // Sample Program: Step 4: Evaluation
    std::cout << "Evaluations..." << std::endl;
    myfile.open(pathPrefix + "Evaluations" + fileSuffix);
    myfile << "NOT, OR, AND, NOR, NAND, XOR_FAST, XNOR_FAST, XOR, XNOR, FullAdder \n";
    for (int i = 0; i < amountOperations; i++) {
        start = std::chrono::high_resolution_clock::now();
        auto ct2Not = cc.EvalNOT(ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ctOR = cc.EvalBinGate(OR, ct1, ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ctAND = cc.EvalBinGate(AND, ct1, ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ctNOR = cc.EvalBinGate(NOR, ct1, ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ct2NAND = cc.EvalBinGate(NAND, ct1, ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ct2XOR_FAST = cc.EvalBinGate(XOR_FAST, ct1, ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ct2XNOR_FAST = cc.EvalBinGate(XNOR_FAST, ct1, ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ct2XOR = cc.EvalBinGate(XOR, ct1, ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ct2XNOR = cc.EvalBinGate(XNOR, ct1, ct2);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << ",";
        start = std::chrono::high_resolution_clock::now();
        auto ctFullAdder = fullAdder(cc, ct1, ct2 ,ct2XOR);
        stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        myfile << duration.count() << "\n";
    }
    myfile.close();

    return 0;
}
