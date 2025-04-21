#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace std::chrono;

int main()
{
    // Parameters
    size_t m = 50; // Number of rows
    size_t n = 350; // Number of columns

    // Set encryption parameters
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // Create context
    SEALContext context(parms);
    
    // Key generation
    auto start = high_resolution_clock::now();
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    auto end = high_resolution_clock::now();
    cout << "Key generation took: " 
         << duration_cast<milliseconds>(end - start).count() 
         << " ms" << endl;

    // Create encryptor, evaluator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // Create batch encoder
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    
    // Create random 2D array (m×n)
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint8_t> dist(0, 255);
    
    vector<vector<uint8_t>> plain_matrix(m, vector<uint8_t>(n));
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < n; j++) {
            plain_matrix[i][j] = dist(gen);
        }
    }
    
    // Create encrypted matrix
    vector<vector<Ciphertext>> enc_matrix(m, vector<Ciphertext>(n));
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < n; j++) {
            Plaintext plain;
            vector<uint64_t> pod_matrix(slot_count, 0ULL);
            pod_matrix[0] = plain_matrix[i][j];
            batch_encoder.encode(pod_matrix, plain);
            encryptor.encrypt(plain, enc_matrix[i][j]);
        }
    }
    
    // Create column vector (one random position set to 1, rest 0)
    size_t col_idx = uniform_int_distribution<size_t>(0, n-1)(gen);
    vector<uint8_t> plain_col_vec(n, 0);
    plain_col_vec[col_idx] = 1;
    
    vector<Ciphertext> enc_col_vec(n);
    for (size_t j = 0; j < n; j++) {
        Plaintext plain;
        vector<uint64_t> pod_matrix(slot_count, 0ULL);
        pod_matrix[0] = plain_col_vec[j];
        batch_encoder.encode(pod_matrix, plain);
        encryptor.encrypt(plain, enc_col_vec[j]);
    }
    
    // Create row vector (one random position set to 1, rest 0)
    size_t row_idx = uniform_int_distribution<size_t>(0, m-1)(gen);
    vector<uint8_t> plain_row_vec(m, 0);
    plain_row_vec[row_idx] = 1;
    
    vector<Ciphertext> enc_row_vec(m);
    for (size_t i = 0; i < m; i++) {
        Plaintext plain;
        vector<uint64_t> pod_matrix(slot_count, 0ULL);
        pod_matrix[0] = plain_row_vec[i];
        batch_encoder.encode(pod_matrix, plain);
        encryptor.encrypt(plain, enc_row_vec[i]);
    }
    
    // Homomorphic operations
    start = high_resolution_clock::now();
    
    // 1. Multiply each row with column vector and sum
    vector<Ciphertext> enc_sum_vec(m);
    for (size_t i = 0; i < m; i++) {
        // Initialize with encryption of 0
        Plaintext zero_plain;
        vector<uint64_t> pod_zero(slot_count, 0ULL);
        batch_encoder.encode(pod_zero, zero_plain);
        encryptor.encrypt(zero_plain, enc_sum_vec[i]);
        
        for (size_t j = 0; j < n; j++) {
            Ciphertext product;
            evaluator.multiply(enc_matrix[i][j], enc_col_vec[j], product);
            evaluator.relinearize_inplace(product, relin_keys);
            evaluator.add_inplace(enc_sum_vec[i], product);
        }
    }
    
    // 2. Multiply row vector with sum vector
    Ciphertext final_result;
    {
        Plaintext zero_plain;
        vector<uint64_t> pod_zero(slot_count, 0ULL);
        batch_encoder.encode(pod_zero, zero_plain);
        encryptor.encrypt(zero_plain, final_result);
        
        for (size_t i = 0; i < m; i++) {
            Ciphertext product;
            evaluator.multiply(enc_row_vec[i], enc_sum_vec[i], product);
            evaluator.relinearize_inplace(product, relin_keys);
            evaluator.add_inplace(final_result, product);
        }
    }
    
    end = high_resolution_clock::now();
    cout << "Homomorphic operations took: " 
         << duration_cast<milliseconds>(end - start).count() 
         << " ms" << endl;
    
    // Decrypt result
    Plaintext decrypted_plain;
    decryptor.decrypt(final_result, decrypted_plain);
    vector<uint64_t> pod_result;
    batch_encoder.decode(decrypted_plain, pod_result);
    uint8_t decrypted_result = static_cast<uint8_t>(pod_result[0]);
    
    // Calculate expected result (for verification)
    uint8_t expected_result = plain_matrix[row_idx][col_idx];
    
    cout << "Column vector index: " << col_idx << endl;
    cout << "Row vector index: " << row_idx << endl;
    cout << "Decrypted result: " << static_cast<int>(decrypted_result) << endl;
    cout << "Expected result: " << static_cast<int>(expected_result) << endl;
    
    if (decrypted_result == expected_result) {
        cout << "Test passed!" << endl;
    } else {
        cout << "Test failed!" << endl;
    }
    
    return 0;
}