#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <cmath>
#include <seal/seal.h>

using namespace std;
using namespace std::chrono;
using namespace seal;

int main() {
    // Parameters
    size_t m = 10;         // Number of clients
    size_t n = 5;          // Number of records per client
    size_t value_range = 16; // Values from 0 to 15

    cout << "--- Private Information Retrieval using Homomorphic Encryption (SEAL) ---" << endl;

    // Create random database
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint8_t> dist(0, value_range-1);

    vector<vector<uint8_t>> database(m, vector<uint8_t>(n));
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < n; j++) {
            database[i][j] = dist(gen);
        }
    }

    // Print database
    cout << "Database:" << endl;
    for (size_t i = 0; i < m; i++) {
        cout << "Client " << i << ": ";
        for (size_t j = 0; j < n; j++) {
            cout << (int)database[i][j] << " ";
        }
        cout << endl;
    }

    // Client wants to retrieve data for client_id at record_idx
    size_t client_id = 3;  // Example: client 3
    size_t record_idx = 2; // Example: record 2

    cout << "\nClient wants to retrieve data for client " << client_id
         << ", record " << record_idx+1 << endl;
    cout << "Expected value: " << (int)database[client_id][record_idx] << endl;

    // Start timing
    auto start = high_resolution_clock::now();

    // Set up encryption parameters
    cout << "\nSetting up encryption parameters..." << endl;
    EncryptionParameters parms(scheme_type::bfv);

    // Polynomial modulus degree
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // Coefficient modulus
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Plain modulus (needs to be large enough for our values but not too large)
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // Create context, keys, and tools
    auto context = SEALContext(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    // Get slot count
    size_t slot_count = batch_encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    // --- CLIENT SIDE: Create encrypted query ---
    cout << "\nClient: Creating encrypted query..." << endl;

    // Create a single selection vector for the specific database element
    // This is a more direct approach than using separate client and record selections
    vector<uint64_t> selection_vector(slot_count, 0ULL);

    // We'll flatten the 2D database into a 1D array for simpler indexing
    // The index in the flattened array is client_id * n + record_idx
    size_t flat_index = client_id * n + record_idx;
    selection_vector[flat_index] = 1ULL;

    // Encode and encrypt the selection vector
    Plaintext selection_plain;
    batch_encoder.encode(selection_vector, selection_plain);
    Ciphertext selection_encrypted;
    encryptor.encrypt(selection_plain, selection_encrypted);

    // --- SERVER SIDE: Process the encrypted query ---
    cout << "Server: Processing encrypted query..." << endl;

    // Flatten the database into a single vector for easier processing
    vector<uint64_t> flat_database(slot_count, 0ULL);
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < n; j++) {
            flat_database[i * n + j] = static_cast<uint64_t>(database[i][j]);
        }
    }

    // Encode the database
    Plaintext database_plain;
    batch_encoder.encode(flat_database, database_plain);

    // Perform the PIR operation (multiply selection vector with database)
    Ciphertext result;
    evaluator.multiply_plain(selection_encrypted, database_plain, result);

    // --- CLIENT SIDE: Decrypt and extract result ---
    cout << "Client: Decrypting result..." << endl;

    Plaintext decrypted_result;
    decryptor.decrypt(result, decrypted_result);

    vector<uint64_t> result_vec;
    batch_encoder.decode(decrypted_result, result_vec);

    // Extract the result - it should be the sum of all elements
    // Since we used a one-hot encoding, only one element should be non-zero
    uint64_t retrieved_value = 0;
    for (size_t i = 0; i < slot_count; i++) {
        retrieved_value += result_vec[i];
    }

    auto end = high_resolution_clock::now();
    cout << "\nHomomorphic PIR computation took: "
         << duration_cast<milliseconds>(end - start).count()
         << " ms" << endl;

    cout << "Retrieved value: " << retrieved_value << endl;
    cout << "Expected value: " << (int)database[client_id][record_idx] << endl;

    cout << "\nNote: This is a simplified demonstration of homomorphic PIR." << endl;
    cout << "A complete implementation would require more complex circuit design" << endl;
    cout << "and optimizations for performance." << endl;

    return 0;
}
