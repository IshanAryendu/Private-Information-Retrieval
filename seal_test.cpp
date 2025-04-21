#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main()
{
    // Print SEAL version information
    cout << "Microsoft SEAL version: " << SEAL_VERSION_MAJOR << "."
         << SEAL_VERSION_MINOR << "." << SEAL_VERSION_PATCH << endl;

    // Set encryption parameters
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // Create context
    cout << "\nSetting up encryption parameters..." << endl;
    SEALContext context(parms);

    // Print parameters
    cout << "Parameter validation: " << context.parameter_error_message() << endl;

    // Generate keys
    cout << "\nGenerating keys..." << endl;
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    // Create encryptor, evaluator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Create batch encoder
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix slot count: " << slot_count << endl;

    // Create test data
    vector<uint64_t> pod_matrix(slot_count, 0);
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix[i] = i;
    }

    cout << "\nEncoding and encrypting..." << endl;
    Plaintext plain_matrix;
    batch_encoder.encode(pod_matrix, plain_matrix);

    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Perform homomorphic operations
    cout << "\nPerforming homomorphic operations..." << endl;

    // Addition
    Plaintext plain_scalar;
    batch_encoder.encode(vector<uint64_t>(slot_count, 5), plain_scalar);
    evaluator.add_plain_inplace(encrypted_matrix, plain_scalar);
    cout << "    + Performed addition" << endl;

    // Multiplication
    batch_encoder.encode(vector<uint64_t>(slot_count, 2), plain_scalar);
    evaluator.multiply_plain_inplace(encrypted_matrix, plain_scalar);
    cout << "    + Performed multiplication" << endl;

    // Decrypt and decode
    cout << "\nDecrypting and decoding..." << endl;
    Plaintext plain_result;
    decryptor.decrypt(encrypted_matrix, plain_result);

    vector<uint64_t> result;
    batch_encoder.decode(plain_result, result);

    // Print results
    cout << "\nResult vector: " << endl;
    cout << "    [";
    for (size_t i = 0; i < 10; i++)
    {
        cout << result[i] << ", ";
    }
    cout << "..., ";
    for (size_t i = slot_count - 10; i < slot_count; i++)
    {
        cout << result[i] << ((i != slot_count - 1) ? ", " : "]\n");
    }

    // Verify results
    cout << "\nVerifying results..." << endl;
    vector<uint64_t> expected_result(slot_count);
    for (size_t i = 0; i < slot_count; i++)
    {
        expected_result[i] = (i + 5) * 2;
    }

    bool correct = true;
    for (size_t i = 0; i < slot_count; i++)
    {
        if (result[i] != expected_result[i])
        {
            correct = false;
            cout << "ERROR at index " << i << ": Expected " << expected_result[i]
                 << ", got " << result[i] << endl;
            break;
        }
    }

    if (correct)
    {
        cout << "All results match expected values!" << endl;
        cout << "\nMicrosoft SEAL is working correctly." << endl;
    }
    else
    {
        cout << "Results do not match expected values." << endl;
        cout << "\nThere might be an issue with the Microsoft SEAL installation." << endl;
    }

    return 0;
}
