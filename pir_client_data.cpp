// Maybe this code works for the Homomorphic Encryption
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <map>
#include <cmath>
#include <stdexcept>
#include <sstream> // For SEAL serialization/deserialization simulation
#include <fstream> // For saving serialized data if needed

// --- Conditional Includes ---
// Only include if needed, reduces compile time if testing one protocol
#ifdef USE_EMP
#include <emp-sh2pc/emp-sh2pc.h>
using namespace emp;
#endif

#ifdef USE_SEAL
#include "seal/seal.h"
using namespace seal;
#endif
// --- End Conditional Includes ---

using namespace std;
using namespace std::chrono;

// ===============================================================
// Configuration (Shared)
// ===============================================================
const int DB_M_CLIENTS = 10;      // m
const int DB_N_RECORDS = 5;       // n
const int DB_TOTAL_RECORDS = DB_M_CLIENTS * DB_N_RECORDS; // N
const int DB_VALUE_BITSIZE = 4;   // 0-15 requires 4 bits minimum
const int HE_PLAIN_MOD_BITSIZE = 20; // SEAL Plaintext modulus size (must hold results)

// Target query (example)
const int TARGET_CLIENT_IDX = 3;
const int TARGET_RECORD_IDX = 2;
// ===============================================================


#ifdef USE_SEAL
// ===============================================================
// Helper Functions for SEAL Serialization (Simulation)
// ===============================================================

// Serialize a vector of Ciphertexts
string serialize_ciphertext_vector(const vector<Ciphertext>& c_vec) {
    stringstream ss;
    size_t vec_size = c_vec.size();
    ss.write(reinterpret_cast<const char*>(&vec_size), sizeof(size_t));
    for (const auto& c : c_vec) {
        c.save(ss);
    }
    return ss.str();
}

// Deserialize a vector of Ciphertexts
vector<Ciphertext> deserialize_ciphertext_vector(const string& s, shared_ptr<SEALContext> context) {
    stringstream ss(s);
    size_t vec_size;
    ss.read(reinterpret_cast<char*>(&vec_size), sizeof(size_t));
    vector<Ciphertext> c_vec;
    c_vec.reserve(vec_size);
    for (size_t i = 0; i < vec_size; ++i) {
        Ciphertext c;
        c.load(context, ss);
        c_vec.push_back(c);
    }
    return c_vec;
}

// Serialize a single Ciphertext
string serialize_ciphertext(const Ciphertext& c) {
    stringstream ss;
    c.save(ss);
    return ss.str();
}

// Deserialize a single Ciphertext
Ciphertext deserialize_ciphertext(const string& s, shared_ptr<SEALContext> context) {
    stringstream ss(s);
    Ciphertext c;
    c.load(context, ss);
    return c;
}

// Serialize PublicKey (optional, can be pre-shared)
string serialize_publickey(const PublicKey& pk) {
    stringstream ss;
    pk.save(ss);
    return ss.str();
}

// Deserialize PublicKey
PublicKey deserialize_publickey(const string& s, shared_ptr<SEALContext> context) {
    stringstream ss(s);
    PublicKey pk;
    pk.load(context, ss);
    return pk;
}

// ===============================================================
// Homomorphic Encryption PIR Function (SEAL BFV)
// ===============================================================
void run_pir_he(map<string, double>& timings, map<string, size_t>& comm_sizes) {
    cout << "\n--- Running PIR with Homomorphic Encryption (SEAL BFV) ---" << endl;

    high_resolution_clock::time_point time_start, time_end;
    double duration;

    // --- HE Setup (Client Side) ---
    time_start = high_resolution_clock::now();
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192; // Example parameter
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // Plaintext modulus needs to be large enough for the result (0-15) + noise
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, HE_PLAIN_MOD_BITSIZE));

    shared_ptr<SEALContext> context = make_shared<SEALContext>(parms);

    KeyGenerator keygen(*context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    // RelinKeys relin_keys; // Not strictly needed for ctxt-ptxt mult
    // keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(*context, public_key);
    Evaluator evaluator(*context);
    Decryptor decryptor(*context, secret_key);
    // BatchEncoder batch_encoder(*context); // Use if batching needed

    time_end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(time_end - time_start).count() / 1e6;
    timings["HE KeyGen (Client)"] = duration;
    cout << "[Client] HE Context & Keys generated. (" << duration << "s)" << endl;

    // --- Client Phase 1: Query Encryption ---
    time_start = high_resolution_clock::now();

    int target_k = TARGET_CLIENT_IDX * DB_N_RECORDS + TARGET_RECORD_IDX;
    if (target_k < 0 || target_k >= DB_TOTAL_RECORDS) {
         throw runtime_error("Client target index out of bounds!");
    }
    cout << "[Client] Encrypting selection vector for index k = " << target_k << "..." << endl;

    vector<int64_t> selection_vector(DB_TOTAL_RECORDS, 0);
    selection_vector[target_k] = 1;

    vector<Ciphertext> enc_selection_vector;
    enc_selection_vector.reserve(DB_TOTAL_RECORDS);
    Plaintext pt_buffer; // Reuse plaintext object

    for (int i = 0; i < DB_TOTAL_RECORDS; ++i) {
        // Encode 0 or 1 as plaintext polynomial
        // For BFV integer encoding is implicit if value fits in plain_modulus
        pt_buffer.set_zero(); // Important to clear
        pt_buffer.data()[0] = selection_vector[i]; // Simple encoding for small integers
        // Alternatively use batch_encoder.encode(...) if batching

        Ciphertext encrypted_val;
        encryptor.encrypt(pt_buffer, encrypted_val);
        enc_selection_vector.push_back(move(encrypted_val));
    }

    time_end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(time_end - time_start).count() / 1e6;
    timings["HE Query Encrypt (Client)"] = duration;
    cout << "[Client] Selection vector encrypted (" << DB_TOTAL_RECORDS << " ciphertexts). (" << duration << "s)" << endl;

    // Simulate sending query to server
    string serialized_query = serialize_ciphertext_vector(enc_selection_vector);
    comm_sizes["Client->Server (bytes)"] = serialized_query.size();
    cout << "[Client] Serialized query size: " << serialized_query.size() << " bytes" << endl;
    // Optionally serialize public key if server doesn't have it
    // string serialized_pk = serialize_publickey(public_key);


    // --- Server Phase: Computation ---
    time_start = high_resolution_clock::now();
    cout << "[Server] Received query. Deserializing..." << endl;

    // Server deserializes the query (needs context)
    vector<Ciphertext> server_enc_query = deserialize_ciphertext_vector(serialized_query, context);
    // Server would also need PublicKey if not pre-shared

    // Server generates/loads its database
    vector<int64_t> db_plaintext(DB_TOTAL_RECORDS);
    srand(time(NULL)); // Seed RNG
    cout << "[Server] Generating dummy database..." << endl;
    for (int i = 0; i < DB_TOTAL_RECORDS; ++i) {
        db_plaintext[i] = rand() % 16; // Value 0-15
    }
    cout << "[Server] Sample DB (first 10): ";
    for(int i = 0; i < min(10, DB_TOTAL_RECORDS); ++i) cout << db_plaintext[i] << " ";
    cout << "..." << endl;

    cout << "[Server] Performing homomorphic computation..." << endl;
    // Initialize result ciphertext (encrypt 0)
    Ciphertext result_ctxt;
    Plaintext zero_pt;
    zero_pt.set_zero();
    encryptor.encrypt(zero_pt, result_ctxt); // Encrypt a zero using client's public key

    Plaintext db_val_pt; // Reuse plaintext object
    Ciphertext temp_product; // Temporary storage for product

    for (int x = 0; x < DB_TOTAL_RECORDS; ++x) {
        // Encode DB value
        db_val_pt.set_zero();
        db_val_pt.data()[0] = db_plaintext[x];

        // Homomorphic Multiplication: Ciphertext * Plaintext
        // result = Enc(S[x]) * DB[x]
        evaluator.multiply_plain(server_enc_query[x], db_val_pt, temp_product);

        // Homomorphic Addition: result_ctxt = result_ctxt + result
        evaluator.add_inplace(result_ctxt, temp_product);

        // Optional: Relinearization - not needed for ctxt-ptxt mult.
        // evaluator.relinearize_inplace(result_ctxt, relin_keys);

        // Optional: Noise check/rescaling if using CKKS or deep BFV circuits
    }
    cout << "[Server] Homomorphic computation complete." << endl;

    time_end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(time_end - time_start).count() / 1e6;
    timings["HE Compute (Server)"] = duration;
    cout << "[Server] Computation time: " << duration << "s)" << endl;

    // Simulate sending result back to client
    string serialized_result = serialize_ciphertext(result_ctxt);
    comm_sizes["Server->Client (bytes)"] = serialized_result.size();
    cout << "[Server] Serialized result size: " << serialized_result.size() << " bytes" << endl;


    // --- Client Phase 2: Decryption ---
    time_start = high_resolution_clock::now();
    cout << "[Client] Received result. Deserializing and decrypting..." << endl;

    Ciphertext client_final_ctxt = deserialize_ciphertext(serialized_result, context);
    Plaintext final_pt;
    decryptor.decrypt(client_final_ctxt, final_pt);

    // Decode the result (simplistic decoding for single integer)
    int64_t final_result = final_pt.data()[0]; // Extract the coefficient

    time_end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(time_end - time_start).count() / 1e6;
    timings["HE Result Decrypt (Client)"] = duration;
    cout << "[Client] Decryption complete. (" << duration << "s)" << endl;

    // --- Verification ---
    cout << "\n--- HE Verification ---" << endl;
    cout << "[Client] Decrypted Result: " << final_result << endl;
    int64_t expected_result = db_plaintext[target_k];
    cout << "[Client] Expected Result (DB[" << target_k << "]): " << expected_result << endl;

    if (final_result == expected_result) {
        cout << "[Client] SUCCESS: HE Decrypted result matches expected value!" << endl;
    } else {
        cout << "[Client] FAILURE: HE Decrypted result does NOT match!" << endl;
    }
}
#endif // USE_SEAL


#ifdef USE_EMP
// ===============================================================
// Garbled Circuit PIR Function (EMP-SH2PC)
// ===============================================================
// Function to perform the secure PIR computation using EMP Garbled Circuits
void run_pir_gc(NetIO *io, int party, map<string, double>& timings) {
    cout << "\n--- Running PIR with Garbled Circuits (EMP-SH2PC) ---" << endl;

    high_resolution_clock::time_point time_start, time_end;
    double duration_input = 0, duration_reveal = 0;

    // Calculate bits needed for the index k (0 to N-1)
    const int INDEX_BITSIZE = static_cast<int>(ceil(log2(DB_TOTAL_RECORDS)));

    // --- Input Phase (Timing includes secure transfer) ---
    time_start = high_resolution_clock::now();
    Integer client_index_k; // Secure integer for the client's desired index k
    vector<Integer> server_db(DB_TOTAL_RECORDS); // Secure integers for server's DB

    if (party == ALICE) { // Client provides the index k
        int target_k = TARGET_CLIENT_IDX * DB_N_RECORDS + TARGET_RECORD_IDX;
        if (target_k < 0 || target_k >= DB_TOTAL_RECORDS) {
             throw runtime_error("[GC Client] Target index out of bounds!");
        }
        cout << "[GC Client] Providing target index k = " << target_k << endl;
        client_index_k = Integer(INDEX_BITSIZE, target_k, ALICE);
        // Server provides dummy inputs for the DB vector (size matters)
        for (int i = 0; i < DB_TOTAL_RECORDS; ++i) {
            server_db[i] = Integer(DB_VALUE_BITSIZE, 0, BOB);
        }
    } else { // Server (BOB) provides the database contents
        // Client provides a dummy index
        client_index_k = Integer(INDEX_BITSIZE, 0, ALICE);

        // Generate or load the actual database
        vector<int> db_plaintext(DB_TOTAL_RECORDS);
        cout << "[GC Server] Generating dummy database..." << endl;
        srand(time(NULL) + 1); // Seed differently from HE if run close together
        for (int i = 0; i < DB_TOTAL_RECORDS; ++i) {
            db_plaintext[i] = rand() % 16; // Random value 0-15
        }
        cout << "[GC Server] Sample DB (first 10): ";
        for(int i = 0; i < min(10, DB_TOTAL_RECORDS); ++i) cout << db_plaintext[i] << " ";
        cout << "..." << endl;

        // Provide database values securely
        cout << "[GC Server] Providing database securely..." << endl;
        for (int i = 0; i < DB_TOTAL_RECORDS; ++i) {
            server_db[i] = Integer(DB_VALUE_BITSIZE, db_plaintext[i], BOB);
        }
    }
    // EMP performs secure input transfer here implicitly
    time_end = high_resolution_clock::now();
    duration_input = duration_cast<microseconds>(time_end - time_start).count() / 1e6;
    timings["GC Input Provision"] = duration_input;
    cout << "GC Input provision finished. (" << duration_input << "s)" << endl;


    // --- Computation Phase (Timed by EMP execution) ---
    cout << "GC Performing secure selection (circuit execution)..." << endl;
    time_start = high_resolution_clock::now(); // Start timing compute phase

    Integer result(DB_VALUE_BITSIZE, 0, PUBLIC); // Start with public zero
    Integer zero_value(DB_VALUE_BITSIZE, 0, PUBLIC);

    for (int x = 0; x < DB_TOTAL_RECORDS; ++x) {
        Integer current_x(INDEX_BITSIZE, x, PUBLIC);
        Bit comparison_result = (client_index_k == current_x);
        Integer selected_value = If(comparison_result, server_db[x], zero_value);
        result = result + selected_value;
    }

    // Execution happens implicitly here and during reveal
    time_end = high_resolution_clock::now(); // End timing compute phase (approximate)
    double duration_compute = duration_cast<microseconds>(time_end - time_start).count() / 1e6;
    timings["GC Circuit Compute (Approx)"] = duration_compute; // Includes setup for reveal
    cout << "GC Secure selection logic defined. (" << duration_compute << "s)" << endl;


    // --- Output Phase (Timed) ---
    cout << "GC Revealing result to Client (ALICE)..." << endl;
    time_start = high_resolution_clock::now();
    long long output_value = result.reveal<long long>(ALICE); // Reveal happens here
    time_end = high_resolution_clock::now();
    duration_reveal = duration_cast<microseconds>(time_end - time_start).count() / 1e6;
    timings["GC Result Reveal"] = duration_reveal;
    cout << "GC Result reveal finished. (" << duration_reveal << "s)" << endl;


    // --- Post-Computation & Verification ---
    if (party == ALICE) {
        cout << "\n--- GC Verification ---" << endl;
        cout << "[GC Client] Received Result: " << output_value << endl;
        // Verification requires knowing the server's DB in this test setup
        // In practice, client wouldn't know this.
        // cout << "[GC Client] Expected Result (DB[" << target_k << "]): " << expected_result << endl;
    } else {
        cout << "[GC Server] Computation finished. Result revealed to Client." << endl;
    }
     timings["GC Total (Approx)"] = duration_input + duration_compute + duration_reveal; // Sum of phases
}
#endif // USE_EMP


// ===============================================================
// Main Comparison Runner
// ===============================================================
int main(int argc, char** argv) {
    string protocol;
    int party = 0;
    int port = 0;
    string server_ip = "127.0.0.1"; // Default

    // --- Argument Parsing ---
    if (argc < 3) {
        cerr << "Usage: ./pir_compare PROTOCOL PARTY_ID [PORT SERVER_IP | options...]" << endl;
        cerr << "  PROTOCOL: 'gc' or 'he'" << endl;
        cerr << "  PARTY_ID: 1 (Client/ALICE) or 2 (Server/BOB)" << endl;
        cerr << "  For 'gc': PORT SERVER_IP (SERVER_IP needed for client)" << endl;
        cerr << "  For 'he': (No extra args needed for this simulation)" << endl;
        return 1;
    }

    protocol = argv[1];
    party = atoi(argv[2]);

    if (protocol != "gc" && protocol != "he") {
        cerr << "Error: PROTOCOL must be 'gc' or 'he'" << endl; return 1;
    }
    if (party != 1 && party != 2) {
        cerr << "Error: PARTY_ID must be 1 (ALICE) or 2 (BOB)" << endl; return 1;
    }

    if (protocol == "gc") {
#ifndef USE_EMP
        cerr << "Error: GC protocol selected, but code not compiled with USE_EMP defined." << endl; return 1;
#endif
        if (argc < 4) {
            cerr << "Error: 'gc' protocol requires PORT." << endl; return 1;
        }
        port = atoi(argv[3]);
        if (party == 1) { // Client needs server IP
            if (argc < 5) {
                cerr << "Error: Client (Party 1) for 'gc' requires SERVER_IP." << endl; return 1;
            }
            server_ip = argv[4];
        }
    } else { // protocol == "he"
#ifndef USE_SEAL
         cerr << "Error: HE protocol selected, but code not compiled with USE_SEAL defined." << endl; return 1;
#endif
        if (party == 2) {
            cout << "Note: HE simulation is driven by Party 1. Run with Party 1 to see timings." << endl;
            // Server role doesn't do anything independently in this HE simulation setup.
             return 0;
        }
    }

    // --- Data Structures for Results ---
    map<string, double> timings; // Stores durations in seconds
    map<string, size_t> comm_sizes; // Stores communication sizes in bytes

    // --- Execute Selected Protocol ---
    try {
        if (protocol == "gc") {
#ifdef USE_EMP
            NetIO * io = new NetIO(party == ALICE ? server_ip.c_str() : nullptr, port);
            cout << "[GC Main] Network setup..." << endl;
            setup_semi_honest(io, party);
            cout << "[GC Main] Network setup complete. Running PIR..." << endl;
            run_pir_gc(io, party, timings);
            finalize_semi_honest();
            delete io;
            cout << "[GC Main] Protocol finished." << endl;
#endif
        } else { // protocol == "he"
#ifdef USE_SEAL
            // In this version, party 1 simulates both client and server sequentially
            if (party == ALICE) {
                run_pir_he(timings, comm_sizes);
            }
            // Party 2 does nothing in this HE simulation setup
#endif
        }
    } catch (const exception& e) {
        cerr << "\n\n**********\nError during execution: " << e.what() << "\n**********" << endl;
        return 1;
    }

    // --- Print Summary ---
    if (party == ALICE) { // Only client prints summary in GC, always in HE sim
        cout << "\n\n========================= Performance Summary =========================" << endl;
        cout << "Protocol: " << protocol << endl;
        cout << "Database Size (m*n): " << DB_M_CLIENTS << " * " << DB_N_RECORDS << " = " << DB_TOTAL_RECORDS << endl;
        cout << "\n--- Timing (seconds) ---" << endl;
        for (const auto& pair : timings) {
            cout << "  " << pair.first << ": " << pair.second << endl;
        }

        if (!comm_sizes.empty()) {
             cout << "\n--- Communication Size Estimates (bytes) ---" << endl;
             for (const auto& pair : comm_sizes) {
                 cout << "  " << pair.first << ": " << pair.second << endl;
             }
        } else if (protocol == "gc") {
            cout << "\n--- Communication Size Estimates (bytes) ---" << endl;
            cout << "  (EMP-SH2PC communication measured implicitly via network traffic)" << endl;
            // Note: EMP's total communication depends on circuit size, OT complexity etc.
            // Typically hundreds of KB to MBs for circuits of this size.
        }
        cout << "=======================================================================" << endl;
    }


    return 0;
}