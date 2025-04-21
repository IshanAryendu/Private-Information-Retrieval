use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;
use std::time::Instant;
use rand::Rng;

fn main() {
    // Parameters
    let m = 50; // Number of rows
    let n = 350; // Number of columns
    
    // Key generation
    let start = Instant::now();
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    println!("Key generation took: {:.2?}", start.elapsed());
    set_server_key(server_key);
    
    // Create a random 2D array (m×n)
    let mut rng = rand::thread_rng();
    let mut plain_matrix = vec![vec![0u8; n]; m];
    for i in 0..m {
        for j in 0..n {
            plain_matrix[i][j] = rng.gen_range(0..=255);
        }
    }
    
    // Create encrypted matrix
    let mut enc_matrix = vec![vec![FheUint8::encrypt(0u8, &client_key); n]; m];
    for i in 0..m {
        for j in 0..n {
            enc_matrix[i][j] = FheUint8::encrypt(plain_matrix[i][j], &client_key);
        }
    }
    
    // Create column vector (one random position set to 1, rest 0)
    let col_idx = rng.gen_range(0..n);
    let mut plain_col_vec = vec![0u8; n];
    plain_col_vec[col_idx] = 1;
    
    let mut enc_col_vec = vec![FheUint8::encrypt(0u8, &client_key); n];
    for j in 0..n {
        enc_col_vec[j] = FheUint8::encrypt(plain_col_vec[j], &client_key);
    }
    
    // Create row vector (one random position set to 1, rest 0)
    let row_idx = rng.gen_range(0..m);
    let mut plain_row_vec = vec![0u8; m];
    plain_row_vec[row_idx] = 1;
    
    let mut enc_row_vec = vec![FheUint8::encrypt(0u8, &client_key); m];
    for i in 0..m {
        enc_row_vec[i] = FheUint8::encrypt(plain_row_vec[i], &client_key);
    }
    
    // Homomorphic operations
    let start = Instant::now();
    
    // 1. Multiply each row with column vector and sum
    let mut enc_sum_vec = vec![FheUint8::encrypt(0u8, &client_key); m];
    for i in 0..m {
        let mut row_sum = FheUint8::encrypt(0u8, &client_key);
        for j in 0..n {
            let product = &enc_matrix[i][j] * &enc_col_vec[j];
            row_sum = &row_sum + &product;
        }
        enc_sum_vec[i] = row_sum;
    }
    
    // 2. Multiply row vector with sum vector
    let mut final_result = FheUint8::encrypt(0u8, &client_key);
    for i in 0..m {
        let product = &enc_row_vec[i] * &enc_sum_vec[i];
        final_result = &final_result + &product;
    }
    
    println!("Homomorphic operations took: {:.2?}", start.elapsed());
    
    // Decrypt result
    let decrypted_result: u8 = final_result.decrypt(&client_key);
    
    // Calculate expected result (for verification)
    let expected_result = plain_matrix[row_idx][col_idx];
    
    println!("Matrix:");
    for row in &plain_matrix {
        println!("{:?}", row);
    }
    println!("Column vector (index {}): {:?}", col_idx, plain_col_vec);
    println!("Row vector (index {}): {:?}", row_idx, plain_row_vec);
    println!("Decrypted result: {}", decrypted_result);
    println!("Expected result: {}", expected_result);
    
    assert_eq!(decrypted_result, expected_result);
}
