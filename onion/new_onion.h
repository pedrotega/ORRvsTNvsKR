// new_onion.h

#ifndef NEW_ONION_H
#define NEW_ONION_H

#include "onion.h"

#define NUM_INT (NUM_WORKERS - 1) // n = N - 1 # We assume that longest route was selected
#define SIGN_SIZE 32 // HMAC-256 in our case
#define B_INIT_SIZE (KEY_SIZE*NUM_WORKERS + SIGN_SIZE + AES_PAD)
#define KDF_OUT_SIZE 32
#define PRNG_BLOCK_SIZE 16


uint8_t** generate_rdm_array(int n, int rdm_size);
void free_keys(uint8_t **keys, int n);
void generate_rdms(int n, int N, uint8_t ***b_blks_out, uint8_t ***ef_keys, uint8_t **ids);
void free_rdms(uint8_t*** rdms, int n, int N);
int enc_dec_xor(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
int generate_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *message, size_t message_len, uint8_t *hmac_output, size_t *hmac_len);
void process_padding(int N, uint8_t **keys, uint8_t *id, uint8_t **b_blks);
void KDF(uint8_t *output, const uint8_t *key, size_t key_len, const uint8_t *id, size_t id_len);
void PRNG(uint8_t *output, size_t out_len, const uint8_t *seed, size_t seed_len);
void calculate_tags(int n, int N, uint8_t **pqc_keys, uint8_t ***ef_keys, 
    uint8_t **onions, int *onions_sizes, uint8_t **b_blks);

#endif // NEW_ONION_H