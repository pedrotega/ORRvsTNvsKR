// onion.h
#ifndef ONION_H
#define ONION_H

#include "../utils/utils.h"

#define KEY_SIZE 32  // AES-256 (256 bits = 32 bytes)
#define IV_SIZE 16   // AES use IV of 16 bytes
#define ID_SIZE 16   // Fixed size for ID
#define AES_PAD 16   // AES block size

int generate_rdm(uint8_t *rdm, int rdm_size);
int encrypt(const uint8_t *plaintext, int plaintext_len, const uint8_t *key, uint8_t *ciphertext, uint8_t *iv);
int decrypt(const uint8_t *ciphertext, int ciphertext_len, const uint8_t *key, uint8_t *plaintext, const uint8_t *iv);
int enc_dec_xor(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);

#endif // ONION_H