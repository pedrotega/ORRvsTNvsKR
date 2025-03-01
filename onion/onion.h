// onion.h
#ifndef ONION_H
#define ONION_H

#include <stddef.h>

#define KEY_SIZE 32  // AES-256 (256 bits = 32 bytes)
#define IV_SIZE 16   // AES IV of 16 bytes
#define ID_SIZE 16   
#define B_SIZE 4

int generate_random_B(uint8_t *b_block);
int generate_random_key_iv(uint8_t *key, uint8_t *iv);
int encrypt(const uint8_t *plaintext, int plaintext_len, const uint8_t *key, uint8_t *ciphertext, uint8_t *iv);
int decrypt(const uint8_t *ciphertext, int ciphertext_len, const uint8_t *key, uint8_t *plaintext, const uint8_t *iv);
void xor_encrypt_decrypt(const uint8_t *input, int input_len, const uint8_t *key, uint8_t *output);
void print_array_hex(const char *label, uint8_t *array, size_t length);

#endif // ONION_H