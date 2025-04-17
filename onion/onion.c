#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "onion.h"


int generate_rdm(uint8_t *rdm, int rdm_size) {
    if (!RAND_bytes(rdm, rdm_size)) {
        return -1;  // Error generating B
    }
    return 0;  // Success
}

// Function to encrypt with AES-256-CBC
int encrypt(const uint8_t *plaintext, int plaintext_len, const uint8_t *key, uint8_t *ciphertext, uint8_t *iv) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) return -1;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) return -1;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) return -1;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Function to decrypt with AES-256-CBC
int decrypt(const uint8_t *ciphertext, int ciphertext_len, const uint8_t *key, uint8_t *plaintext, const uint8_t *iv) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) return -1;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) return -1;
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) return -4;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
