#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "onion.h"

int generate_random_B(uint8_t *b_block) {
    if (!RAND_bytes(b_block, B_SIZE)) {
        return -1;  // Error generating B
    }
    return 0;  // Success
}

int generate_random_key_iv(uint8_t *key, uint8_t *iv) {
    if (!RAND_bytes(key, KEY_SIZE)) {
        return -1;  // Error generating key
    }
    if (!RAND_bytes(iv, IV_SIZE)) {
        return -1;  // Error generating IV
    }
    return 0;  // Success
}

// Función para cifrar con AES-256-CBC
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

// Función para descifrar con AES-256-CBC
int decrypt(const uint8_t *ciphertext, int ciphertext_len, const uint8_t *key, uint8_t *plaintext, const uint8_t *iv) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) return -1;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) return -1;
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) return -1;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Función para imprimir en hexadecimal
void print_hex(const char *label, const uint8_t *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02X", data[i]);
    printf("\n");
}
