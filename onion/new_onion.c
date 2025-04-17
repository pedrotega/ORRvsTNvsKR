#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <oqs/oqs.h>

#include "new_onion.h"

// Función para crear el array bidimensional de claves
uint8_t** generate_rdm_array(int n, int rdm_size) {
    // Reservar memoria para el array de claves
    uint8_t **rdms = (uint8_t **)malloc(n * sizeof(uint8_t *));

    // Reservar memoria para cada clave
    for (int i = 0; i < n; i++) {
        rdms[i] = (uint8_t *)malloc(rdm_size * sizeof(uint8_t));
        generate_rdm(rdms[i], rdm_size);
    }

    return rdms;  // Retornar el array de claves
}

// Función para liberar la memoria del array de claves
void free_keys(uint8_t **keys, int n) {
    for (int i = 0; i < n; i++) {
        free(keys[i]);
    }
    free(keys);
}


void generate_rdms(int n, int N, uint8_t ***b_blks_out, uint8_t ***ef_keys, uint8_t **ids) {
    // Create B_N random blocks
    uint8_t **blks = generate_rdm_array(N, B_INIT_SIZE);

    for (int i = 0; i < n; i++) {
        process_padding(N, ef_keys[i], ids[i], blks);
    }

    // Asignar los resultados a los punteros de salida
    *b_blks_out = blks;
}

// Liberar memoria de rdms
void free_rdms(uint8_t*** rdms, int n, int N) {
    for (int i = 0; i < n; i++) {
        int start = n - i - 1;
        int cols = N - start;
        for (int j = 0; j < cols; j++) {
            free(rdms[i][j]);
        }
        free(rdms[i]);
    }
    free(rdms);
}

int enc_dec_xor(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
    if (plaintext == NULL || key == NULL || ciphertext == NULL) {
        fprintf(stderr, "Error: Argumentos nulos en encrypt_xor.\n");
        return -1;
    }

    // Generar una clave adaptada al tamaño del mensaje usando PRNG
    uint8_t *adapted_key = (uint8_t *)malloc(plaintext_len);
    // if (adapted_key == NULL) {
    //     fprintf(stderr, "Error: No se pudo asignar memoria para la clave adaptada.\n");
    //     return -1;
    // }

    PRNG(adapted_key, plaintext_len, key, KEY_SIZE);

    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ adapted_key[i];
    }

    free(adapted_key); // Liberar la memoria de la clave adaptada

    return plaintext_len; // Devuelve la longitud del texto cifrado
}

// Function to generate PQC sign
int generate_pqc_sign(const uint8_t *key, size_t key_len, const uint8_t *message, size_t message_len, uint8_t *signature, size_t *signature_len) {
    if (key == NULL || message == NULL || signature == NULL || signature_len == NULL) {
        fprintf(stderr, "Error: Null arguments for function generate_pqc_sign.\n");
        return -1;
    }

    uint8_t *sig_key = (uint8_t *)malloc(OQS_SIG_dilithium_3_length_secret_key);
    if (key_len != OQS_SIG_dilithium_3_length_secret_key) {
        fprintf(stderr, "Error: Invalid key length for PQC signature.\n");
        return -1;
    }
    OQS_STATUS rc = OQS_SIG_dilithium_3_sign(signature, signature_len, message, message_len, key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG__sign failed!\n");
		return -1;
	}

}
// Función para generar una firma HMAC-SHA256
int generate_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *message, size_t message_len, uint8_t *hmac_output, size_t *hmac_len) {
    if (key == NULL || message == NULL || hmac_output == NULL || hmac_len == NULL) {
        fprintf(stderr, "Error: Null argumets for function generate_hmac_sha256.\n");
        return -1;
    }

    // Generar la firma HMAC-SHA256
    unsigned int len = 0;
    uint8_t *result = HMAC(EVP_sha256(), key, key_len, message, message_len, hmac_output, &len);

    if (result == NULL) {
        fprintf(stderr, "Error: Falló la generación de HMAC-SHA256.\n");
        return -1;
    }

    *hmac_len = len; // Guardar la longitud de la firma generada
    return 0; // Éxito
}

void process_padding(int N, uint8_t **keys, uint8_t *id, uint8_t **b_blks) {

    uint8_t kdf_output[KDF_OUT_SIZE];
    uint8_t key[N*KEY_SIZE];
    for (int i = 0; i < N; i++) {
        memcpy(key + i*KEY_SIZE, keys[i], KEY_SIZE);
    }
    KDF(kdf_output, key, N*KEY_SIZE, id, ID_SIZE);

    uint8_t ri[B_INIT_SIZE];
    PRNG(ri,sizeof(ri),kdf_output, KDF_OUT_SIZE);

    for (int i = 0; i < N-1; i++) {
        int dec_len = enc_dec_xor(b_blks[i+1],B_INIT_SIZE,keys[i],b_blks[i]);
    }

    b_blks[N-1] = (uint8_t *)malloc(sizeof(ri));
    memcpy(b_blks[N-1], ri, sizeof(ri));        
}

// KDF: HMAC-SHA256 (Output 32B)
void KDF(uint8_t *output, const uint8_t *key, size_t key_len, const uint8_t *id, size_t id_len) {
    unsigned int len = KDF_OUT_SIZE;
    HMAC(EVP_sha256(), key, key_len, id, id_len, output, &len);
}

void PRNG(uint8_t *output, size_t out_len, const uint8_t *seed, size_t seed_len) {
    uint8_t counter[4] = {0};
    uint8_t input[seed_len + sizeof(counter)]; 
    size_t generated = 0;

    while (generated < out_len) {
        // Combine seed + counter
        memcpy(input, seed, seed_len);
        memcpy(input + seed_len, counter, sizeof(counter));

        // Use SHA-256 to generate the output block
        uint8_t hash[SHA256_DIGEST_LENGTH]; 
        SHA256(input, sizeof(input), hash);

        // Copy the first 16 bytes of the hash to the output
        size_t chunk = (out_len - generated > PRNG_BLOCK_SIZE) ? PRNG_BLOCK_SIZE : (out_len - generated);
        memcpy(output + generated, hash, chunk);
        generated += chunk;

        for (int i = 3; i >= 0; i--) {
            if (++counter[i] != 0) break;  
        }
    }
}

void calculate_tags(int n, int N, uint8_t **pqc_keys, uint8_t ***ef_keys, 
    uint8_t **onions, int *onions_sizes, uint8_t **b_blks) {

    for (int i = n - 1; i >= 0; i--) {  

        uint8_t **b_prime = (uint8_t **)malloc((N - 1) * sizeof(uint8_t *));
        // a) b'_i = Enc(ef_key_i, B'_1 || ... || B'_{N-1})
        for (int j = 0; j < N - 1; j++) {
            b_prime[j] = (uint8_t *)malloc(B_INIT_SIZE);
            int res = enc_dec_xor(b_blks[j], B_INIT_SIZE, ef_keys[i][j], b_prime[j]);
        }

        // b) tau_i = Sig(sig_keys_i, (onions_i || B'_1 || ... || B'_{N-1}))
        uint8_t *sig_key = (uint8_t *)malloc(N*KEY_SIZE);
        for (int j = 0; j < N; j++) {
            memcpy(sig_key + j*KEY_SIZE, ef_keys[i][j], KEY_SIZE);
        }
        int tau_input_length = onions_sizes[i+1];
        for (int j = 0; j < N - 1; j++) {
            tau_input_length += B_INIT_SIZE;
        }
        uint8_t *tau_input = (uint8_t *)malloc(tau_input_length);
        memcpy(tau_input, onions[i+1], onions_sizes[i+1]);

        int offset = onions_sizes[i+1];
        for (int j = 0; j < N - 1; j++) {
            memcpy(tau_input + offset, b_prime[j], B_INIT_SIZE);
            offset += B_INIT_SIZE;
        }
        uint8_t tau[SIGN_SIZE]; 
        size_t tau_length = SIGN_SIZE;
        

        int res = generate_hmac_sha256(sig_key, N*KEY_SIZE, tau_input, tau_input_length, tau, &tau_length); 

        // c) B_new <- Enc(pqc_keys_i, (ef_key_i || tau))
        int embed_size = N*KEY_SIZE + tau_length;
        uint8_t *embed = (uint8_t *)malloc(embed_size);

        // Copy ef_key[i] to the beginning of embed
        memcpy(embed, sig_key, N*KEY_SIZE);
        memcpy(embed + N*KEY_SIZE, tau, tau_length);

        // Encrypt the message embed to generate b_new
        uint8_t *b_new = (uint8_t *)malloc(embed_size + 16); // +16 for IV
        int b_new_size = encrypt(embed, embed_size, pqc_keys[i], b_new, NULL);
        
        free(b_blks[0]);
        b_blks[0] = b_new;
        for (int j = 0; j < N - 1; j++) {
            free(b_blks[j + 1]);
            b_blks[j + 1] = b_prime[j];
        }

        free(tau_input);
        free (embed);
        free(b_prime);
    }
}