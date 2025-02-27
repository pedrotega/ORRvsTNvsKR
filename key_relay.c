// gcc -o key_relay key_relay.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Requests
#include <oqs/oqs.h>
#include "kms/kms.h"
#include "onion/onion.h"

#define NUM_WORKERS 11
#define NUM_EXEC 20

char *key_db_name = "key_distribution.csv";
char *enc_db_name = "encryption_time.csv";

clock_t key_init_time, key_end_time;
clock_t enc_init_time, enc_end_time;

typedef struct {
    int id;
    int ready;
    int finished;
    uint8_t *ciphertext;
    char *qkd_id;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} WorkerData;

WorkerData workers[NUM_WORKERS];

void print_array_hex(const char *label, uint8_t *array, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", array[i]);
    }
    printf("\n");
}

// Función para cifrado/descifrado XOR
void xor_encrypt_decrypt(const uint8_t *input, int input_len, const uint8_t *key, uint8_t *output) {
    for (int i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % KEY_SIZE];
    }
}

void *worker_thread(void *arg) {
    WorkerData *worker = (WorkerData *)arg;
    uint8_t qkd_key[KEY_SIZE];
    uint8_t next_qkd_key[KEY_SIZE];
    char next_qkd_id[QKD_KEY_ID];
    char url[256];
    char *response;
    char qkd_id[256] = {0};

    pthread_mutex_lock(&worker->mutex);    
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;

    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/dec_keys", KMSS_IP, C1_ENC);
    char post_data[512];
    snprintf(post_data, sizeof(post_data), "{\"key_IDs\":[{\"key_ID\":\"%s\"}]}", worker->qkd_id);

    response = request_https(url, C2_PUB_KEY, C2_PRIV_KEY, C2_ROOT_CA, post_data);
    if (response) {
        extract_key8_and_id(response, qkd_key, KEY_SIZE, qkd_id, QKD_KEY_ID);
        // printf("[NODE %i] - ",worker->id);
        // print_array_hex("QKDKEY", qkd_key, KEY_SIZE);
        // printf("[NODE %i] - QKD_ID: %s\n", worker->id,qkd_id);
        free(response);
    }

    // Read QKD Key from the KMS

    // Preparamos info para el próximo nodo
    if(worker->id < NUM_WORKERS-1){        

        snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
        response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
        if (response) {
            extract_key8_and_id(response, next_qkd_key, KEY_SIZE, next_qkd_id, QKD_KEY_ID);
            // printf("[NODE %i] - ",worker->id);
            // print_array_hex("QKDKEY", next_qkd_key, KEY_SIZE);
            // printf("[NODE %i] - QKD_ID: %s\n", worker->id,next_qkd_id);
            workers[worker->id+1].qkd_id = next_qkd_id;
            free(response);
        }
        // printf("[NODE %i]: Cediendo paso a nodo %i\n",worker->id,worker->id+1);
        workers[worker->id+1].ready = 1;
        pthread_cond_signal(&workers[worker->id+1].cond);
        pthread_mutex_unlock(&workers[worker->id+1].mutex);
    } else {
        // printf("[NODE %i]: Cediendo paso a main\n",worker->id);
        worker->finished = 1;
        pthread_cond_signal(&worker->cond);
        pthread_mutex_unlock(&worker->mutex);
    }

    pthread_mutex_lock(&worker->mutex);    
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;

    // Decrypt secret and forward.

    uint8_t secret[KEY_SIZE];
    xor_encrypt_decrypt(worker->ciphertext, KEY_SIZE, qkd_key, secret);

    // Preparamos info para el próximo nodo
    if(worker->id < NUM_WORKERS-1){
        uint8_t ciphertext[KEY_SIZE];
        xor_encrypt_decrypt(secret, KEY_SIZE, next_qkd_key, ciphertext);
        
        // printf("[NODE %i]: Cediendo paso a nodo %i\n",worker->id,worker->id+1);
        workers[worker->id+1].ciphertext = ciphertext; 
        workers[worker->id+1].ready = 1;
        pthread_cond_signal(&workers[worker->id+1].cond);
        pthread_mutex_unlock(&workers[worker->id+1].mutex);
    } else {
        printf("[NODE %i] - ",worker->id);
        print_array_hex("SECRET", secret, KEY_SIZE);
        worker->finished = 1;
        pthread_cond_signal(&worker->cond);
        pthread_mutex_unlock(&worker->mutex);
    }

    return NULL;
}

void *main_thread(void *arg) {

    uint8_t secret[KEY_SIZE];
    uint8_t qkd_key[KEY_SIZE];
    char url[256];
    char *response;
    char qkd_id[256] = {0};

    // Read QKD Key from ID from the KMS
    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
    // printf("\nLeer clave del nodo maestro (Alice):\n");
    response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
    if (response) {
        extract_key8_and_id(response, qkd_key, KEY_SIZE, qkd_id, QKD_KEY_ID);
        // printf("[ MAIN ] - ");
        // print_array_hex("QKDKEY", qkd_key, KEY_SIZE);
        // printf("[ MAIN ] - QKD_ID: %s\n",qkd_id);
        free(response);
    }

    workers[0].qkd_id = qkd_id;

    workers[0].ready = 1;
    pthread_cond_signal(&workers[0].cond);
    pthread_mutex_unlock(&workers[0].mutex);

    pthread_mutex_lock(&workers[NUM_WORKERS-1].mutex);
    while (!workers[NUM_WORKERS-1].finished) {
        pthread_cond_wait(&workers[NUM_WORKERS-1].cond, &workers[NUM_WORKERS-1].mutex);
    }
    workers[NUM_WORKERS-1].finished = 0;

    // Encrypt secret with QKD key
    key_init_time = clock();
    RAND_bytes(secret, KEY_SIZE);
    printf("[ MAIN ] - ");
    print_array_hex("SECRET",secret,KEY_SIZE);

    uint8_t ciphertext[KEY_SIZE];
    enc_init_time = clock();
    xor_encrypt_decrypt(secret, KEY_SIZE, qkd_key, ciphertext);
    enc_end_time = clock();

    workers[0].ciphertext = ciphertext;

    workers[0].ready = 1;
    pthread_cond_signal(&workers[0].cond);
    pthread_mutex_unlock(&workers[0].mutex);

    pthread_mutex_lock(&workers[NUM_WORKERS-1].mutex);
    while (!workers[NUM_WORKERS-1].finished) {
        pthread_cond_wait(&workers[NUM_WORKERS-1].cond, &workers[NUM_WORKERS-1].mutex);
    }
    workers[NUM_WORKERS-1].finished = 0;
    key_end_time = clock();

    return NULL;
}

int main() {
    pthread_t worker_threads[NUM_WORKERS], main;

    int num_exec = 0;
    double key_cpu_time;
    double enc_cpu_time;
    FILE *key_db;
    FILE *enc_db;
    int first_exec = 1;

    // Abrir db para añadir o crear si no existe
    key_db = fopen(key_db_name, "w");
    enc_db = fopen(enc_db_name, "w");
    if (key_db == NULL) {
        printf("Error opening key_db.\n");
        return 1;
    }
    if (enc_db == NULL) {
        printf("Error opening enc_db.\n");
        return 1;
    }

    while (num_exec<NUM_EXEC) {
        printf("\n===== EXECUTION %d =====\n\n", num_exec + 1);
        for (int i = 0; i < NUM_WORKERS; i++) {
            workers[i].id = i;
            workers[i].ready = 0;
            workers[i].finished = 0;
            pthread_mutex_init(&workers[i].mutex, NULL);
            pthread_cond_init(&workers[i].cond, NULL);
        }

        pthread_create(&main, NULL, main_thread, NULL);

        for (int i = 0; i < NUM_WORKERS; i++) {
            pthread_create(&worker_threads[i], NULL, worker_thread, &workers[i]);
        }

        pthread_join(main, NULL);
        for (int i = 0; i < NUM_WORKERS; i++) {
            pthread_join(worker_threads[i], NULL);
        }

        for (int i = 0; i < NUM_WORKERS; i++) {
            pthread_mutex_destroy(&workers[i].mutex);
            pthread_cond_destroy(&workers[i].cond);
        }

        key_cpu_time = ((double) (key_end_time - key_init_time));
        enc_cpu_time = ((double) (enc_end_time - enc_init_time));
        printf("\nKEY CPU_TIME: %.2f us", key_cpu_time);
        printf("\nENC CPU_TIME: %.2f us\n", enc_cpu_time);

        if (first_exec) {
            fprintf(key_db, "KR-%i\n",NUM_WORKERS);
            fprintf(enc_db, "KR-%i\n",NUM_WORKERS);
            first_exec = 0;
        } 
        
        fprintf(key_db, "%.2f\n", key_cpu_time);
        fprintf(enc_db, "%.2f\n", enc_cpu_time);      
        
        num_exec++;
    }

    fclose(key_db);
    fclose(enc_db);

    return 0;
}