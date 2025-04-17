// gcc -DNUM_WORKERS=5 -DNUM_EXEC=2 -o key_relay key_relay.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <oqs/oqs.h>
#include "kms/kms.h"
#include "onion/onion.h"

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

// XOR function to encrypt and decrypt
void xor_encrypt_decrypt(const uint8_t *input, int input_len, const uint8_t *key, uint8_t *output) {
    for (int i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % KEY_SIZE];
    }
}

// Represent the onion routers intermediates and destination
void *worker_thread(void *arg) {
    WorkerData *worker = (WorkerData *)arg;
    uint8_t qkd_key[KEY_SIZE];
    uint8_t next_qkd_key[KEY_SIZE];
    char next_qkd_id[QKD_KEY_ID];
    char url[256];
    char *response;
    char qkd_id[256] = {0};

    // ############ - Initial Syncronization & QKD-KEY Exchange - ############

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
        free(response);
    }

    // Read QKD Key from the KMS and prepare information for the next node
    if(worker->id < NUM_WORKERS-1){        
        snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
        response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
        if (response) {
            extract_key8_and_id(response, next_qkd_key, KEY_SIZE, next_qkd_id, QKD_KEY_ID);
            workers[worker->id+1].qkd_id = next_qkd_id;
            free(response);
        }
        // Yield control to the next node
        workers[worker->id+1].ready = 1;
        pthread_cond_signal(&workers[worker->id+1].cond);
        pthread_mutex_unlock(&workers[worker->id+1].mutex);
    } else {
        // Yield control to initiator node
        worker->finished = 1;
        pthread_cond_signal(&worker->cond);
        pthread_mutex_unlock(&worker->mutex);
    }

    // ######### - Second Syncronization, ENC/DEC secret & Forward - #########

    pthread_mutex_lock(&worker->mutex);    
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;

    uint8_t secret[KEY_SIZE];
    xor_encrypt_decrypt(worker->ciphertext, KEY_SIZE, qkd_key, secret);

    // Prepare information for the next node
    if(worker->id < NUM_WORKERS-1){
        uint8_t ciphertext[KEY_SIZE];
        xor_encrypt_decrypt(secret, KEY_SIZE, next_qkd_key, ciphertext);
        
        // Yield control to the next node
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

// Represent the initiator onion router
void *main_thread(void *arg) {

    uint8_t secret[KEY_SIZE];
    uint8_t qkd_key[KEY_SIZE];
    char url[256];
    char *response;
    char qkd_id[256] = {0};

    // Read QKD Key from the KMS
    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
    response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
    if (response) {
        extract_key8_and_id(response, qkd_key, KEY_SIZE, qkd_id, QKD_KEY_ID);
        free(response);
    }
    workers[0].qkd_id = qkd_id;

    // ############ - Initial Syncronization & QKD-KEY Exchange - ############

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

    // ######### - Second Syncronization, ENC/DEC secret & Forward - #########

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

    key_db = fopen(DB_KEY_DIST, "a");
    enc_db = fopen(DB_ENC_TIME, "a");
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
        printf("\nKEY CPU_TIME: %.0f us", key_cpu_time);
        printf("\nENC CPU_TIME: %.0f us\n", enc_cpu_time);

        if (first_exec) {
            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            char timestamp[64];
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

            fprintf(key_db, "%s,KR-%i,", timestamp, NUM_WORKERS);
            fprintf(enc_db, "%s,KR-%i,", timestamp, NUM_WORKERS);
            first_exec = 0;
        } 
        
        fprintf(key_db, "%.0f,", key_cpu_time);
        fprintf(enc_db, "%.0f,", enc_cpu_time);  
        
        num_exec++;

        sleep(WAIT_TIME);
    }

    fprintf(key_db, "\n");
    fprintf(enc_db, "\n");

    fclose(key_db);
    fclose(enc_db);

    return 0;
}