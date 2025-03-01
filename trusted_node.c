// gcc -o trusted_node trusted_node.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <oqs/oqs.h>
#include "kms/kms.h"
#include "onion/onion.h"

#define NUM_WORKERS 4
#define NUM_EXEC 100

char *key_db_name = "key_distribution.csv";
char *enc_db_name = "encryption_time.csv";

clock_t key_init_time, key_end_time;
clock_t enc_init_time, enc_end_time;

typedef struct {
    int id;
    uint8_t *ciphertext;
    char *qkd_id;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int ready;
    int finished;
} WorkerData;

WorkerData workers[NUM_WORKERS];
pthread_mutex_t main_mutex;
pthread_cond_t main_cond;
int main_ready = 0;

void *worker_thread(void *arg) {
    WorkerData *worker = (WorkerData *)arg;
    uint8_t qkd_key[KEY_SIZE];
    uint8_t next_qkd_key[KEY_SIZE];
    char *next_qkd_id;
    char url[256];
    char *response;
    char qkd_id[256] = {0};

    next_qkd_id = malloc(QKD_KEY_ID);
    
    // Phase 1: Sequential communication
    pthread_mutex_lock(&worker->mutex);
    
    // Wait for main to signal this worker to start phase 1
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;
    
    // Process data in sequential phase    
    // Unlock the next worker in the chain (or main if this is the last worker)
    if (worker->id == 0) {
        // Read QKD Key from the KMS (To be shared with the next node)
        snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
        response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
        if (response) {
            extract_key8_and_id(response, next_qkd_key, KEY_SIZE, next_qkd_id, QKD_KEY_ID);
            workers[worker->id+1].qkd_id = next_qkd_id;
            // printf("[NODE %i] - ",worker->id);
            // print_array_hex("QKDKEY", next_qkd_key, KEY_SIZE);
            // printf("[NODE %i] - QKD_ID: %s\n", worker->id,next_qkd_id);
            free(response);
        }
        workers[worker->id + 1].ready = 1;
        pthread_cond_signal(&workers[worker->id + 1].cond);

    } else if (worker->id < NUM_WORKERS - 1) {

        // Read QKD KEY from the KMS using the QKD_ID (Shared with the previous node)
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

        // Read QKD Key from the KMS (To be shared with the next node)
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
        workers[worker->id + 1].ready = 1;
        pthread_cond_signal(&workers[worker->id + 1].cond);
    } else {
        // Read QKD KEY from the KMS using the QKD_ID (Shared with the previous node)
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
        main_ready = 1;
        pthread_cond_signal(&main_cond);
    }
    
    // Phase 2: Concurrent communication
    // Wait for the main thread to signal the start of phase 2
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;

    
    worker->ciphertext = malloc(KEY_SIZE);

    if(worker->id == 0) {
        uint8_t secret[KEY_SIZE];
        RAND_bytes(secret, KEY_SIZE);
        printf("[NODE %i] - ",worker->id);
        print_array_hex("SECRET", secret, KEY_SIZE);

        xor_encrypt_decrypt(secret,KEY_SIZE,next_qkd_key,worker->ciphertext);
    } else if (worker->id < NUM_WORKERS-1){
        xor_encrypt_decrypt(qkd_key,KEY_SIZE,next_qkd_key,worker->ciphertext);
    } 

    worker->finished = 1;    
    pthread_cond_signal(&worker->cond);
    pthread_mutex_unlock(&worker->mutex);

    if(worker->id == NUM_WORKERS-1){
        // Phase 3: Decrypt the secret in the final node
        // Wait for the main thread to signal the start of phase 3
        while (!worker->ready) {
            pthread_cond_wait(&worker->cond, &worker->mutex);
        }
        worker->ready = 0;

        uint8_t secret[KEY_SIZE];
        xor_encrypt_decrypt(worker->ciphertext,KEY_SIZE,qkd_key,secret);
        printf("[NODE %i] - ",worker->id);
        print_array_hex("SECRET", secret, KEY_SIZE);

        worker->finished = 1;    
        pthread_cond_signal(&worker->cond);
        pthread_mutex_unlock(&worker->mutex);
    }
    
    return NULL;
}

void *main_thread(void *arg) {

    // Phase 1: Sequential communication    
    // Lock main mutex to wait for phase 1 completion
    pthread_mutex_lock(&main_mutex);
    
    // Signal only the first worker to begin phase 1
    pthread_mutex_lock(&workers[0].mutex);
    workers[0].ready = 1;
    pthread_cond_signal(&workers[0].cond);
    pthread_mutex_unlock(&workers[0].mutex);
    
    // Wait for the last worker to signal completion of phase 1
    while (!main_ready) {
        pthread_cond_wait(&main_cond, &main_mutex);
    }
    pthread_mutex_unlock(&main_mutex);
    main_ready = 0;
    
    // Phase 2: Concurrent communication
    key_init_time = clock();

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_mutex_lock(&workers[i].mutex);
        workers[i].ready = 1;
        pthread_cond_signal(&workers[i].cond);
        pthread_mutex_unlock(&workers[i].mutex);
    }

    // Wait for all workers to finish phase 2
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_mutex_lock(&workers[i].mutex);
        while (!workers[i].finished) {
            pthread_cond_wait(&workers[i].cond, &workers[i].mutex);
        }
        workers[i].finished = 0;
        pthread_mutex_unlock(&workers[i].mutex);
    }

    // Phase 3: Send to destination node the ciphertext
    pthread_mutex_lock(&workers[NUM_WORKERS-1].mutex);

    enc_init_time = clock();

    uint8_t ciphertext[KEY_SIZE];
    uint8_t temp[KEY_SIZE];
    for (int i = 0; i < NUM_WORKERS-1; i++) {
        xor_encrypt_decrypt(ciphertext,KEY_SIZE,workers[i].ciphertext,temp);
        memcpy(ciphertext,temp,KEY_SIZE);
    }

    enc_end_time = clock();

    workers[NUM_WORKERS-1].ciphertext = ciphertext;

    workers[NUM_WORKERS-1].ready = 1;
    pthread_cond_signal(&workers[NUM_WORKERS-1].cond);
    pthread_mutex_unlock(&workers[NUM_WORKERS-1].mutex);
    
    pthread_mutex_lock(&workers[NUM_WORKERS-1].mutex);
    while (!workers[NUM_WORKERS-1].finished) {
        pthread_cond_wait(&workers[NUM_WORKERS-1].cond, &workers[NUM_WORKERS-1].mutex);
    }
    pthread_mutex_unlock(&workers[NUM_WORKERS-1].mutex);
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

    // Open DataBase to add or create a new one
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
        // Initialize worker data and synchronization primitives
        for (int i = 0; i < NUM_WORKERS; i++) {
            workers[i].id = i;
            workers[i].ready = 0;
            workers[i].finished = 0;
            pthread_mutex_init(&workers[i].mutex, NULL);
            pthread_cond_init(&workers[i].cond, NULL);
        }
        
        // Initialize main thread synchronization primitives
        pthread_mutex_init(&main_mutex, NULL);
        pthread_cond_init(&main_cond, NULL);

        // Create and start threads
        for (int i = 0; i < NUM_WORKERS; i++) {
            pthread_create(&worker_threads[i], NULL, worker_thread, &workers[i]);
        }
        pthread_create(&main, NULL, main_thread, NULL);

        // Wait for threads to complete
        pthread_join(main, NULL);
        for (int i = 0; i < NUM_WORKERS; i++) {
            pthread_join(worker_threads[i], NULL);
        }

        // Clean up
        pthread_mutex_destroy(&main_mutex);
        pthread_cond_destroy(&main_cond);
        for (int i = 0; i < NUM_WORKERS; i++) {
            pthread_mutex_destroy(&workers[i].mutex);
            pthread_cond_destroy(&workers[i].cond);
        }

        key_cpu_time = ((double) (key_end_time - key_init_time));
        enc_cpu_time = ((double) (enc_end_time - enc_init_time));
        printf("\nKEY CPU_TIME: %.2f us", key_cpu_time);
        printf("\nENC CPU_TIME: %.2f us\n", enc_cpu_time);

        if (first_exec) {
            fprintf(key_db, "TN-%i\n",NUM_WORKERS-1);
            fprintf(enc_db, "TN-%i\n",NUM_WORKERS-1);
            first_exec = 0;
        } 
        
        fprintf(key_db, "%.0f\n", key_cpu_time);
        fprintf(enc_db, "%.0f\n", enc_cpu_time);      
        
        num_exec++;
    }

    fclose(key_db);
    fclose(enc_db);

    return 0;
}
