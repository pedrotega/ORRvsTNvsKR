// gcc -DNUM_WORKERS=5 -DNUM_EXEC=2 -o trusted_node trusted_node.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64

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

#define NUM_WORKERS_TN (NUM_WORKERS + 1) // Number of workers

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

WorkerData workers[NUM_WORKERS_TN];
pthread_mutex_t main_mutex;
pthread_cond_t main_cond;
int main_ready = 0;

// XOR function to encrypt and decrypt
void xor_encrypt_decrypt(const uint8_t *input, int input_len, const uint8_t *key, uint8_t *output) {
    for (int i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % KEY_SIZE];
    }
}

// Represent the onion routers intermediates, initiator and destination
void *worker_thread(void *arg) {
    WorkerData *worker = (WorkerData *)arg;
    uint8_t qkd_key[KEY_SIZE];
    uint8_t next_qkd_key[KEY_SIZE];
    char *next_qkd_id;
    char url[256];
    char *response;
    char qkd_id[256] = {0};
    uint8_t msg_tn[KEY_SIZE];

    next_qkd_id = malloc(QKD_KEY_ID);
    
    // ############ - Initial Syncronization & QKD-KEY Exchange - ############

    pthread_mutex_lock(&worker->mutex);
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;
    
    if (worker->id == 0) {
        // Read QKD Key from the KMS (To be shared with the next node)
        snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
        response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
        if (response) {
            extract_key8_and_id(response, next_qkd_key, KEY_SIZE, next_qkd_id, QKD_KEY_ID);
            workers[worker->id+1].qkd_id = next_qkd_id;
            free(response);
        }
        // Yield control to the next node
        workers[worker->id + 1].ready = 1;
        pthread_cond_signal(&workers[worker->id + 1].cond);

    } else if (worker->id < NUM_WORKERS_TN - 1) {
        // Read QKD KEY from the KMS using the QKD_ID (Shared with the previous node)
        snprintf(url, sizeof(url), "%s/api/v1/keys/%s/dec_keys", KMSS_IP, C1_ENC);
        char post_data[512];
        snprintf(post_data, sizeof(post_data), "{\"key_IDs\":[{\"key_ID\":\"%s\"}]}", worker->qkd_id);

        response = request_https(url, C2_PUB_KEY, C2_PRIV_KEY, C2_ROOT_CA, post_data);
        if (response) {
            extract_key8_and_id(response, qkd_key, KEY_SIZE, qkd_id, QKD_KEY_ID);
            free(response);
        }

        // Read QKD Key from the KMS (To be shared with the next node)
        snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
        response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
        if (response) {
            extract_key8_and_id(response, next_qkd_key, KEY_SIZE, next_qkd_id, QKD_KEY_ID);
            workers[worker->id+1].qkd_id = next_qkd_id;
            free(response);
        }
        // Yield control to the next node
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
            free(response);
        }
        main_ready = 1;
        pthread_cond_signal(&main_cond);
    }
    
    // ########### - Second Syncronization & MSG exchange to TN - ############
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
    } else if (worker->id < NUM_WORKERS_TN-1){
        xor_encrypt_decrypt(qkd_key,KEY_SIZE,next_qkd_key,worker->ciphertext);
    } 

    worker->finished = 1;    
    pthread_cond_signal(&worker->cond);
    pthread_mutex_unlock(&worker->mutex);

    if(worker->id == NUM_WORKERS_TN-1){

        // ############### - Decrypt the secret in the final node - ###############

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

// Represent the Trusted Node
void *main_thread(void *arg) {
    uint8_t qkd_key[KEY_SIZE];
    char url[256];
    char *response;
    char qkd_id[256] = {0};

    // ########### - Initial Syncronization & QKD-KEY Exchange - #############

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
    
    // ########### - Second Syncronization & MSG exchange to TN - ############
    // Phase 2: Concurrent communication

    key_init_time = clock();

    for (int i = 0; i < NUM_WORKERS_TN; i++) {
        pthread_mutex_lock(&workers[i].mutex);
        workers[i].ready = 1;
        pthread_cond_signal(&workers[i].cond);
        pthread_mutex_unlock(&workers[i].mutex);
    }

    // Wait for all workers to finish phase 2
    for (int i = 0; i < NUM_WORKERS_TN; i++) {
        pthread_mutex_lock(&workers[i].mutex);
        while (!workers[i].finished) {
            pthread_cond_wait(&workers[i].cond, &workers[i].mutex);
        }
        workers[i].finished = 0;
        pthread_mutex_unlock(&workers[i].mutex);
    }

    // ########### - Send the encrypted secret to the final node - ###########

    // Phase 3: Send to destination node the ciphertext
    pthread_mutex_lock(&workers[NUM_WORKERS_TN-1].mutex);

    enc_init_time = clock();

    uint8_t ciphertext[KEY_SIZE];
    uint8_t temp[KEY_SIZE];
    for (int i = 0; i < NUM_WORKERS_TN-1; i++) {
        xor_encrypt_decrypt(ciphertext,KEY_SIZE,workers[i].ciphertext,temp);
        memcpy(ciphertext,temp,KEY_SIZE);
    }

    enc_end_time = clock();

    workers[NUM_WORKERS_TN-1].ciphertext = ciphertext;

    workers[NUM_WORKERS_TN-1].ready = 1;
    pthread_cond_signal(&workers[NUM_WORKERS_TN-1].cond);
    pthread_mutex_unlock(&workers[NUM_WORKERS_TN-1].mutex);
    
    // ######### - Final Syncronization to terminate the threads - ###########

    pthread_mutex_lock(&workers[NUM_WORKERS_TN-1].mutex);
    while (!workers[NUM_WORKERS_TN-1].finished) {
        pthread_cond_wait(&workers[NUM_WORKERS_TN-1].cond, &workers[NUM_WORKERS_TN-1].mutex);
    }
    pthread_mutex_unlock(&workers[NUM_WORKERS_TN-1].mutex);
    workers[NUM_WORKERS_TN-1].finished = 0;

    key_end_time = clock();

    return NULL;
}

int main() {
    pthread_t worker_threads[NUM_WORKERS_TN], main;

    int num_exec = 0;
    double key_cpu_time;
    double enc_cpu_time;
    FILE *key_db;
    FILE *enc_db;
    int first_exec = 1;

    // Abrir db para añadir o crear si no existe
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
        // Initialize worker data and synchronization primitives
        for (int i = 0; i < NUM_WORKERS_TN; i++) {
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
        for (int i = 0; i < NUM_WORKERS_TN; i++) {
            pthread_create(&worker_threads[i], NULL, worker_thread, &workers[i]);
        }
        pthread_create(&main, NULL, main_thread, NULL);

        // Wait for threads to complete
        pthread_join(main, NULL);
        for (int i = 0; i < NUM_WORKERS_TN; i++) {
            pthread_join(worker_threads[i], NULL);
        }

        // Clean up
        pthread_mutex_destroy(&main_mutex);
        pthread_cond_destroy(&main_cond);
        for (int i = 0; i < NUM_WORKERS_TN; i++) {
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

            fprintf(key_db, "%s,TN-%i,", timestamp, NUM_WORKERS);
            fprintf(enc_db, "%s,TN-%i,", timestamp, NUM_WORKERS);
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
