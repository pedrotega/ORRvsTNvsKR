// gcc -DNUM_WORKERS=5 -DNUM_EXEC=2 -o or_relay or_relay.c utils/utils.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include <unistd.h>

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "kms/kms.h"
#include "onion/onion.h"

clock_t key_init_time, key_end_time;
clock_t enc_init_time, enc_end_time;

typedef struct {
    int id;
    int ready;
    int finished;
    uint8_t *public_key;
    uint8_t *ciphertext;
    uint8_t *onion;
    uint8_t *next_onion;
    char *qkd_id;
    int onion_len;
    uint8_t *iv_onion;
    uint8_t *qkd_iv;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} WorkerData;

WorkerData workers[NUM_WORKERS];

void *worker_thread(void *arg) {
    WorkerData *worker = (WorkerData *)arg;
    uint8_t shared_secret[OQS_KEM_kyber_768_length_shared_secret];
    uint8_t qkd_key[KEY_SIZE];
    char url[256];
    char *response;
    char qkd_id[256] = {0};


    pthread_mutex_lock(&worker->mutex);    
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;

    OQS_KEM_kyber_768_encaps(worker->ciphertext, shared_secret, worker->public_key);
    
    worker->finished = 1;    
    pthread_cond_signal(&worker->cond);
    pthread_mutex_unlock(&worker->mutex);

    pthread_mutex_lock(&worker->mutex);    
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;

    // Read QKD Key from ID from the KMS
    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/dec_keys", KMSS_IP, C1_ENC);
    char post_data[512];
    snprintf(post_data, sizeof(post_data), "{\"key_IDs\":[{\"key_ID\":\"%s\"}]}", worker->qkd_id);

    response = request_https(url, C2_PUB_KEY, C2_PRIV_KEY, C2_ROOT_CA, post_data);
    if (response) {
        extract_key8_and_id(response, qkd_key, KEY_SIZE, qkd_id, QKD_KEY_ID);
        free(response);
    }
    
    // Read QKD Key from the KMS
    uint8_t *next_qkd_key;
    char *next_qkd_id;
    uint8_t *next_qkd_iv;

    next_qkd_key = malloc(KEY_SIZE);
    next_qkd_id = malloc(QKD_KEY_ID);
    next_qkd_iv = malloc(IV_SIZE);

    // Prepare information for the next node
    if(worker->id < NUM_WORKERS-1){        

        snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
        response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
        if (response) {
            extract_key8_and_id(response, next_qkd_key, KEY_SIZE, next_qkd_id, QKD_KEY_ID);
            RAND_bytes(next_qkd_iv, IV_SIZE);
            workers[worker->id+1].qkd_id = next_qkd_id;
            workers[worker->id+1].qkd_iv = next_qkd_iv;
            free(response);
        }
        workers[worker->id+1].ready = 1;
        pthread_cond_signal(&workers[worker->id+1].cond);
        pthread_mutex_unlock(&workers[worker->id+1].mutex);
    } else {
        worker->finished = 1;
        pthread_cond_signal(&worker->cond);
        pthread_mutex_unlock(&worker->mutex);
    }

    pthread_mutex_lock(&worker->mutex);    
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;

    // Process new onion
    uint8_t temp[1024];
    uint8_t temp2[1024];

    int decrypted_len = decrypt(worker->onion, worker->onion_len, qkd_key, 
        temp, worker->qkd_iv);
    if (decrypted_len < 0) {
        printf("[NODE %i] - Error decrypting QKD!\n", worker->id);
        return NULL;
    }   

    decrypted_len = decrypt(temp, decrypted_len, shared_secret, 
                                    temp, worker->iv_onion);
    
    if (decrypted_len < 0) {
        printf("[NODE %i] - Error decrypting QKD!\n", worker->id);
        return NULL;
    }

    worker->onion_len = decrypted_len;
    memcpy(worker->onion, temp, worker->onion_len);
    memmove(worker->onion, worker->onion + ID_SIZE, worker->onion_len - ID_SIZE);
    worker->onion_len -= ID_SIZE;

    // Prepare information for the next node
    if(worker->id < NUM_WORKERS-1){
        uint8_t ciphertext[1024];
        int ciph_len = encrypt(worker->onion, worker->onion_len, next_qkd_key, ciphertext, next_qkd_iv);
        if (ciph_len < 0) {
            printf("[NODE %i] - Error encrypting QKD!\n", worker->id);
            return NULL;
        }
        
        workers[worker->id+1].onion = ciphertext; 
        workers[worker->id+1].onion_len = ciph_len; 
        workers[worker->id+1].ready = 1;
        pthread_cond_signal(&workers[worker->id+1].cond);
        pthread_mutex_unlock(&workers[worker->id+1].mutex);
    } else {
        worker->finished = 1;
        pthread_cond_signal(&worker->cond);
        pthread_mutex_unlock(&worker->mutex);
        printf("[NODE %i] - ",worker->id);
        print_array_hex("SECRET", worker->onion, worker->onion_len);
    }

    return NULL;
}

void *main_thread(void *arg) {
    uint8_t *shared_secrets[NUM_WORKERS];
    uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_mutex_lock(&workers[i].mutex);
        workers[i].public_key = public_key;
        workers[i].ciphertext = malloc(OQS_KEM_kyber_768_length_ciphertext);
        if (workers[i].ciphertext == NULL) {
            perror("Error al asignar memoria para ciphertext");
            exit(EXIT_FAILURE);
        }
        workers[i].ready = 1;
        pthread_cond_signal(&workers[i].cond);
        pthread_mutex_unlock(&workers[i].mutex);
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_mutex_lock(&workers[i].mutex);
        while (!workers[i].finished) {
            pthread_cond_wait(&workers[i].cond, &workers[i].mutex);
        }
        workers[i].finished = 0;
        shared_secrets[i] = malloc(OQS_KEM_kyber_768_length_shared_secret);
        OQS_KEM_kyber_768_decaps(shared_secrets[i], workers[i].ciphertext, secret_key);
        workers[i].ciphertext = NULL;
    }

    // ########################### - Get QKD Key - ###########################

    char url[256];
    char *response;
    uint8_t *qkd_key;
    uint8_t *qkd_iv;
    char qkd_id[256] = {0};

    qkd_key = malloc(KEY_SIZE);
    qkd_iv = malloc(IV_SIZE);

    snprintf(url, sizeof(url), "%s/api/v1/keys/%s/enc_keys", KMSM_IP, C2_ENC);
    response = request_https(url, C1_PUB_KEY, C1_PRIV_KEY, C1_ROOT_CA, NULL);
    if (response) {
        extract_key8_and_id(response, qkd_key, KEY_SIZE, qkd_id, QKD_KEY_ID);
        RAND_bytes(qkd_iv, IV_SIZE);
        workers[0].qkd_id = qkd_id;
        workers[0].qkd_iv = qkd_iv;
        free(response);
    }

    workers[0].ready = 1;
    pthread_cond_signal(&workers[0].cond);
    pthread_mutex_unlock(&workers[0].mutex);

    pthread_mutex_lock(&workers[NUM_WORKERS-1].mutex);
    while (!workers[NUM_WORKERS-1].finished) {
        pthread_cond_wait(&workers[NUM_WORKERS-1].cond, &workers[NUM_WORKERS-1].mutex);
    }
    workers[NUM_WORKERS-1].finished = 0;

     // ########################## - Compute Onion - ##########################
   
    key_init_time = clock();

    uint8_t secret[KEY_SIZE];
    uint8_t iv_secret[IV_SIZE];
    uint8_t ivs_onion[NUM_WORKERS][IV_SIZE];    // IVs for each layer
    uint8_t *onions[NUM_WORKERS];
    int onions_len[NUM_WORKERS];
    uint8_t **ids = malloc(NUM_WORKERS * sizeof(uint8_t *));
    for (int i = 0; i < NUM_WORKERS; i++) {
        ids[i] = malloc(ID_SIZE);
        snprintf((char *)ids[i], ID_SIZE, "ID_NODE_%d", i + 1); 
        RAND_bytes(ivs_onion[i], IV_SIZE);
        workers[i].iv_onion = malloc(IV_SIZE);
        workers[i].iv_onion = ivs_onion[i];
    }    
    
    // generate_rdm_key_iv(secret, iv_secret);
    generate_rdm(secret, KEY_SIZE);
    generate_rdm(iv_secret, IV_SIZE);
    print_array_hex("[ MAIN ] - SECRET",secret,KEY_SIZE);

    // Onion Routing: encrypt in layers from the last to the first

    enc_init_time = clock();

    uint8_t buffer[1024];
    int buffer_len = KEY_SIZE;
    int id_len;
    memcpy(buffer, secret, buffer_len);

    for (int i = NUM_WORKERS - 1; i >= 0; i--) {
        uint8_t temp[1024];

        // Concatenar el ID al mensaje cifrado
        memcpy(temp, ids[i], ID_SIZE);
        memcpy(temp + ID_SIZE, buffer, buffer_len);

        buffer_len = encrypt(temp, ID_SIZE + buffer_len, shared_secrets[i], buffer, ivs_onion[i]);
    }

    buffer_len = encrypt(buffer, buffer_len, qkd_key, buffer, qkd_iv);

    enc_end_time = clock();

    workers[0].onion = buffer;
    workers[0].onion_len = buffer_len;

    workers[0].ready = 1;
    pthread_cond_signal(&workers[0].cond);
    pthread_mutex_unlock(&workers[0].mutex);

    pthread_mutex_lock(&workers[NUM_WORKERS-1].mutex);
    while (!workers[NUM_WORKERS-1].finished) {
        pthread_cond_wait(&workers[NUM_WORKERS-1].cond, &workers[NUM_WORKERS-1].mutex);
    }
    workers[NUM_WORKERS-1].finished = 0;

    key_end_time = clock();

    for(int i = 0; i<NUM_WORKERS;i++) {
        free(shared_secrets[i]);
        free(ids[i]);
        free(workers[i].ciphertext);
    }
    free(ids);

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

            fprintf(key_db, "%s,OR-%i,", timestamp, NUM_WORKERS);
            fprintf(enc_db, "%s,OR-%i,", timestamp, NUM_WORKERS);
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