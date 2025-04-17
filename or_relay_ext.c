// gcc -DNUM_WORKERS=5 -DNUM_EXEC=2 -o or_relay_ext.o or_relay_ext.c kms/kms.c onion/onion.c onion/new_onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64

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
#include "onion/new_onion.h"


clock_t key_init_time, key_end_time;
clock_t enc_init_time, enc_end_time;

typedef struct {
    int id;
    int ready;
    int finished;
    uint8_t *public_key;
    uint8_t *ciphertext;
    uint8_t *onion;
    uint8_t *new_onion;
    uint8_t *next_onion;
    char *qkd_id;
    int onion_len;
    int new_onion_len;
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

    // ############ - Initial Syncronization & PQC-KEM Exchange - ############

    pthread_mutex_lock(&worker->mutex);    
    while (!worker->ready) {
        pthread_cond_wait(&worker->cond, &worker->mutex);
    }
    worker->ready = 0;

    OQS_KEM_kyber_768_encaps(worker->ciphertext, shared_secret, worker->public_key);
    
    worker->finished = 1;    
    pthread_cond_signal(&worker->cond);
    pthread_mutex_unlock(&worker->mutex);

    // ############ - Read QKD Key shared with the previous node - ###########

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
    
    // Read QKD Key from the KMS and preparing data for the next node
    uint8_t *next_qkd_key;
    char *next_qkd_id;
    uint8_t *next_qkd_iv;

    next_qkd_key = malloc(KEY_SIZE);
    next_qkd_id = malloc(QKD_KEY_ID);
    next_qkd_iv = malloc(IV_SIZE);

    if(worker->id < NUM_WORKERS-1){        
        // ############################# - PQC-KEM - #############################
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

    // ########################## - Process Onion - ##########################

    uint8_t temp[(NUM_WORKERS+1)*B_INIT_SIZE];
    uint8_t original_on[NUM_WORKERS*2*KEY_SIZE];
    uint8_t ext[worker->new_onion_len];
    int ext_len;

    int qkd_dec_len = decrypt(worker->new_onion, worker->new_onion_len, qkd_key, 
        temp, worker->qkd_iv);

    if (qkd_dec_len < 0) {
        printf("[NODE %i] - Error decrypting QKD!\n", worker->id);
        return NULL;
    }   

    memcpy(original_on, temp, worker->onion_len);
    ext_len = qkd_dec_len - worker->onion_len;
    memcpy(ext, temp + worker->onion_len, ext_len);

    // Extract ID of current node
    uint8_t my_id[ID_SIZE];
    memcpy(my_id, original_on, ID_SIZE);
    char my_id_str[ID_SIZE + 1];
    memcpy(my_id_str, my_id, ID_SIZE);
    my_id_str[ID_SIZE] = '\0';

    int pqc_dec_len = decrypt(original_on + ID_SIZE, worker->onion_len - ID_SIZE, shared_secret, 
        original_on, worker->iv_onion);

    if (pqc_dec_len < 0) {
        printf("[NODE %i] - Error decrypting PQC!\n", worker->id);
        return NULL;
    } 

    // ####################### - Process New Onion  - ########################

    if(worker->id < NUM_WORKERS-1){
        //  **********************  //
        //  Message Verification    //
        //  **********************  //
        int num_blocks = ext_len / B_INIT_SIZE;
        
        // Create the array of blocks
        uint8_t **b_blks = (uint8_t **)malloc(num_blocks * sizeof(uint8_t *));
        
        // Process the blocks
        int offset = 0;
        for (int i = 0; i < num_blocks; i++) {
            b_blks[i] = (uint8_t *)malloc(B_INIT_SIZE);
            memcpy(b_blks[i], ext + offset, B_INIT_SIZE);
        
            offset += B_INIT_SIZE;
        }
      
        uint8_t b1_dec[B_INIT_SIZE];
        int b1_dec_len = decrypt(b_blks[0], B_INIT_SIZE, shared_secret, b1_dec, NULL); 
        if (b1_dec_len < 0) {
            printf("[NODE %i] - Error decrypting B[1]!\n", worker->id);
            return NULL;
        } 

        int b2_bN_len = ext_len - B_INIT_SIZE; // Length of the extension minus the first block
        uint8_t b2_bN[b2_bN_len];
        memcpy(b2_bN, ext + B_INIT_SIZE, b2_bN_len);

        // b) Obtain k_i, tau_i and the message to verify (O_{i+1}||B_2||...||B_N)
        uint8_t ef_k_i[NUM_WORKERS*KEY_SIZE];
        uint8_t tau_i[SIGN_SIZE];
        
        memcpy(ef_k_i, b1_dec, sizeof(ef_k_i)); // Extract K_i[]
        memcpy(tau_i, b1_dec + sizeof(ef_k_i), SIGN_SIZE);

        // c) Verify the signature
        size_t tau_input_length = pqc_dec_len + b2_bN_len;
        uint8_t tau_input[tau_input_length];
        memcpy(tau_input, original_on, pqc_dec_len);
        memcpy(tau_input + pqc_dec_len, b2_bN, b2_bN_len);

        // Compute the HMAC of the received message
        uint8_t tau[SIGN_SIZE];
        size_t tau_length = SIGN_SIZE;
        int res = generate_hmac_sha256(ef_k_i, sizeof(ef_k_i), tau_input, tau_input_length, tau, &tau_length); 
        if (res < 0) {
            printf("Error generating HMAC-SHA256.\n");
        }

        if (memcmp(tau, tau_i, SIGN_SIZE) != 0) {
            fprintf(stderr, "ERROR: HMAC comparison failed!\n");
            return NULL;
        }
        
        // Extract ID of the next node
        uint8_t next_id[ID_SIZE];
        memcpy(next_id, original_on, ID_SIZE);
        char next_id_str[ID_SIZE + 1];
        memcpy(next_id_str, next_id, ID_SIZE);
        next_id_str[ID_SIZE] = '\0';

        uint8_t **ef_keys = (uint8_t **)malloc((NUM_WORKERS) * sizeof(uint8_t *));
        for (int i = 0; i < NUM_WORKERS; i++) {
            ef_keys[i] = (uint8_t *)malloc(KEY_SIZE);
            memcpy(ef_keys[i], ef_k_i + i*KEY_SIZE, KEY_SIZE);
        }
        process_padding(NUM_WORKERS, ef_keys, my_id, b_blks);

        int next_new_on_len = worker->onion_len - AES_PAD - IV_SIZE; // Offset for the new onion;
        uint8_t next_new_on[(NUM_WORKERS+1)*B_INIT_SIZE];
        memcpy(next_new_on, original_on, worker->onion_len - AES_PAD); // Copy original onion
        
        for (int i = 0; i < num_blocks; i++) {
            memcpy(next_new_on + next_new_on_len, b_blks[i], B_INIT_SIZE);
            next_new_on_len += B_INIT_SIZE;
        }

        worker->new_onion_len = next_new_on_len;
        worker->new_onion = malloc(next_new_on_len);
        memcpy(worker->new_onion, next_new_on, next_new_on_len);

        uint8_t ciphertext[(NUM_WORKERS+1)*B_INIT_SIZE];
        int ciph_len = encrypt(worker->new_onion, worker->new_onion_len, next_qkd_key, ciphertext, next_qkd_iv);
        if (ciph_len < 0) {
            printf("[NODE %i] - Error encrypting QKD!\n", worker->id);
            return NULL;
        } 

        workers[worker->id+1].new_onion = malloc(ciph_len);
        memcpy(workers[worker->id+1].new_onion, ciphertext, ciph_len);
        workers[worker->id+1].new_onion_len = ciph_len; 
        workers[worker->id+1].onion_len = pqc_dec_len;
        workers[worker->id+1].ready = 1;
        pthread_cond_signal(&workers[worker->id+1].cond);
        pthread_mutex_unlock(&workers[worker->id+1].mutex);
    } else {
        worker->finished = 1;
        pthread_cond_signal(&worker->cond);
        pthread_mutex_unlock(&worker->mutex);
        printf("\n[%s] - ",my_id_str);
        print_array_hex("SECRET", original_on, KEY_SIZE);
    }

    return NULL;
}

void *main_thread(void *arg) {

    // ############ - Initial Syncronization & PQC-KEM Exchange - ############

    uint8_t *shared_secrets[NUM_WORKERS];
    uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_mutex_lock(&workers[i].mutex);
        workers[i].public_key = public_key;
        workers[i].ciphertext = malloc(OQS_KEM_kyber_768_length_ciphertext);
        if (workers[i].ciphertext == NULL) {
            perror("Error assigning memory for ciphertext");
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

    // ############ - Initial Syncronization & QKD-KEY Exchange - ############

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
    uint8_t ivs_onion[NUM_WORKERS][IV_SIZE];    // IVs para cada capa
    uint8_t **onions = (uint8_t **)malloc(NUM_WORKERS * sizeof(uint8_t *)); 
    int *onions_lens = (int *)malloc(NUM_WORKERS * sizeof(int));
    uint8_t **ids = malloc(NUM_WORKERS * ID_SIZE);
    for (int i = 0; i < NUM_WORKERS; i++) {
        ids[i] = malloc(ID_SIZE);
        snprintf((char *)ids[i], ID_SIZE, "ID_NODE_%d", i + 1);  
        RAND_bytes(ivs_onion[i], IV_SIZE);
        workers[i].iv_onion = malloc(IV_SIZE);
        workers[i].iv_onion = ivs_onion[i];
    }    

    // generate_random_key_iv(secret, iv_secret);
    generate_rdm(secret, KEY_SIZE);
    generate_rdm(iv_secret, IV_SIZE);
    print_array_hex("[ MAIN ] - SECRET",secret,KEY_SIZE);
    printf("\n");

    // Onion Routing: layer encryption from last to first router
    enc_init_time = clock();

    uint8_t buffer[(NUM_WORKERS+1)*B_INIT_SIZE];
    int buffer_len = KEY_SIZE;
    int id_len;
    memcpy(buffer, secret, buffer_len);


    for (int i = NUM_WORKERS - 1; i >= 0; i--) {
        uint8_t encrypted_msg[(NUM_WORKERS+1)*B_INIT_SIZE];
    
        int encrypted_len = encrypt(buffer, buffer_len, shared_secrets[i], encrypted_msg, ivs_onion[i]);
    
        if (encrypted_len < 0) {
            printf("[ MAIN ] - Error encrypting at step %i\n", i);
        }
    
        uint8_t temp[(NUM_WORKERS+1)*B_INIT_SIZE];

        memcpy(temp, ids[i], ID_SIZE);
        memcpy(temp + ID_SIZE, encrypted_msg, encrypted_len);
    
        buffer_len = encrypted_len + ID_SIZE;
        memcpy(buffer, temp, buffer_len); 

        // Store each layer of the "onion" in the array
        onions[i] = (uint8_t *)malloc(buffer_len * sizeof(uint8_t));  
        memcpy(onions[i], buffer, buffer_len);  
        onions_lens[i] = buffer_len;  
    }

    uint8_t ***ef_keys = (uint8_t ***)malloc(NUM_INT * sizeof(uint8_t **));
    
    for (int i = 0; i < NUM_INT; i++) {
        ef_keys[i] = (uint8_t **)malloc(NUM_WORKERS * sizeof(uint8_t *));
        ef_keys[i] = generate_rdm_array(NUM_WORKERS, KEY_SIZE);
    }
    uint8_t **b_blks = NULL;

    generate_rdms(NUM_INT, NUM_WORKERS, &b_blks, ef_keys, ids);

    calculate_tags(NUM_INT, NUM_WORKERS, shared_secrets, ef_keys, onions, onions_lens,
        b_blks);
    
    // Add the blocks new_b_blks to the buffer before encrypting
    for (int i = 0; i < NUM_WORKERS; i++) {
        memcpy(buffer + buffer_len, b_blks[i], B_INIT_SIZE);
        buffer_len += B_INIT_SIZE;
    }

    buffer_len = encrypt(buffer, buffer_len, qkd_key, buffer, qkd_iv);

    enc_end_time = clock();

    workers[0].new_onion = buffer;
    workers[0].new_onion_len = buffer_len;
    workers[0].onion_len = onions_lens[0];

    workers[0].ready = 1;
    pthread_cond_signal(&workers[0].cond);
    pthread_mutex_unlock(&workers[0].mutex);

    pthread_mutex_lock(&workers[NUM_WORKERS-1].mutex);
    while (!workers[NUM_WORKERS-1].finished) {
        pthread_cond_wait(&workers[NUM_WORKERS-1].cond, &workers[NUM_WORKERS-1].mutex);
    }
    workers[NUM_WORKERS-1].finished = 0;

    key_end_time = clock();

    // ######################## - Free Memory - ############################
    for(int i = 0; i<NUM_WORKERS;i++) {
        free(shared_secrets[i]);
        free(ids[i]);
        free(onions[i]);
        free(b_blks[i]);
    }
    free(ids);
    free(onions);
    free(b_blks);

    for (int i = 0; i < NUM_INT; i++) {
        for (int j = 0; j < NUM_WORKERS; j++) {
            free(ef_keys[i][j]);
        }
        free(ef_keys[i]);
    }
    free(ef_keys);

    free(onions_lens);
    free(qkd_key);
    free(qkd_iv);
   
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

            fprintf(key_db, "%s,OR-EXT-%i,", timestamp, NUM_WORKERS);
            fprintf(enc_db, "%s,OR-EXT-%i,", timestamp, NUM_WORKERS);
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