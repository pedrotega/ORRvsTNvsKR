// kms.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <stdint.h>
#include <b64/cdecode.h>
#include "kms.h"

// Define global variables
// IP addresses of the Key Management System (KMS) servers  
const char *KMSM_IP = "https://kms-main.example.com:443";  // Main KMS server  
const char *KMSS_IP = "https://kms-secondary.example.com:443";  // Secondary KMS server  

// Paths to public and private keys for Alice  
const char *C1_PUB_KEY = "kms/certs/alice/public.pem";  // Public key for Alice  
const char *C1_PRIV_KEY = "kms/certs/alice/private-key.pem";  // Private key for Alice  
const char *C1_ROOT_CA = "kms/certs/ca/rootCA.pem";  // Root CA certificate for Alice  

// Paths to public and private keys for Bob   
const char *C2_PUB_KEY = "kms/certs/bob/public.pem";  // Public key for Bob  
const char *C2_PRIV_KEY = "kms/certs/bob/private-key.pem";  // Private key for Bob  
const char *C2_ROOT_CA = "kms/certs/ca/rootCA.pem";  // Root CA certificate for Bob  

// Encryption scheme identifiers for Alice and Bob  
const char *C1_ENC = "ENC_SCHEME_1";  // Encryption scheme used by Alice  
const char *C2_ENC = "ENC_SCHEME_2";  // Encryption scheme used by Bob 

// Structure to hold the response data of cURL
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Callback function to handle cURL response
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        printf("There is not enough memory\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void print_array_hex(const char *label, uint8_t *array, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", array[i]);
    }
    printf("\n");
}

// Function to make HTTPS requests
char *request_https(const char *url, const char *cert, const char *key, const char *ca_cert, const char *post_data) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, cert);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, key);
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        if (post_data != NULL) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        }

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Error en curl_easy_perform(): %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            chunk.memory = NULL;
        }

        curl_easy_cleanup(curl);
    }

    return chunk.memory;
}

// Function to extract key and ID from a JSON string
void extract_key_and_id(const char *json_str, char *key_buffer, size_t key_buffer_len, char *key_id_buffer, size_t key_id_buffer_len) {
    json_t *root;
    json_error_t error;

    root = json_loads(json_str, 0, &error);
    if (!root) {
        fprintf(stderr, "Error de JSON en la línea %d: %s\n", error.line, error.text);
        return;
    }

    json_t *keys = json_object_get(root, "keys");
    if (json_is_array(keys)) {
        json_t *key_data = json_array_get(keys, 0);
        json_t *key = json_object_get(key_data, "key");
        json_t *key_id = json_object_get(key_data, "key_ID");

        snprintf(key_buffer, key_buffer_len, "%s", json_string_value(key));
        snprintf(key_id_buffer, key_id_buffer_len, "%s", json_string_value(key_id));
    }

    json_decref(root);
}

// Function to extract key and ID from a JSON string and decode the Base64 key
void extract_key8_and_id(const char *json_str, uint8_t *key_buffer, size_t key_buffer_len, char *key_id_buffer, size_t key_id_buffer_len) {
    json_t *root;
    json_error_t error;

    // Load the JSON
    root = json_loads(json_str, 0, &error);
    if (!root) {
        fprintf(stderr, "Error de JSON en la línea %d: %s\n", error.line, error.text);
        return;
    }

    json_t *keys = json_object_get(root, "keys");
    if (json_is_array(keys)) {
        json_t *key_data = json_array_get(keys, 0);
        json_t *key = json_object_get(key_data, "key");
        json_t *key_id = json_object_get(key_data, "key_ID");

        // Extract the key ID
        snprintf(key_id_buffer, key_id_buffer_len, "%s", json_string_value(key_id));

        // Extraer la clave en formato Base64
        const char *base64_key = json_string_value(key);
        size_t input_length = strlen(base64_key);
   
        // Inicializar el buffer de salida
        base64_decodestate state;
        base64_init_decodestate(&state);

        // Decode the Base64 string
        int result = base64_decode_block(base64_key, input_length, (char *)key_buffer, &state);
        
        if (result < 0) {
            fprintf(stderr, "Error al decodificar Base64.\n");
            json_decref(root);
            return;
        }

        key_buffer[result] = '\0'; 
    }

    json_decref(root);
}
