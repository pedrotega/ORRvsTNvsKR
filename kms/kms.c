// kms.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <stdint.h>
#include <b64/cdecode.h>
#include "kms.h"

// Definimos las variables globales
// IP addresses of the Key Management System (KMS) servers  
const char *KMSM_IP = "https://kms-main.example.com:443";  // Main KMS server  
const char *KMSS_IP = "https://kms-secondary.example.com:443";  // Secondary KMS server  

// Paths to public and private keys for Client 1 (C1)  
const char *C1_PUB_KEY = "kms/certs/client1/public.pem";  // Public key for Client 1  
const char *C1_PRIV_KEY = "kms/certs/client1/private-key.pem";  // Private key for Client 1  
const char *C1_ROOT_CA = "kms/certs/ca/rootCA.pem";  // Root CA certificate for Client 1  

// Paths to public and private keys for Client 2 (C2)  
const char *C2_PUB_KEY = "kms/certs/client2/public.pem";  // Public key for Client 2  
const char *C2_PRIV_KEY = "kms/certs/client2/private-key.pem";  // Private key for Client 2  
const char *C2_ROOT_CA = "kms/certs/ca/rootCA.pem";  // Root CA certificate for Client 2  

// Encryption scheme identifiers for Client 1 and Client 2  
const char *C1_ENC = "ENC_SCHEME_1";  // Encryption scheme used by Client 1  
const char *C2_ENC = "ENC_SCHEME_2";  // Encryption scheme used by Client 2 

// Estructura para almacenar la respuesta de cURL
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Callback para manejar la respuesta de cURL
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        printf("No hay suficiente memoria\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Función para realizar solicitudes HTTPS
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

// Función para extraer clave e ID de un JSON
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

// Función para extraer clave e ID de un JSON y decodificar la clave de Base64
void extract_key8_and_id(const char *json_str, uint8_t *key_buffer, size_t key_buffer_len, char *key_id_buffer, size_t key_id_buffer_len) {
    json_t *root;
    json_error_t error;

    // Cargar el JSON
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

        // Extraer el ID de la clave
        snprintf(key_id_buffer, key_id_buffer_len, "%s", json_string_value(key_id));

        // Extraer la clave en formato Base64
        const char *base64_key = json_string_value(key);
        size_t input_length = strlen(base64_key);
        
        // Calcular el tamaño del buffer para la salida decodificada
        // size_t output_length = (input_length * 3) / 4; // Tamaño máximo
        // if (output_length > key_buffer_len) {
        //     fprintf(stderr, "El buffer de clave es demasiado pequeño.\n");
        //     json_decref(root);
        //     return;
        // }

        // Inicializar la estructura de decodificación
        base64_decodestate state;
        base64_init_decodestate(&state);

        // Decodificar la cadena Base64
        int result = base64_decode_block(base64_key, input_length, (char *)key_buffer, &state);
        
        if (result < 0) {
            fprintf(stderr, "Error al decodificar Base64.\n");
            json_decref(root);
            return;
        }

        // La longitud real de la clave decodificada
        key_buffer[result] = '\0'; // Opcional, agregar terminador nulo si se va a tratar como cadena
    }

    json_decref(root);
}
