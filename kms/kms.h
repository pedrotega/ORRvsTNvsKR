// kms.h
#ifndef KMS_H
#define KMS_H

#include <stddef.h>

#define QKD_KEY_ID 37

// Configuración de nodos y certificados
extern const char *KMSM_IP;
extern const char *KMSS_IP;
extern const char *C1_PUB_KEY;
extern const char *C1_PRIV_KEY;
extern const char *C1_ROOT_CA;
extern const char *C2_PUB_KEY;
extern const char *C2_PRIV_KEY;
extern const char *C2_ROOT_CA;
extern const char *C1_ENC;
extern const char *C2_ENC;


char *request_https(const char *url, const char *cert, const char *key, const char *ca_cert, const char *post_data);
void extract_key_and_id(const char *json_str, char *key_buffer, size_t key_buffer_len, char *key_id_buffer, size_t key_id_buffer_len);
void extract_key8_and_id(const char *json_str, uint8_t *key_buffer, size_t key_buffer_len, char *key_id_buffer, size_t key_id_buffer_len);
void print_array_hex(const char *label, uint8_t *array, size_t length);

#endif // KMS_H
