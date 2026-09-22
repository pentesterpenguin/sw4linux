#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#define X25519_KEYLEN 32
#define X25519_SHARED_SECRET_LEN 32
#define AES_KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16

typedef struct {
    uint8_t public_key[X25519_KEYLEN];
    uint8_t private_key[X25519_KEYLEN];
} X25519_Keypair;

extern uint8_t _binary_grid_bin_start[];

void reconstruct_key(uint8_t *aes_key);
int decrypt_payload(uint8_t *nonce, uint8_t *aes_key, uint8_t *ciphertext, uint8_t *tag, uint8_t *plaintext);

int x25519_generate_keypair(X25519_Keypair *keypair);
int x25519_compute_shared_secret(uint8_t *shared_secret, const uint8_t *private_key, const uint8_t *peer_public_key);
int hkdf_derive_key(uint8_t *derived_key, const uint8_t *shared_secret, uint32_t shared_secret_len);
int encrypt_aes_gcm(uint8_t *ciphertext, uint8_t *tag, const uint8_t *plaintext, uint32_t plaintext_len, const uint8_t *key, uint8_t *nonce);
int decrypt_aes_gcm(uint8_t *plaintext, const uint8_t *ciphertext, uint32_t ciphertext_len, const uint8_t *tag, const uint8_t *key, const uint8_t *nonce);

#endif