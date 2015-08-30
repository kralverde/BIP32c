#include "../include/hdwallet.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <libbase58.h>


// Suggested key from spec is "Bitcoin seed"
const char *DEFAULT_KEY = "Bitcoin seed";

const uint8_t KEY_VERSIONS_VALUES[4][4] = {
        {0x04, 0X88, 0XB2, 0X1E}, // xpub
        {0x04, 0X88, 0XAD, 0XE4}, // xprv
        {0x04, 0X35, 0X87, 0XCF}, // tpub
        {0x04, 0X35, 0X83, 0X94}  // tprv
};


int HDW_double_SHA256(uint8_t *input,
                      uint32_t input_len,
                      uint8_t output[SHA256_DIGEST_LENGTH]);


int HDW_generate_master_node(uint8_t *seed,
                             size_t seed_len,
                             HDW_key_t *key) {

    int res;

    HMAC_CTX hmac_ctx;

    res = HMAC_Init(&hmac_ctx, DEFAULT_KEY, (int) strlen(DEFAULT_KEY), EVP_sha512());

    if (!res) {
        fprintf(stderr, "Could not HMAC_Init\n");
        return res;
    }

    res = HMAC_Update(&hmac_ctx, seed, seed_len);

    if (!res) {
        fprintf(stderr, "Could not HMAC_Update\n");
        goto cleanup_hmac_context;
    }

    uint8_t master_digest[SHA512_DIGEST_LENGTH];
    uint32_t digest_len;
    res = HMAC_Final(&hmac_ctx, master_digest, &digest_len);

    if (digest_len != SHA512_DIGEST_LENGTH) {
        // Oh ho, we might have smashed the stack :( . Abort everything!
        // This should not happen at all.
        fprintf(stderr, "Big problem at %s%d\n", __FILE__, __LINE__);
        exit(-1);
    }

    if (!res) {
        fprintf(stderr, "Could not HMAC_Final\n");
        goto cleanup_hmac_context;
    }

    size_t half_hash_len = SHA512_DIGEST_LENGTH / 2;


    memcpy(key->version, KEY_VERSIONS_VALUES[KEY_VERSION_MAINNET_PRIVATE], sizeof(key->version));

    // Copy the L and R part into the key.
    key->key_data[0] = 0;
    memcpy(key->key_data + 1, master_digest, half_hash_len);
    memcpy(key->chain_code, master_digest + half_hash_len, half_hash_len);

    // Set the rest of the data as master key.
    key->depth = (uint8_t) 0;
    memset(key->parent_fingerprint, 0, sizeof(key->parent_fingerprint));
    memset(key->child_number, 0, sizeof(key->child_number));


    cleanup_hmac_context:
    HMAC_CTX_cleanup(&hmac_ctx);

    return res;
}

#define NUM_OF_CHECKSUM_BYTES_TO_ADD 4

int HDW_serialize_key(HDW_key_t *key,
                      uint8_t *destination,
                      size_t *destination_len) {

    int res;

    uint8_t buffer_to_encode[sizeof(HDW_key_t) + NUM_OF_CHECKSUM_BYTES_TO_ADD];
    uint8_t key_checksum[SHA256_DIGEST_LENGTH];


    res = HDW_double_SHA256((uint8_t *) key, sizeof(*key), key_checksum);
    if (!res) {
        fprintf(stderr,
                "[ERR] double SHA256 failed.\n");
        return res;
    }

    // We build `buffer_to_encode`: key || key_checksum[0:4]
    memcpy(buffer_to_encode, key, sizeof(*key));
    memcpy(buffer_to_encode + sizeof(*key), key_checksum, NUM_OF_CHECKSUM_BYTES_TO_ADD);


    res = b58enc((char *) destination, destination_len, buffer_to_encode, sizeof(buffer_to_encode));
    if (!res) {
        fprintf(stderr,
                "[ERR] b58 encoding has failed. We need destination buffer of '%lu' bytes.\n",
                *destination_len);
    }

    return res;
}


int HDW_double_SHA256(uint8_t *input,
                      uint32_t input_len,
                      uint8_t output[SHA256_DIGEST_LENGTH]) {

    int res;
    uint8_t intermediate_hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256_ctx;

    // Hashing: first pass
    res = SHA256_Init(&sha256_ctx);
    if (res != 1) { goto problem; }

    res = SHA256_Update(&sha256_ctx, input, input_len);
    if (res != 1) { goto problem; }

    res = SHA256_Final(intermediate_hash, &sha256_ctx);
    if (res != 1) { goto problem; }


    // Hashing: second passgenerated_string_len
    res = SHA256_Init(&sha256_ctx);
    if (res != 1) { goto problem; }

    res = SHA256_Update(&sha256_ctx, intermediate_hash, sizeof(intermediate_hash));
    if (res != 1) { goto problem; }

    res = SHA256_Final(output, &sha256_ctx);
    if (res != 1) { goto problem; }

    return true;

    problem:
    memset(output, 0, SHA256_DIGEST_LENGTH);
    fprintf(stderr, "[ERR] Problem in %s\n", __func__);
    return res;
}