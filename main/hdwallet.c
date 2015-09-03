#include "../include/hdwallet.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
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


    memcpy(key->version, KEY_VERSIONS_VALUES[HDW_KEY_NET_MAINNET | HDW_KEY_TYPE_PRIVATE], sizeof(key->version));

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

int HDW_get_key_type(HDW_key_t *key) {

    if (!memcmp(key->version, KEY_VERSIONS_VALUES[HDW_KEY_NET_MAINNET | HDW_KEY_TYPE_PUBLIC], VERSION_IDENTIFIER_LEN)) {
        return HDW_KEY_NET_MAINNET | HDW_KEY_TYPE_PUBLIC;
    }
    if (!memcmp(key->version, KEY_VERSIONS_VALUES[HDW_KEY_NET_MAINNET | HDW_KEY_TYPE_PRIVATE], VERSION_IDENTIFIER_LEN)) {
        return HDW_KEY_NET_MAINNET | HDW_KEY_TYPE_PRIVATE;
    }
    if (!memcmp(key->version, KEY_VERSIONS_VALUES[HDW_KEY_NET_TESTNET | HDW_KEY_TYPE_PUBLIC], VERSION_IDENTIFIER_LEN)) {
        return HDW_KEY_NET_TESTNET | HDW_KEY_TYPE_PUBLIC;
    }
    if (!memcmp(key->version, KEY_VERSIONS_VALUES[HDW_KEY_NET_TESTNET | HDW_KEY_TYPE_PRIVATE], VERSION_IDENTIFIER_LEN)) {
        return HDW_KEY_NET_TESTNET | HDW_KEY_TYPE_PRIVATE;
    }

    return -1;
}

int HDW_public_data_from_private_data(uint8_t *key_data, size_t key_data_len, BIGNUM *public_compressed_key) {

    int res = 1;

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM *priv = BN_new();
    EC_POINT *ec_point = EC_POINT_new(group);

    BN_bin2bn(key_data, (int) key_data_len, priv);

    // Generate public key.
    res = EC_POINT_mul(group, ec_point, priv, NULL, NULL, NULL);

    EC_POINT_point2bn(group, ec_point, POINT_CONVERSION_COMPRESSED, public_compressed_key, NULL);

    if (BN_num_bytes(public_compressed_key) != 33) {
        fprintf(stderr, "[ERR] Derived public compressed key is not of the size we expect.");
        res = 0;
        goto cleanup;
    }

    cleanup:
        EC_POINT_free(ec_point);
        BN_free(priv);
        EC_GROUP_free(group);
    return res;

}
int HDW_derive_public (HDW_key_t *private_key, HDW_key_t *public_key) {


    int res = 1; // So far so good!

    BIGNUM *compressed_key = BN_new();

    int key_type = HDW_get_key_type(private_key);
    bool key_is_private = (key_type & HDW_KEY_TYPE_PRIVATE) != 0;

    memcpy(public_key, private_key, sizeof(*public_key));

    if (key_is_private) {
        memset(public_key->key_data, 0, sizeof(public_key->key_data)); // Trash the private key from there ASAP.
        memcpy(public_key->version, KEY_VERSIONS_VALUES[HDW_get_key_type(private_key) ^ HDW_KEY_TYPE_PRIVATE], sizeof(public_key->version));

        if (!HDW_public_data_from_private_data(private_key->key_data + 1, sizeof(private_key->key_data) - 1,
                                               compressed_key)) {
            // Public key derivation failed.
            res = 1;
            goto cleanup;
        }
        BN_bn2bin(compressed_key, public_key->key_data);
    }

    cleanup:
        BN_free(compressed_key);

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