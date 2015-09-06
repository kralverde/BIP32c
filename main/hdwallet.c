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

int HDW_hash160(uint8_t *input,
                uint32_t input_len,
                uint8_t output[RIPEMD160_DIGEST_LENGTH]);


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

int HDW_calculate_key_identifier(HDW_key_t *key, uint8_t identifier[RIPEMD160_DIGEST_LENGTH]) {

    int key_type = HDW_get_key_type(key);
    bool key_is_private = (key_type & HDW_KEY_TYPE_PRIVATE) != 0;


    BIGNUM *serialized_public_key = BN_new();

    uint8_t *public_key_data;
    uint8_t tmp_public_key[33];

    if (key_is_private) {
        // We must calculate the public key
        HDW_public_data_from_private_data(key->key_data + 1, sizeof(key->key_data) - 1, serialized_public_key);
        BN_bn2bin(serialized_public_key, tmp_public_key);
        public_key_data = tmp_public_key;
    }
    else {
        public_key_data = key->key_data;
    }

    HDW_hash160(public_key_data, 33, identifier);

    return 1;


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


int HDW_derive_private_child(HDW_key_t *parent_key, HDW_key_t *child_key, uint32_t index) {

    // Todo: Watch for key depth overflow

    int res = 1;

    int parent_key_type = HDW_get_key_type(parent_key);
    bool parent_key_is_private = (parent_key_type & HDW_KEY_TYPE_PRIVATE) != 0;

    uint8_t hash_result[SHA512_DIGEST_LENGTH];
    uint32_t hash_result_len = sizeof(hash_result);

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    if (parent_key_is_private) {

        HDW_key_t parent_public_key;
        HDW_derive_public(parent_key, &parent_public_key);

        HMAC_CTX hmac_ctx;
        HMAC_Init(&hmac_ctx, parent_key->chain_code, sizeof(parent_key->chain_code), EVP_sha512());

        bool child_key_is_hardened = index > INT32_MAX;

        if (child_key_is_hardened) {
            HMAC_Update(&hmac_ctx, parent_key->key_data, sizeof(parent_key->key_data));
        }
        else {
            HMAC_Update(&hmac_ctx, parent_public_key.key_data, sizeof(parent_public_key.key_data));
        }

        int32_t index_be = htobe32(index);
        HMAC_Update(&hmac_ctx, (const unsigned char *) &index_be, sizeof(int32_t));

        HMAC_Final(&hmac_ctx, hash_result, &hash_result_len);

        // First half is part of ki, second part is chain code

        BIGNUM *temp_parent_key = BN_new();
        BIGNUM *temp_child_key = BN_new();
        BIGNUM *curve_order = BN_new();

        BN_bin2bn(parent_key->key_data + 1, sizeof(parent_key->key_data) - 1, temp_parent_key);
        BN_bin2bn(hash_result, SHA512_DIGEST_LENGTH / 2, temp_child_key);

        EC_GROUP_get_order(group, curve_order, NULL);

        if (BN_cmp(temp_child_key, curve_order) >= 0 || BN_is_zero(temp_child_key)) {
            // Key is invalid
            res = 0;
            goto cleanup0;
        }

        BN_CTX *bn_ctx;
        bn_ctx = BN_CTX_new();

        BN_mod_add(temp_child_key, temp_child_key, temp_parent_key, curve_order, bn_ctx);

        // Put the private key in.
        BN_bn2bin(temp_child_key, child_key->key_data + 1);
        child_key->key_data[0] = 0;

        // Put the version in.
        memcpy(child_key->version, parent_key->version, sizeof(child_key->version));

        // Put the depth in.
        child_key->depth = (uint8_t) (parent_key->depth + 1);

        // Put the child number in.
        *((uint32_t *) &(child_key->child_number)) = htobe32(index);

        // Generate parent key identifier and put it on the key we are generating.
        uint8_t parent_fingerprint[RIPEMD160_DIGEST_LENGTH];
        HDW_calculate_key_identifier(parent_key, parent_fingerprint);
        memcpy(child_key->parent_fingerprint, parent_fingerprint, sizeof(child_key->parent_fingerprint));

        // Put the chain code in.
        memcpy(child_key->chain_code, hash_result + SHA512_DIGEST_LENGTH / 2, sizeof(child_key->chain_code));


        // Let's cleanup our current scope.
        BN_free(temp_parent_key);
        BN_free(temp_child_key);
        BN_free(curve_order);
        BN_CTX_free(bn_ctx);
    }
    else {
        fprintf(stderr, "There is no such thing as 'public parent' -> 'private child' derivation.\n");
        res = 0;
        goto cleanup0;
    }

    cleanup0:
    EC_GROUP_free(group);

    return res;
};

int HDW_derive_public_child(HDW_key_t *parent_key, HDW_key_t *child_key, uint32_t index) {

};

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

int HDW_hash160(uint8_t *input,
                uint32_t input_len,
                uint8_t output[RIPEMD160_DIGEST_LENGTH]) {

    int res = 1;
    uint8_t intermediate_hash[SHA256_DIGEST_LENGTH];

    // Digest input with SHA256
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    res &= SHA256_Init(&sha256_ctx);
    res &= SHA256_Update(&sha256_ctx, input, input_len);
    res &= SHA256_Final(intermediate_hash, &sha256_ctx);


    // Digest previous digest with RIPEMD160
    RIPEMD160_CTX ripemd160_ctx;
    RIPEMD160_Init(&ripemd160_ctx);
    res &= RIPEMD160_Init(&ripemd160_ctx);
    res &= RIPEMD160_Update(&ripemd160_ctx, intermediate_hash, SHA256_DIGEST_LENGTH);
    res &= RIPEMD160_Final(output, &ripemd160_ctx);

    return res;
}