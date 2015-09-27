#include "../include/hdwallet.h"

#include <string.h>

#include <openssl/hmac.h>
#include <openssl/ec.h>

#include <libbase58.h>

// Fail check macro
#define  FCHK(STATEMENT, FAIL_COMP, RESULT, FAIL_TAG) if ((RESULT = STATEMENT) FAIL_COMP) { goto FAIL_TAG; }
#define FCHK_SET(STATEMENT, FAIL_COMP, RESULT, FAIL_TAG, RES_WHEN_FAIL) if (STATEMENT FAIL_COMP) { RESULT = RES_WHEN_FAIL; goto FAIL_TAG; }

// Suggested key from spec is "Bitcoin seed"
const char *BIP32_SPEC_DEFAULT_KEY = "Bitcoin seed";

const uint8_t KEY_VERSIONS_VALUES[4][4] = {
        {0x04, 0X88, 0XB2, 0X1E}, // xpub
        {0x04, 0X88, 0XAD, 0XE4}, // xprv
        {0x04, 0X35, 0X87, 0XCF}, // tpub
        {0x04, 0X35, 0X83, 0X94}  // tprv
};


int HDW_generate_master_node(uint8_t *seed,
                             size_t seed_len,
                             HDW_XKEY_NET net,
                             HDW_xkey_t *key) {

    int res;

    HMAC_CTX hmac_ctx;

    res = HMAC_Init(&hmac_ctx, BIP32_SPEC_DEFAULT_KEY, (int) strlen(BIP32_SPEC_DEFAULT_KEY), EVP_sha512());

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


    memcpy(key->version, KEY_VERSIONS_VALUES[net | HDW_XKEY_TYPE_PRIVATE], sizeof(key->version));

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

int HDW_serialize_key(HDW_xkey_t *key,
                      uint8_t *destination,
                      size_t *destination_len) {

    int res = 1;

    uint8_t buffer_to_encode[sizeof(HDW_xkey_t) + NUM_OF_CHECKSUM_BYTES_TO_ADD];
    uint8_t key_checksum[SHA256_DIGEST_LENGTH];

    FCHK(HDW_double_SHA256((uint8_t *) key, sizeof(*key), key_checksum), ==0, res, fail);

    // We build `buffer_to_encode`: key || key_checksum[0:4]
    memcpy(buffer_to_encode, key, sizeof(*key));
    memcpy(buffer_to_encode + sizeof(*key), key_checksum, NUM_OF_CHECKSUM_BYTES_TO_ADD);

    FCHK(b58enc((char *) destination, destination_len, buffer_to_encode, sizeof(buffer_to_encode)), ==0, res, fail);

    fail:
    return res;
}

int HDW_get_key_type(HDW_xkey_t *key) {

    if (!memcmp(key->version, KEY_VERSIONS_VALUES[HDW_XKEY_NET_MAINNET | HDW_XKEY_TYPE_PUBLIC],
                VERSION_IDENTIFIER_LEN)) {
        return HDW_XKEY_NET_MAINNET | HDW_XKEY_TYPE_PUBLIC;
    }
    if (!memcmp(key->version, KEY_VERSIONS_VALUES[HDW_XKEY_NET_MAINNET | HDW_XKEY_TYPE_PRIVATE],
                VERSION_IDENTIFIER_LEN)) {
        return HDW_XKEY_NET_MAINNET | HDW_XKEY_TYPE_PRIVATE;
    }
    if (!memcmp(key->version, KEY_VERSIONS_VALUES[HDW_XKEY_NET_TESTNET | HDW_XKEY_TYPE_PUBLIC],
                VERSION_IDENTIFIER_LEN)) {
        return HDW_XKEY_NET_TESTNET | HDW_XKEY_TYPE_PUBLIC;
    }
    if (!memcmp(key->version, KEY_VERSIONS_VALUES[HDW_XKEY_NET_TESTNET | HDW_XKEY_TYPE_PRIVATE],
                VERSION_IDENTIFIER_LEN)) {
        return HDW_XKEY_NET_TESTNET | HDW_XKEY_TYPE_PRIVATE;
    }

    return -1;
}

int HDW_public_data_from_private_data(uint8_t *key_data, size_t key_data_len, BIGNUM *public_compressed_key) {

    int res = 1;

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM *priv = BN_new();
    EC_POINT *ec_point = EC_POINT_new(group);

    FCHK_SET(BN_bin2bn(key_data, (int) key_data_len, priv), ==0, res, fail, 0);

    // Generate public key.
    FCHK(EC_POINT_mul(group, ec_point, priv, NULL, NULL, NULL), ==0, res, fail);

    FCHK_SET(EC_POINT_point2bn(group, ec_point, POINT_CONVERSION_COMPRESSED, public_compressed_key, NULL), ==0, res,
             fail, 0);

    FCHK_SET(BN_num_bytes(public_compressed_key), !=33, res, fail, 0);


    fail:
    if (res == 0) {
        BN_zero(public_compressed_key);
    }
    EC_POINT_free(ec_point);
    BN_free(priv);
    EC_GROUP_free(group);
    return res;

}

int HDW_calculate_key_identifier(HDW_xkey_t *key, uint8_t identifier[RIPEMD160_DIGEST_LENGTH]) {

    int res = 1;

    uint8_t *public_key_data;
    uint8_t tmp_public_key[33];

    int key_type = HDW_get_key_type(key);
    bool key_is_private = (key_type & HDW_XKEY_TYPE_PRIVATE) != 0;

    BIGNUM *serialized_public_key = BN_new();
    FCHK_SET(serialized_public_key, ==0, res, fail, 0);


    if (key_is_private) {
        // We must calculate the public key
        FCHK(HDW_public_data_from_private_data(key->key_data + 1, sizeof(key->key_data) - 1, serialized_public_key),
             !=1, res, fail);
        FCHK(BN_bn2bin(serialized_public_key, tmp_public_key), ==0, res, fail);
        public_key_data = tmp_public_key;
    }
    else {
        public_key_data = key->key_data;
    }

    FCHK(HDW_hash160(public_key_data, 33, identifier), !=1, res, fail);

    fail:
    if (res == 0) {
        memset(identifier, 0, RIPEMD160_DIGEST_LENGTH);
        return 0;
    }
    return 1;
}

int HDW_derive_public(HDW_xkey_t *private_key, HDW_xkey_t *public_key) {


    int res = 1; // So far so good!

    BIGNUM *compressed_key = BN_new();

    FCHK_SET(compressed_key, ==0, res, fail, 0);

    int key_type = HDW_get_key_type(private_key);
    bool key_is_private = (key_type & HDW_XKEY_TYPE_PRIVATE) != 0;

    memcpy(public_key, private_key, sizeof(*public_key));

    if (key_is_private) {
        memset(public_key->key_data, 0, sizeof(public_key->key_data)); // Trash the private key from there ASAP.
        memcpy(public_key->version, KEY_VERSIONS_VALUES[HDW_get_key_type(private_key) ^ HDW_XKEY_TYPE_PRIVATE],
               sizeof(public_key->version));

        FCHK(HDW_public_data_from_private_data(private_key->key_data + 1, sizeof(private_key->key_data) - 1,
                                               compressed_key), ==0, res, fail);
        FCHK(BN_bn2bin(compressed_key, public_key->key_data), ==0, res, fail);
    }

    fail:
    BN_free(compressed_key);

    if (res == 0) {
        memset(public_key, 0, sizeof(*public_key));
        return 0;
    }
    else {
        return 1;
    }
}


int HDW_derive_private_child(HDW_xkey_t *parent_key, HDW_xkey_t *child_key, uint32_t index) {

    int res = 1;

    // Watch for key depth overflow
    FCHK_SET(parent_key->depth, == UINT8_MAX, res, fail, 0);

    int parent_key_type = HDW_get_key_type(parent_key);
    bool parent_key_is_private = (parent_key_type & HDW_XKEY_TYPE_PRIVATE) != 0;

    uint8_t hash_result[SHA512_DIGEST_LENGTH];
    uint32_t hash_result_len = sizeof(hash_result);

    if (parent_key_is_private) {

        HDW_xkey_t parent_public_key;
        HMAC_CTX hmac_ctx;

        BN_CTX *bn_ctx = BN_CTX_new();

        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

        BIGNUM *temp_parent_key = BN_new();
        BIGNUM *temp_child_key = BN_new();
        BIGNUM *curve_order = BN_new();

        FCHK(HDW_derive_public(parent_key, &parent_public_key), !=1, res, fail_private_derivation);
        FCHK(HMAC_Init(&hmac_ctx, parent_key->chain_code, sizeof(parent_key->chain_code), EVP_sha512()), !=1, res,
             fail_private_derivation);

        bool child_key_is_hardened = index > INT32_MAX;

        if (child_key_is_hardened) {
            FCHK(HMAC_Update(&hmac_ctx, parent_key->key_data, sizeof(parent_key->key_data)), !=1, res,
                 fail_private_derivation);
        }
        else {
            FCHK(HMAC_Update(&hmac_ctx, parent_public_key.key_data, sizeof(parent_public_key.key_data)), !=1, res,
                 fail_private_derivation);
        }

        int32_t index_be = htobe32(index);

        FCHK(HMAC_Update(&hmac_ctx, (const unsigned char *) &index_be, sizeof(int32_t)), !=1, res,
             fail_private_derivation);
        FCHK(HMAC_Final(&hmac_ctx, hash_result, &hash_result_len), !=1, res, fail_private_derivation);

        // First half is part of ki, second part is chain code

        FCHK_SET(BN_bin2bn(parent_key->key_data + 1, sizeof(parent_key->key_data) - 1, temp_parent_key), ==0, res,
                 fail_private_derivation, 0);
        FCHK_SET(BN_bin2bn(hash_result, SHA512_DIGEST_LENGTH / 2, temp_child_key), ==0, res, fail_private_derivation,
                 0);

        FCHK(EC_GROUP_get_order(group, curve_order, NULL), !=1, res, fail_private_derivation);

        if (BN_cmp(temp_child_key, curve_order) >= 0 || BN_is_zero(temp_child_key)) {
            // Key is invalid
            res = 0;
            goto fail_private_derivation;
        }

        FCHK(BN_mod_add(temp_child_key, temp_child_key, temp_parent_key, curve_order, bn_ctx), !=1, res,
             fail_private_derivation);

        // Put the private key in.
        FCHK(BN_bn2bin(temp_child_key, child_key->key_data + 1), ==0, res, fail_private_derivation);
        child_key->key_data[0] = 0;

        // Put the version in.
        memcpy(child_key->version, parent_key->version, sizeof(child_key->version));

        // Put the depth in.
        child_key->depth = (uint8_t) (parent_key->depth + 1);

        // Put the child number in.
        *((uint32_t *) &(child_key->child_number)) = htobe32(index);

        // Generate parent key identifier and put it on the key we are generating.
        uint8_t parent_fingerprint[RIPEMD160_DIGEST_LENGTH];
        FCHK(HDW_calculate_key_identifier(parent_key, parent_fingerprint), !=1, res, fail_private_derivation);
        memcpy(child_key->parent_fingerprint, parent_fingerprint, sizeof(child_key->parent_fingerprint));

        // Put the chain code in.
        memcpy(child_key->chain_code, hash_result + SHA512_DIGEST_LENGTH / 2, sizeof(child_key->chain_code));


        fail_private_derivation:
        // Let's cleanup our current scope.
        BN_free(temp_parent_key);
        BN_free(temp_child_key);
        BN_free(curve_order);
        EC_GROUP_free(group);
        BN_CTX_free(bn_ctx);
    }
    else {
        fprintf(stderr, "There is no such thing as 'public parent' -> 'private child' derivation.\n");
        res = 0;
    }

    fail:
    if (res == 0) {
        memset(child_key, 0, sizeof(*child_key));
        return 0;
    }
    return 1;
}

int HDW_derive_public_child(HDW_xkey_t *parent_key, HDW_xkey_t *child_key, uint32_t index) {

    int res = 1;

    // Watch for key depth overflow
    FCHK_SET(parent_key->depth, == UINT8_MAX, res, fail, 0);

    uint8_t hash_result[SHA512_DIGEST_LENGTH];
    uint32_t hash_result_len = sizeof(hash_result);

    int parent_key_type = HDW_get_key_type(parent_key);
    bool parent_key_is_private = (parent_key_type & HDW_XKEY_TYPE_PRIVATE) != 0;

    BN_CTX *bn_ctx = BN_CTX_new();
    FCHK_SET(bn_ctx, =0, res, fail, 0);

    if (parent_key_is_private) {
        HDW_xkey_t tmp_private_child;
        FCHK(HDW_derive_private_child(parent_key, &tmp_private_child, index), !=1, res, fail_bn_ctx);
        FCHK(HDW_derive_public(&tmp_private_child, child_key), !=1, res, fail_bn_ctx);
    }
    else {

        // Check if it is an hardened key. We can't derive from hardened extended keys.
        if (HDW_is_xkey_hardened(parent_key)) {
            // Todo: Handle failure
            res = 0;
            goto fail_bn_ctx;
        }
        else {

            // All checks are made. Now we derive for real.

            HMAC_CTX hmac_ctx;
            uint8_t parent_key_identifier[RIPEMD160_DIGEST_LENGTH];

            EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

            BIGNUM *child_serialized_temp_point = BN_new();
            BIGNUM *parent_serialized_key = BN_new();
            BIGNUM *point_sum_serialized = BN_new();

            EC_POINT *child_intermediate_point = EC_POINT_new(group);
            EC_POINT *parent_point_key = EC_POINT_new(group);
            EC_POINT *point_sum = EC_POINT_new(group);

            FCHK_SET(child_serialized_temp_point, =0, res, fail_public_child_derivation, 0);
            FCHK_SET(parent_serialized_key, =0, res, fail_public_child_derivation, 0);
            FCHK_SET(point_sum_serialized, =0, res, fail_public_child_derivation, 0);

            FCHK_SET(child_intermediate_point, =0, res, fail_public_child_derivation, 0);
            FCHK_SET(parent_point_key, =0, res, fail_public_child_derivation, 0);
            FCHK_SET(point_sum, =0, res, fail_public_child_derivation, 0);

            FCHK(HMAC_Init(&hmac_ctx, parent_key->chain_code, sizeof(parent_key->chain_code), EVP_sha512()), !=1, res,
                 fail_public_child_derivation);
            FCHK(HMAC_Update(&hmac_ctx, parent_key->key_data, sizeof(parent_key->key_data)), !=1, res, fail_bn_ctx);

            int32_t index_be = htobe32(index);
            FCHK(HMAC_Update(&hmac_ctx, (const unsigned char *) &index_be, sizeof(int32_t)), !=1, res,
                 fail_public_child_derivation);
            FCHK(HMAC_Final(&hmac_ctx, hash_result, &hash_result_len), !=1, res, fail_public_child_derivation);

            memcpy(child_key, parent_key, sizeof(HDW_xkey_t));
            memset(child_key->key_data, 0, sizeof(child_key->key_data));

            child_key->depth++;

            FCHK(HDW_calculate_key_identifier(parent_key, parent_key_identifier), !=1, res, fail_bn_ctx);
            memcpy(child_key->parent_fingerprint, parent_key_identifier, sizeof(child_key->parent_fingerprint));
            memcpy(child_key->child_number, &index_be, sizeof(child_key->child_number));

            // Build the points

            FCHK_SET(group, =0, res, fail_bn_ctx, 0);

            FCHK_SET(BN_bin2bn(hash_result, SHA512_DIGEST_LENGTH / 2, child_serialized_temp_point), >0, res,
                     fail_public_child_derivation, 0);
            FCHK_SET(EC_POINT_bn2point(group, child_serialized_temp_point, child_intermediate_point, bn_ctx), >0, res,
                     fail_public_child_derivation, 0);


            FCHK_SET(BN_bin2bn(parent_key->key_data, sizeof(parent_key->key_data), parent_serialized_key), >0, res,
                     fail_public_child_derivation, 0);

            FCHK_SET(EC_POINT_bn2point(group, parent_serialized_key, parent_point_key, bn_ctx), >0, res,
                     fail_public_child_derivation, 0);

            FCHK(EC_POINT_add(group, point_sum, child_intermediate_point, parent_point_key, bn_ctx), >0, res,
                 fail_public_child_derivation);

            FCHK_SET(EC_POINT_point2bn(group, point_sum, POINT_CONVERSION_COMPRESSED, point_sum_serialized, bn_ctx), >0,
                     res, fail_public_child_derivation, 0);

            // Public key should be 33 bytes
            FCHK_SET(BN_num_bytes(point_sum_serialized), !=33, res, fail_public_child_derivation, 0);
            FCHK(BN_bn2bin(point_sum_serialized, child_key->key_data), != 0, res, fail_public_child_derivation);

            // Put the chain in.
            memcpy(child_key->chain_code, hash_result + SHA512_DIGEST_LENGTH / 2, SHA512_DIGEST_LENGTH / 2);

            // Todo: handle invalid key.

            fail_public_child_derivation:
            EC_POINT_free(point_sum);
            EC_POINT_free(parent_point_key);
            EC_POINT_free(child_intermediate_point);

            BN_free(point_sum_serialized);
            BN_free(parent_serialized_key);
            BN_free(child_serialized_temp_point);
            EC_GROUP_free(group);

        }
    }

    fail_bn_ctx:
    BN_CTX_free(bn_ctx);

    fail:
    if (res == 0) {
        memset(child_key, 0, sizeof(*child_key));
        return 0;
    }
    return 1;
}

bool HDW_is_xkey_hardened(HDW_xkey_t *key) {
    return be32toh(*((uint32_t *) key->child_number)) > INT32_MAX;
}

int HDW_double_SHA256(uint8_t *input,
                      uint32_t input_len,
                      uint8_t output[SHA256_DIGEST_LENGTH]) {

    int res = 1;
    uint8_t intermediate_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;


    // Hashing: first pass
    FCHK(SHA256_Init(&sha256_ctx), !=1, res, fail);
    FCHK(SHA256_Update(&sha256_ctx, input, input_len), !=1, res, fail);
    FCHK(SHA256_Final(intermediate_hash, &sha256_ctx), !=1, res, fail);

    // Hashing: second pass generated_string_len
    FCHK(SHA256_Init(&sha256_ctx), !=1, res, fail);
    FCHK(SHA256_Update(&sha256_ctx, intermediate_hash, sizeof(intermediate_hash)), !=1, res, fail);
    FCHK(SHA256_Final(output, &sha256_ctx), !=1, res, fail);

    fail:
    if (res != 1) {
        memset(output, 0, SHA256_DIGEST_LENGTH);
        return 0;
    }
    return 1;
}

int HDW_hash160(uint8_t *input,
                uint32_t input_len,
                uint8_t output[RIPEMD160_DIGEST_LENGTH]) {

    int res = 1;
    uint8_t intermediate_hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256_ctx;
    RIPEMD160_CTX ripemd160_ctx;

    // Hashing input with SHA256
    FCHK(SHA256_Init(&sha256_ctx), !=1, res, fail);
    FCHK(SHA256_Init(&sha256_ctx), !=1, res, fail);
    FCHK(SHA256_Update(&sha256_ctx, input, input_len), !=1, res, fail);
    FCHK(SHA256_Final(intermediate_hash, &sha256_ctx), !=1, res, fail);

    // Hashing previous digest with RIPEMD160
    FCHK(RIPEMD160_Init(&ripemd160_ctx), !=1, res, fail);
    FCHK(RIPEMD160_Init(&ripemd160_ctx), !=1, res, fail);
    FCHK(RIPEMD160_Update(&ripemd160_ctx, intermediate_hash, SHA256_DIGEST_LENGTH), !=1, res, fail);
    FCHK(RIPEMD160_Final(output, &ripemd160_ctx), !=1, res, fail);

    fail:
    if (res != 1) {
        memset(output, 0, RIPEMD160_DIGEST_LENGTH);
        return 0;
    }
    return 1;
}