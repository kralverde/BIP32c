
#ifndef HIERARCHICALDETERMINISTICWALLETS_HDWALLET_H
#define HIERARCHICALDETERMINISTICWALLETS_HDWALLET_H

#define SERIALIZED_KEY_BUFFER_LEN 112
#define VERSION_IDENTIFIER_LEN 4

#include <stddef.h>
#include <stdint.h>

#include <openssl/ripemd.h>


typedef struct {
    uint8_t version[VERSION_IDENTIFIER_LEN];
    uint8_t depth;
    uint8_t parent_fingerprint[4];
    uint8_t child_number[4];
    uint8_t chain_code[32];
    uint8_t key_data[33];
} __attribute__ ((packed)) HDW_key_t;

enum {
    HDW_KEY_TYPE_PUBLIC = 0,
    HDW_KEY_TYPE_PRIVATE = 1
};
enum {
    HDW_KEY_NET_MAINNET = 0,
    HDW_KEY_NET_TESTNET = 2
};

/*
 * Contains the values of version prefixes
 */
extern const uint8_t KEY_VERSIONS_VALUES[4][VERSION_IDENTIFIER_LEN];

/*
 * Generates the Master Node from a `seed` and puts it into `key`
 */
int HDW_generate_master_node(uint8_t *seed,
                             size_t seed_len,
                             HDW_key_t *key);

/*
 * Takes the `key` and turns it into a BIP32 compliant Base58 representation.
 * Outputs the string in a buffer of size `SERIALIZED_KEY_BUFFER_LEN`
 */
int HDW_serialize_key(HDW_key_t *key,
                      uint8_t *destination,
                      size_t *destination_len);

/*
 * Generates the extended public key from an extended private key
 * If provided private key is in fact public, the content pointed by `private_key` is copied to `public key`
 * Returns: 0 on failure
 *          1 on success
 */

int HDW_derive_public(HDW_key_t *private_key, HDW_key_t *public_key);

/*
 * Derives a private
 * Returns: 0 on failure
 *          1 on success
 */
int HDW_derive_private_child(HDW_key_t *parent_key, HDW_key_t *child_key, uint32_t index);
int HDW_derive_public_child(HDW_key_t *parent_key, HDW_key_t *child_key, uint32_t index);

int HDW_hash160(uint8_t *input,
                uint32_t input_len,
                uint8_t output[RIPEMD160_DIGEST_LENGTH]);

#endif //HIERARCHICALDETERMINISTICWALLETS_HDWALLET_H
