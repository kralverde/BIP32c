
#include <stdio.h>

#include <hdwallet.h>

int main(int argc, char *argv[]) {


    int res;

    uint8_t seed[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    HDW_key_t master_key;

    HDW_generate_master_node(seed, sizeof(seed), &master_key);



    uint8_t buff[SERIALIZED_KEY_BUFFER_LEN];
    size_t buff_len = sizeof(buff);

    res = HDW_serialize_key(&master_key, buff, &buff_len);

    if (!res) {
        // This should not happen while using a buffer of size `SERIALIZED_KEY_BUFFER_LEN`.
        fprintf(stderr, "Key serialization failed.");
        return -1;
    }

    printf("Serialized key: %s\n", buff);


    return 0;
}