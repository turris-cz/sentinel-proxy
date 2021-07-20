#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <device_token.h>

#define CRC_BYTES 4
// Every byte of device token random data equals two hexadecimal characters
#define RANDOM_BYTES (DEVICE_TOKEN_LEN / 2 - CRC_BYTES)

const char const *state_messages[] = {
    "device_token check passed",
    "device_token must be specified",
    "device_token must be 64 characters long",
    "device_token must consist of lowercase hexachars",
    "device_token crc check failed",
};

const char *device_token_state_msg(enum dt_state state) {
    switch(state) {
        case DT_OK: case DT_UNDEF: case DT_LENGTH: case DT_DECODE: case DT_CRC:
            return state_messages[state];
        default:
            return NULL;
    };
}

static uint32_t get_crc(uint8_t *data, unsigned len) {
    #if CRC_BYTES != 4
    #error Template for outputting CRC bytes has to be updated.
    #endif
    uint32_t crc = crc32(0L, Z_NULL, 0);
    for (int i = 0; i < len; ++i) {
        crc = crc32(crc, data + i, 1);
    }
    return crc;
}

// Hexastring consists of ASCII values for 0-9 and a-f
// These values are only four bits at most
static inline char val2hex(uint8_t val) {
    assert(val < 16);
    if (val < 10)
        return val + '0';
    return val - 10 + 'a';
}

static inline void bytes2hex(uint8_t *bytes, char *hexastring, unsigned len) {
    for (int i = 0; i < len; i++) {
        hexastring[2*i] = val2hex(bytes[i] >> 4);
        hexastring[2*i + 1] = val2hex(bytes[i] & 0xf);
    }
}

static inline int hex2val(char hex) {
    if ('0' <= hex && hex <= '9')
        return hex - '0';
    if ('a' <= hex && hex <= 'f')
        return hex + 10 - 'a';
    return -1;
}

static inline int hex2bytes(const char *hexastring, uint8_t *bytes, unsigned len) {
    int val;
    for (int i = 0; i < len; i++) {
        val = hex2val(hexastring[2*i]);
        if (val < 0)
            return val;
        bytes[i] = val << 4;

        val = hex2val(hexastring[2*i + 1]);
        if (val < 0)
            return val;
        bytes[i] += val;
    }
    return 0;
}

char *device_token_generate() {
    uint8_t token_data[RANDOM_BYTES];
    RAND_priv_bytes(token_data, RANDOM_BYTES);

    uint32_t crc = get_crc(token_data, RANDOM_BYTES);

    char *device_token = malloc(DEVICE_TOKEN_LEN +1);
    if (!device_token)
        return NULL;
    bytes2hex(token_data, device_token, RANDOM_BYTES);
    //This ensures that crc is displayed in big endian
    #if CRC_BYTES != 4
    #error Template for outputting CRC bytes has to be updated.
    #endif
    snprintf(device_token + 2*RANDOM_BYTES,
             2*CRC_BYTES + 1 ,
             "%08x",
             crc);
    return device_token;
}

static enum dt_state check_base(const char *device_token) {
    if (!device_token)
        return DT_UNDEF;
    if (strlen(device_token) != DEVICE_TOKEN_LEN)
        return DT_LENGTH;
    return DT_OK;
}

static enum dt_state check_crc(const char *device_token) {
    uint8_t token_data[RANDOM_BYTES];

    if (hex2bytes(device_token, token_data, RANDOM_BYTES) < 0)
        return DT_DECODE;

    uint32_t computed_crc = get_crc(token_data, RANDOM_BYTES);
    uint32_t provided_crc = (uint32_t)strtoul(
            device_token + 2*RANDOM_BYTES, NULL, 16);

    if (computed_crc != provided_crc)
        return DT_CRC;
    return DT_OK;

}

enum dt_state device_token_verify(const char *device_token) {
    enum dt_state base_check_result = check_base(device_token);
    if (base_check_result != DT_OK)
        return base_check_result;
    return check_crc(device_token);
}
