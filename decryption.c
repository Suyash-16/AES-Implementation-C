// decryption.c


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "scheduling.h"

//helpers
static uint8_t xtime(uint8_t x) {
    return (uint8_t) ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

static uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

//inverse sbox
static const uint8_t inv_sbox[256] = {
  0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
  0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
  0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
  0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
  0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
  0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
  0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
  0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
  0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
  0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
  0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
  0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
  0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
  0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
  0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
  0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

// add round key
static void add_round_key(uint8_t state[4][4], const roundkeys_t *rk, int round) {
    for (int col = 0; col < 4; ++col)
        for (int row = 0; row < 4; ++row)
            state[row][col] ^= rk->w[round * 4 + col][row];
}

// inverse 
static void inv_sub_bytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = inv_sbox[state[r][c]];
}

static void inv_shift_rows(uint8_t state[4][4]) {
    uint8_t tmp[4];
    for (int c = 0; c < 4; ++c) tmp[c] = state[1][(c + 3) % 4];
    for (int c = 0; c < 4; ++c) state[1][c] = tmp[c];

    for (int c = 0; c < 4; ++c) tmp[c] = state[2][(c + 2) % 4];
    for (int c = 0; c < 4; ++c) state[2][c] = tmp[c];

    for (int c = 0; c < 4; ++c) tmp[c] = state[3][(c + 1) % 4];
    for (int c = 0; c < 4; ++c) state[3][c] = tmp[c];
}

static void inv_mix_columns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t a0 = state[0][c];
        uint8_t a1 = state[1][c];
        uint8_t a2 = state[2][c];
        uint8_t a3 = state[3][c];

        state[0][c] = (uint8_t)( mul(a0,14) ^ mul(a1,11) ^ mul(a2,13) ^ mul(a3,9) );
        state[1][c] = (uint8_t)( mul(a0,9)  ^ mul(a1,14) ^ mul(a2,11) ^ mul(a3,13));
        state[2][c] = (uint8_t)( mul(a0,13) ^ mul(a1,9)  ^ mul(a2,14) ^ mul(a3,11));
        state[3][c] = (uint8_t)( mul(a0,11) ^ mul(a1,13) ^ mul(a2,9)  ^ mul(a3,14));
    }
}

// decrypt block 
static void decrypt_block(uint8_t state[4][4], const roundkeys_t *rk) {
    add_round_key(state, rk, 10);
    for (int round = 9; round >= 0; --round) {
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, rk, round);
    }
}

// string conversion 
static void print_state_hex(const uint8_t state[4][4]) {
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c)
            printf("%02X ", state[r][c]);
        printf("\n");
    }
}

static void state_to_string(uint8_t state[4][4], char out16[17]) {
    for (int i = 0; i < 16; ++i) {
        int row = i % 4;
        int col = i / 4;
        out16[i] = (char) state[row][col];
    }
    out16[16] = '\0';
}

// parsing hex token 
static int parse_hex_byte(const char *tok, uint8_t *out) {
    int hi = -1, lo = -1;
    int len = (int)strlen(tok);
    int i = 0;
    
    if (len > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) i = 2;
    
    while (i < len && isspace((unsigned char)tok[i])) ++i;
    if (i >= len) return -1;
    int start = i;
   
    char hex[3] = {0,0,0};
    int k = 0;
    while (i < len && k < 2 && isxdigit((unsigned char)tok[i])) {
        hex[k++] = tok[i++];
    }
    if (k == 0) return -1;
    if (k == 1) { hex[1] = hex[0]; hex[0] = '0'; }
    unsigned int val = 0;
    if (sscanf(hex, "%x", &val) != 1) return -1;
    *out = (uint8_t) val;
    return 0;
}


static int read_16_bytes_from_string_or_stdin(const char *input_str, uint8_t bytes[16]) {
    char buf[512];
    if (input_str) {
        strncpy(buf, input_str, sizeof(buf)-1);
        buf[sizeof(buf)-1] = 0;
    } else {
        
        size_t off = 0;
        while (off + 1 < sizeof(buf)) {
            int c = fgetc(stdin);
            if (c == EOF) break;
            buf[off++] = (char)c;
        }
        buf[off] = '\0';
    }

    char *p = buf;
    int count = 0;
    while (count < 16) {
 
        while (*p && (isspace((unsigned char)*p) || *p == ',')) ++p;
        if (!*p) break;
        
        char *q = p;
        while (*q && !(isspace((unsigned char)*q) || *q == ',')) ++q;
        char tok[16];
        size_t toklen = (size_t)(q - p);
        if (toklen >= sizeof(tok)) toklen = sizeof(tok)-1;
        memcpy(tok, p, toklen);
        tok[toklen] = '\0';
        uint8_t val;
        if (parse_hex_byte(tok, &val) != 0) return -1;
        bytes[count++] = val;
        p = q;
    }
    if (count != 16) return -1;
    return 0;
}

int main(int argc, char **argv) {
    const char *key_in = NULL;
    const char *ct_in = NULL;

    if (argc >= 2) key_in = argv[1];
    if (argc >= 3) ct_in = argv[2];

    const char *default_key = "Thats my Kung Fu";
    char key16[17];
    if (key_in == NULL) {
        strncpy(key16, default_key, 16);
        key16[16] = '\0';
    } else {
        size_t klen = strlen(key_in);
        if (klen >= 16) {
            memcpy(key16, key_in, 16);
        } else {
            memcpy(key16, key_in, klen);
            for (size_t i = klen; i < 16; ++i) key16[i] = ' ';
        }
        key16[16] = '\0';
    }

    uint8_t bytes[16];
    if (read_16_bytes_from_string_or_stdin(ct_in, bytes) != 0) {
        fprintf(stderr, "Sorry: could not read 16 hex bytes for ciphertext.\n");
        fprintf(stderr, "  ./decrypt \"%s\" \"34 A0 D0 46 3B 8D C2 BE 60 E5 A8 67 10 6B 03 DE\"\n", key16);
        return 1;
    }
    uint8_t state[4][4];
    for (int i = 0; i < 16; ++i) {
        int row = i % 4;
        int col = i / 4;
        state[row][col] = bytes[i];
    }

    roundkeys_t rk;
    generateRoundKeys_from_keystring(key16, &rk);

    printf("Using key (16 chars/padded): '%.16s'\n", key16);
    printf("Ciphertext state (hex):\n");
    print_state_hex(state);

    decrypt_block(state, &rk);

    printf("\nDecrypted state (hex):\n");
    print_state_hex(state);

    char recovered[17];
    state_to_string(state, recovered);
    printf("\nRecovered plaintext (ASCII): '%.16s'\n", recovered);

    return 0;
}
