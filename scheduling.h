#ifndef SCHEDULING_H
#define SCHEDULING_H

#include <stdint.h>

/* roundkeys_t: 44 words x 4 bytes = AES-128 expanded key schedule */
typedef struct {
    uint8_t w[44][4];
} roundkeys_t;

/* Build 4x4 state from 16-char ASCII input (column-major) */
void string_to_state_bytes(const char *in16, uint8_t state[4][4]);

/* Generate AES-128 round keys from 16-byte key string */
void generateRoundKeys_from_keystring(const char *key16, roundkeys_t *out);

/* Print round keys (debug) */
void printRoundKeys(const roundkeys_t *rk);

#endif /* SCHEDULING_H */
