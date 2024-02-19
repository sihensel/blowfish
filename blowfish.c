#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "blowfish.h"
#include "constants.h"

uint32_t 
feistel_function(uint32_t arg)
{
    uint32_t a = 0, b = 0, c = 0, d = 0;
    uint32_t int_value = 0;

    a = sbox[0][(uint8_t)(arg >> 24)];
    b = sbox[1][(uint8_t)(arg >> 16)];
    c = sbox[2][(uint8_t)(arg >> 8)];
    d = sbox[3][(uint8_t)(arg)];

    int_value = a + b;
    int_value ^= c;
    int_value += d;

    return int_value;
}

void 
_encrypt(uint32_t *left, uint32_t *right)
{
    uint32_t i, t;
    for (i = 0; i < 16; i++) {
        *left ^= pbox[i];
        *right ^= feistel_function(*left);

        SWAP(*left, *right, t);
    }

    SWAP(*left, *right, t);
    *right ^= pbox[16];

    *left ^= pbox[17];
}

void
blowfish_init(uint8_t key[], int size)
{
    int keysize = size, i, j;
    uint32_t left = 0x00000000, right = 0x00000000;

    /* subkey generation */
    for (i = 0; i < 18; i++) {
        pbox[i] ^= ((uint32_t)key[(i + 0) % keysize] << 24) |
                   ((uint32_t)key[(i + 1) % keysize] << 16) |
                   ((uint32_t)key[(i + 2) % keysize] <<  8) |
                   ((uint32_t)key[(i + 3) % keysize]);
    }

    /* encrypt the zeroes, modifying the p-array and s-boxes accordingly */
    for (i = 0; i <= 17; i += 2) {
        _encrypt(&left, &right);
        pbox[i]     = left;
        pbox[i + 1] = right;
    }

    for (i = 0; i <= 3; i++) {
        for (j = 0; j <= 254; j += 2) {
            _encrypt(&left, &right);
            sbox[i][j]     = left;
            sbox[i][j + 1] = right;
        }
    }
    // dump sboxes after key scheduler
    // for (int x=0; x<4;x++) {
    //     for (int y=0;y<256;y++) {
    //         printf("%X\n", sbox[x][y]);
    //     }
    //     printf("\n\n");
    // }
}

void
blowfish_encrypt(uint8_t data[], uint8_t ct[])
{
    uint32_t left, right;
    uint64_t chunk;

    /* make 8 byte chunks */
    chunk = 0x0000000000000000;
    memmove(&chunk, data, sizeof(chunk));

    /* split into two 4 byte chunks */
    left = right = 0x00000000;
    left   = (uint32_t)(chunk >> 32);
    right  = (uint32_t)(chunk);

    _encrypt(&left, &right);

    /* merge encrypted halves into a single 8 byte chunk again */
    chunk = 0x0000000000000000;
    chunk |= left; chunk <<= 32;
    chunk |= right;
    // printf("%016llX\t<- chunk\n", chunk);

    memcpy(ct, &chunk, sizeof(chunk));
}

void
_decrypt(uint32_t *left, uint32_t *right)
{
    uint32_t i, t;
    for (i = 17; i > 1; i--) {
        *left  ^= pbox[i];
        *right ^= feistel_function(*left);

        SWAP(*left, *right, t);
    }

    SWAP(*left, *right, t);
    *right ^=  pbox[1];
    *left  ^= pbox[0];
}

void
blowfish_decrypt(uint8_t data[], uint8_t ct[])
{
    uint32_t left, right;
    uint64_t chunk;

    chunk = 0x0000000000000000;
    memmove(&chunk, data, sizeof(chunk));

    left = right = 0x00000000;
    left   = (uint32_t)(chunk >> 32);
    right  = (uint32_t)(chunk);

    _decrypt(&left, &right);

    chunk = 0x0000000000000000;
    chunk |= left; chunk <<= 32;
    chunk |= right;

    memcpy(ct, &chunk, sizeof(chunk));
}

void
attack_sbox(uint8_t data[])
{
    // extract round keys via the s-box lookup
    // only works when sboxes are known
    uint32_t left, right;
    uint64_t chunk;
    uint32_t i, t;

    /* make 8 byte chunks */
    chunk = 0x0000000000000000;
    memmove(&chunk, data, sizeof(chunk));

    /* split into two 4 byte chunks */
    left = right = 0x00000000;
    left  = (uint32_t)(chunk >> 32);
    right = (uint32_t)(chunk);

    for (i = 0; i < 16; i++) {
        // stop to get the key of round i + 1
        // if (i == 1) { break; }

        left ^= pbox[i];
        right ^= feistel_function(left);

        SWAP(left, right, t);
    }
    // when attacking the last 2 round keys
    SWAP(left, right, t);

    uint32_t int_value = 0;
    for (uint32_t j = 0; j < 256; j++) {
        // intermediate value during the 16 rounds
        // int_value = sbox[0][((uint8_t)(left >> 24)) ^ j];
        // int_value = sbox[1][((uint8_t)(left >> 16)) ^ j];
        // int_value = sbox[2][((uint8_t)(left >> 8)) ^ j];
        // int_value = sbox[3][((uint8_t)(left)) ^ j];

        // get the last two round keys
        // first byte
        int_value = (uint8_t)(right >> 24) ^ j;

        // second byte
        // right ^= (uint32_t)(0xD4 << 24);
        // int_value = (uint8_t)(right >> 16) ^ j;

        // third byte
        // right ^= (uint32_t)(0xD455 << 16);
        // int_value = (uint8_t)(right >> 8) ^ j;

        // fourth byte
        // right ^= (uint32_t)(0xD455EA << 8);
        // int_value = (uint8_t)(right) ^ j;

        printf("%d ", __builtin_popcount(int_value));
    }
    return;
}

void
attack_xor(uint8_t data[])
{
    // attack left half XOR p
    uint32_t left;
    uint64_t chunk;

    chunk = 0x0000000000000000;
    memmove(&chunk, data, sizeof(chunk));

    left  = 0x00000000;
    left  = (uint32_t)(chunk >> 32);

    // insert previously extracted bytes here
    left ^= (uint32_t)(0x75ACA6 << 8);

    uint8_t int_value = 0;
    for (uint32_t i = 0; i < 256; i++) {
        // int_value = (uint8_t)(left >> 24) ^ i;

        // int_value = (uint8_t)(left >> 16) ^ i;

        // int_value = (uint8_t)(left >> 8) ^ i;

        int_value = (uint8_t)(left) ^ i;
        printf("%d ", __builtin_popcount(int_value));
    }
}

void
attack_feistel(uint8_t data[])
{
    // attack the result of f()
    uint32_t right;
    uint64_t chunk;

    chunk = 0x0000000000000000;
    memmove(&chunk, data, sizeof(chunk));

    right = 0x00000000;
    right = (uint32_t)(chunk);

    // insert previously extracted bytes here
    // right ^= (uint32_t)(0x7D10F1 << 8);

    uint8_t int_value = 0;
    for (uint32_t i = 0; i < 256; i++) {
        int_value = (uint8_t)(right >> 24) ^ i;

        // int_value = (uint8_t)(right >> 16) ^ i;

        // int_value = (uint8_t)(right >> 8) ^ i;

        // int_value = (uint8_t)(right) ^ i;
        printf("%d ", __builtin_popcount(int_value));
    }
}

void
print_feistel(uint8_t data[])
{
    // print the result of f() for a given plaintext so we don't have to
    // manually attack f() for all 500 plaintexts
    uint32_t left;
    uint64_t chunk;

    chunk = 0x0000000000000000;
    memmove(&chunk, data, sizeof(chunk));

    left  = 0x00000000;
    left  = (uint32_t)(chunk >> 32);

    uint32_t temp = 0;

    left ^= pbox[0];
    temp = feistel_function(left);
    printf("%X", temp);
}
