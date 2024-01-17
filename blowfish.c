#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "blowfish.h"
#include "constants.h"

uint32_t 
feistel_function(uint32_t arg, uint8_t is_init)
{
    uint32_t a = 0, b = 0, c = 0, d = 0;
    uint32_t int_value = 0;

    // if (is_init == 0) { printf("%X\n", pbox[0]); }
    a = sbox[0][(uint8_t)(arg >> 24)];
    b = sbox[1][(uint8_t)(arg >> 16)];
    c = sbox[2][(uint8_t)(arg >> 8)];
    d = sbox[3][(uint8_t)(arg)];

    // only calc the hamming weight when we are actually encrypting
    if (is_init == 0) {
        printf("%d ", __builtin_popcount(a));
        printf("%d ", __builtin_popcount(b));
        printf("%d ", __builtin_popcount(c));
        printf("%d ", __builtin_popcount(d));
    }

    int_value = a + b;
    if (is_init == 0) { printf("%d ", __builtin_popcount(int_value)); }
    int_value ^= c;
    if (is_init == 0) { printf("%d ", __builtin_popcount(int_value)); }
    int_value += d;
    if (is_init == 0) { printf("%d ", __builtin_popcount(int_value)); }

	return int_value;
}

void 
_encrypt(uint32_t *left, uint32_t *right, uint8_t is_init)
{
	uint32_t i, t;
	for (i = 0; i < 16; i++) {
		*left ^= pbox[i];
        if (is_init == 0) { printf("%d ", __builtin_popcount(*left)); }
		*right ^= feistel_function(*left, is_init);
        if (is_init == 0) { printf("%d ", __builtin_popcount(*right)); }

        // only try to get the first roundkey for now
        // if (is_init == 0) { return; }
		
		SWAP(*left, *right, t);
	}

    // we will ignore the last two round keys for now
    // if (is_init == 0) { return; }

	SWAP(*left, *right, t);
	*right ^= pbox[16];
    if (is_init == 0) { printf("%d ", __builtin_popcount(*right)); }

	*left ^= pbox[17];
    if (is_init == 0) { printf("%d\n", __builtin_popcount(*left)); }
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
		_encrypt(&left, &right, 1);
		pbox[i]     = left;
		pbox[i + 1] = right;
	}

	for (i = 0; i <= 3; i++) {
		for (j = 0; j <= 254; j += 2) {
			_encrypt(&left, &right, 1);
			sbox[i][j]     = left;
			sbox[i][j + 1] = right;
		}
	}
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

    _encrypt(&left, &right, 0);

    /* merge encrypted halves into a single 8 byte chunk again */
    chunk = 0x0000000000000000;
    chunk |= left; chunk <<= 32;
    chunk |= right;
    // printf("%016llX\t<- chunk\n", chunk);

    memcpy(ct, &chunk, sizeof(chunk));
}

void
model(uint8_t data[])
{
	uint32_t left, right;
	uint64_t chunk;
    uint32_t left_k;    // left half after XOR with round key (our key hypothesis)

    /* make 8 byte chunks */
    chunk = 0x0000000000000000;
    memmove(&chunk, data, sizeof(chunk));

    /* split into two 4 byte chunks */
    left = right = 0x00000000;
    left   = (uint32_t)(chunk >> 32);
    right  = (uint32_t)(chunk);

    // check the round key
    // printf("%X\n", pbox[1]);

    uint8_t shift_amount = 0;
	uint32_t i, t;

    // try each byte of the 32-bit round key
    for (uint8_t k = 0; k < 4; k++) {
        switch (k) {
            case 0: shift_amount = 24; break;
            case 1: shift_amount = 16; break;
            case 2: shift_amount = 8; break;
            case 3: shift_amount = 0; break;
        }

        // guess each possible value of each key byte
        for (uint32_t j = 0; j < 256; j++) {
            uint32_t int_value = 0;

            int_value = sbox[k][(uint8_t)((left >> shift_amount) ^ j)];
            printf("%d ", __builtin_popcount(int_value));

        }
        printf("\n");
    }
    return;

	SWAP(left, right, t);
	right  ^= pbox[16];
    printf("%d\n", __builtin_popcount(right));

	left ^= pbox[17];
    printf("%d\n", __builtin_popcount(left));
    return;
}


void
model_cpa(uint8_t data[])
{
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

    // printf("%X\n", pbox[0]);
    // printf("%d\n", (uint8_t)(pbox[16] >> 16));

    uint32_t int_value = 0;
    for (i = 0; i < 16; i++) {
        // stop to get the key of round i + 1
        // if (i == 0) { break; }

        left ^= pbox[i];
        right ^= feistel_function(left, 1);

        SWAP(left, right, t);
    }
    SWAP(left, right, t);

    for (uint32_t j = 0; j < 256; j++) {
        // intermediate value during the 16 rounds
        // int_value = sbox[0][((uint8_t)(left >> 24)) ^ j];

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
reverse_sbox(uint8_t data[])
{
	uint32_t left, right;
	uint64_t chunk;
	uint32_t i, t;

    chunk = 0x0000000000000000;
    memmove(&chunk, data, sizeof(chunk));

    left  = 0x00000000;
    right = 0x00000000;
    left  = (uint32_t)(chunk >> 32);
    right = (uint32_t)(chunk);

    // uint32_t temp = 0;
    // left ^= pbox[0];
    // temp = feistel_function(left, 1);
    // printf("%X\n", temp);

    // TODO use 3 different constant left halves
    // -> we get 3 different results for f()
    // create a linear equation system and find values for d
    // G + d = y

    uint8_t int_value = 0;
    right ^= (uint32_t)(0x7D10F1 << 8);
    for (i = 0; i < 256; i++) {

        // int_value = (uint8_t)(right >> 24) ^ i;

        // right ^= (uint32_t)(0x7D << 24);
        // int_value = (uint8_t)(right >> 16) ^ i;

        int_value = (uint8_t)(right >> 8) ^ i;

        // right ^= (uint32_t)(0x7D10F1 << 8);
        // int_value = (uint8_t)(right) ^ i;
        printf("%d ", __builtin_popcount(int_value));
    }
}
