#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "blowfish.h"
#include "constants.h"

uint32_t 
feistel_function(uint32_t arg, uint8_t round, uint8_t is_init)
{
    // only get the intermediate value during the first round and
    // only when we are actually encrypting the plain text
    if (round == 0 && is_init == 0) {
        // printf("\nRound %d\n", round + 1);
        uint32_t a = 0, b = 0, c = 0, d = 0;

        a = sbox[0][(uint8_t) (arg >> 24)];
        // printf("intermediate value\t%02X\n", a);
        // printf("HW\t%d\n", __builtin_popcount(a));
        printf("%d ", __builtin_popcount(a));

        b = sbox[1][(uint8_t)(arg >> 16)];
        // printf("intermediate value\t%02X\n", b);
        printf("%d ", __builtin_popcount(b));

        c = sbox[2][(uint8_t)(arg >> 8)];
        // printf("intermediate value\t%02X\n", c);
        printf("%d ", __builtin_popcount(c));

        d = sbox[3][(uint8_t)(arg)];
        // printf("intermediate value\t%02X\n", d);
        printf("%d", __builtin_popcount(d));
        printf("\n");

        // printf("arg\t%X\n", arg);

        // for (int i = 0; i<256; i++) {
        //     if (sbox[0][i] == a) {
        //         printf("Index\t%X\n", i);
        //         break;
        //     }
        // }
        // for (int i = 0; i<256; i++) {
        //     if (sbox[1][i] == b) {
        //         printf("Index\t%X\n", i);
        //         break;
        //     }
        // }
        // for (int i = 0; i<256; i++) {
        //     if (sbox[2][i] == c) {
        //         printf("Index\t%X\n", i);
        //         break;
        //     }
        // }
        // for (int i = 0; i<256; i++) {
        //     if (sbox[3][i] == d) {
        //         printf("Index\t%X\n", i);
        //         break;
        //     }
        // }
    }

    // Original code
	uint32_t var = sbox[0][arg >> 24] + sbox[1][(uint8_t)(arg >> 16)];
	return (var ^ sbox[2][(uint8_t)(arg >> 8)]) + sbox[3][(uint8_t)(arg)];
}

void 
_encrypt(uint32_t *left, uint32_t *right, uint8_t is_init)
{
	uint32_t i, t;
	for (i = 0; i < 16; i++) {
        // if (is_init == 0) {
        //     printf("left plaintext\t%X\n", *left);
        //     printf("round key\t%X\n", pbox[i]);
        //     printf("arg\t%X\n", pbox[i] ^ *left);
        //     printf("check\t%X\n", 0x4D9B90CC ^ *left);
        // }
		*left  ^= pbox[i];
		*right ^= feistel_function(*left, i, is_init);
		
		SWAP(*left, *right, t);
        // stop after the first round of encryption to save some time
        if (is_init == 0 && i == 0) { return; }
	}

	SWAP(*left, *right, t);
	*right  ^= pbox[16];
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
	uint8_t byte;
	uint32_t i, j, index = 0;
	uint32_t left, right, factor;
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
