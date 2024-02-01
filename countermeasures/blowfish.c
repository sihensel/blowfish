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
     
    /* dummy instructions
    int r = rand() % 30;
    for (int i = 0; i < r; i++) {
        int j = rand() % 2;
        int v = rand() % 4;
        if (i % 2 == 0) {
            // gerade
            if (j == 1) {
                switch(v) {
                        case 0: a = a + 0; break;
                        case 1: b = b + 0; break;
                        case 2: c = c + 0; break;
                        case 3: d = d + 0; break;
                }
            }
            else {
                switch(v) {
                        case 0: a = a / 1; break;
                        case 1: b = b / 1; break;
                        case 2: c = c / 1; break;
                        case 3: d = d / 1; break;
                }
            }
        }
        else {
            // ungerade
            if (j == 1) {
                switch(v) {
                        case 0: a = a * 1; break;
                        case 1: b = b * 1; break;
                        case 2: c = c * 1; break;
                        case 3: d = d * 1; break;
                }
            }
            else {
                switch(v) {
                        case 0: a = a - 0; break;
                        case 1: b = b - 0; break;
                        case 2: c = c - 0; break;
                        case 3: d = d - 0; break;
                }
            }
        }
    }
     */

    int_value = a + b;
    int_value ^= c;
    int_value += d;
	return int_value;

	/* dummy instuctions
	for (int i = 0; i < 3; i++) {
        int_value = int_value + 0;
        int_value = int_value - 0;
    }
    */
}

void 
_encrypt(uint32_t *left, uint32_t *right)
{
	uint32_t i, t;
	for (i = 0; i < 16; i++) {
		*left ^= pbox[i];
		*right ^= feistel_function(*left);

    /* Dummy XOR Operation
        *left ^= *left;
        *right ^= *right;
        *left ^= 0x00000000;
    */
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

    /* Hier könnte man random Instructions einbauen (vor oder nach der Subkey generation)*/

	/* subkey generation */
	for (i = 0; i < 18; i++) {
		pbox[i] ^= ((uint32_t)key[(i + 0) % keysize] << 24) | 
		           ((uint32_t)key[(i + 1) % keysize] << 16) | 
		           ((uint32_t)key[(i + 2) % keysize] <<  8) | 
		           ((uint32_t)key[(i + 3) % keysize]);
	}

	/*  Dummy-Berechnung
    uint32_t dummy_left = 0x00000000, dummy_right = 0x00000000;
    for (i = 0; i < 40; i++) {
        dummy_left ^= i;
        dummy_right ^= i + 1;
        _encrypt(&dummy_left, &dummy_right);
	*/


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

    memcpy(ct, &chunk, sizeof(chunk));
}
