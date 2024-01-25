#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "blowfish.h"

/* MUST NOT BE ALTERED */
#define KEYSIZE   56
#define DATASIZE  1024

/* change these to change the ciphertext and the secret key */
// #define PLAINTEXT "123"
#define KEY       "AAAAAAAA"

int main(int argc, char *argv[])
{
    if (argc != 9) {
        printf("Invalid number of args\n");
        return 0;
    }

	int Osize, Psize, Pbyte;
	int KOsize, KPsize, KPbyte;
	uint8_t key[KEYSIZE],
	        data[DATASIZE];
    uint8_t ct[8];

	/* no string NULL termination bugs now :) */
	memset(data, 0, DATASIZE);
	memset(key,  0, KEYSIZE);

    // the plaintext is input as 8 decimal strings now
    uint8_t temp;
    for (int i = 0; i < 7; i++) {
        temp = (uint8_t) strtol(argv[i + 1], NULL, 10);
        data[i] = temp;
    }

	// strncpy(data, argv[2], sizeof(data));
	strncpy(key, KEY, sizeof(key));

	Osize = strlen(data);            KOsize = strlen(key);
	Psize = ceil(Osize / 8.0) * 8;   KPsize = ceil(KOsize / 8.0) * 8;
	Pbyte = Psize - Osize;           KPbyte = KPsize - KOsize;

	/* padding bytes added to the data and key */
	memset(data + Osize, Pbyte, sizeof *data * Pbyte);
	memset(key + KOsize, KPbyte, sizeof *key * KPbyte);

	blowfish_init(key, KPsize);
    blowfish_encrypt(data, ct);

    printf("%02X%02X%02X%02X%02X%02X%02X%02X\n",
            ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7]);
	return 0;
}
