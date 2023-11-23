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
    if (argc == 1) {
        printf("ERROR: requires at least on argument\n");
        return 0 ;
    }

    // convert the input to an int and cast to to a char
    // uint8_t p = (char) atoi(argv[1]);
    // printf("%x\n", p);

	int i, Osize, Psize, Pbyte;
	int KOsize, KPsize, KPbyte;
	uint8_t *encrypted,
	        key[KEYSIZE],
	        data[DATASIZE];

	/* no string NULL termination bugs now :) */
	memset(data, 0, DATASIZE);
	memset(key,  0, KEYSIZE);

	strncpy(data, argv[1], sizeof(data));
	strncpy(key, KEY, sizeof(key));

	Osize = strlen(data);            KOsize = strlen(key);
	Psize = ceil(Osize / 8.0) * 8;   KPsize = ceil(KOsize / 8.0) * 8;
	Pbyte = Psize - Osize;           KPbyte = KPsize - KOsize;

	/* padding bytes added to the data and key */
	memset(data + Osize, Pbyte, sizeof *data * Pbyte);
	memset(key + KOsize, KPbyte, sizeof *key * KPbyte);
    // printf("%02X%02X%02X%02X%02X%02X%02X%02X\n",
    //         data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);

	blowfish_init(key, KPsize);

    uint8_t ct[8];
    blowfish_encrypt(data, ct);

    // printf("%02X%02X%02X%02X%02X%02X%02X%02X\n",
    //         ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7]);

	return 0;
}
