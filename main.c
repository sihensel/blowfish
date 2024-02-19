#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "blowfish.h"

/* MUST NOT BE ALTERED */
#define KEYSIZE   56
#define DATASIZE  1024

/* change these to change the ciphertext and the secret key */
#define KEY       "AAAAAAAA"

/* usage (see args below):
    ./blowfish <arg> <plaintext>
    ./blowfish xor 10 11 12 13 14 15 16 17
*/

int main(int argc, char *argv[])
{
    if (argc != 10) {
        printf("Invalid number of args\n");
        return 0;
    }

    int Osize, Psize, Pbyte;
    int KOsize, KPsize, KPbyte;
    uint8_t key[KEYSIZE],
            data[DATASIZE];

    /* no string NULL termination bugs now :) */
    memset(data, 0, DATASIZE);
    memset(key,  0, KEYSIZE);

    // the plaintext is input as 8 decimal strings now
    uint8_t a;
    for (int i = 0; i < 8; i++) {
        a = (uint8_t) strtol(argv[i + 2], NULL, 10);
        data[i] = a;
    }

    // strncpy(data, argv[2], sizeof(data));
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

    if (strcmp(argv[1], "encrypt") == 0) {
        // perform a regular blowfish encryption
        blowfish_encrypt(data, ct);
    }
    else if (strcmp(argv[1], "sbox") == 0) {
        attack_sbox(data);
    }
    else if (strcmp(argv[1], "xor") == 0) {
        attack_xor(data);
    }
    else if (strcmp(argv[1], "feistel") == 0) {
        attack_feistel(data);
    }
    else if (strcmp(argv[1], "print_feistel") == 0) {
        print_feistel(data);
    }

    // printf("%02X%02X%02X%02X%02X%02X%02X%02X\n",
    //         ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7]);
    return 0;
}
