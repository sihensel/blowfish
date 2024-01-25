#ifndef __BLOWFISH__
#define __BLOWFISH__

/* integer overflow isn't an issue here :) */
#define SWAP(x, y, temp) {temp = (x); (x) = (y); (y) = temp;}

typedef unsigned char          uint8_t;
typedef unsigned int           uint32_t;
typedef unsigned long long int uint64_t;

uint32_t 
feistel_function(uint32_t arg);

void 
_encrypt(uint32_t *left, uint32_t *right);

void
blowfish_init(uint8_t key[], int padsize);

void
blowfish_encrypt(uint8_t data[], uint8_t ct[]);

#endif
