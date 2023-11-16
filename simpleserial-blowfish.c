/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hal.h"
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#include "blowfish.c"

#include "simpleserial.h"

#define KEYSIZE   56
#define DATASIZE  1024
#define KEY       "A"

uint8_t get_key(uint8_t* k, uint8_t len)
{
	// Load key here
	return 0x00;
}

uint8_t get_pt(uint8_t *pt, uint8_t len)
{
	int i, Osize, Psize, Pbyte;
	int KOsize, KPsize, KPbyte;
	uint8_t key[KEYSIZE],
	        data[DATASIZE];
    uint8_t ct[8];

	/* no string NULL termination bugs now :) */
	memset(data, 0, DATASIZE);
	memset(key,  0, KEYSIZE);

	strncpy(data, pt, sizeof(data));
	strncpy(key, KEY, sizeof(key));

	Osize = strlen(data);            KOsize = strlen(key);
	Psize = ceil(Osize / 8.0) * 8;   KPsize = ceil(KOsize / 8.0) * 8;
	Pbyte = Psize - Osize;           KPbyte = KPsize - KOsize;
	
	/* padding bytes added to the data and key */
	memset(data + Osize, Pbyte, sizeof *data * Pbyte);
	memset(key + KOsize, KPbyte, sizeof *key * KPbyte);

	blowfish_init(key, KPsize);
	
    // Start our measurement here
    trigger_high();
    blowfish_encrypt(data, ct);

	trigger_low();
	simpleserial_put('r', 8, ct);
    return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
	// Reset key here if needed
	return 0x00;
}

void no_op(uint8_t* x, uint8_t len)
{
}

int main(void)
{
    platform_init();
	init_uart();
	trigger_setup();

 	/* Uncomment this to get a HELLO message for debug */
	/*
	putch('h');
	putch('e');
	putch('l');
	putch('l');
	putch('o');
	putch('\n');
	*/

	simpleserial_init();
	simpleserial_addcmd('p', 8, get_pt);
	simpleserial_addcmd('k', 16, get_key);
	simpleserial_addcmd('x', 0, reset);
	while(1)
		simpleserial_get();
}

