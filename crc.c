/* -*- Mode: C -*- */

/*-
 * Copyright (c) 2020 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * zlib CRC32 checksum -- input bytes and output CRC both have lsb as
 * highest-degree coefficient, initial and final values are both
 * complemented, and the generator polynomial is:
 *
 * G := x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11
 *	+ x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1.
 *
 *	P. Deutsch, `GZIP file format specification version 4.3',
 *	RFC 1952, May 1996.
 *	https://tools.ietf.org/html/rfc1952.html
 */

#include "crc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static uint32_t crc32_tab[256];

static uint32_t
crc32_8(uint8_t b, uint32_t crc)
{
	unsigned i;

	crc ^= b;
	for (i = 8; i --> 0;)
		crc = (crc >> 1) ^ (UINT32_C(0xEDB88320) & -(crc & 1));
	return crc;
}

uint32_t
crc32(const void *buf, size_t len, uint32_t crc)
{
	static bool init = false;
	const uint8_t *p = buf;
	size_t n = len;

	if (!init) {
		unsigned i;

		for (i = 0; i < 256; i++)
			crc32_tab[i] = crc32_8(i, 0);
		init = true;
	}

	crc = ~crc;
	while (n --> 0)
		crc = (crc >> 8) ^ crc32_tab[(crc & 0xff) ^ *p++];
	return ~crc;
}
