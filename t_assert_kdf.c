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

#define	_POSIX_C_SOURCE	200809L

#include <err.h>
#include <stdint.h>
#include <stdio.h>

#include <fido.h>

#include "kdf.h"
#include "assert_kdf.h"

static const char rp_id[] = "example.com";

static const unsigned char pkconf[FIDOCRYPT_KDF_CONFBYTES] = {
	0x74,0xcd,0xb2,0xa7, 0xc4,0x6b,0x97,0x3d,
	0x4a,0x43,0x14,0x4f, 0x5e,0x91,0x74,0xb8,
	0xcb,0xb7,0x0e,0x9f, 0x30,0x9a,0xa5,0x85,
	0x2e,0xea,0x7c,0x5f, 0xaa,0x69,0x8e,0xb3,
};

/*
 * {"type": "webauthn.get",
 *  "origin": "test-fidocrypt://example.com",
 *  "challenge": "cO4SMakXlpX2FTE15FcFzfztc6lkKHcjxt_Mx1CiG2A",
 *  "clientExtensions": {}}
 */
static const unsigned char clientdata_hash[32] = {
	0xa1,0xe1,0x18,0x52,0xd7,0x6c,0xc5,0xc2,
	0xc1,0x27,0x72,0x28,0x06,0x47,0x0f,0x5a,
	0xcd,0x79,0xed,0x75,0x94,0x10,0xff,0xd1,
	0x0a,0x3a,0x69,0x9e,0xe5,0x29,0x4e,0x41,
};

static const unsigned char authdata[] = {
	0xa3,0x79,0xa6,0xf6, 0xee,0xaf,0xb9,0xa5,
	0x5e,0x37,0x8c,0x11, 0x80,0x34,0xe2,0x75,
	0x1e,0x68,0x2f,0xab, 0x9f,0x2d,0x30,0xab,
	0x13,0xd2,0x12,0x55, 0x86,0xce,0x19,0x47,
	0x01,0x00,0x00,0x00, 0x14,
};

static const unsigned char sig[] = {
	0x30,0x45,0x02,0x20, 0x41,0xe7,0x0e,0xd0,
	0x57,0x0d,0xa0,0x00, 0x4b,0x19,0xda,0x9e,
	0x85,0x73,0x9c,0x75, 0xa2,0x98,0x50,0x59,
	0x74,0x81,0x3f,0x7a, 0x80,0xbb,0xbd,0x98,
	0x2c,0x26,0xea,0xe4, 0x02,0x21,0x00,0x94,
	0x5f,0xc3,0xc6,0x55, 0x31,0x7f,0x9d,0x91,
	0xe3,0x25,0x82,0x51, 0xb7,0x0d,0xf0,0xe6,
	0x01,0xcb,0x65,0x82, 0x5e,0x15,0x4c,0x48,
	0x71,0x80,0xdf,0x2a, 0x2b,0xfd,0x18,
};

int
main(void)
{
	fido_assert_t *assert;
	uint8_t key[FIDOCRYPT_KDF_KEYBYTES];
	unsigned i;
	int error;

	/* Initialize libfido2.  */
	fido_init(0);

	/* Create the assertion and set its parameters.  */
	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");
	if ((error = fido_assert_set_rp(assert, rp_id)) != FIDO_OK)
		errx(1, "fido_assert_set_rp: %s", fido_strerr(error));
	if ((error = fido_assert_set_clientdata_hash(assert,
		    clientdata_hash, sizeof(clientdata_hash))) != FIDO_OK)
		errx(1, "fido_assert_set_clientdata_hash: %s",
		    fido_strerr(error));

	/* Fill in the assertion response.  */
	if ((error = fido_assert_set_count(assert, 1)) != FIDO_OK)
		errx(1, "fido_assert_set_count: %s", fido_strerr(error));
	if ((error = fido_assert_set_authdata_raw(assert, 0, authdata,
		    sizeof(authdata))) != FIDO_OK)
		errx(1, "fido_assert_set_authdata_raw: %s",
		    fido_strerr(error));
	if ((error = fido_assert_set_sig(assert, 0, sig, sizeof(sig)))
	    != FIDO_OK)
		errx(1, "fido_assert_set_sig: %s", fido_strerr(error));

	/* Derive a key from the assertion.  */
	if ((error = fido_assert_kdf(assert, 0, COSE_ES256, pkconf, key))
	    != FIDO_OK)
		errx(1, "fido_assert_kdf: %s", fido_strerr(error));

	/* Print the key in hex.  */
	for (i = 0; i < FIDOCRYPT_KDF_KEYBYTES; i++)
		printf("%02hhx", key[i]);
	printf("\n");

	fflush(stdout);
	return ferror(stdout);
}
