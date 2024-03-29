/* -*- Mode: C -*- */

/*-
 * Copyright (c) 2020-2022 Taylor R. Campbell
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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <fido.h>

#include "cred_kdf.h"

static const char rp_id[] = "example.com";
static const char rp_name[] = "Example LLC";

static const char user_id[] = "falken";
static const char user_name[] = "Falken";

static const unsigned char clientdata_hash[32] = {
	0xe8,0xbd,0xf0,0xfa, 0x42,0x75,0x53,0x43,
	0xe5,0x8e,0x62,0x65, 0x37,0x61,0x43,0x31,
	0x28,0x83,0x7f,0xc0, 0x07,0x94,0x0a,0xc8,
	0x5b,0xee,0x22,0xcc, 0x6a,0xdb,0x1c,0xe1,
};

static const unsigned char authdata[] = {
	0xa3,0x79,0xa6,0xf6, 0xee,0xaf,0xb9,0xa5,
	0x5e,0x37,0x8c,0x11, 0x80,0x34,0xe2,0x75,
	0x1e,0x68,0x2f,0xab, 0x9f,0x2d,0x30,0xab,
	0x13,0xd2,0x12,0x55, 0x86,0xce,0x19,0x47,
	0x41,0x00,0x00,0x00, 0x01,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x00,0x40,0xbf,
	0x74,0x40,0xcc,0xdc, 0xd0,0x38,0x98,0x11,
	0xfb,0x33,0xf2,0xdc, 0xc9,0x00,0x4e,0x16,
	0xbf,0xa3,0xbb,0x4d, 0xd9,0xd9,0x89,0x20,
	0x1f,0xd7,0xa0,0x9b, 0xec,0x95,0x1e,0xf4,
	0x3c,0x46,0xe0,0xd3, 0xb0,0xc9,0xb8,0xea,
	0x36,0x9d,0x16,0xf6, 0xe0,0xa5,0xa9,0x03,
	0x09,0x4c,0x9e,0x27, 0xa4,0x67,0x86,0xdd,
	0xac,0xf5,0x50,0xf5, 0x6c,0x78,0xa8,0xa5,
	0x01,0x02,0x03,0x26, 0x20,0x01,0x21,0x58,
	0x20,0x56,0x8e,0xa3, 0xdc,0x2c,0x35,0x12,
	0x16,0xf7,0x54,0x77, 0xa2,0xbb,0x3b,0x54,
	0xdd,0x9f,0xfa,0x61, 0xac,0x95,0xfc,0xde,
	0x12,0x4c,0x8c,0x94, 0x02,0x12,0x9c,0x33,
	0x7f,0x22,0x58,0x20, 0x47,0x2b,0x5c,0x13,
	0x41,0x3a,0x5b,0x28, 0x91,0x87,0x21,0xfc,
	0xd1,0x1e,0x3c,0xfb, 0x1f,0xb7,0x8b,0x33,
	0x71,0x7e,0xc7,0xbd, 0x2a,0x5c,0x9a,0xd1,
	0xd6,0x00,0xa5,0x36
};

int
main(void)
{
	fido_cred_t *cred;
	uint8_t pkconf[FIDOCRYPT_KDF_CONFBYTES];
	uint8_t key[FIDOCRYPT_KDF_KEYBYTES];
	unsigned i;
	int error;

	/* Initialize libfido2.  */
	fido_init(0);

	/* Create the credential and set its parameters.  */
	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");
	if ((error = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK)
		errx(1, "fido_cred_set_type: %s", fido_strerr(error));
	if ((error = fido_cred_set_rp(cred, rp_id, rp_name)) != FIDO_OK)
		errx(1, "fido_cred_set_rp: %s", fido_strerr(error));
	if ((error = fido_cred_set_user(cred,
		    (const void *)user_id, strlen(user_id),
		    user_name, /*displayname*/NULL, /*icon*/NULL)) != FIDO_OK)
		errx(1, "fido_cred_set_user: %s", fido_strerr(error));
	if ((error = fido_cred_set_clientdata_hash(cred,
		    clientdata_hash, sizeof(clientdata_hash))) != FIDO_OK)
		errx(1, "fido_cred_set_clientdata_hash: %s",
		    fido_strerr(error));

	/*
	 * Fill in the credential response -- just the auth data; we're
	 * really only interested in the public key, not in the device
	 * attestation.
	 */
	if ((error = fido_cred_set_authdata_raw(cred, authdata,
		    sizeof(authdata))) != FIDO_OK)
		errx(1, "fido_cred_set_authdata_raw: %s", fido_strerr(error));

	/* Derive a key from the credential.  */
	if ((error = fido_cred_kdf(cred, COSE_ES256, pkconf, key))
	    != FIDO_OK)
		errx(1, "fido_cred_kdf: %s", fido_strerr(error));

	/* Print the public key confirmation hash in hex.  */
	printf("pkconf: ");
	for (i = 0; i < FIDOCRYPT_KDF_CONFBYTES; i++)
		printf("%02hhx", pkconf[i]);
	printf("\n");

	/* Print the key in hex.  */
	printf("key: ");
	for (i = 0; i < FIDOCRYPT_KDF_KEYBYTES; i++)
		printf("%02hhx", key[i]);
	printf("\n");

	fflush(stdout);
	return ferror(stdout);
}
