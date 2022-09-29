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

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <fido.h>

#include "fidocrypt.h"
#include "assert_decrypt.h"

#ifndef HAVE_FIDO_ASSERT_SET_HMAC_SECRET /* XXX not until libfido2 >1.6.0 */
/* XXX BEGIN HORRIBLE KLUDGE */

/*
 * This is copypasta (lightly tossed and oiled) from fido/types.h,
 * normally available only inside libfido2 and not part of the ABI.
 * These types haven't changed from libfido2 1.4.0 to 1.6.0, so for now
 * this will do.
 *
 * We bring it in here only so that we can set the hmac-secret of an
 * assertion statement without mocking up the entire interaction.
 */

typedef struct fido_blob {
	unsigned char	*ptr;
	size_t		 len;
} fido_blob_t;

typedef struct fido_blob_array {
	fido_blob_t	*ptr;
	size_t		 len;
} fido_blob_array_t;

typedef struct fido_authdata {
	unsigned char rp_id_hash[32]; /* sha256 of fido_rp.id */
	uint8_t       flags;          /* user present/verified */
	uint32_t      sigcount;       /* signature counter */
	/* actually longer */
} __attribute__((packed)) fido_authdata_t;

typedef struct fido_user {
	fido_blob_t  id;           /* required */
	char        *icon;         /* optional */
	char        *name;         /* optional */
	char        *display_name; /* required */
} fido_user_t;

typedef struct _fido_assert_stmt {
	fido_blob_t     id;              /* credential id */
	fido_user_t     user;            /* user attributes */
	fido_blob_t     hmac_secret_enc; /* hmac secret, encrypted */
	fido_blob_t     hmac_secret;     /* hmac secret */
	int             authdata_ext;    /* decoded extensions */
	fido_blob_t     authdata_cbor;   /* raw cbor payload */
	fido_authdata_t authdata;        /* decoded authdata payload */
	fido_blob_t     sig;             /* signature of cdh + authdata */
} fido_assert_stmt;

typedef struct fido_assert {
	char              *rp_id;        /* relying party id */
	fido_blob_t        cdh;          /* client data hash */
	fido_blob_t        hmac_salt;    /* optional hmac-secret salt */
	fido_blob_array_t  allow_list;   /* list of allowed credentials */
	fido_opt_t         up;           /* user presence */
	fido_opt_t         uv;           /* user verification */
	int                ext;          /* enabled extensions */
	fido_assert_stmt  *stmt;         /* array of expected assertions */
	size_t             stmt_cnt;     /* number of allocated assertions */
	size_t             stmt_len;     /* number of received assertions */
} fido_assert_t;

static int
fido_assert_set_hmac_secret(fido_assert_t *assert, size_t idx,
    const unsigned char *ptr, size_t len)
{

	if (idx >= assert->stmt_len)
		return FIDO_ERR_INVALID_ARGUMENT;
	if (len != 32 && len != 64)
		return FIDO_ERR_INVALID_ARGUMENT;

	free(assert->stmt[idx].hmac_secret.ptr);
	if ((assert->stmt[idx].hmac_secret.ptr = malloc(len)) == NULL)
		return FIDO_ERR_INTERNAL;
	memcpy(assert->stmt[idx].hmac_secret.ptr, ptr, len);
	assert->stmt[idx].hmac_secret.len = len;

	return FIDO_OK;
}

/* XXX END HORRIBLE KLUDGE */
#endif

static const char rp_id[] = "example.com";

static const struct {
	size_t nciphertext;
	const unsigned char *ciphertext;
	unsigned char clientdata_hash[32];
	size_t nauthdata;
	const unsigned char *authdata;
	size_t nsig;
	const unsigned char *sig;
	const unsigned char *hmacsecret;
} C[] = {
	[0] = {			/* no hmac-secret */
		.nciphertext = 71,
		.ciphertext = (const unsigned char[71]) {
			0xa3,0x01,0x02,0x03, 0x26,0x20,0x01,
			0x77,0xd3,0x66,0xf7, 0xdd,0x59,0x98,0x45,
			0x58,0x1b,0x5f,0x81, 0x19,0x72,0x75,0x34,
			0x57,0xb9,0x30,0x36, 0x59,0xf2,0x94,0xbe,
			0xb6,0x29,0x62,0xc1, 0x4d,0x50,0x47,0x56,
			0x09,0xaa,0xb7,0xfa, 0xd2,0x0f,0xb3,0x36,
			0x83,0x7f,0xe7,0xa7, 0x18,0x3c,0x21,0x56,
			0xdc,0x94,0xed,0xcb, 0x92,0x8f,0x83,0x59,
			0x54,0x58,0x51,0x1f, 0x81,0xa6,0xe5,0x0b,
		},
		/*
		 * {"type": "webauthn.get",
		 *  "origin": "test-fidocrypt://example.com",
		 *  "challenge": "cO4SMakXlpX2FTE15FcFzfztc6lkKHcjxt_Mx1CiG2A",
		 *  "clientExtensions": {}}
		 */
		.clientdata_hash = {
			0xa1,0xe1,0x18,0x52, 0xd7,0x6c,0xc5,0xc2,
			0xc1,0x27,0x72,0x28, 0x06,0x47,0x0f,0x5a,
			0xcd,0x79,0xed,0x75, 0x94,0x10,0xff,0xd1,
			0x0a,0x3a,0x69,0x9e, 0xe5,0x29,0x4e,0x41,
		},
		.nauthdata = 37,
		.authdata = (const unsigned char[37]) {
			0xa3,0x79,0xa6,0xf6, 0xee,0xaf,0xb9,0xa5,
			0x5e,0x37,0x8c,0x11, 0x80,0x34,0xe2,0x75,
			0x1e,0x68,0x2f,0xab, 0x9f,0x2d,0x30,0xab,
			0x13,0xd2,0x12,0x55, 0x86,0xce,0x19,0x47,
			0x01,0x00,0x00,0x00, 0x14,
		},
		.nsig = 71,
		.sig = (const unsigned char[71]) {
			0x30,0x45,0x02,0x20, 0x41,0xe7,0x0e,0xd0,
			0x57,0x0d,0xa0,0x00, 0x4b,0x19,0xda,0x9e,
			0x85,0x73,0x9c,0x75, 0xa2,0x98,0x50,0x59,
			0x74,0x81,0x3f,0x7a, 0x80,0xbb,0xbd,0x98,
			0x2c,0x26,0xea,0xe4, 0x02,0x21,0x00,0x94,
			0x5f,0xc3,0xc6,0x55, 0x31,0x7f,0x9d,0x91,
			0xe3,0x25,0x82,0x51, 0xb7,0x0d,0xf0,0xe6,
			0x01,0xcb,0x65,0x82, 0x5e,0x15,0x4c,0x48,
			0x71,0x80,0xdf,0x2a, 0x2b,0xfd,0x18,
		},
		.hmacsecret = NULL,
	},
	[1] = {			/* with hmac-secret */
		.nciphertext = 71,
		.ciphertext = (const unsigned char[71]) {
			0xa3,0x01,0x02,0x03, 0x26,0x20,0x01,0xb3,
			0xd6,0x53,0x37,0x0a, 0xc8,0xfa,0x68,0x9d,
			0xe6,0x00,0x38,0x05, 0x8a,0x8f,0xc3,0xfb,
			0x15,0xb4,0xb7,0xb8, 0xf4,0xbc,0x01,0x26,
			0xdb,0x01,0xb7,0x27, 0x2b,0x3d,0x50,0xa8,
			0x06,0x57,0x5c,0x2e, 0xd0,0x6a,0xd8,0xa3,
			0x26,0xc5,0xef,0xd8, 0x90,0x4f,0x6c,0x41,
			0xee,0x70,0xdf,0xdc, 0x74,0x68,0x60,0x67,
			0x68,0xf3,0xb4,0x90, 0xe6,0x0d,0x61,
		},
		.clientdata_hash = {
			0xa2,0x4b,0x5b,0xb3, 0x32,0x6a,0x86,0xa5,
			0x9d,0x06,0x89,0x9d, 0x9f,0xa3,0x99,0x94,
			0x4d,0x86,0xba,0x4f, 0xdb,0xa3,0x47,0x6f,
			0xc0,0xc6,0x28,0x36, 0x28,0xd0,0x79,0x96,
		},
		.nauthdata = 84,
		.authdata = (const unsigned char[84]) {
			0xa3,0x79,0xa6,0xf6, 0xee,0xaf,0xb9,0xa5,
			0x5e,0x37,0x8c,0x11, 0x80,0x34,0xe2,0x75,
			0x1e,0x68,0x2f,0xab, 0x9f,0x2d,0x30,0xab,
			0x13,0xd2,0x12,0x55, 0x86,0xce,0x19,0x47,
			0x81,0x00,0x00,0x0d, 0x42,0xa1,0x6b,0x68,
			0x6d,0x61,0x63,0x2d, 0x73,0x65,0x63,0x72,
			0x65,0x74,0x58,0x20, 0x8b,0xa9,0x6c,0xe6,
			0x89,0xa7,0x54,0x24, 0x81,0x2f,0x1f,0x51,
			0x28,0x98,0xea,0xba, 0xcb,0xfc,0xed,0x35,
			0xac,0x91,0x89,0x9f, 0xbc,0xef,0x7b,0x7c,
			0x4d,0x75,0xf5,0x13,
		},
		.nsig = 71,
		.sig = (const unsigned char[71]) {
			0x30,0x45,0x02,0x20, 0x20,0xe9,0xba,0x07,
			0x1b,0xd3,0xe5,0xf2, 0x16,0x7a,0x19,0x93,
			0xfb,0xe8,0xf8,0x6b, 0xe1,0xfb,0x45,0x47,
			0xa9,0x79,0xd5,0xd5, 0xb3,0x44,0x6d,0x35,
			0xb6,0x0f,0x4e,0xed, 0x02,0x21,0x00,0xa7,
			0xd8,0x32,0x1b,0xcd, 0xbe,0x71,0x3f,0x75,
			0xc8,0x38,0xa2,0x0f, 0xbf,0x75,0xdf,0x26,
			0x64,0x78,0x09,0xbf, 0xed,0xc7,0x83,0xa8,
			0x4e,0x07,0x62,0x27, 0x77,0x5e,0x04,
		},
		.hmacsecret = (const unsigned char[32]) {
			0x71,0xfc,0x1d,0xf4, 0xd4,0x9b,0x2d,0x4e,
			0x52,0x21,0x43,0xfe, 0xc6,0x17,0x36,0xe5,
			0x42,0x18,0x90,0x6e, 0x29,0x7c,0xdc,0x69,
			0xa9,0x87,0x35,0xc8, 0x83,0xf8,0x04,0x37,
		},
	},
};

int
main(void)
{
	fido_assert_t *assert = NULL;
	unsigned char *secret = NULL;
	size_t nsecret = 0;
	unsigned i, j;
	int error;

	/* Initialize libfido2.  */
	fido_init(0);

	for (i = 0; i < sizeof(C)/sizeof(C[0]); i++) {
		/* Create the assertion and set its parameters.  */
		if ((assert = fido_assert_new()) == NULL)
			errx(1, "fido_assert_new");
		if ((error = fido_assert_set_rp(assert, rp_id)) != FIDO_OK)
			errx(1, "fido_assert_set_rp: %s", fido_strerr(error));
		if ((error = fido_assert_set_clientdata_hash(assert,
			    C[i].clientdata_hash,
			    sizeof(C[i].clientdata_hash))) != FIDO_OK)
			errx(1, "fido_assert_set_clientdata_hash: %s",
			    fido_strerr(error));

		/* Fill in the assertion response.  */
		if ((error = fido_assert_set_count(assert, 1)) != FIDO_OK)
			errx(1, "fido_assert_set_count: %s",
			    fido_strerr(error));
		if ((error = fido_assert_set_authdata_raw(assert, 0,
			    C[i].authdata, C[i].nauthdata)) != FIDO_OK)
			errx(1, "fido_assert_set_authdata_raw: %s",
			    fido_strerr(error));
		if ((error = fido_assert_set_sig(assert, 0,
			    C[i].sig, C[i].nsig)) != FIDO_OK)
			errx(1, "fido_assert_set_sig: %s", fido_strerr(error));

		if (C[i].hmacsecret) {
			if ((error = fido_assert_set_extensions(assert,
				    FIDO_EXT_HMAC_SECRET)) != FIDO_OK)
				errx(1, "fido_assert_set_extensions"
				    "(FIDO_EXT_HMAC_SECRET): %s",
				    fido_strerr(error));
			if ((error = fido_assert_set_hmac_secret(assert, 0,
				    C[i].hmacsecret, 32))
			    != FIDO_OK)
				errx(1, "fido_assert_set_hmac_secret: %s",
				    fido_strerr(error));
		}

		/* Verify the assertion and decrypt the ciphertext.  */
		if ((error = fido_assert_decrypt(assert, 0,
			    C[i].ciphertext, C[i].nciphertext,
			    &secret, &nsecret)) != FIDO_OK)
			errx(1, "fido_assert_decrypt: %s", fido_strerr(error));

		/* Print the secret in hex.  */
		printf("%u: ", i);
		for (j = 0; j < nsecret; j++)
			printf("%02hhx", secret[j]);
		printf("\n");

		free(secret);
		secret = NULL;
		nsecret = 0;
		fido_assert_free(&assert);
	}

	fflush(stdout);
	return ferror(stdout);
}
