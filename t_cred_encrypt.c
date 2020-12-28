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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <fido.h>

#include "fidocrypt.h"
#include "cred_encrypt.h"

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

static const char user_id[] = "falken";
static const char user_name[] = "Falken";

static const struct {
	size_t nsecret;
	const unsigned char *secret;
	unsigned char clientdata_hash[32];
	size_t nauthdata;
	const unsigned char *authdata;
	const unsigned char *hmacsecret;
	size_t assert_nauthdata;
	const unsigned char *assert_authdata;
	size_t assert_nsig;
	const unsigned char *assert_sig;
	size_t assert_ncdh;
	const unsigned char *assert_cdh;
} C[] = {
	[0] = {
		.nsecret = 32,
		.secret = (const unsigned char[]) {
			0xc6,0xa3,0x86,0x85, 0xa9,0x37,0xec,0x62,
			0x52,0x8f,0xc1,0xa0, 0x3a,0xb7,0x03,0xf0,
			0x9e,0x4c,0x75,0xc9, 0x55,0xff,0x84,0x0d,
			0xea,0x75,0x0e,0x03, 0x0b,0x25,0xc2,0xa2,
		},
		/*
		 * {"type": "webauthn.create",
		 *  "origin": "test-fidocrypt://example.com",
		 *  "challenge": "pjpe5SAd6k_0lisO9VIXYG87C5x0iqAn0MdY_ILcKMU",
		 *  "clientExtensions": {}}
		 */
		.clientdata_hash = {
			0xe8,0xbd,0xf0,0xfa, 0x42,0x75,0x53,0x43,
			0xe5,0x8e,0x62,0x65, 0x37,0x61,0x43,0x31,
			0x28,0x83,0x7f,0xc0, 0x07,0x94,0x0a,0xc8,
			0x5b,0xee,0x22,0xcc, 0x6a,0xdb,0x1c,0xe1,
		},
		.nauthdata = 196,
		.authdata = (const unsigned char[]) {
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
			0xd6,0x00,0xa5,0x36,
		},
		.hmacsecret = NULL,
		.assert_ncdh = 0,
		.assert_cdh = NULL,
		.assert_nauthdata = 0,
		.assert_authdata = NULL,
		.assert_nsig = 0,
		.assert_sig = NULL,
	},
	[1] = {
		.nsecret = 32,
		.secret = (const unsigned char[]) {
			0x65,0x65,0x8a,0xbf, 0xac,0x70,0xb7,0x3c,
			0xa4,0x64,0xd6,0x1d, 0xed,0x3f,0x1f,0xa5,
			0xae,0x2d,0xe9,0xdd, 0xdd,0x6f,0x98,0x1f,
			0x4b,0x9e,0x91,0x5c, 0x09,0x93,0xbb,0x88,
		},
		.clientdata_hash = {
			0x9c,0xb9,0x6a,0xf1, 0x97,0xa8,0x1e,0x32,
			0x63,0x25,0x9a,0xd5, 0x0b,0x5f,0x4f,0x8f,
			0x90,0xc6,0x60,0x6c, 0x0b,0x19,0xe3,0xec,
			0xf6,0x1a,0x50,0x2e, 0x0e,0xf1,0xc8,0xe8,
		},
		.nauthdata = 202,
		.authdata = (const unsigned char[]) {
			0xa3,0x79,0xa6,0xf6, 0xee,0xaf,0xb9,0xa5,
			0x5e,0x37,0x8c,0x11, 0x80,0x34,0xe2,0x75,
			0x1e,0x68,0x2f,0xab, 0x9f,0x2d,0x30,0xab,
			0x13,0xd2,0x12,0x55, 0x86,0xce,0x19,0x47,
			0x41,0x00,0x00,0x0c, 0xae,0x89,0x76,0x63,
			0x1b,0xd4,0xa0,0x42, 0x7f,0x57,0x73,0x0e,
			0xc7,0x1c,0x9e,0x02, 0x79,0x00,0x46,0xde,
			0x74,0xc1,0x72,0xae, 0xf6,0x2f,0x76,0x82,
			0xd2,0xce,0x82,0xa2, 0x0c,0x5b,0x68,0x96,
			0x5c,0x01,0x21,0x50, 0x47,0x3e,0x10,0x55,
			0xa4,0x4a,0x69,0x36, 0x8a,0x9c,0x8b,0xf9,
			0xc6,0xa3,0x79,0xa6, 0xf6,0xee,0xaf,0xb9,
			0xa5,0x5e,0x37,0x8c, 0x11,0x80,0x34,0xe2,
			0x75,0x1e,0x68,0x2f, 0xab,0x9f,0x2d,0x30,
			0xab,0x13,0xd2,0x12, 0x55,0x86,0xce,0x19,
			0x47,0xae,0x0c,0x00, 0x00,0xa5,0x01,0x02,
			0x03,0x26,0x20,0x01, 0x21,0x58,0x20,0x6e,
			0x5b,0x76,0xcb,0xb3, 0x58,0x7d,0x12,0xdc,
			0xb7,0x17,0x27,0x5b, 0x53,0x8b,0xa9,0xe7,
			0x9d,0xb9,0x9e,0x6e, 0x96,0xf8,0x98,0xca,
			0x0a,0x12,0x63,0x68, 0x64,0x27,0x57,0x22,
			0x58,0x20,0x5e,0x0a, 0x4c,0x60,0xc5,0xf9,
			0xea,0x25,0xca,0xfb, 0x8b,0x7b,0x97,0x2c,
			0x62,0x34,0x21,0x75, 0x05,0x5c,0x0a,0x92,
			0x9b,0x0f,0x17,0x25, 0x0f,0x30,0xa7,0x3d,
			0xca,0x6e,
		},
		.hmacsecret = (const unsigned char[]) {
			0x71,0xfc,0x1d,0xf4, 0xd4,0x9b,0x2d,0x4e,
			0x52,0x21,0x43,0xfe, 0xc6,0x17,0x36,0xe5,
			0x42,0x18,0x90,0x6e, 0x29,0x7c,0xdc,0x69,
			0xa9,0x87,0x35,0xc8, 0x83,0xf8,0x04,0x37,
		},
		.assert_ncdh = 32,
		.assert_cdh = (const unsigned char[]) {
			0x8f,0x15,0xbb,0x6d, 0x29,0xb0,0x55,0xa4,
			0x5a,0x87,0xdc,0x35, 0xdf,0x6f,0x3c,0xea,
			0x27,0xe5,0xce,0x4c, 0x79,0xa6,0xe8,0x39,
			0x22,0x83,0xa8,0x8c, 0xcd,0x88,0xeb,0x1e,
		},
		.assert_nauthdata = 84,
		.assert_authdata = (const unsigned char[]) {
			0xa3,0x79,0xa6,0xf6, 0xee,0xaf,0xb9,0xa5,
			0x5e,0x37,0x8c,0x11, 0x80,0x34,0xe2,0x75,
			0x1e,0x68,0x2f,0xab, 0x9f,0x2d,0x30,0xab,
			0x13,0xd2,0x12,0x55, 0x86,0xce,0x19,0x47,
			0x81,0x00,0x00,0x0d, 0xa1,0xa1,0x6b,0x68,
			0x6d,0x61,0x63,0x2d, 0x73,0x65,0x63,0x72,
			0x65,0x74,0x58,0x20, 0x54,0xa2,0xe6,0x4e,
			0xb5,0xbd,0xaf,0xa8, 0x9f,0xe5,0x2c,0xf9,
			0xb4,0x91,0x10,0x55, 0x9c,0x53,0x0e,0x5e,
			0x3a,0x2a,0x35,0xac, 0xf7,0x7c,0x36,0x8a,
			0x24,0x7b,0x93,0x95,
		},
		.assert_nsig = 72,
		.assert_sig = (const unsigned char[]) {
			0x30,0x46,0x02,0x21, 0x00,0xd7,0x45,0x53,
			0xdb,0x27,0xa3,0x61, 0xd6,0x88,0x2d,0x29,
			0x48,0xc1,0x30,0xb7, 0x5e,0xb3,0x28,0x93,
			0xc8,0xc1,0xe7,0x2a, 0x9c,0xc0,0x8d,0x72,
			0xc1,0xa2,0xe9,0xb5, 0x76,0x02,0x21,0x00,
			0x86,0xb5,0x58,0xa6, 0x88,0xb4,0x7e,0xc8,
			0xa2,0x21,0xd9,0xbb, 0x9a,0x2c,0xcf,0xcd,
			0x1c,0x7d,0x1f,0xc8, 0x1e,0x54,0x69,0xe9,
			0xfc,0x8f,0xe3,0x84, 0x28,0x4e,0x2b,0x8b,
		},
	},
};

int
main(void)
{
	fido_cred_t *cred = NULL;
	fido_assert_t *assert = NULL;
	unsigned char *ciphertext = NULL;
	size_t nciphertext = 0;
	unsigned i, j;
	int error;

	/* Initialize libfido2.  */
	fido_init(0);

	for (i = 0; i < sizeof(C)/sizeof(C[0]); i++) {
		/* Create the credential and set its parameters.  */
		if ((cred = fido_cred_new()) == NULL)
			errx(1, "fido_cred_new");
		if ((error = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK)
			errx(1, "fido_cred_set_type: %s", fido_strerr(error));
		if ((error = fido_cred_set_rp(cred, rp_id, NULL)) != FIDO_OK)
			errx(1, "fido_cred_set_rp: %s", fido_strerr(error));
		if ((error = fido_cred_set_user(cred,
			    (const void *)user_id, strlen(user_id),
			    user_name, /*displayname*/NULL, /*icon*/NULL))
		    != FIDO_OK)
			errx(1, "fido_cred_set_user: %s", fido_strerr(error));
		if ((error = fido_cred_set_clientdata_hash(cred,
			    C[i].clientdata_hash,
			    sizeof(C[i].clientdata_hash))) != FIDO_OK)
			errx(1, "fido_cred_set_clientdata_hash: %s",
			    fido_strerr(error));

		/*
		 * Fill in the credential response -- just the auth
		 * data; we're really only interested in the public
		 * key, not in the device attestation.
		 */
		if ((error = fido_cred_set_authdata_raw(cred, C[i].authdata,
			    C[i].nauthdata)) != FIDO_OK)
			errx(1, "fido_cred_set_authdata_raw: %s",
			    fido_strerr(error));

		/* If we're doing hmac-secret, set it up.  */
		if (C[i].hmacsecret) {
			if ((assert = fido_assert_new()) == NULL)
				errx(1, "fido_assert_new");
			if ((error = fido_assert_set_rp(assert, rp_id))
			    != FIDO_OK)
				errx(1, "fido_assert_set_rp: %s",
				    fido_strerr(error));
			if ((error = fido_assert_set_count(assert, 1))
			    != FIDO_OK)
				errx(1, "fido_assert_set_count: %s",
				    fido_strerr(error));
			if ((error = fido_assert_set_clientdata_hash(assert,
				    C[i].assert_cdh, C[i].assert_ncdh))
			    != FIDO_OK)
				errx(1, "fido_assert_set_clientdata_hash: %s",
				    fido_strerr(error));
			if ((error = fido_assert_set_authdata_raw(assert, 0,
				    C[i].assert_authdata,
				    C[i].assert_nauthdata))
			    != FIDO_OK)
				errx(1, "fido_assert_set_authdata_raw: %s",
				    fido_strerr(error));
			if ((error = fido_assert_set_sig(assert, 0,
				    C[i].assert_sig, C[i].assert_nsig))
			    != FIDO_OK)
				errx(1, "fido_assert_set_sig: %s",
				    fido_strerr(error));
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

		/*
		 * Encrypt the secret with a key derived from the
		 * credential.
		 */
		if ((error = fido_cred_encrypt(cred, assert, 0, C[i].secret,
			    C[i].nsecret, &ciphertext, &nciphertext))
		    != FIDO_OK)
			errx(1, "fido_cred_encrypt: %s", fido_strerr(error));

		/* Print the ciphertext in hex.  */
		printf("%u: ", i);
		for (j = 0; j < nciphertext; j++)
			printf("%02hhx", ciphertext[j]);
		printf("\n");

		free(ciphertext);
		ciphertext = NULL;
		nciphertext = 0;
		fido_assert_free(&assert);
		fido_cred_free(&cred);
	}

	fflush(stdout);
	return ferror(stdout);
}
