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
#include <string.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>

#include "recover.h"

static const unsigned char hash[32] = { /* SHA-256(`hello world') */
	0xb9,0x4d,0x27,0xb9, 0x93,0x4d,0x3e,0x08,
	0xa5,0x2e,0x52,0xd7, 0xda,0x7d,0xab,0xfa,
	0xc4,0x84,0xef,0xe3, 0x7a,0x53,0x80,0xee,
	0x90,0x88,0xf7,0xac, 0xe2,0xef,0xcd,0xe9,
};

static const unsigned char signature[] = {
	0x30,0x45,0x02,0x20, 0x20,0xc8,0x88,0xdb,
	0x55,0x3d,0x31,0x16, 0xce,0xaa,0x52,0x58,
	0x47,0x6d,0x54,0x1d, 0xc2,0x16,0x58,0x9c,
	0x23,0x5c,0x09,0x5c, 0xce,0x55,0xb5,0x28,
	0x40,0xb6,0x08,0xfe, 0x02,0x21,0x00,0xc9,
	0xa1,0xdd,0xa5,0x33, 0x21,0x5b,0xa4,0x54,
	0xea,0xd5,0x7a,0xfd, 0x55,0xa2,0xa4,0xf7,
	0xcf,0x4a,0x55,0xda, 0x90,0xea,0xb8,0x63,
	0xaf,0x12,0xee,0xef, 0x09,0xe9,0xc3,
};

static void
show(const char *s, const EC_KEY *pk)
{
	const EC_GROUP *group = EC_KEY_get0_group(pk);
	const EC_POINT *A = EC_KEY_get0_public_key(pk);
	BN_CTX *ctx = NULL;
	BIGNUM *x = NULL, *y = NULL;
	char *x_hex = NULL, *y_hex = NULL;

	if ((ctx = BN_CTX_new()) == NULL) {
		errx(1, "BN_CTX_new: %s",
		    ERR_error_string(ERR_get_error(), NULL));
	}
	BN_CTX_start(ctx);
	if ((x = BN_CTX_get(ctx)) == NULL ||
	    (y = BN_CTX_get(ctx)) == NULL ||
	    !EC_POINT_get_affine_coordinates(group, A, x, y, NULL) ||
	    (x_hex = BN_bn2hex(x)) == NULL ||
	    (y_hex = BN_bn2hex(y)) == NULL)
		errx(1, "failed: %s", ERR_error_string(ERR_get_error(), NULL));

	printf("x%s = 0x%s\n", s, x_hex);
	printf("y%s = 0x%s\n", s, y_hex);

	OPENSSL_free(y_hex);
	OPENSSL_free(x_hex);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
}

int
main(void)
{
	EC_GROUP *nistp256;
	ECDSA_SIG *sig;
	const unsigned char *ptr = signature;
	unsigned char *der;
	int derlen;
	EC_KEY *pk[2];

	/* Get NIST P-256.  */
	nistp256 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (nistp256 == NULL)
		errx(1, "can't find NIST P-256");

	/* Create an in-memory signature representative and parse.  */
	if ((sig = ECDSA_SIG_new()) == NULL)
		errx(1, "out of memory");
	if (d2i_ECDSA_SIG(&sig, &ptr, sizeof signature) == NULL)
		errx(1, "malformed signature");

	/* Verify that the signature encoding is canonical.  */
	der = NULL;
	derlen = i2d_ECDSA_SIG(sig, &der);
	if (derlen != sizeof signature ||
	    CRYPTO_memcmp(signature, der, (size_t)derlen) != 0)
		errx(1, "noncanonical signature");
	OPENSSL_free(der);

	/* Recover the public key.  */
	if (!ECDSA_recover_pubkey(pk, sig, hash, sizeof hash, nistp256))
		errx(1, "failed: %s", ERR_error_string(ERR_get_error(), NULL));

	/* Show the coordinates.  */
	show("+", pk[0]);
	show("-", pk[1]);

	fflush(stdout);
	return ferror(stdout);
}
