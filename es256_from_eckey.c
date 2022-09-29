/* -*- Mode: C -*- */

/*-
 * Copyright (c) 2022 Taylor R. Campbell
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

#include "es256_from_eckey.h"

#include <string.h>

#include <fido.h>
#include <openssl/ec.h>

#ifndef HAVE_FIDO_ES256_PK_FROM_EC_KEY_FIX	/* XXX libfido2 <1.11.0 */
struct es256_pk {
	unsigned char x[32];
	unsigned char y[32];
};
#endif

int
fidocrypt_es256_pk_from_EC_KEY(es256_pk_t *pk, const EC_KEY *eckey)
{
#ifdef HAVE_FIDO_ES256_PK_FROM_EC_KEY_FIX	/* XXX libfido2 >=1.11.0 */
	return es256_pk_from_EC_KEY(pk, ec);
#else
	const EC_POINT *point = EC_KEY_get0_public_key(eckey);
	EC_GROUP *group = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *x = NULL, *y = NULL;
	int error = FIDO_ERR_INTERNAL;

	if ((group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
		goto out;
	if ((ctx = BN_CTX_secure_new()) == NULL)
		goto out;
	BN_CTX_start(ctx);

	/*
	 * Verify the point is on the correct curve;
	 *
	 *	`EC_POINT_is_on_curve returns 1 if the point is on the
	 *	 curve, 0 if not, or -1 on error.'
	 */
	switch (EC_POINT_is_on_curve(group, point, ctx)) {
	case -1:		/* error */
	default:
		goto out;
	case 0:			/* not on curve */
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	case 1:			/* on curve */
		break;
	}

	/* Get the affine x/y coordinates.  */
	if ((x = BN_CTX_get(ctx)) == NULL ||
	    (y = BN_CTX_get(ctx)) == NULL ||
	    !EC_POINT_get_affine_coordinates(group, point, x, y, ctx))
		goto out;

	/* Convert the coordinates to big-endian 32-byte strings.  */
	if (BN_bn2binpad(x, pk->x, sizeof(pk->x)) == -1 ||
	    BN_bn2binpad(y, pk->y, sizeof(pk->y)) == -1)
		goto out;

	/* Success!  */
	error = FIDO_OK;

out:	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
	return error;
#endif
}
