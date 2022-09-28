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
 * es256_pk_encode is not exported by libfido2, so we reimplement it
 * here -- at least, the parts for ECDSA; don't care about ECDH.
 */

#include "es256_encode.h"

#include <string.h>

#include <cbor.h>
#include <fido.h>
#include <fido/es256.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

cbor_item_t *
es256_pk_encode(const es256_pk_t *pk, int ecdh)
{
	EVP_PKEY *evp_pkey = NULL;
	const EC_KEY *ec_key;
	const EC_GROUP *ec_group;
	const EC_POINT *ec_point;
	BN_CTX *ctx = NULL;
	BIGNUM *x, *y;
	int nbytes;
	unsigned char xb[32], yb[32];
	cbor_item_t *item = NULL;
	struct cbor_pair ent[5];
	unsigned i = 0;
	int ok = 0;

	/*
	 * Zero the array of entries so we can safely free everything
	 * in the array that's not zero.
	 */
	memset(ent, 0, sizeof(ent));

	/* Refuse ECDH -- we only do ECDSA here.  */
	if (ecdh)
		goto out;

	/* Create a CBOR map.  */
	if ((item = cbor_new_definite_map(5)) == NULL)
		goto out;

	/* Convert the es256_pk to OpenSSL group and point.  */
	if ((evp_pkey = es256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey)) == NULL ||
	    (ec_group = EC_KEY_get0_group(ec_key)) == NULL ||
	    (ec_point = EC_KEY_get0_public_key(ec_key)) == NULL)
		goto out;

	/* Create a bignum context.  */
	if ((ctx = BN_CTX_new()) == NULL)
		goto out;
	BN_CTX_start(ctx);

	/* Get the affine x/y coordinates.  */
	if ((x = BN_CTX_get(ctx)) == NULL ||
	    (y = BN_CTX_get(ctx)) == NULL ||
	    !EC_POINT_get_affine_coordinates(ec_group, ec_point, x, y, ctx))
		goto out;

	/* Convert the coordinates to big-endian 32-byte strings.  */
	if ((nbytes = BN_num_bytes(x)) < 0 || (size_t)nbytes > sizeof(xb) ||
	    (nbytes = BN_num_bytes(y)) < 0 || (size_t)nbytes > sizeof(yb))
		goto out;
	if ((nbytes = BN_bn2bin(x, xb)) < 0 || (size_t)nbytes > sizeof(xb) ||
	    (nbytes = BN_bn2bin(y, yb)) < 0 || (size_t)nbytes > sizeof(yb))
		goto out;

	/* kty(1) [key type] = EC2(2) (two-coordinate elliptic curve point) */
	if ((ent[i].key = cbor_build_uint8(1)) == NULL ||
	    (ent[i].value = cbor_build_uint8(2)) == NULL ||
	    !cbor_map_add(item, ent[i++]))
		goto out;

	/* alg(3) = ES256(-7) */
	if ((ent[i].key = cbor_build_uint8(3)) == NULL ||
	    (ent[i].value = cbor_build_negint8(~(-7))) == NULL ||
	    !cbor_map_add(item, ent[i++]))
		goto out;

	/* curve(-1) = P-256(1) */
	if ((ent[i].key = cbor_build_negint8(~(-1))) == NULL ||
	    (ent[i].value = cbor_build_uint8(1)) == NULL ||
	    !cbor_map_add(item, ent[i++]))
		goto out;

	/* x(-2) */
	if ((ent[i].key = cbor_build_negint8(~(-2))) == NULL ||
	    (ent[i].value = cbor_build_bytestring(xb, sizeof(xb))) == NULL ||
	    !cbor_map_add(item, ent[i++]))
		goto out;

	/* y(-3) */
	if ((ent[i].key = cbor_build_negint8(~(-3))) == NULL ||
	    (ent[i].value = cbor_build_bytestring(yb, sizeof(yb))) == NULL ||
	    !cbor_map_add(item, ent[i++]))
		goto out;

	/* Success!  */
	ok = 1;

out:	for (i = sizeof(ent)/sizeof(ent[0]); i --> 0;) {
		if (ent[i].value)
			cbor_decref(&ent[i].value);
		if (ent[i].key)
			cbor_decref(&ent[i].key);
	}
	if (ctx) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (evp_pkey)
		EVP_PKEY_free(evp_pkey);
	if (!ok && item)
		cbor_decref(&item);
	return item;
}
