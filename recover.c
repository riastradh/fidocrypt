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
 * ECDSA public key recovery.  An ECDSA public key is an encoding of a
 * point A on an elliptic curve with standard base point B; an ECDSA
 * signature on a message m is an encoding of pair of integers (r, s)
 * satisfying the equation
 *
 *	r = x(H(m) s^{-1} * B + r s^{-1} * A),
 *
 * where s^{-1} and the equation are taken modulo the order of the
 * curve, and where H is a hash function mapping messages into scalars.
 *
 * Given r, s, and H(m), we can solve for either of two candidate
 * public keys by choosing a point R such that x(R) = r (if there is
 * any -- if r^3 + a r + b has a square root in the coordinate field)
 * and computing
 *
 *	r^{-1} (s * R - H(m) * B),
 *	r^{-1} (-s * R - H(m) * B)
 *
 * as the two candidates for the public key A.  Both of them will
 * verify the signature by construction, so the caller must have some
 * way to discriminate valid public keys.
 */

#include "recover.h"

#include <assert.h>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

int
ECDSA_recover_pubkey(EC_KEY *pk[static 2], const ECDSA_SIG *sig,
    const unsigned char *hash, size_t hashbytes, EC_GROUP *group)
{
	BN_CTX *ctx = NULL;
	BIGNUM *zero;
	BIGNUM *p;		/* curve field's modulus */
	const BIGNUM *n;	/* curve order */
	const BIGNUM *r, *s;	/* signature components */
	BIGNUM *h = NULL;	/* hash mod n */
	BIGNUM *r_ = NULL;	/* r^{-1} mod n */
	EC_POINT *R[2] = {0,0};	/* candidate values of x^{-1}(r) */
	EC_POINT *A[2] = {0,0};	/* candidate values of A */
	int ok = 0;

	pk[0] = NULL;
	pk[1] = NULL;

	/*
	 * Create a context for operations.  The public key may be
	 * treated as a secret (as when abusing^Wcleverly using U2F to
	 * derive secrets), so use BN_CTX_secure_new, not BN_CTX_new.
	 */
	if ((ctx = BN_CTX_secure_new()) == NULL)
		goto out;

	/* Allocate the objects we'll need.  */
	if ((zero = BN_CTX_get(ctx)) == NULL ||
	    (p = BN_CTX_get(ctx)) == NULL ||
	    (h = BN_CTX_get(ctx)) == NULL ||
	    (R[0] = EC_POINT_new(group)) == NULL ||
	    (R[1] = EC_POINT_new(group)) == NULL ||
	    (A[0] = EC_POINT_new(group)) == NULL ||
	    (A[1] = EC_POINT_new(group)) == NULL ||
	    (pk[0] = EC_KEY_new()) == NULL ||
	    (pk[1] = EC_KEY_new()) == NULL)
		goto out;

	/*
	 * Get all the inputs: zero, the NIST P-256 group, the order,
	 * and the signature r/s components.
	 */
	BN_zero(zero);
	if (!EC_GROUP_get_curve(group, p, NULL, NULL, ctx))
		goto out;
	if ((n = EC_GROUP_get0_order(group)) == NULL)
		goto out;
	ECDSA_SIG_get0(sig, &r, &s);

	/* Interpret the message hash as an integer, and negate it.  */
	if (BN_bin2bn(hash, hashbytes, h) == NULL)
		goto out;
	if (!BN_mod_sub(h, zero, h, n, ctx))
		goto out;

	/* r_ := r^{-1} mod n */
	if ((r_ = BN_mod_inverse(NULL, r, n, ctx)) == NULL)
		goto out;

	/* R := x^{-1}(r) */
	if (!EC_POINT_set_compressed_coordinates(group, R[0], r, 0, ctx) ||
	    !EC_POINT_set_compressed_coordinates(group, R[1], r, 1, ctx))
		goto out;

	/* A := r^{-1} (s * R - h * B) */
	if (!EC_POINT_mul(group, A[0], h, R[0], s, ctx) ||
	    !EC_POINT_mul(group, A[1], h, R[1], s, ctx) ||
	    !EC_POINT_mul(group, A[0], NULL, A[0], r_, ctx) ||
	    !EC_POINT_mul(group, A[1], NULL, A[1], r_, ctx))
		goto out;

	/* Set the public keys.  */
	if (!EC_KEY_set_group(pk[0], group) ||
	    !EC_KEY_set_group(pk[1], group) ||
	    !EC_KEY_set_public_key(pk[0], A[0]) ||
	    !EC_KEY_set_public_key(pk[1], A[1]))
		goto out;

	/* The signature should verify under both keys.  */
	assert(ECDSA_do_verify(hash, hashbytes, sig, pk[0]));
	assert(ECDSA_do_verify(hash, hashbytes, sig, pk[1]));

	/* Success!  */
	ok = 1;

out:	if (!ok && pk[1]) {
		EC_KEY_free(pk[1]);
		pk[1] = NULL;
	}
	if (!ok && pk[0]) {
		EC_KEY_free(pk[0]);
		pk[0] = NULL;
	}
	if (A[1])
		EC_POINT_free(A[1]);
	if (A[0])
		EC_POINT_free(A[0]);
	if (R[1])
		EC_POINT_free(R[1]);
	if (R[0])
		EC_POINT_free(R[0]);
	if (ctx)
		BN_CTX_free(ctx);
	return ok;
}
