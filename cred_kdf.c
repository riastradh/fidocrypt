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

#include "cred_kdf.h"

#include <stddef.h>
#include <stdint.h>

#include <cbor.h>
#include <fido.h>
#include <fido/es256.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include "es256_encode.h"

int
fido_cred_kdf(const fido_cred_t *cred, int cose_alg, uint8_t pkconf[static 32],
    uint8_t key[static 32])
{
	const es256_pk_t *es256_pk;
	cbor_item_t *pkcbor = NULL;
	unsigned char *pkcborbuf = NULL;
	size_t npkcbor = 0, npkcborbuf = 0;
	SHA256_CTX ctx;
	int error;

	/* Verify that the COSE algorithm is ECDSA with SHA-256.  */
	/* XXX Also verify the curve is NIST P-256.  */
	if (cose_alg != COSE_ES256) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	/* Get the public key.  */
	if ((es256_pk = (const void *)fido_cred_pubkey_ptr(cred)) == NULL) {
		/*
		 * XXX Should also check fido_cred_pubkey_len, but the
		 * size of es256_pk_t is private to libfido2.
		 */
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	/* Encode the public key in CBOR.  */
	if ((pkcbor = es256_pk_encode(es256_pk, /*ecdh*/0)) == NULL) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}
	if ((npkcbor = cbor_serialize_alloc(pkcbor, &pkcborbuf, &npkcborbuf))
	    == 0) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/* Create the public key confirmation hash.  */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, "FIDOKDF1", 8);
	SHA256_Update(&ctx, pkcborbuf, npkcbor);
	SHA256_Final(pkconf, &ctx);

	/* Derive the key.  */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, "FIDOKDF2", 8);
	SHA256_Update(&ctx, pkcborbuf, npkcbor);
	SHA256_Final(key, &ctx);

	/* Success!  */
	error = FIDO_OK;

out:	if (pkcborbuf) {
		OPENSSL_cleanse(pkcborbuf, npkcbor);
		free(pkcborbuf);
	}
	if (pkcbor)
		cbor_decref(&pkcbor);
	OPENSSL_cleanse(&ctx, sizeof(ctx));
	return error;
}
