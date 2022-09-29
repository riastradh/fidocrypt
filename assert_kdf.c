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

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cbor.h>
#include <fido.h>
#include <fido/es256.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "es256_encode.h"
#include "es256_from_eckey.h"
#include "recover.h"

static int
es256_recover_kdf(const void *sig, size_t nsig, const void *hash, size_t nhash,
    const uint8_t pkconf[static 32], uint8_t key[static 32], void **pkp)
{
	EC_GROUP *nistp256 = NULL;
	ECDSA_SIG *sigobj = NULL;
	const unsigned char *sigptr = sig;
	EC_KEY *ec_pk[2] = {0,0};
	unsigned char *der = NULL;
	int derlen;
	es256_pk_t *es256_pk = NULL;
	cbor_item_t *pkcbor = NULL;
	unsigned char *pkcborbuf = NULL;
	size_t npkcbor = 0, npkcborbuf = 0;
	SHA256_CTX ctx;
	uint8_t pkhash[32];
	int error = FIDO_ERR_INVALID_SIG;

	/* Verify the signature length fits in the OpenSSL API.  */
	if (nsig > INT_MAX || nhash > INT_MAX)
		goto out;

	/* Get the NIST P-256 parameters.  */
	nistp256 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (nistp256 == NULL)
		goto out;

	/* Allocate an in-memory ECDSA signature object.  */
	if ((sigobj = ECDSA_SIG_new()) == NULL)
		goto out;

	/* Parse the signature.  */
	if (d2i_ECDSA_SIG(&sigobj, &sigptr, (int)nsig) == NULL)
		goto out;

	/* Verify the signature is canonical.  */
	if ((derlen = i2d_ECDSA_SIG(sigobj, &der)) < 0)
		goto out;
	if (derlen != (int)nsig ||
	    CRYPTO_memcmp(sig, der, (size_t)derlen) != 0)
		goto out;
	OPENSSL_clear_free(der, (size_t)derlen);
	der = NULL;

	/* Recover the candidate public keys.  */
	if (!ECDSA_recover_pubkey(ec_pk, sigobj, hash, nhash, nistp256))
		goto out;

	/* Hash the first one and see if it matches.  */
	if ((es256_pk = es256_pk_new()) == NULL)
		goto out;
	if (fidocrypt_es256_pk_from_EC_KEY(es256_pk, ec_pk[0]))
		goto out;
	if ((pkcbor = es256_pk_encode(es256_pk, /*ecdh*/0)) == NULL)
		goto out;
	if ((npkcbor = cbor_serialize_alloc(pkcbor, &pkcborbuf, &npkcborbuf))
	    == 0)
		goto out;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, "FIDOKDF1", 8);
	SHA256_Update(&ctx, pkcborbuf, npkcbor);
	SHA256_Final(pkhash, &ctx);
	if (CRYPTO_memcmp(pkhash, pkconf, 32) != 0) {
		/* Nope.  Hash the second one and see if it matches.  */
		OPENSSL_cleanse(pkcborbuf, npkcbor);
		free(pkcborbuf);
		pkcborbuf = NULL;
		cbor_decref(&pkcbor);
		es256_pk_free(&es256_pk);
		es256_pk = NULL;

		if ((es256_pk = es256_pk_new()) == NULL)
			goto out;
		if (fidocrypt_es256_pk_from_EC_KEY(es256_pk, ec_pk[1]))
			goto out;
		if ((pkcbor = es256_pk_encode(es256_pk, /*ecdh*/0)) == NULL)
			goto out;
		if ((npkcbor = cbor_serialize_alloc(pkcbor, &pkcborbuf,
			    &npkcborbuf)) == 0)
			goto out;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, "FIDOKDF1", 8);
		SHA256_Update(&ctx, pkcborbuf, npkcbor);
		SHA256_Final(pkhash, &ctx);
		if (CRYPTO_memcmp(pkhash, pkconf, 32) != 0) {
			/* Tough -- bad signature.  */
			goto out;
		}
	}

	/* Hash matches -- derive the secret key.  */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, "FIDOKDF2", 8);
	SHA256_Update(&ctx, pkcborbuf, npkcbor);
	SHA256_Final(key, &ctx);

	/*
	 * Success!  Return the public key to the caller in order to
	 * let them verify anything else about the assertion response
	 * (and then erase it).
	 */
	*pkp = es256_pk;
	es256_pk = NULL;	/* returned to caller */
	error = FIDO_ERR_SUCCESS;

out:	if (pkcborbuf) {
		OPENSSL_cleanse(pkcborbuf, npkcbor);
		free(pkcborbuf);
	}
	if (pkcbor)
		cbor_decref(&pkcbor);
	if (es256_pk)
		es256_pk_free(&es256_pk);
	if (ec_pk[0])
		EC_KEY_free(ec_pk[0]);
	if (ec_pk[1])
		EC_KEY_free(ec_pk[1]);
	if (der)
		OPENSSL_clear_free(der, (size_t)derlen);
	if (sigobj)
		ECDSA_SIG_free(sigobj);
	if (nistp256)
		EC_GROUP_free(nistp256);
	OPENSSL_cleanse(pkhash, sizeof(pkhash));
	return error;
}

int
fido_assert_kdf(const fido_assert_t *assert, size_t idx, int cose_alg,
    const uint8_t pkconf[static 32], uint8_t key[static 32])
{
	const void *cdh, *authdata_enc, *authdata, *sig;
	size_t ncdh, nauthdata_enc, nauthdata, nsig;
	cbor_item_t *authdata_cbor = NULL;
	struct cbor_load_result load;
	SHA256_CTX ctx;
	unsigned char hash[32];
	void *pk = NULL;
	int error;

	/*
	 * Paranoia: Verify that the public key confirmation hash and
	 * the key buffer are provided.
	 */
	if (pkconf == NULL || key == NULL) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	/* Get the client data hash.  */
	if ((cdh = fido_assert_clientdata_hash_ptr(assert)) == NULL ||
	    (ncdh = fido_assert_clientdata_hash_len(assert)) == 0) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	/* Get the auth data and signature.  */
	if (idx >= fido_assert_count(assert) ||
	    (authdata_enc = fido_assert_authdata_ptr(assert, idx)) == NULL ||
	    (nauthdata_enc = fido_assert_authdata_len(assert, idx)) == 0 ||
	    (sig = fido_assert_sig_ptr(assert, idx)) == NULL ||
	    (nsig = fido_assert_sig_len(assert, idx)) == 0) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	/* Parse the authdata as a CBOR bytestring.  */
	if (((authdata_cbor = cbor_load(authdata_enc, nauthdata_enc, &load))
		== NULL) ||
	    load.read != nauthdata_enc ||
	    !cbor_isa_bytestring(authdata_cbor) ||
	    !cbor_bytestring_is_definite(authdata_cbor)) {
		error = FIDO_ERR_INVALID_SIG;
		goto out;
	}
	authdata = cbor_bytestring_handle(authdata_cbor);
	nauthdata = cbor_bytestring_length(authdata_cbor);

	/*
	 * Discriminate on the signature algorithm and recover the
	 * public key.  Public key recovery works for ECDSA, but not
	 * for RSA or EdDSA.
	 */
	switch (cose_alg) {
	case COSE_ES256:
		/* Compute the message hash.  */
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, authdata, nauthdata);
		SHA256_Update(&ctx, cdh, ncdh);
		SHA256_Final(hash, &ctx);
		error = es256_recover_kdf(sig, nsig, hash, sizeof(hash),
		    pkconf, key, &pk);
		break;
	case COSE_RS256:
	case COSE_EDDSA:
	default:
		error = FIDO_ERR_UNSUPPORTED_OPTION;
		break;
	}
	if (error)
		goto out;

	/*
	 * Now that we have the public key, defer to fido_assert_verify
	 * to do any remaining verification we didn't do (e.g., rp id);
	 * this is necessary because we don't have access to some parts
	 * of a fido_assert_t.
	 */
	error = fido_assert_verify(assert, 0, cose_alg, pk);

out:	if (pk) {
		switch (cose_alg) {
		case COSE_ES256: {
			es256_pk_t *es256_pk = pk;
			es256_pk_free(&es256_pk);
		}
		case COSE_RS256:
		case COSE_EDDSA:
		default:
			break;
		}
	}
	if (authdata_cbor)
		cbor_decref(&authdata_cbor);
	OPENSSL_cleanse(hash, sizeof(hash));
	OPENSSL_cleanse(&ctx, sizeof(ctx));
	return error;
}
