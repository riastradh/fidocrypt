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

#include "assert_decrypt.h"
#include "fidocrypt.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cbor.h>
#include <fido.h>
#include <fido/eddsa.h>
#include <fido/es256.h>
#include <fido/rs256.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "dae.h"
#include "eddsa_decode.h"
#include "es256_encode.h"
#include "export.h"
#include "recover.h"
#include "rs256_decode.h"

static int
hash_hmac_secret(SHA256_CTX *ctx, const void *hmac_secret, size_t nhmac_secret)
{
	unsigned char h[8];
	size_t n;

	n = cbor_encode_bytestring_start(nhmac_secret, h, sizeof(h));
	if (n == 0 || n > sizeof(h))
		return FIDO_ERR_INTERNAL;
	SHA256_Update(ctx, h, n);
	SHA256_Update(ctx, hmac_secret, nhmac_secret);

	return 0;
}

static int
es256_recover_decrypt(const void *sig, size_t nsig,
    const void *hash, size_t nhash,
    const void *hmac_secret, size_t nhmac_secret,
    const unsigned char ciphertext[static DAE_TAGBYTES], size_t nciphertext,
    unsigned char *payload, es256_pk_t **pkp)
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
	unsigned char key[32];
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

	/*
	 * XXX This sequential trial of public keys may leak one bit of
	 * information through a timing side channel.  Is that bit
	 * relevant?
	 */
	/* Hash the first one and see if it matches.  */
	if ((es256_pk = es256_pk_new()) == NULL)
		goto out;
	if (es256_pk_from_EC_KEY(es256_pk, ec_pk[0]))
		goto out;
	if ((pkcbor = es256_pk_encode(es256_pk, /*ecdh*/0)) == NULL)
		goto out;
	if ((npkcbor = cbor_serialize_alloc(pkcbor, &pkcborbuf, &npkcborbuf))
	    == 0)
		goto out;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, "FIDOKDF0", 8);
	SHA256_Update(&ctx, pkcborbuf, npkcbor);
	if (nhmac_secret) {
		if (hash_hmac_secret(&ctx, hmac_secret, nhmac_secret) != 0)
			goto out;
	}
	SHA256_Final(key, &ctx);
	if (!dae_decrypt(payload, pkcborbuf, npkcbor, ciphertext, nciphertext,
		key)) {
		/* Nope.  Hash the second one and see if it matches.  */
		OPENSSL_cleanse(pkcborbuf, npkcbor);
		free(pkcborbuf);
		pkcborbuf = NULL;
		cbor_decref(&pkcbor);
		es256_pk_free(&es256_pk);
		es256_pk = NULL;

		if ((es256_pk = es256_pk_new()) == NULL)
			goto out;
		if (es256_pk_from_EC_KEY(es256_pk, ec_pk[1]))
			goto out;
		if ((pkcbor = es256_pk_encode(es256_pk, /*ecdh*/0)) == NULL)
			goto out;
		if ((npkcbor = cbor_serialize_alloc(pkcbor, &pkcborbuf,
			    &npkcborbuf)) == 0)
			goto out;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, "FIDOKDF0", 8);
		SHA256_Update(&ctx, pkcborbuf, npkcbor);
		if (nhmac_secret) {
			if (hash_hmac_secret(&ctx, hmac_secret, nhmac_secret)
			    != 0)
				goto out;
		}
		SHA256_Final(key, &ctx);
		if (!dae_decrypt(payload, pkcborbuf, npkcbor,
			ciphertext, nciphertext, key)) {
			/* Tough -- bad signature.  */
			goto out;
		}
	}

	/*
	 * Success!  Return the public key to the caller in order to
	 * let them verify anything else about the assertion response
	 * (and then erase it).
	 */
	*pkp = es256_pk;
	es256_pk = NULL;	/* returned to caller */
	error = FIDO_OK;

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
	OPENSSL_cleanse(key, sizeof(key));
	return error;
}

static int
decrypt(const void *pkenc, size_t npkenc,
    const void *hmac_secret, size_t nhmac_secret,
    const unsigned char ciphertext[static DAE_TAGBYTES], size_t nciphertext,
    unsigned char *payload)
{
	SHA256_CTX ctx;
	unsigned char key[32];
	int error = FIDO_ERR_INVALID_SIG;

	/* The ciphertext had better be large enough for a tag.  */
	if (nciphertext < DAE_TAGBYTES)
		goto out;

	/* There had better be an HMAC secret.  */
	if (hmac_secret == NULL || nhmac_secret == 0)
		goto out;

	/*
	 * Derive the key from the public key and the HMAC secret.
	 * Since we're not recovering the public key from the
	 * signature, the HMAC secret is mandatory here.
	 */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, "FIDOKDF0", 8);
	SHA256_Update(&ctx, pkenc, npkenc);
	if (hash_hmac_secret(&ctx, hmac_secret, nhmac_secret) != 0)
		goto out;
	SHA256_Final(key, &ctx);

	/* Try to decrypt the ciphertext.  */
	if (!dae_decrypt(payload, pkenc, npkenc, ciphertext, nciphertext, key))
		goto out;

	/* Success!  */
	error = 0;

out:	OPENSSL_cleanse(key, sizeof(key));
	OPENSSL_cleanse(&ctx, sizeof(ctx));
	if (error && nciphertext > DAE_TAGBYTES)
		OPENSSL_cleanse(payload, nciphertext - DAE_TAGBYTES);
	return error;
}

EXPORT
int
fido_assert_decrypt(const fido_assert_t *assert, size_t idx,
    const unsigned char *ciphertext, size_t nciphertext,
    unsigned char **payloadp, size_t *npayloadp)
{
	struct cbor_load_result load;
	const void *cdh, *authdata_enc, *authdata, *sig, *hmac_secret = NULL;
	size_t ncdh, nauthdata_enc, nauthdata, nsig, nhmac_secret = 0;
	cbor_item_t *authdata_cbor = NULL;
	const unsigned char *pkenc;
	size_t npkenc;
	cbor_item_t *pkcbor = NULL;
	const struct cbor_pair *entry;
	size_t i, n;
	int kty = 0, alg = 0, crv = 0;
	unsigned char *payload = NULL;
	size_t npayload = 0;
	SHA256_CTX ctx;
	unsigned char hash[32];
	es256_pk_t *es256_pk = NULL;
	eddsa_pk_t *eddsa_pk = NULL;
	rs256_pk_t *rs256_pk = NULL;
	int error;

	/* Paranoia: Verify that necessary inputs are nonnull.  */
	if (ciphertext == NULL || nciphertext < DAE_TAGBYTES) {
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

	/* Get the HMAC secret if available.  */
	hmac_secret = fido_assert_hmac_secret_ptr(assert, idx);
	nhmac_secret = fido_assert_hmac_secret_len(assert, idx);
	if (nhmac_secret > 0 && hmac_secret == NULL) { /* paranoia */
		error = FIDO_ERR_INVALID_SIG;
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

	/* Parse the public key as a CBOR map.  */
	if ((pkcbor = cbor_load(ciphertext, nciphertext, &load)) == NULL ||
	    load.read >= nciphertext ||
	    !cbor_isa_map(pkcbor) ||
	    !cbor_map_is_definite(pkcbor)) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	/*
	 * Record where the encoded public key was and advance the
	 * ciphertext.  We will use this encoded public key if we
	 * aren't doing public key recovery.
	 */
	pkenc = ciphertext;
	npkenc = load.read;
	ciphertext += load.read;
	nciphertext -= load.read;

	/* Verify there's enough room for a tag and payload.  */
	if (nciphertext < DAE_TAGBYTES) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	/* Find the key type, algorithm, and curve.  */
	entry = cbor_map_handle(pkcbor);
	n = cbor_map_size(pkcbor);
	for (i = 0; i < n; i++) {
		int key;

		/* Sanity check: Make sure the entry is initialized.  */
		if (entry[i].key == NULL || entry[i].value == NULL) {
			error = FIDO_ERR_INVALID_CREDENTIAL;
			goto out;
		}

		/* Get the entry key as an integer.  */
		if (cbor_isa_uint(entry[i].key)) {
			if (cbor_get_int(entry[i].key) > INT_MAX)
				continue;
			key = (int)cbor_get_int(entry[i].key);
		} else if (cbor_isa_negint(entry[i].key)) {
			if ((int64_t)~cbor_get_int(entry[i].key) < INT_MIN)
				continue;
			key = (int)~cbor_get_int(entry[i].key);
		} else {
			continue;
		}

		/* Dispatch on the entry key.  */
		switch (key) {
		case 1:		/* kty (key type) */
			if (!cbor_isa_uint(entry[i].value) ||
			    cbor_get_int(entry[i].value) > INT_MAX ||
			    kty != 0) {
				error = FIDO_ERR_INVALID_CREDENTIAL;
				goto out;
			}
			kty = (int)cbor_get_int(entry[i].value);
			break;
		case 3:		/* alg (algorithm) */
			if (!cbor_isa_negint(entry[i].value) ||
			    (int64_t)~cbor_get_int(entry[i].value) < INT_MIN ||
			    alg != 0) {
				error = FIDO_ERR_INVALID_CREDENTIAL;
				goto out;
			}
			alg = (int)~cbor_get_int(entry[i].value);
			break;
		case -1:	/* crv (curve, for EC algorithms) */
			if (!cbor_isa_uint(entry[i].value) ||
			    cbor_get_int(entry[i].value) > INT_MAX ||
			    crv != 0) {
				error = FIDO_ERR_INVALID_CREDENTIAL;
				goto out;
			}
			crv = (int)cbor_get_int(entry[i].value);
			break;
		}
	}

	/* Verify that we have a key type and algorithm.  */
	if (kty == 0 || alg == 0) {
		error = FIDO_ERR_INVALID_CREDENTIAL;
		goto out;
	}

	/* Allocate a buffer for the payload.  */
	npayload = nciphertext - DAE_TAGBYTES;
	if ((payload = malloc(npayload)) == NULL) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/* Discriminate on the algorithm (and curve, if appropriate).  */
	switch (alg) {
	case COSE_ES256: {
		/*
		 * ECDSA w/ SHA-256.  Do public key recovery.
		 *
		 * XXX We could support ECDSA public key recovery with
		 * other hash functions too (ES384, ES512).
		 *
		 * First verify that the key type is EC2
		 * (two-coordinate elliptic curve point) and that we
		 * support the curve (currently just NIST P-256).
		 */
		if (kty != COSE_KTY_EC2) {
			error = FIDO_ERR_INVALID_CREDENTIAL;
			goto out;
		}
		switch (crv) {
		case COSE_P256:
			break;
		default:
			error = FIDO_ERR_UNSUPPORTED_ALGORITHM;
			goto out;
		}

		/* Compute the message hash as in FIDO protocol.  */
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, authdata, nauthdata);
		SHA256_Update(&ctx, cdh, ncdh);
		SHA256_Final(hash, &ctx);

		/*
		 * Recover the public key from the signature, verify it
		 * matches, and decrypt the ciphertext.
		 */
		error = es256_recover_decrypt(sig, nsig, hash, sizeof(hash),
		    hmac_secret, nhmac_secret, ciphertext, nciphertext,
		    payload, &es256_pk);
		if (error)
			goto out;

		/*
		 * Verify anything else about the assertion now that we
		 * have the public key to defer to fido_assert_verify.
		 */
		error = fido_assert_verify(assert, idx, alg, es256_pk);
		break;
	}
	case COSE_EDDSA:	/* Ed25519 */
		/* Create and decode our Ed25519 public key.  */
		if ((eddsa_pk = eddsa_pk_new()) == NULL) {
			error = FIDO_ERR_INTERNAL;
			goto out;
		}
		if (eddsa_pk_decode(pkcbor, eddsa_pk) != 0) {
			error = FIDO_ERR_INVALID_ARGUMENT;
			goto out;
		}

		/* Verify the assertion.  */
		if ((error = fido_assert_verify(assert, idx, alg, eddsa_pk))
		    != FIDO_OK)
			goto out;

		/* Decrypt the ciphertext.  */
		error = decrypt(pkenc, npkenc, hmac_secret, nhmac_secret,
		    ciphertext, nciphertext, payload);
		break;
	case COSE_RS256:	/* RSASSA-PKCS1-v1_5 w/ SHA-256 */
		/* Create and decode our RSA public key.  */
		if ((rs256_pk = rs256_pk_new()) == NULL) {
			error = FIDO_ERR_INTERNAL;
			goto out;
		}
		if (rs256_pk_decode(pkcbor, rs256_pk) != 0) {
			error = FIDO_ERR_INVALID_ARGUMENT;
			goto out;
		}

		/* Verify the assertion.  */
		if ((error = fido_assert_verify(assert, idx, alg, rs256_pk))
		    != FIDO_OK)
			goto out;

		/* Decrypt the ciphertext.  */
		error = decrypt(pkenc, npkenc, hmac_secret, nhmac_secret,
		    ciphertext, nciphertext, payload);
		break;
	default:
		/* Unknown algorithm.  */
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (error)
		goto out;

	/* Success!  */
	*payloadp = payload;
	payload = NULL;
	*npayloadp = npayload;
	error = FIDO_OK;

out:	rs256_pk_free(&rs256_pk);
	eddsa_pk_free(&eddsa_pk);
	es256_pk_free(&es256_pk);
	OPENSSL_cleanse(hash, sizeof(hash));
	OPENSSL_cleanse(&ctx, sizeof(ctx));
	if (payload) {
		OPENSSL_cleanse(payload, npayload);
		free(payload);
	}
	if (pkcbor)
		cbor_decref(&pkcbor);
	if (authdata_cbor)
		cbor_decref(&authdata_cbor);
	return error;
}
