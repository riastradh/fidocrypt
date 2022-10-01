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

#include "cred_encrypt.h"
#include "fidocrypt.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cbor.h>
#include <fido.h>
#include <fido/es256.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "dae.h"
#include "es256_encode.h"
#include "export.h"

/* Webauthn 6.1 Authenticator Data */
struct authdata {
	uint8_t	rpIdHash[32];
	uint8_t	flags;
	uint8_t	signCount_be[4];
	/* attestedCredentialData */
	uint8_t aaguid[16];
	uint8_t credentialIdLength_be[2];
	uint8_t credentialId[/*credentialIdLength*/];
	/* uint8_t credentialPublicKey[]; */
	/* uint8_t extensions[]; */
};

static uint16_t
dec16be(const void *buf)
{
	const uint8_t *p = buf;
	uint16_t v = 0;

	v |= p[0] << 8;
	v |= p[1];

	return v;
}

static int
es256_strip_pk(const fido_cred_t *cred, cbor_item_t **pkcanoncborp,
    cbor_item_t **pkstripcborp)
{
	const es256_pk_t *pk;
	cbor_item_t *pkcanoncbor = NULL;
	cbor_item_t *pkstripcbor = NULL;
	struct cbor_pair entry[3];
	unsigned i = 0;
	int error;

	memset(entry, 0, sizeof(entry));

	/* Get the public key as decoded by libfido2.  */
	if ((pk = (const void *)fido_cred_pubkey_ptr(cred)) == NULL) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/*
	 * Encode the public key canonically -- just in case the
	 * device's attested credential data had extraneous crud we do
	 * not recover in the public key recovery process for
	 * decryption.
	 */
	if ((pkcanoncbor = es256_pk_encode(pk, /*ecdh*/0)) == NULL) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/*
	 * Create a stripped CBOR public key containing only kty, alg,
	 * and curve, no coordinates.
	 */
	if ((pkstripcbor = cbor_new_definite_map(3)) == NULL) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/* kty(1) [key type] = verify(2) */
	if ((entry[i].key = cbor_build_uint8(1)) == NULL ||
	    (entry[i].value = cbor_build_uint8(2)) == NULL ||
	    !cbor_map_add(pkstripcbor, entry[i++])) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/* alg(3) = ES256(-7) */
	if ((entry[i].key = cbor_build_uint8(3)) == NULL ||
	    (entry[i].value = cbor_build_negint8(~(-7))) == NULL ||
	    !cbor_map_add(pkstripcbor, entry[i++])) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/* curve(-1) = P-256(1) */
	if ((entry[i].key = cbor_build_negint8(~(-1))) == NULL ||
	    (entry[i].value = cbor_build_uint8(1)) == NULL ||
	    !cbor_map_add(pkstripcbor, entry[i++])) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/* Success!  */
	*pkcanoncborp = pkcanoncbor;
	pkcanoncbor = NULL;
	*pkstripcborp = pkstripcbor;
	pkstripcbor = NULL;
	error = FIDO_OK;

out:	while (i --> 0) {
		if (entry[i].value)
			cbor_decref(&entry[i].value);
		if (entry[i].key)
			cbor_decref(&entry[i].key);
	}
	if (pkstripcbor)
		cbor_decref(&pkstripcbor);
	if (pkcanoncbor)
		cbor_decref(&pkcanoncbor);
	return error;
}

static int
strip_pk(const fido_cred_t *cred, unsigned char **pkcanonp, size_t *npkcanonp,
    unsigned char **pkstripp, size_t *npkstripp, bool *recovery_supportedp)
{
	const struct authdata *authdata;
	size_t nauthdata, ncredid;
	const unsigned char *pk;
	size_t npk_max, npk;
	cbor_item_t *pkcbor = NULL;
	struct cbor_load_result load;
	struct cbor_pair *entry;
	size_t i, n;
	int kty = 0, alg = 0, crv = 0;
	cbor_item_t *pkcanoncbor = NULL, *pkstripcbor = NULL;
	unsigned char *pkcanon = NULL, *pkstrip = NULL;
	size_t npkcanon = 0, npkcanonbuf = 0, npkstrip = 0, npkstripbuf = 0;
	bool recovery_supported;
	int error;

	/* Get the authdata.  */
#ifdef HAVE_FIDO_CRED_AUTHDATA_RAW_PTR	/* XXX libfido2 >=1.6.0 */
	if ((authdata = (const void *)fido_cred_authdata_raw_ptr(cred))
	    == NULL) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((nauthdata = fido_cred_authdata_raw_len(cred))
	    < sizeof(*authdata)) {
		error = FIDO_ERR_INVALID_CREDENTIAL;
		goto out;
	}
#else
	const unsigned char *authdata_enc;
	cbor_item_t *authdatacbor = NULL;
	size_t nauthdata_enc;

	if ((authdata_enc = fido_cred_authdata_ptr(cred)) == NULL ||
	    (nauthdata_enc = fido_cred_authdata_len(cred)) == 0) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if ((authdatacbor = cbor_load(authdata_enc, nauthdata_enc, &load))
	    == NULL) {
		error = FIDO_ERR_INVALID_CREDENTIAL;
		goto out;
	}

	if (nauthdata_enc != load.read ||
	    !cbor_isa_bytestring(authdatacbor) ||
	    !cbor_bytestring_is_definite(authdatacbor)) {
		error = FIDO_ERR_INVALID_CREDENTIAL;
		goto out;
	}

	authdata = (const void *)cbor_bytestring_handle(authdatacbor);
	nauthdata = cbor_bytestring_length(authdatacbor);
#endif

	/* Find the suffix where the credential public key starts.  */
	if ((ncredid = dec16be(authdata->credentialIdLength_be))
	    > nauthdata - offsetof(struct authdata, credentialId)) {
		error = FIDO_ERR_INVALID_CREDENTIAL;
		goto out;
	}
	pk = authdata->credentialId + ncredid;
	npk_max = nauthdata - (pk - (const unsigned char *)authdata);

	/* Decode the credential public key as a CBOR item.  */
	if ((pkcbor = cbor_load(pk, npk_max, &load)) == NULL) {
		error = FIDO_ERR_INVALID_CREDENTIAL;
		goto out;
	}
	npk = load.read;

	/* Verify that pk matches the syntax of a COSE public key.  */
	if (!cbor_isa_map(pkcbor) || !cbor_map_is_definite(pkcbor)) {
		error = FIDO_ERR_INVALID_CREDENTIAL;
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

	/* Discriminate on the algorithm (and curve, if appropriate).  */
	switch (alg) {
	case COSE_ES256:
		/*
		 * ECDSA w/ SHA-256.  We can do public key recovery
		 * from a signature, so strip the public key and use
		 * its content as a secret input.
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
		error = es256_strip_pk(cred, &pkcanoncbor, &pkstripcbor);
		if (error)
			goto out;
		if ((npkcanon = cbor_serialize_alloc(pkcanoncbor, &pkcanon,
			    &npkcanonbuf)) == 0 ||
		    (npkstrip = cbor_serialize_alloc(pkstripcbor, &pkstrip,
			    &npkstripbuf)) == 0) {
			error = FIDO_ERR_INTERNAL;
			goto out;
		}
		recovery_supported = true;
		break;
	case COSE_EDDSA:
		/*
		 * Can't do public key recovery with these algorithms.
		 * Just return the public key as is; we will require
		 * the hmac-secret extension.
		 */
		if ((pkcanon = malloc(npk)) == NULL ||
		    (pkstrip = malloc(npk)) == NULL) {
			error = FIDO_ERR_INTERNAL;
			goto out;
		}
		memcpy(pkcanon, pk, npk);
		memcpy(pkstrip, pk, npk);
		npkcanon = npkstrip = npk;
		recovery_supported = false;
		break;
	case COSE_RS256:	/* XXX not yet implemented */
	default:
		error = FIDO_ERR_UNSUPPORTED_ALGORITHM;
		goto out;
	}

	/* Success!  */
	*pkcanonp = pkcanon;
	pkcanon = NULL;
	*npkcanonp = npkcanon;
	*pkstripp = pkstrip;
	pkstrip = NULL;
	*npkstripp = npkstrip;
	*recovery_supportedp = recovery_supported;
	error = 0;

out:	if (pkstrip)
		free(pkstrip);
	if (pkcanon) {
		OPENSSL_cleanse(pkcanon, npkcanon);
		free(pkcanon);
	}
	if (pkstripcbor)
		cbor_decref(&pkstripcbor);
	if (pkcanoncbor)
		cbor_decref(&pkcanoncbor);
	if (pkcbor)
		cbor_decref(&pkcbor);
#ifndef HAVE_FIDO_CRED_AUTHDATA_RAW_PTR	/* XXX libfido2 >=1.6.0 */
	if (authdatacbor)
		cbor_decref(&authdatacbor);
#endif
	return error;
}

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

EXPORT
int
fido_cred_encrypt(const fido_cred_t *cred,
    const fido_assert_t *assert, size_t idx,
    const unsigned char *payload, size_t npayload,
    unsigned char **ciphertextp, size_t *nciphertextp)
{
	unsigned char *pkcanon = NULL, *pkstrip = NULL;
	size_t npkcanon = 0, npkstrip = 0;
	bool recovery_supported = false;
	const unsigned char *hmac_secret = NULL;
	size_t nhmac_secret = 0;
	SHA256_CTX ctx;
	unsigned char key[32];
	unsigned char *ciphertext = NULL;
	size_t nciphertext = 0;
	int error;

	/*
	 * - Fail if the algorithm has no public key recovery and
	 *   there's no hmac-secret extension in the assertion.
	 * - Strip the public key down to parameters if appropriate.
	 * - Hash the public key content and hmac-secret into a key.
	 * - Encrypt with the key, using the public key content as header.
	 *   XXX Is it really necessary to use this as the header?
	 * - Return encode(pk) || ciphertext, where pk is stripped for
	 *   schemes with public key recovery.
	 */

	/* Get the canonical and stripped encoded public keys if we can.  */
	if ((error = strip_pk(cred, &pkcanon, &npkcanon, &pkstrip, &npkstrip,
		    &recovery_supported)) != FIDO_OK)
		return error;

	/*
	 * If an assertion was provided, verify it and get the HMAC
	 * secret from it.
	 */
	if (assert) {
		int alg;
		const void *pk;

		if ((alg = fido_cred_type(cred)) == 0 ||
		    (pk = fido_cred_pubkey_ptr(cred)) == NULL) {
			error = FIDO_ERR_INVALID_CREDENTIAL;
			goto out;
		}
		if ((error = fido_assert_verify(assert, idx, alg, pk))
		    != FIDO_OK)
			goto out;

		hmac_secret = fido_assert_hmac_secret_ptr(assert, idx);
		nhmac_secret = fido_assert_hmac_secret_len(assert, idx);
	}

	/*
	 * If we can't do public key recovery from signatures, and we
	 * don't have an HMAC secret, then we don't have any secret, so
	 * we can't encrypt anything, so fail.
	 */
	if (!recovery_supported && nhmac_secret == 0) {
		error = FIDO_ERR_UNSUPPORTED_OPTION;
		goto out;
	}

	/*
	 * Derive the key.  Each item is self-delimiting/prefix-free,
	 * so we can safely add more inputs to the end later.
	 */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, "FIDOKDF0", 8);
	SHA256_Update(&ctx, pkcanon, npkcanon);
	if (nhmac_secret) {
		if ((error = hash_hmac_secret(&ctx, hmac_secret, nhmac_secret))
		    != 0)
			goto out;
	}
	SHA256_Final(key, &ctx);

	/*
	 * Encrypt the payload with the CBOR representation of the
	 * public key as the header, so that the ciphertext serves as a
	 * commitment to the public key.
	 */
	if (npayload > SIZE_MAX - DAE_TAGBYTES ||
	    npkstrip > SIZE_MAX - DAE_TAGBYTES - npayload) {
		error = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}
	nciphertext = npkstrip + DAE_TAGBYTES + npayload;
	if ((ciphertext = malloc(nciphertext)) == NULL) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}
	memcpy(ciphertext, pkstrip, npkstrip);
	if (!dae_encrypt(ciphertext + npkstrip, pkcanon, npkcanon,
		payload, npayload, key)) {
		error = FIDO_ERR_INTERNAL;
		goto out;
	}

	/* Success!  */
	*ciphertextp = ciphertext;
	ciphertext = NULL;
	*nciphertextp = nciphertext;
	error = FIDO_OK;

out:	if (ciphertext) {
		OPENSSL_cleanse(ciphertext, nciphertext);
		free(ciphertext);
	}
	OPENSSL_cleanse(key, sizeof(key));
	OPENSSL_cleanse(&ctx, sizeof(ctx));
	if (pkstrip) {
		OPENSSL_cleanse(pkstrip, npkstrip);
		free(pkstrip);
	}
	if (pkcanon) {
		OPENSSL_cleanse(pkcanon, npkcanon);
		free(pkcanon);
	}
	return error;
}
