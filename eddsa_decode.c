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

#include "eddsa_decode.h"

#ifdef HAVE_FIDO_ED25519	/* XXX libfido2 >=1.4.0 */

#include <stddef.h>
#include <string.h>

#include <cbor.h>
#include <fido/eddsa.h>
#include <openssl/evp.h>

int
eddsa_pk_decode(const cbor_item_t *item, eddsa_pk_t *pk)
{
	const struct cbor_pair *entry;
	size_t i, n;
	int kty = 0, alg = 0, crv = 0, xset = 0;
	unsigned char x[32];
	EVP_PKEY *pkey = NULL;
	int error;

	if (!cbor_isa_map(item) || !cbor_map_is_definite(item))
		return -1;

	entry = cbor_map_handle(item);
	n = cbor_map_size(item);
	for (i = 0; i < n; i++) {
		int key;

		/* Sanity check: Make sure the entry is initialized.  */
		if (entry[i].key == NULL || entry[i].value == NULL)
			return -1;

		/* Get the entry key as an integer.  */
		if (cbor_isa_uint(entry[i].key)) {
			if (cbor_get_int(entry[i].key) > INT_MAX)
				return -1;
			key = (int)cbor_get_int(entry[i].key);
		} else if (cbor_isa_negint(entry[i].key)) {
			if ((int64_t)~cbor_get_int(entry[i].key) < INT_MIN)
				return -1;
			key = (int)~cbor_get_int(entry[i].key);
		} else {
			return -1;
		}

		/* Dispatch on the entry key.  */
		switch (key) {
		case 1:		/* kty (key type) */
			if (!cbor_isa_uint(entry[i].value) ||
			    cbor_get_int(entry[i].value) > INT_MAX ||
			    kty != 0)
				return -1;
			kty = (int)cbor_get_int(entry[i].value);
			break;
		case 3:		/* alg (algorithm) */
			if (!cbor_isa_negint(entry[i].value) ||
			    (int64_t)~cbor_get_int(entry[i].value) < INT_MIN ||
			    alg != 0)
				return -1;
			alg = (int)~cbor_get_int(entry[i].value);
			break;
		case -1:	/* crv (curve) */
			if (!cbor_isa_uint(entry[i].value) ||
			    cbor_get_int(entry[i].value) > INT_MAX ||
			    crv != 0)
				return -1;
			crv = (int)cbor_get_int(entry[i].value);
			break;
		case -2:	/* `x coordinate' (also y sign bit) */
			if (!cbor_isa_bytestring(entry[i].value) ||
			    cbor_bytestring_length(entry[i].value) != 32 ||
			    xset != 0)
				return -1;
			memcpy(x, cbor_bytestring_handle(entry[i].value), 32);
			xset = 1;
			break;
		default:
			fprintf(stderr, "key=%d\n", key);
			return -1;
		}
	}

	if (kty != COSE_KTY_OKP || alg != COSE_EDDSA || crv != COSE_ED25519)
		return -1;
	if (!xset)
		return -1;

	if ((pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, x,
		    sizeof(x))) == NULL)
		return -1;
	error = eddsa_pk_from_EVP_PKEY(pk, pkey);
	EVP_PKEY_free(pkey);
	return error ? -1 : 0;
}

#endif	/* HAVE_FIDO_ED25519 */
