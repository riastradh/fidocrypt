/* -*- Mode: C -*- */

/*-
 * Copyright (c) 2021-2022 Taylor R. Campbell
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
 * XXX TODO:
 *
 * - provide way to keep persistent counter state in file
 * - simulate keepalives
 * - implement fault injection
 * - implement other kinds of fuzzing
 * - implement CTAP2/FIDO2
 * - implement Ed25519 certificates
 * - fix libfido2 API to pass cookies through transport layer
 * - implement I/O layer too
 * - reconsider key handle format to support metadata like solokeys
 *   => cookie(32) || masked-metadata(16) || tag(16)
 */

#include "softfido.h"

#ifdef HAVE_FIDO_CUSTOM_TRANSPORT

#include <sys/cdefs.h>
#include <sys/param.h>

#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <string.h>

#if __STDC_VERSION__ >= 201112L
#include <assert.h>
#define	CTASSERT(x)	static_assert(x, #x)
#else
#ifdef __COUNTER__
#define	CTASSERT(x)		CTASSERT1(x, ctassert, __COUNTER__)
#else
#define	CONCAT(u,v)		u##v
#define	CTASSERT(x)		CTASSERT0(x, __INCLUDE_LEVEL__, __LINE__)
#define	CTASSERT0(x,u,v)	CTASSERT1(x, CONCAT(level_,u), CONCAT(line_,v))
#endif
#define	CTASSERT1(x,u,v)	CTASSERT2(x,u,v)
#define	CTASSERT2(x,u,v)						      \
	struct ctassert_##u##_##v {					      \
		unsigned int u##v : ((x) ? 1 : -1);			      \
	}
#endif

static inline void
be16enc(void *buf, uint32_t x)
{
	uint8_t *p = buf;

	p[0] = x >> 8;
	p[1] = x;
}

static inline void
be32enc(void *buf, uint32_t x)
{
	uint8_t *p = buf;

	p[0] = x >> 24;
	p[1] = x >> 16;
	p[2] = x >> 8;
	p[3] = x;
}

#define	SOFTFIDO_VERSION_MAJOR	0
#define	SOFTFIDO_VERSION_MINOR	0
#define	SOFTFIDO_VERSION_BUILD	0

#define	SOFTFIDO_V0	"//softfido/v0/"

/*
 * Original upstream reference for this from the U2F specification has
 * vanished:
 *
 * [U2FHIDHeader] J. Ehrensvard, FIDO U2F HID Header Files v1.0. FIDO
 *   Alliance Review Draft (Work in progress.) URL:
 *   https://github.com/fido-alliance/u2f-specs/blob/master/inc/u2f_hid.h
 *
 * Instead, we use the CTAPHID commands in CTAP 2.1:
 *
 * [CTAP2.1] Client to Authenticator Protocol (CTAP), version 2.1, June
 *   15, 2021.
 *   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-commands
 */
#define	CTAPHID_PING		0x01
#define	CTAPHID_MSG		0x03
#define	CTAPHID_LOCK		0x04
#define	CTAPHID_INIT		0x06
#define	CTAPHID_WINK		0x08
#define	CTAPHID_CBOR		0x10 /* CTAP2 */
#define	CTAPHID_CANCEL		0x11 /* CTAP2 */
#define	CTAPHID_ERROR		0x3f
#define	CTAPHID_KEEPALIVE	0x3b

struct ctaphid_init_req {
	uint8_t nonce[8];
};
CTASSERT(sizeof(struct ctaphid_init_req) == 8);

struct ctaphid_init_rep {
	uint8_t	nonce[8];
	uint8_t	cid[4];
	uint8_t	proto_version;
	uint8_t	dev_major;
	uint8_t	dev_minor;
	uint8_t	dev_build;
	uint8_t	cap;
#define	CTAPHID_CAPABILITY_WINK	0x01
#define	CTAPHID_CAPABILITY_CBOR	0x04
#define	CTAPHID_CAPABILITY_NMSG	0x08
};
CTASSERT(sizeof(struct ctaphid_init_rep) == 17);

struct ctaphid_error {
	uint8_t	code;
#define	CTAPHID_ERR_INVALID_CMD		0x01
#define	CTAPHID_ERR_INVALID_PAR		0x02
#define	CTAPHID_ERR_INVALID_LEN		0x03
#define	CTAPHID_ERR_INVALID_SEQ		0x04
#define	CTAPHID_ERR_MSG_TIMEOUT		0x05
#define	CTAPHID_ERR_CHANNEL_BUSY	0x06
#define	CTAPHID_ERR_LOCK_REQUIRED	0x0a
#define	CTAPHID_ERR_INVALID_CHANNEL	0x0b
#define	CTAPHID_ERR_OTHER		0x7f
};

struct ctaphid_keepalive {
	uint8_t	status;
#define	CTAPHID_KEEPALIVE_PROCESSING	1
#define	CTAPHID_KEEPALIVE_UPNEEDED	2
};

struct ctaphid_lock {
	uint8_t	time_sec;
};

struct iso7816 {
	uint8_t cla;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	uint8_t lc1;
	uint8_t lc2;
	uint8_t lc3;
	uint8_t payload[];
};

#define	U2F_SW_NO_ERROR			0x9000
#define	U2F_SW_CONDITIONS_NOT_SATISFIED	0x6985
#define	U2F_SW_WRONG_DATA		0x6a80
#define	U2F_SW_WRONG_LENGTH		0x6700
#define	U2F_SW_CLA_NOT_SUPPORTED	0x6e00
#define	U2F_SW_INS_NOT_SUPPORTED	0x6d00
#define	U2F_SW_INTERNAL_EXCEPTION	0x6f00 /* not in U2F but in ISO 7816 */

#define	U2F_CMD_REGISTER	0x01
#define	U2F_CMD_AUTHENTICATE	0x02
#define	U2F_CMD_VERSION		0x03

#define	U2F_MAXSIGLEN	73

struct u2f_register_req {
	uint8_t challenge[32];
	uint8_t application[32];
};

struct u2f_register_rep {
	uint8_t reserved0;
	uint8_t pubkey[65];
	uint8_t L;
	uint8_t stuff[];
	/*
	 * uint8_t keyhandle[L];
	 * uint8_t attestation[];	// variable-length, X.509 DER
	 * uint8_t sig[];		// variable-length, ECDSA signature
	 */
};

struct u2f_authenticate_req {
	uint8_t challenge[32];
	uint8_t application[32];
	uint8_t L;
	uint8_t keyhandle[/*L*/];
};

struct u2f_authenticate_rep {
	uint8_t user_presence;
	uint8_t counter[4];
	uint8_t sig[];		/* variable-length, ECDSA signature */
};

#include <fido.h>

struct softfido {
	uint8_t masterkey[32];

	/* channel state */
	uint8_t nonce[8];

	/* signature counter */
	int (*countsig)(struct softfido *, uint32_t *);

	/* fast key erasure RNG */
	unsigned nrandom;
	uint8_t randomnonce[24];
	uint8_t randombuf[1024];

	/* pending reply */
	uint8_t replycode;
	size_t replylen;
	union {
		struct ctaphid_init_rep init;
		/* XXX CBOR */
		struct ctaphid_error error;
		struct ctaphid_keepalive keepalive;
		uint8_t buf[65536];
	} reply;
};

#include <openssl/evp.h>

static uint8_t softfido_seed[32];

void
softfido_randomseed(const uint8_t seed[static 32])
{

	memcpy(softfido_seed, seed, 32);
}

static int
softfido_randomrefill(struct softfido *S)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int L = 0;
	unsigned i, c;
	int error = -1;

	CTASSERT(sizeof(S->randombuf) <= INT_MAX);

	assert(S->nrandom == 0);

	/*
	 * k := S->randombuf[0..32)
	 * S->randombuf[0..1024) := ChaCha_k(0)[0..1024)
	 */
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		goto out;
	if (!EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, S->randombuf,
		S->randomnonce))
		goto out;
	memset(S->randombuf, 0, sizeof(S->randombuf));
	if (!EVP_EncryptUpdate(ctx, S->randombuf, &L, S->randombuf,
		(int)sizeof(S->randombuf)))
		goto out;
	assert(L == (int)sizeof(S->randombuf));
	if (!EVP_EncryptFinal(ctx, NULL, &L))
		goto out;
	assert(L == 0);

	/* Success!  */
	S->nrandom = sizeof(S->randombuf) - 32;
	error = 0;

out:	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	/* increment nonce (unconditionally, out of paranoia) */
	for (i = 0, c = 1; i < sizeof(S->randomnonce); i++) {
		c += S->randomnonce[i];
		S->randomnonce[i] = c & 0xff;
	}
	return error;
}

static int
softfido_randombytes(struct softfido *S, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t k, n = len;

	assert(S->nrandom <= sizeof(S->randombuf) - 32);
	for (;;) {
		k = MIN(n, S->nrandom);
		memcpy(p, &S->randombuf[sizeof(S->randombuf) - S->nrandom], k);
		memset(&S->randombuf[sizeof(S->randombuf) - S->nrandom], 0, k);
		S->nrandom -= k;
		n -= k;
		if (n == 0)
			break;
		if (softfido_randomrefill(S))
			return -1;
	}

	return 0;
}

#include <openssl/hmac.h>
#include <openssl/crypto.h>

static int
u2f_derive_token(uint8_t token[32],
    const uint8_t masterkey[32],
    const uint8_t randomization[32],
    const uint8_t challenge[32],
    const uint8_t application[32])
{
	static const uint8_t prefix[32] = "softfido key handle tokenization";
	HMAC_CTX *hmac = NULL;
	uint8_t hash[64];
	int error = -1;

	if ((hmac = HMAC_CTX_new()) == NULL)
		goto out;
	if (!HMAC_Init_ex(hmac, masterkey, 32, EVP_sha512(), NULL))
		goto out;
	if (!HMAC_Update(hmac, prefix, 32))
		goto out;
	if (!HMAC_Update(hmac, randomization, 32))
		goto out;
	if (!HMAC_Update(hmac, challenge, 32))
		goto out;
	if (!HMAC_Update(hmac, application, 32))
		goto out;
	if (!HMAC_Final(hmac, hash, NULL))
		goto out;

	/* Success!  */
	memcpy(token, hash, 32);
	error = 0;

out:	OPENSSL_cleanse(hash, sizeof(hash));
	if (hmac)
		HMAC_CTX_free(hmac);
	return error;
}

/*
 * seed(32) || tag(32) := HMAC-SHA512_masterkey(
 *   `softfido key handle derivation\0'(32) || token(32) || application(32))
 */
static int
u2f_handle_kdf(uint8_t seed[const 32],
    uint8_t tag[static 32],
    const uint8_t masterkey[static 32],
    const uint8_t token[static 32],
    const uint8_t application[static 32])
{
	static const uint8_t prefix[32] = "softfido key handle derivation";
	HMAC_CTX *hmac = NULL;
	uint8_t hash[64];
	int error = -1;

	if ((hmac = HMAC_CTX_new()) == NULL)
		goto out;
	if (!HMAC_Init_ex(hmac, masterkey, 32, EVP_sha512(), NULL))
		goto out;
	if (!HMAC_Update(hmac, prefix, 32))
		goto out;
	if (!HMAC_Update(hmac, token, 32))
		goto out;
	if (!HMAC_Update(hmac, application, 32))
		goto out;
	if (!HMAC_Final(hmac, hash, NULL))
		goto out;

	/* Success!  */
	memcpy(seed, hash, 32);
	memcpy(tag, hash + 32, 32);
	error = 0;

out:	OPENSSL_cleanse(hash, sizeof(hash));
	if (hmac)
		HMAC_CTX_free(hmac);
	return error;
}

#include <openssl/ec.h>
#include <openssl/crypto.h>

struct keyhandle {
	uint8_t	token[32];
	/* XXX use 16 bytes of metadata and a 16-byte tag */
	uint8_t	tag[32];
};

struct u2f_key {
	EC_KEY *signkey;
	uint8_t pubkey[65];
};

static void
u2f_key_destroy(struct u2f_key *K)
{

	if (K->signkey)
		EC_KEY_free(K->signkey);

	OPENSSL_cleanse(K, sizeof(*K));
}

static int
u2f_key_expand(struct u2f_key *K, const uint8_t seed[static 32])
{
	EC_GROUP *nistp256 = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *scalar;
	EC_POINT *point = NULL;
	unsigned char *pubkey = NULL;
	size_t npubkey;
	int error = -1;

	/* Get the NIST P-256 parameters.  */
	nistp256 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (nistp256 == NULL)
		goto out;

	/* Create a bignum context for operation with secret keys.  */
	if ((ctx = BN_CTX_secure_new()) == NULL)
		goto out;

	/*
	 * Allocate a temporary scalar, a public point, and an EC_KEY
	 * to return.
	 */
	if ((scalar = BN_CTX_get(ctx)) == NULL ||
	    (point = EC_POINT_new(nistp256)) == NULL ||
	    (K->signkey = EC_KEY_new()) == NULL)
		goto out;

	/* Interpret the 32-byte seed in little-endian as a scalar.  */
	if ((BN_lebin2bn(seed, 32, scalar)) == NULL)
		goto out;

	/* Compute the public point.  */
	if (!EC_POINT_mul(nistp256, point, scalar, NULL, NULL, ctx))
		goto out;

	/* Set the group and private scalar of the EC_KEY.  */
	if (!EC_KEY_set_group(K->signkey, nistp256) ||
	    !EC_KEY_set_private_key(K->signkey, scalar) ||
	    !EC_KEY_set_public_key(K->signkey, point))
		goto out;

	if (!EC_KEY_check_key(K->signkey))
		goto out;

	/* Format the public key.  */
	npubkey = EC_KEY_key2buf(K->signkey, POINT_CONVERSION_UNCOMPRESSED,
	    &pubkey, ctx);
	if (npubkey == 0)
		goto out;
	assert(npubkey == sizeof(K->pubkey));
	memcpy(K->pubkey, pubkey, sizeof(K->pubkey));

	/* Success!  */
	error = 0;

out:	if (pubkey)
		OPENSSL_clear_free(pubkey, npubkey);
	if (point)
		EC_POINT_free(point);
	if (ctx)
		BN_CTX_free(ctx);
	if (nistp256)
		EC_GROUP_free(nistp256);
	if (error)
		u2f_key_destroy(K);
	return error;
}

static int
u2f_key_generate(struct softfido *S, struct u2f_key *K, struct keyhandle *H,
    const uint8_t challenge[static 32],
    const uint8_t application[static 32])
{
	uint8_t randomization[32], token[32], seed[32], tag[32];
	int error = -1;

	memset(K, 0, sizeof(*K)); /* paranoia */

	/* Randomize the key handle.  */
	if (softfido_randombytes(S, randomization, sizeof(randomization)))
		goto out;

	/*
	 * Derive a token from the master key, the randomization, the
	 * challenge, and the application.  This 256-bit quantity
	 * uniquely identifies a key pair.
	 */
	if (u2f_derive_token(token, S->masterkey, randomization, challenge,
		application))
		goto out;

	/*
	 * Derive a seed and a tag from the master key, the token, and
	 * the application.
	 */
	if (u2f_handle_kdf(seed, tag, S->masterkey, token, application))
		goto out;

	/* Expand the seed into a key pair.  */
	if (u2f_key_expand(K, seed))
		goto out;

	/* Format the key handle.  */
	memcpy(H->token, token, 32);
	memcpy(H->tag, tag, 32);

	/* Success!  */
	error = 0;

out:	OPENSSL_cleanse(randomization, sizeof(randomization));
	if (error)
		u2f_key_destroy(K);
	return error;
}

static int
u2f_key_open(struct softfido *S, struct u2f_key *K,
    const struct keyhandle *H,
    const uint8_t application[static 32])
{
	uint8_t seed[32], tag[32];
	int error = -1;

	/*
	 * Derive the seed and expected tag from the softfido, master
	 * key, the key handle's token, and the calling application.
	 */
	if (u2f_handle_kdf(seed, tag, S->masterkey, H->token, application))
		goto out;

	/* Verify the tag.  */
	if (CRYPTO_memcmp(tag, H->tag, 32) != 0) {
		error = 1;	/* invalid key handle */
		goto out;
	}

	/* Expand the seed into a key pair.  */
	if (u2f_key_expand(K, seed))
		goto out;

	/* Success!  */
	error = 0;

out:	OPENSSL_cleanse(seed, sizeof(seed));
	OPENSSL_cleanse(tag, sizeof(tag));
	if (error)
		u2f_key_destroy(K);
	return error;
}

#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

int
u2f_sign(void *sig, size_t maxsiglen, size_t *siglenp,
    const void *buf, size_t len,
    EC_KEY *eckey)
{
	SHA256_CTX sha256;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	unsigned siglen = MIN(maxsiglen, INT_MAX);
	int error = -1;

	/* Hash the message with SHA-256.  */
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, buf, len);
	SHA256_Final(hash, &sha256);

	/* Compute the elliptic curve part of the ECDSA signature.  */
	if (!ECDSA_sign(/*ignore*/0, hash, sizeof(hash), sig, &siglen, eckey))
		goto out;
	assert(siglen <= INT_MAX);

	/*
	 * Verify the signature matches the intermediate hash.  (This
	 * detects faults during the elliptic curve arithmetic,
	 * although not during the hashing.)
	 */
	if (!ECDSA_verify(/*ignore*/0, hash, sizeof(hash), sig, siglen, eckey))
		goto out;

	/* Success!  Return the signature length.  */
	*siglenp = siglen;
	error = 0;

out:	if (error)		/* paranoia: don't expose faulty signature */
		OPENSSL_cleanse(sig, maxsiglen);
	OPENSSL_cleanse(hash, sizeof(hash));
	OPENSSL_cleanse(&sha256, sizeof(sha256));
	return error;
}

#include <openssl/ec.h>
#include <openssl/crypto.h>

static const unsigned char the_attestation_cert[] = {
	0x30,0x82,0x01,0x3b,0x30,0x81,0xe1,0x02,
	0x14,0x09,0x82,0x33,0x85,0x47,0x36,0x74,
	0x12,0x03,0x14,0x20,0x61,0x04,0xb1,0xcd,
	0xb9,0x5e,0x14,0xd6,0x52,0x30,0x0a,0x06,
	0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,
	0x02,0x30,0x20,0x31,0x1e,0x30,0x1c,0x06,
	0x03,0x55,0x04,0x03,0x0c,0x15,0x66,0x69,
	0x64,0x6f,0x63,0x72,0x79,0x70,0x74,0x2e,
	0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x2e,
	0x63,0x6f,0x6d,0x30,0x1e,0x17,0x0d,0x32,
	0x31,0x31,0x31,0x31,0x33,0x31,0x38,0x35,
	0x37,0x30,0x34,0x5a,0x17,0x0d,0x34,0x31,
	0x30,0x37,0x33,0x31,0x31,0x38,0x35,0x37,
	0x30,0x34,0x5a,0x30,0x20,0x31,0x1e,0x30,
	0x1c,0x06,0x03,0x55,0x04,0x03,0x0c,0x15,
	0x66,0x69,0x64,0x6f,0x63,0x72,0x79,0x70,
	0x74,0x2e,0x65,0x78,0x61,0x6d,0x70,0x6c,
	0x65,0x2e,0x63,0x6f,0x6d,0x30,0x59,0x30,
	0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,
	0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,
	0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,
	0xc0,0x9e,0x3d,0x3c,0xa9,0x71,0x79,0x1b,
	0x10,0x75,0x4b,0xf7,0x1e,0x3a,0x4d,0x95,
	0x10,0x2d,0x97,0xb7,0x90,0x55,0xe8,0x16,
	0xec,0x55,0x0e,0x1e,0x30,0x9e,0xf9,0xd3,
	0xc7,0x6f,0x2a,0x0a,0xf3,0x2a,0xa0,0x97,
	0x1a,0xac,0xf0,0x6e,0xca,0xb4,0x46,0x17,
	0xf3,0x24,0xfc,0x30,0xeb,0x42,0x93,0x65,
	0xe3,0x32,0x1e,0xe9,0x26,0x29,0xbb,0x70,
	0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,
	0x3d,0x04,0x03,0x02,0x03,0x49,0x00,0x30,
	0x46,0x02,0x21,0x00,0xf5,0x15,0x2f,0x88,
	0xf2,0xd0,0x8f,0x74,0x84,0x4b,0xdf,0x9b,
	0x6b,0x5f,0xd0,0x89,0x0f,0xb6,0x49,0xe1,
	0x89,0xf9,0xa5,0x12,0xf8,0x43,0xf3,0x9c,
	0xe1,0xf7,0x7a,0x37,0x02,0x21,0x00,0xa3,
	0xfa,0xba,0x3a,0x11,0x93,0x89,0x40,0x73,
	0x4d,0x1f,0x6d,0xf9,0xf2,0x32,0x61,0x45,
	0x21,0x63,0xee,0x80,0x5f,0x82,0x02,0x8c,
	0x8c,0x87,0xd6,0xa4,0x92,0x64,0x22,
};

static EC_KEY *the_attestation_key;
static const char the_attestation_key_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWJGFbePp9etv2oLM\n"
    "42PvRDtHlXdfB7ZLH6T/ept79W6hRANCAATAnj08qXF5GxB1S/ceOk2VEC2Xt5BV\n"
    "6BbsVQ4eMJ7508dvKgrzKqCXGqzwbsq0RhfzJPww60KTZeMyHukmKbtw\n"
    "-----END PRIVATE KEY-----\n";

static uint16_t
u2f_register(struct softfido *S, uint8_t p1, uint8_t p2,
    const void *reqbuf, size_t reqlen,
    void *repbuf, size_t replen, size_t *replenp)
{
	const struct u2f_register_req *req = reqbuf;
	struct u2f_register_rep *rep = repbuf;
	struct u2f_key key;
	struct keyhandle handle;
	struct {
		uint8_t zero[1];
		uint8_t application[32];
		uint8_t challenge[32];
		uint8_t handle[sizeof(handle)];
		uint8_t pubkey[sizeof(key.pubkey)];
	} sigdata;
	const uint8_t *cert;
	uint8_t sig[U2F_MAXSIGLEN];
	size_t certlen, siglen;
	size_t handleoff, certoff, sigoff;
	uint16_t sw = U2F_SW_INTERNAL_EXCEPTION;

	memset(&key, 0, sizeof(key));
	memset(&handle, 0, sizeof(handle));
	memset(&sigdata, 0, sizeof(sigdata));
	memset(sig, 0, sizeof(sig));

	/* Caller should have provided ample storage for reply.  */
	assert(sizeof(*rep) <= replen);

	/* Verify the P1 and P2 bytes of the ISO 4718 APDU are zero.  */
	if (p1 != 0 || p2 != 0) {
		sw = U2F_SW_WRONG_DATA;
		goto out;
	}

	/* Verify the request is the right length.  */
	if (reqlen != sizeof(*req)) {
		sw = U2F_SW_WRONG_LENGTH;
		goto out;
	}

	/* Create a key from the challenge and application.  */
	if (u2f_key_generate(S, &key, &handle, req->challenge,
		req->application))
		goto out;

	/* Determine the attestation certificate.  */
	cert = the_attestation_cert;
	certlen = sizeof(the_attestation_cert);

	/*
	 * Sign the application, challenge, key handle, and public key
	 * for device attestation.
	 */
	memset(sigdata.zero, 0, sizeof(sigdata.zero));
	memcpy(sigdata.application, req->application, 32);
	memcpy(sigdata.challenge, req->challenge, 32);
	memcpy(sigdata.handle, &handle, sizeof(handle));
	memcpy(sigdata.pubkey, key.pubkey, sizeof(key.pubkey));
	if (u2f_sign(sig, sizeof(sig), &siglen, &sigdata, sizeof(sigdata),
		the_attestation_key))
		goto out;
	assert(siglen <= sizeof(sig));

	/*
	 * Compute where the attestation certificate and signature go,
	 * relative to rep->stuff.
	 */
	handleoff = 0;
	if (sizeof(handle) > replen - handleoff)
		goto out;
	certoff = handleoff + sizeof(handle);
	if (certlen > replen - certoff)
		goto out;
	sigoff = certoff + certlen;
	if (siglen > replen - sigoff)
		goto out;

	/* Format the reply.  */
	rep->reserved0 = 0x05;
	memcpy(rep->pubkey, key.pubkey, sizeof(key.pubkey));
	CTASSERT(sizeof(handle) <= UINT8_MAX);
	rep->L = sizeof(handle);
	memcpy(&rep->stuff[handleoff], &handle, sizeof(handle));
	memcpy(&rep->stuff[certoff], cert, certlen);
	memcpy(&rep->stuff[sigoff], sig, siglen);
	*replenp = offsetof(struct u2f_register_rep, stuff[sigoff + siglen]);

	/* Success!  */
	sw = U2F_SW_NO_ERROR;

out:	u2f_key_destroy(&key);
	OPENSSL_cleanse(sig, sizeof(sig));
	OPENSSL_cleanse(&sigdata, sizeof(sigdata));
	OPENSSL_cleanse(&handle, sizeof(handle));
	OPENSSL_cleanse(&key, sizeof(key));
	return sw;
}

static uint16_t
u2f_authenticate(struct softfido *S, uint8_t p1, uint8_t p2,
    const void *reqbuf, size_t reqlen,
    void *repbuf, size_t replen, size_t *replenp)
{
	const struct u2f_authenticate_req *req = reqbuf;
	const struct keyhandle *handle = (const void *)req->keyhandle;
	struct u2f_key key;
	uint8_t user_presence = 1; /* XXX make controllable */
	struct {
		uint8_t application[32];
		uint8_t user_presence;
		uint8_t counter[4];
		uint8_t challenge[32];
	} sigdata;
	uint32_t counter;
	uint8_t sig[U2F_MAXSIGLEN];
	size_t siglen;
	struct u2f_authenticate_rep *rep = repbuf;
	uint16_t sw = U2F_SW_INTERNAL_EXCEPTION;

	memset(&key, 0, sizeof(key));
	memset(&sigdata, 0, sizeof(sigdata));

	/* Caller should have provided ample storage for reply.  */
	assert(offsetof(struct u2f_authenticate_rep, sig[U2F_MAXSIGLEN]) <=
	    replen);

	/* Verify the P2 byte of the ISO 4718 APDU is zero.  */
	if (p2 != 0) {
		sw = U2F_SW_WRONG_DATA;
		goto out;
	}

	/* Validate the P1 byte.  */
	switch (p1) {
	case 0x03:		/* check only */
	case 0x07:		/* enforce user presence and sign */
	case 0x08:		/* don't enforce user presence and sign */
		break;
	default:
		sw = U2F_SW_WRONG_DATA;
		goto out;
	}

	/* Verify the key handle length is what we use.  */
	if (req->L != sizeof(*handle)) {
		sw = U2F_SW_WRONG_LENGTH;
		goto out;
	}

	/* Verify the request length.  */
	if (reqlen != offsetof(struct u2f_authenticate_req,
		keyhandle[sizeof(*handle)])) {
		sw = U2F_SW_WRONG_LENGTH;
		goto out;
	}

	/* Validate the key handle and get the key.  */
	switch (u2f_key_open(S, &key, handle, req->application)) {
	case 0:			/* success */
		break;
	case 1:			/* invalid handle */
		sw = U2F_SW_WRONG_DATA;
		goto out;
	case -1:		/* internal error */
	default:
		sw = U2F_SW_INTERNAL_EXCEPTION;
		goto out;
	}

	/* If the caller asked for check-only, then stop here.  */
	if (p1 == 0x07) {
		/* Simulate user-not-present.  */
		sw = U2F_SW_CONDITIONS_NOT_SATISFIED;
		goto out;
	}
	assert(p1 == 0x03 || p1 == 0x08);

	/* Count another authentication operation.  */
	if ((*S->countsig)(S, &counter))
		goto out;

	/*
	 * Sign the application, user presence byte, big-endian 32-bit
	 * signature counter, and challenge.
	 */
	memcpy(sigdata.application, req->application, 32);
	sigdata.user_presence = user_presence;
	be32enc(sigdata.counter, counter);
	memcpy(sigdata.challenge, req->challenge, 32);
	if (u2f_sign(&sig, sizeof(sig), &siglen, &sigdata, sizeof(sigdata),
		key.signkey))
		goto out;
	assert(siglen <= sizeof(sig));

	/* Format the reply.  */
	rep->user_presence = user_presence;
	be32enc(rep->counter, counter);
	memcpy(rep->sig, sig, siglen);
	*replenp = offsetof(struct u2f_authenticate_rep, sig[siglen]);

	/* Success!  */
	sw = U2F_SW_NO_ERROR;

out:	OPENSSL_cleanse(&sig, sizeof(sig));
	OPENSSL_cleanse(&sigdata, sizeof(sigdata));
	u2f_key_destroy(&key);
	return sw;
}

static uint16_t
u2f_version(struct softfido *S, uint8_t p1, uint8_t p2,
    const void *reqbuf, size_t reqlen,
    void *repbuf, size_t replen, size_t *replenp)
{
	static const uint8_t version[6] = "U2F_V2"; /* no NUL terminator */
	uint16_t sw = U2F_SW_INTERNAL_EXCEPTION;

	(void)S;
	(void)reqbuf;

	/* Caller should have provided ample storage for reply.  */
	assert(sizeof(version) <= replen);

	/* Verify the P1 and P2 bytes of the ISO 4718 APDU are zero.  */
	if (p1 != 0 || p2 != 0) {
		sw = U2F_SW_WRONG_DATA;
		goto out;
	}

	/* Verify the request is empty.  */
	if (reqlen > 0) {
		sw = U2F_SW_WRONG_LENGTH;
		goto out;
	}

	/* Return the reply.  */
	memcpy(repbuf, version, sizeof(version));
	*replenp = sizeof(version);

	/* Success!  */
	sw = U2F_SW_NO_ERROR;

out:	return sw;
}

#include <openssl/crypto.h>

static size_t
softfido_u2f(struct softfido *S,
    const void *reqbuf, size_t reqlen,
    void *repbuf, size_t replen_max)
{
	const struct iso7816 *req = reqbuf;
	const void *payload;
	uint16_t payloadlen;
	uint8_t *rep = repbuf;
	size_t replen = 0;
	uint16_t sw;

	/* Caller should have provided ample storage for reply.  */
	assert(sizeof(sw) <= replen_max);

	/*
	 * Verify the request has enough space for a header and uses
	 * extended length encoding.
	 */
	if (reqlen < sizeof(*req) || req->lc1 != 0) {
		sw = U2F_SW_WRONG_LENGTH;
		goto out;
	}

	/*
	 * Get the payload pointer and determine the payload length.
	 * Verify the payload fits within the request framing.
	 */
	payload = req->payload;
	payloadlen = ((uint16_t)req->lc2 << 8) | req->lc3;
	if (payloadlen > reqlen - offsetof(struct iso7816, payload)) {
		sw = U2F_SW_WRONG_LENGTH;
		goto out;
	}

	/* Verify CLA is zero.  */
	if (req->cla != 0) {
		sw = U2F_SW_CLA_NOT_SUPPORTED;
		goto out;
	}

	/* Dispatch on the U2F command in INS.  */
	switch (req->ins) {
	case U2F_CMD_REGISTER:
		sw = u2f_register(S, req->p1, req->p2, payload, payloadlen,
		    rep, replen_max, &replen);
		break;
	case U2F_CMD_AUTHENTICATE:
		sw = u2f_authenticate(S, req->p1, req->p2, payload, payloadlen,
		    rep, replen_max, &replen);
		break;
	case U2F_CMD_VERSION:
		sw = u2f_version(S, req->p1, req->p2, payload, payloadlen,
		    rep, replen_max, &replen);
		break;
	default:
		sw = U2F_SW_INS_NOT_SUPPORTED;
		break;
	}

out:	/* Set the status word and return the length.  */
	assert(replen <= replen_max);
	if (replen > replen_max - sizeof(sw)) {
		/*
		 * If adding the status word would overflow the buffer,
		 * nix the reply and just fail.
		 */
		OPENSSL_cleanse(rep, replen);
		sw = U2F_SW_INTERNAL_EXCEPTION;
		replen = 0;
	}
	be16enc(&rep[replen], sw);
	return replen + sizeof(sw);
}

static const uint8_t the_cid[4] = {0x10, 0x32, 0x54, 0x76}; /* XXX */

static int
softfido_transport_tx(fido_dev_t *D, uint8_t cmd,
    const unsigned char *buf, size_t len)
{
	struct softfido *S = fido_dev_io_handle(D);

	/* Paranoia: zero the reply buffer.  */
	memset(S->reply.buf, 0, sizeof(S->reply.buf));

	switch (cmd) {
	case CTAPHID_PING:
		if (len > sizeof(S->reply.buf)) {
			S->replycode = CTAPHID_ERROR;
			S->replylen = sizeof(S->reply.error);
			S->reply.error.code = CTAPHID_ERR_INVALID_LEN;
			break;
		}
		S->replycode = CTAPHID_PING;
		S->replylen = len;
		memcpy(S->reply.buf, buf, len);
		break;
	case CTAPHID_MSG:
		S->replycode = CTAPHID_MSG;
		S->replylen = softfido_u2f(S, buf, len,
		    S->reply.buf, sizeof(S->reply.buf));
		assert(S->replylen <= sizeof(S->reply.buf));
		break;
	case CTAPHID_INIT: {
		const struct ctaphid_init_req *req = (const void *)buf;
		if (len != sizeof(*req)) {
			S->replycode = CTAPHID_ERR_INVALID_LEN;
			break;
		}
		S->replycode = CTAPHID_INIT;
		S->replylen = sizeof(S->reply.init);
		memcpy(S->reply.init.nonce, req->nonce, 8);
		memcpy(S->reply.init.cid, the_cid, 4);
		S->reply.init.proto_version = 2;
		S->reply.init.dev_major = SOFTFIDO_VERSION_MAJOR;
		S->reply.init.dev_minor = SOFTFIDO_VERSION_MINOR;
		S->reply.init.dev_build = SOFTFIDO_VERSION_BUILD;
		S->reply.init.cap = 0;
		break;
	}
	case CTAPHID_LOCK:	/* XXX NYI lock */
	case CTAPHID_WINK:	/* XXX NYI winking */
	case CTAPHID_CBOR:	/* XXX NYI FIDO CTAP2 */
	case CTAPHID_CANCEL:	/* XXX NYI cancel CTAP2 */
	case CTAPHID_ERROR:
	case CTAPHID_KEEPALIVE:
	default:
		S->replycode = CTAPHID_ERROR;
		S->replylen = sizeof(S->reply.error);
		S->reply.error.code = CTAPHID_ERR_INVALID_CMD;
		break;
	}

	return 0;
}

static int
softfido_transport_rx(fido_dev_t *D, uint8_t cmd,
    unsigned char *buf, size_t len, int timeout_ms)
{
	struct softfido *S = fido_dev_io_handle(D);
	int n;

	(void)timeout_ms;

	if (S->replycode != cmd)
		return -1;
	assert(S->replylen <= INT_MAX);
	n = MIN(len, S->replylen);
	memcpy(buf, S->reply.buf, n);
	return n;
}

static const fido_dev_transport_t softfido_transport = {
	.tx = softfido_transport_tx,
	.rx = softfido_transport_rx,
};

static uint32_t sigcounter;	/* XXX */

static int
countsig(struct softfido *S, uint32_t *counterp)
{

	/* XXX store counter persistently somewhere */
	(void)S;
	*counterp = sigcounter++;
	return 0;
}

static int
hexdec(unsigned char c)
{

	if ('0' <= c && c <= '9')
		return c - '0';
	if ('a' <= c && c <= 'f')
		return 10 + c - 'a';
	return -1;
}

static void *
softfido_io_open(const char *path)
{
	uint8_t key[32];
	struct softfido *S;
	SHA256_CTX sha256;
	unsigned i;

	if (strncmp(path, SOFTFIDO_V0, strlen(SOFTFIDO_V0)) != 0)
		return NULL;
	path += strlen(SOFTFIDO_V0);
	for (i = 0; i < 32; i++) {
		int lo, hi;

		if ((hi = hexdec(path[2*i + 0])) == -1 ||
		    (lo = hexdec(path[2*i + 1])) == -1)
			return NULL;
		key[i] = (hi << 4) | lo;
	}
	if (path[2*i] != '\0')
		return NULL;

	if ((S = malloc(sizeof(*S))) == NULL)
		return NULL;
	S->countsig = &countsig;
	memcpy(S->masterkey, key, 32);
	S->nrandom = 0;
	memset(S->randombuf, 0, sizeof(S->randombuf));
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, key, sizeof(key));
	SHA256_Update(&sha256, softfido_seed, sizeof(softfido_seed));
	SHA256_Final(S->randombuf, &sha256);
	return S;
}

static void
softfido_io_close(void *cookie)
{
	struct softfido *S = cookie;

	OPENSSL_cleanse(S, sizeof(*S));
	free(S);
}

static int
softfido_io_read(void *cookie, unsigned char *buf, size_t len, int timeout_ms)
{

	(void)cookie;
	(void)buf;
	(void)len;
	(void)timeout_ms;
	assert(!"no read");
}

static int
softfido_io_write(void *cookie, const unsigned char *buf, size_t len)
{

	(void)cookie;
	(void)buf;
	(void)len;
	assert(!"no read");
}

static const fido_dev_io_t softfido_io = {
	.open = softfido_io_open,
	.close = softfido_io_close,
	.read = softfido_io_read,
	.write = softfido_io_write,
};

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

static int
load_attestation_key(void)
{
	BIO *bio = NULL;
	EC_KEY *eckey = NULL;
	int error = -1;

	bio = BIO_new_mem_buf(the_attestation_key_pem,
	    strlen(the_attestation_key_pem));
	if (bio == NULL)
		goto out;
	if ((eckey = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL)) == NULL)
		goto out;

	the_attestation_key = eckey;
	eckey = NULL;
	error = 0;

out:	if (bio)
		BIO_free_all(bio);
	if (eckey)
		EC_KEY_free(eckey);
	return error;
}

struct softfido_key {
	uint8_t masterkey[32];
};
static struct softfido_key *softfido_keys = NULL;
static size_t softfido_nkeys = 0;

int
softfido_attach_key(const uint8_t key[static 32])
{
	struct softfido_key *old, *new;
	size_t i, n;

	if ((n = softfido_nkeys) == SIZE_MAX)
		return FIDO_ERR_INTERNAL;

	i = n++;
	if (n > SIZE_MAX/sizeof(softfido_keys[0]))
		return FIDO_ERR_INTERNAL;

	old = softfido_keys;
	if ((new = realloc(old, n * sizeof(softfido_keys[0]))) == NULL)
		return FIDO_ERR_INTERNAL;

	memset(&new[i], 0, sizeof(new[i]));
	memcpy(new[i].masterkey, key, 32);
	softfido_keys = new;
	softfido_nkeys = n;
	return FIDO_OK;
}

int
softfido_dev_info_manifest(fido_dev_info_t *devlist, size_t nmax, size_t *np)
{
	static const char hex[16] = "0123456789abcdef";
	const char vendor[] = "Random Float LLC";
	char product[128];
	size_t i;
	int error;

	if (load_attestation_key())
		return FIDO_ERR_INTERNAL;

	snprintf(product, sizeof(product), "Softfido %d.%d",
	    SOFTFIDO_VERSION_MAJOR, SOFTFIDO_VERSION_MINOR);

	error = FIDO_OK;
	if (nmax > softfido_nkeys)
		nmax = softfido_nkeys;
	for (i = 0; i < nmax; i++) {
		const uint8_t *key = softfido_keys[i].masterkey;
		char keyhex[64 + 1];
		char path[512];
		size_t j;

		for (j = 0; j < 32; j++) {
			keyhex[2*j + 0] = hex[key[j] >> 4];
			keyhex[2*j + 1] = hex[key[j] & 0xf];
		}
		keyhex[64] = '\0';
		snprintf(path, sizeof(path), "%s%s", SOFTFIDO_V0, keyhex);
		error = fido_dev_info_set(devlist, i, path, vendor, product,
		    &softfido_io, &softfido_transport);
		if (error != FIDO_OK)
			break;
	}

	*np = i;
	return error;
}

#else

void
softfido_randomseed(const uint8_t seed[static 32])
{

	(void)seed;
}

int
softfido_attach_key(const uint8_t key[static 32])
{

	(void)key;

	return FIDO_ERR_INTERNAL;
}

int
softfido_dev_info_manifest(fido_dev_info_t *devlist, size_t nmax, size_t *np)
{

	(void)devlist;
	(void)nmax;
	(void)np;

	return FIDO_ERR_INTERNAL;
}

#endif	/* HAVE_FIDO_CUSTOM_TRANSPORT */
