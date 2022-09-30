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

#define	_NETBSD_SOURCE

#include <err.h>
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fido.h>
#include <openssl/rand.h>

#include "assert_kdf.h"
#include "crc.h"
#include "cred_kdf.h"

static void
writecred(const char *path, const uint8_t pkconf[static 32],
    const void *credential_id, size_t ncredential_id)
{
	FILE *file;
	const uint8_t header[8] = "FIDOKDFC";
	uint8_t len16[2];
	uint32_t crc = 0;
	uint8_t crcbuf[4];

	/*
	 * Open the file for writing; fail if it already exists so we
	 * don't inadvertently clobber precious existing credentials;
	 * or use stdout if the path is `-'.
	 */
	if (strcmp(path, "-") != 0) {
		if ((file = fopen(path, "wbx")) == NULL)
			err(1, "fopen");
	} else {
		file = stdout;
	}

	/* Write the header.  */
	if (fwrite(header, 8, 1, file) != 1)
		err(1, "fwrite header");
	crc = crc32(header, 8, crc);

	/* Encode and write the 2-byte big-endian credential id length.  */
	be16enc(len16, ncredential_id);
	if (fwrite(&len16, 2, 1, file) != 1)
		err(1, "fwrite len");
	crc = crc32(len16, 2, crc);

	/* Write the credential id.  */
	if (fwrite(credential_id, ncredential_id, 1, file) != 1)
		err(1, "fwrite cred");
	crc = crc32(credential_id, ncredential_id, crc);

	/* Write the 32-byte public key confirmation hash.  */
	if (fwrite(pkconf, 32, 1, file) != 1)
		err(1, "fwrite pkconf");
	crc = crc32(pkconf, 32, crc);

	/* Encode and write the 32-bit CRC.  */
	le32enc(crcbuf, crc);
	if (fwrite(crcbuf, 4, 1, file) != 1)
		err(1, "fwrite crc");

	/*
	 * Make sure it has hit disk before we let the caller proceed;
	 * otherwise the caller might stash some important data with a
	 * key that has been lost if the credential file is eaten by a
	 * power failure.
	 */
	if (fsync_range(fileno(file), FFILESYNC|FDISKSYNC, 0, 0) == -1)
		err(1, "fsync_range");

	/* All set -- close the file.  */
	if (strcmp(path, "-") != 0)
		fclose(file);
}

static void *
readcred(const char *path, uint8_t pkconf[static 32], size_t *ncredential_id)
{
	FILE *file;
	uint8_t header[8];
	uint8_t len16[2];
	void *credential_id;
	uint32_t crc = 0;
	uint8_t crcbuf[5];

	/* Open the file for reading, or use stdin if it's `-'.  */
	if (strcmp(path, "-") != 0) {
		if ((file = fopen(path, "rb")) == NULL)
			err(1, "fopen");
	} else {
		file = stdin;
	}

	/* Read and verify the FIDOKDFC header.  */
	if (fread(header, 8, 1, file) != 1)
		err(1, "fread header");
	crc = crc32(header, 8, crc);
	if (CRYPTO_memcmp(header, "FIDOKDFC", 8) != 0)
		errx(1, "malformed credential header");

	/*
	 * Read and decode the 2-byte big-endian credential id length.
	 * Return it to the caller as *ncredential_id.
	 */
	if (fread(len16, 2, 1, file) != 1)
		err(1, "fread len");
	crc = crc32(len16, 2, crc);
	*ncredential_id = be16dec(len16);

	/* Allocate a buffer for the credential id and read it.  */
	if ((credential_id = calloc(1, *ncredential_id)) == NULL)
		err(1, "calloc");
	if (fread(credential_id, *ncredential_id, 1, file) != 1)
		err(1, "fread cred");
	crc = crc32(credential_id, *ncredential_id, crc);

	/* Read the 32-byte public key confirmation hash.  */
	if (fread(pkconf, 32, 1, file) != 1)
		err(1, "fread pkconf");
	crc = crc32(pkconf, 32, crc);

	/* Read the 32-bit CRC and confirm we hit EOF.  */
	if (fread(crcbuf, 1, 5, file) != 4 || !feof(file))
		err(1, "malformed credential");
	crc = crc32(crcbuf, 4, crc);

	/* Check the CRC.  */
	if (crc != UINT32_C(0x2144df1c))
		errx(1, "malformed credential crc=0x%x", crc);

	/* All set -- close the file and return the credential id.  */
	if (strcmp(path, "-") != 0)
		fclose(file);
	return credential_id;
}

static fido_dev_t *
opendev(const char *devpath)
{
	fido_dev_t *dev = NULL;
	int error;

	/* Create a fido dev representative.  */
	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	if (devpath) {
		/* If the user provided a device path, just open it.  */
		if ((error = fido_dev_open(dev, devpath)) != FIDO_OK)
			errx(1, "fido_dev_open: %s", fido_strerr(error));
	} else {
		/* None provided -- try the first one from the system.  */
		fido_dev_info_t *devlist = NULL;
		const fido_dev_info_t *devinfo;
		size_t ndevs = 0;

		if ((devlist = fido_dev_info_new(1)) == NULL)
			errx(1, "fido_dev_info_new");
		if ((error = fido_dev_info_manifest(devlist, 1, &ndevs))
		    != FIDO_OK)
			errx(1, "fido_dev_info_manifest: %s",
			    fido_strerr(error));
		if (ndevs < 1)
			errx(1, "no devices found");
		if ((devinfo = fido_dev_info_ptr(devlist, 0)) == NULL)
			errx(1, "fido_dev_info_ptr");
		if ((error = fido_dev_open(dev, fido_dev_info_path(devinfo)))
		    != FIDO_OK)
			errx(1, "fido_dev_open: %s", fido_strerr(error));
		fido_dev_info_free(&devlist, ndevs);
	}

	return dev;
}

static void __dead
usage_make(void)
{

	fprintf(stderr,
	    "Usage: %s make [-d <dev>] [-f <credfile>] [-N <username>]\n",
	    getprogname());
	fprintf(stderr,
	    "           [-r <rpid>] [-u <userid>]\n");
	exit(1);
}

static void
make(int argc, char **argv)
{
	const char *rp_id = NULL;
	const char *user_name = NULL;
	const char *user_id = NULL;
	const char *credpath = NULL;
	const char *devpath = NULL;
	fido_dev_t *dev = NULL;
	fido_cred_t *cred = NULL;
	uint8_t challenge[32];
	uint8_t pkconf[FIDOCRYPT_KDF_CONFBYTES];
	uint8_t key[FIDOCRYPT_KDF_KEYBYTES];
	const void *credential_id;
	size_t ncredential_id;
	int ch, error = 0;

	/* Parse arguments.  */
	while ((ch = getopt(argc, argv, "d:f:N:r:u:")) != -1) {
		switch (ch) {
		case 'd':
			if (devpath) {
				warnx("multiple devices");
				error = 1;
				break;
			}
			devpath = optarg;
			break;
		case 'f':
			if (credpath) {
				warnx("multiple credential files");
				error = 1;
				break;
			}
			credpath = optarg;
			break;
		case 'N':
			if (user_name) {
				warnx("multiple user names");
				error = 1;
				break;
			}
			user_name = optarg;
			break;
		case 'r':
			if (rp_id) {
				warnx("multiple relying party ids");
				error = 1;
				break;
			}
			rp_id = optarg;
			break;
		case 'u':
			if (user_id) {
				warnx("multiple user ids");
				error = 1;
				break;
			}
			user_id = optarg;
			break;
		case '?':
		default:
			usage_make();
		}
	}

	/* Verify we have all the inputs we need.  */
	if (credpath == NULL) {
		warnx("specify credential file");
		error = 1;
	}
	if (rp_id == NULL &&
	    (rp_id = getenv("FIDOKDF_RPID")) == NULL) {
		warnx("specify relying party id");
		error = 1;
	}
	if (user_id == NULL &&
	    (user_id = getenv("FIDOKDF_USERID")) == NULL) {
		warnx("specify user id");
		error = 1;
	}
	if (user_name == NULL &&
	    (user_name = getenv("FIDOKDF_USERNAME")) == NULL) {
		warnx("specify user name");
		error = 1;
	}

	/* Reject extraneous arguments; print usage if anything was wrong.  */
	argc -= optind;
	argv += optind;
	if (argc) {
		warnx("extraneous arguments");
		error = 1;
	}
	if (error)
		usage_make();

	/* Open the device.  */
	dev = opendev(devpath);

	/* Generate a challenge.  */
	if (RAND_bytes(challenge, sizeof(challenge)) != 1)
		errx(1, "RAND_bytes");

	/* Create the credential and set its parameters.  */
	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");
	if ((error = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK)
		errx(1, "fido_cred_set_type: %s", fido_strerr(error));
	if ((error = fido_cred_set_rp(cred, rp_id, NULL)) != FIDO_OK)
		errx(1, "fido_cred_set_rp: %s", fido_strerr(error));
	if ((error = fido_cred_set_user(cred,
		    (const void *)user_id, strlen(user_id),
		    user_name, /*displayname*/NULL, /*icon*/NULL)) != FIDO_OK)
		errx(1, "fido_cred_set_user: %s", fido_strerr(error));
	if ((error = fido_cred_set_clientdata_hash(cred,
		    challenge, sizeof(challenge))) != FIDO_OK)
		errx(1, "fido_cred_set_clientdata_hash: %s",
		    fido_strerr(error));

	/* Make the credential.  */
	if ((error = fido_dev_make_cred(dev, cred, NULL)) != FIDO_OK)
		errx(1, "fido_dev_make_cred: %s", fido_strerr(error));

	/* Get the credential id.  */
	if ((credential_id = fido_cred_id_ptr(cred)) == NULL ||
	    (ncredential_id = fido_cred_id_len(cred)) == 0)
		errx(1, "missingfido_cred_id");

	/* Verify the credential.  */
	if (fido_cred_x5c_ptr(cred) == NULL) {
		if ((error = fido_cred_verify_self(cred)) != FIDO_OK)
			errx(1, "fido_cred_verify_self: %s",
			    fido_strerr(error));
	} else {
		if ((error = fido_cred_verify(cred)) != FIDO_OK)
			errx(1, "fido_cred_verify: %s", fido_strerr(error));
	}

	/* Derive the key.  */
	if ((error = fido_cred_kdf(cred, COSE_ES256, pkconf, key)) != FIDO_OK)
		errx(1, "fido_cred_kdf: %s", fido_strerr(error));

	/* Write the credential to file.  */
	writecred(credpath, pkconf, credential_id, ncredential_id);

	/* After the credential has been written to disk, print the key.  */
	if (fwrite(key, FIDOCRYPT_KDF_KEYBYTES, 1, stdout) != 1)
		err(1, "write key");

	fido_cred_free(&cred);
	fido_dev_free(&dev);
	OPENSSL_cleanse(key, sizeof(key));
	OPENSSL_cleanse(challenge, sizeof(challenge));
}

static void __dead
usage_get(void)
{

	fprintf(stderr,
	    "Usage: %s get [-d <dev>] [-f <credfile>] [-r <rpid>]\n",
	    getprogname());
	exit(1);
}

static void
get(int argc, char **argv)
{
	const char *rp_id = NULL;
	const char *devpath = NULL;
	const char *credpath = NULL;
	void *credential_id = NULL;
	size_t ncredential_id = 0;
	uint8_t pkconf[32] = {0};
	fido_dev_t *dev = NULL;
	fido_assert_t *assert = NULL;
	uint8_t challenge[32];
	uint8_t key[FIDOCRYPT_KDF_KEYBYTES];
	int ch, error = 0;

	/* Parse arguments.  */
	while ((ch = getopt(argc, argv, "d:f:r:")) != -1) {
		switch (ch) {
		case 'd':
			if (devpath) {
				warnx("multiple devices");
				error = 1;
				break;
			}
			devpath = optarg;
			break;
		case 'f':
			if (credpath) {
				warnx("multiple credential files");
				error = 1;
				break;
			}
			credpath = optarg;
			break;
		case 'r':
			if (rp_id) {
				warnx("multiple relying party ids");
				error = 1;
				break;
			}
			rp_id = optarg;
			break;
		case '?':
		default:
			error = 1;
			break;
		}
	}

	/* Verify we have all the inputs we need.  */
	if (credpath == NULL) {
		warnx("specify credential file");
		error = 1;
	}
	if (rp_id == NULL) {
		if ((rp_id = getenv("FIDOKDF_RPID")) == NULL) {
			warnx("specify relying party");
			error = 1;
		}
	}

	/* Reject extraneous arguments; print usage if anything was wrong.  */
	argc -= optind;
	argv += optind;
	if (argc) {
		warnx("extraneous arguments");
		error = 1;
	}
	if (error)
		usage_get();

	/* Get the credential id and public key confirmation.  */
	credential_id = readcred(credpath, pkconf, &ncredential_id);

	/* Open the device.  */
	dev = opendev(devpath);

	/* Generate a challenge.  */
	if (RAND_bytes(challenge, sizeof(challenge)) != 1)
		errx(1, "RAND_bytes");

	/* Create the assertion and set its parameters.  */
	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");
	if ((error = fido_assert_set_rp(assert, rp_id)) != FIDO_OK)
		errx(1, "fido_assert_set_rp: %s", fido_strerr(error));
	if ((error = fido_assert_set_clientdata_hash(assert,
		    challenge, sizeof(challenge))) != FIDO_OK)
		errx(1, "fido_assert_set_clientdata_hash: %s",
		    fido_strerr(error));
	if ((error = fido_assert_allow_cred(assert, credential_id,
		    ncredential_id)) != FIDO_OK)
		errx(1, "fido_assert_allow_cred: %s", fido_strerr(error));

	/* Get an assertion response.  */
	if ((error = fido_dev_get_assert(dev, assert, NULL)) != FIDO_OK)
		errx(1, "fido_dev_get_assert: %s", fido_strerr(error));

	/* Verify we got an assertion response.  */
	if (fido_assert_count(assert) != 1)
		errx(1, "failed to get one assertion response");

	/* Verify the assertion response and derive a key.  */
	if ((error = fido_assert_kdf(assert, 0, COSE_ES256, pkconf, key))
	    != FIDO_OK)
		errx(1, "fido_assert_kdf: %s", fido_strerr(error));

	/* Print the key.  */
	if (fwrite(key, FIDOCRYPT_KDF_KEYBYTES, 1, stdout) != 1)
		err(1, "write key");

	fido_assert_free(&assert);
	fido_dev_free(&dev);
	free(credential_id);
	OPENSSL_cleanse(key, sizeof(key));
	OPENSSL_cleanse(challenge, sizeof(challenge));
}

static void
usage(void)
{

	fprintf(stderr,
	    "Usage: %s make [-d <dev>] [-f <credfile>] [-N <username>]\n",
	    getprogname());
	fprintf(stderr,
	    "           [-r <rpid>] [-u <userid>]\n");
	fprintf(stderr,
	    "       %s get [-d <dev>] [-f <credfile>] [-r <rpid>]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{

	/* Initialize libfido2.  */
	fido_init(0);

	/* Set progname.  */
	setprogname(*argv++);
	argc--;

	/* Verify we have a command and dispatch on it.  */
	if (argc < 1)
		usage();
	if (strcmp(*argv, "make") == 0)
		make(argc, argv);
	else if (strcmp(*argv, "get") == 0)
		get(argc, argv);
	else
		usage();

	return 0;
}
