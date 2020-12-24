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

#include <sys/stat.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <cbor.h>
#include <fido.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "assert_decrypt.h"
#include "crc.h"
#include "cred_encrypt.h"
#include "fidocrypt.h"

static struct state {
	pthread_mutex_t		mtx;
	pthread_cond_t		cond;

	int			ttyfd;
	bool			quiet;
	bool			verbose;
	bool			debug;

	const char		*rp_id;
	const char		*user_id;
	const char		*user_name;

	unsigned		pending;
	const fido_dev_info_t	*devlist;
	const cbor_item_t	*cryptmap;

	union {			/* XXX */
		fido_cred_t		*cred;
		fido_assert_t		*assert;
		void			*result;
	};
	bool			done;

	struct {
		pthread_t		pt;
		bool			exited;
	}			thread[64];
} state, *S = &state;

static void
MSG(const char *fmt, ...)
{
	char buf[1024];
	va_list va;

	if (S->quiet)
		return;

	va_start(va, fmt);
	(void)vsnprintf_ss(buf, sizeof(buf), fmt, va);
	va_end(va);

	(void)write(S->ttyfd, buf, strlen(buf));
}

static void
DBG(const char *fmt, ...)
{
	char buf[1024];
	va_list va;

	if (!S->debug)
		return;

	/*
	 * This is used in a signal handler, so we must use the
	 * signal-safe variant of vsnprintf.
	 */
	va_start(va, fmt);
	(void)vsnprintf_ss(buf, sizeof(buf), fmt, va);
	va_end(va);

	(void)write(STDERR_FILENO, buf, strlen(buf));
}

static int
b64write(const void *buf, size_t len, FILE *file)
{
	BIO *bio_file = NULL, *bio_b64 = NULL;
	int ok = 0;

	if (len > INT_MAX)
		goto out;

	if ((bio_file = BIO_new_fp(file, BIO_NOCLOSE)) == NULL)
		goto out;
	if ((bio_b64 = BIO_new(BIO_f_base64())) == NULL)
		goto out;
	BIO_push(bio_b64, bio_file);

	if (!BIO_write(bio_b64, buf, len))
		goto out;
	if (BIO_flush(bio_b64) != 1)	/* returns 0 _or_ -1 for failure */
		goto out;

	/* Success!  */
	ok = 1;

out:	if (bio_b64)
		BIO_free(bio_b64);
	if (bio_file)
		BIO_free(bio_file);
	return ok;
}

static void
signal_handler(int signo)
{

	DBG("signal %d thread=%p\n", signo, (const void *)pthread_self());

	/* Nothing to do -- just need syscalls to wake with EINTR.  */
	(void)signo;
}

static void
signals_init(void)
{
	struct sigaction act;

	/* Establish a signal handler to interrupt libfido2's I/O.  */
	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGUSR1, &act, NULL) == -1)
		err(1, "sigaction");
}

static void
threads_init(void)
{
	int error;

	/* Initialize the mutex and condition variable.  */
	if ((error = pthread_mutex_init(&S->mtx, NULL)) != 0)
		errc(1, error, "pthread_mutex_init");
	if ((error = pthread_cond_init(&S->cond, NULL)) != 0)
		errc(1, error, "pthread_mutex_init");
}

static bool
isdone(void)
{
	bool answer;
	int error;

	if ((error = pthread_mutex_lock(&S->mtx)) != 0)
		errc(1, error, "pthread_mutex_lock");
	answer = S->done;
	if ((error = pthread_mutex_unlock(&S->mtx)) != 0)
		errc(1, error, "pthread_mutex_unlock");

	return answer;
}

static void *
done(unsigned i, void *result, const fido_dev_info_t *devinfo)
{
	int error;

	if ((error = pthread_mutex_lock(&S->mtx)) != 0)
		errc(1, error, "pthread_mutex_lock");
	assert(S->pending);
	S->pending--;
	S->thread[i].exited = true;
	if (result != NULL && S->result == NULL) {
		S->done = true;
		S->result = result;
		result = NULL;
		if (devinfo) {
			DBG("got %s vendor=%04hx (%s) product=%04hx (%s)\n",
			    fido_dev_info_path(devinfo),
			    fido_dev_info_vendor(devinfo),
			    fido_dev_info_manufacturer_string(devinfo),
			    fido_dev_info_product(devinfo),
			    fido_dev_info_product_string(devinfo));
		}
	}
	if ((error = pthread_cond_signal(&S->cond)) != 0)
		errc(1, error, "pthread_cond_signal");
	if ((error = pthread_mutex_unlock(&S->mtx)) != 0)
		errc(1, error, "pthread_mutex_unlock");

	return result;
}

static void *
enroll_thread(void *cookie)
{
	unsigned i = (unsigned)(uintptr_t)cookie;
	const fido_dev_info_t *devinfo = NULL;
	fido_dev_t *dev = NULL;
	sigset_t mask, omask;
	uint8_t challenge[32];
	const char *path;
	fido_cred_t *cred = NULL;
	const struct cbor_pair *entry;
	unsigned j;
	int error, ok = 0;

	/* libfido2 logging is per-thread, so redo fido_init.  */
	fido_init(0);

	/* Generate a challenge.  */
	if (!RAND_bytes(challenge, sizeof(challenge))) {
		warnx("RAND_bytes");
		goto out;
	}

	/* Set up signal masks: block SIGUSR1.  */
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	if ((error = pthread_sigmask(SIG_BLOCK, &mask, &omask)) != 0)
		errc(1, error, "pthread_sigmask");

	/*
	 * Now that SIGUSR1 is blocked, verify that we aren't done
	 * already, before we wait for any I/O.
	 */
	if (isdone()) {
		warnx("%s: done early", __func__);
		goto out;
	}

	/* Get the device path.  */
	if ((devinfo = fido_dev_info_ptr(S->devlist, i)) == NULL) {
		warnx("fido_dev_info_ptr %u", i);
		goto out;
	}
	if ((path = fido_dev_info_path(devinfo)) == NULL) {
		warnx("fido_dev_info_path");
		goto out;
	}

	/* Open the device, and arrange to unblock SIGUSR1 while we wait.  */
	if ((dev = fido_dev_new()) == NULL) {
		warnx("fido_dev_new");
		goto out;
	}
	if ((error = fido_dev_open(dev, path)) != FIDO_OK) {
		warnx("fido_dev_open: %s", fido_strerr(error));
		goto out;
	}
	if ((error = fido_dev_set_sigmask(dev, &omask)) != FIDO_OK) {
		warnx("fido_dev_set_sigmask: %s", fido_strerr(error));
		goto out;
	}

	/* Create a credential and set its parameters.  */
	if ((cred = fido_cred_new()) == NULL) {
		warnx("fido_cred_new");
		goto out;
	}
	if ((error = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK) {
		warnx("fido_cred_set_type: %s", fido_strerr(error));
		goto out;
	}
	if ((error = fido_cred_set_rp(cred, S->rp_id, NULL)) != FIDO_OK) {
		warnx("fido_cred_set_rp: %s", fido_strerr(error));
		goto out;
	}
	if ((error = fido_cred_set_user(cred,
		    (const void *)S->user_id, strlen(S->user_id),
		    S->user_name, /*displayname*/NULL, /*icon*/NULL))
	    != FIDO_OK) {
		warnx("fido_cred_set_user: %s", fido_strerr(error));
		goto out;
	}
	if ((error = fido_cred_set_clientdata_hash(cred,
		    challenge, sizeof(challenge))) != FIDO_OK) {
		warnx("fido_cred_set_clientdata_hash: %s", fido_strerr(error));
		goto out;
	}

	/* Specify the excluded credential ids, if any.  */
	if (S->cryptmap) {
		entry = cbor_map_handle(S->cryptmap);
		for (j = cbor_map_size(S->cryptmap); j --> 0;) {
			const void *credential_id =
			    cbor_bytestring_handle(entry[j].key);
			size_t ncredential_id =
			    cbor_bytestring_length(entry[j].key);
			if ((error = fido_cred_exclude(cred,
				    credential_id, ncredential_id)) != FIDO_OK)
				errx(1, "fido_cred_exclude: %s",
				    fido_strerr(error));
		}
	}

	DBG("try %s vendor=%04hx (%s) product=%04hx (%s)\n",
	    path,
	    fido_dev_info_vendor(devinfo),
	    fido_dev_info_manufacturer_string(devinfo),
	    fido_dev_info_product(devinfo),
	    fido_dev_info_product_string(devinfo));

	/* Make the credential.  */
	if ((error = fido_dev_make_cred(dev, cred, NULL)) != FIDO_OK) {
		if (S->verbose && !isdone())
			warnx("fido_dev_make_cred: %s", fido_strerr(error));
		DBG("cancel %s vendor=%04hx (%s) product=%04hx (%s)\n",
		    path,
		    fido_dev_info_vendor(devinfo),
		    fido_dev_info_manufacturer_string(devinfo),
		    fido_dev_info_product(devinfo),
		    fido_dev_info_product_string(devinfo));
		/*
		 * XXX This may block, but it's relatively unlikely
		 * because fido_dev_cancel only issues tx, not rx.
		 */
		if ((error = fido_dev_cancel(dev)) != FIDO_OK)
			warnx("fido_dev_cancel: %s", fido_strerr(error));
		goto out;
	}

	/* Verify the credential.  */
	if (fido_cred_x5c_ptr(cred) == NULL) {
		if ((error = fido_cred_verify_self(cred)) != FIDO_OK) {
			warnx("fido_cred_verify_self: %s",
			    fido_strerr(error));
			goto out;
		}
	} else {
		if ((error = fido_cred_verify(cred)) != FIDO_OK) {
			warnx("fido_cred_verify: %s", fido_strerr(error));
			goto out;
		}
	}

	/* Success!  */
	ok = 1;

out:	if (!ok) {
		if (cred)
			fido_cred_free(&cred);
	}
	cred = done(i, cred, devinfo);
	if (cred)
		fido_cred_free(&cred);
	fido_dev_close(dev);
	fido_dev_free(&dev);
	return NULL;		/* pthread return value */
}

static void *
get_thread(void *cookie)
{
	unsigned i = (unsigned)(uintptr_t)cookie;
	const fido_dev_info_t *devinfo = NULL;
	fido_dev_t *dev = NULL;
	sigset_t mask, omask;
	uint8_t challenge[32];
	const char *path;
	fido_assert_t *assert = NULL;
	const struct cbor_pair *entry;
	unsigned j;
	int error, ok = 0;

	/* libfido2 logging is per-thread, so redo fido_init.  */
	fido_init(0);

	/* Generate a challenge.  */
	if (!RAND_bytes(challenge, sizeof(challenge))) {
		warnx("RAND_bytes");
		goto out;
	}

	/* Set up signal masks: block SIGUSR1.  */
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	if ((error = pthread_sigmask(SIG_BLOCK, &mask, &omask)) != 0)
		errc(1, error, "pthread_sigmask");

	/*
	 * Now that SIGUSR1 is blocked, verify that we aren't done
	 * already, before we wait for any I/O.
	 */
	if (isdone()) {
		warnx("%s: done early", __func__);
		goto out;
	}

	/* Get the device path.  */
	if ((devinfo = fido_dev_info_ptr(S->devlist, i)) == NULL) {
		warnx("fido_dev_info_ptr %u", i);
		goto out;
	}
	if ((path = fido_dev_info_path(devinfo)) == NULL) {
		warnx("fido_dev_info_path");
		goto out;
	}

	/* Open the device, and arrange to unblock SIGUSR1 while we wait.  */
	if ((dev = fido_dev_new()) == NULL) {
		warnx("fido_dev_new");
		goto out;
	}
	if ((error = fido_dev_open(dev, path)) != FIDO_OK) {
		warnx("fido_dev_open: %s", fido_strerr(error));
		goto out;
	}
	if ((error = fido_dev_set_sigmask(dev, &omask)) != FIDO_OK) {
		warnx("fido_dev_set_sigmask: %s", fido_strerr(error));
		goto out;
	}

	/* Create an assertion and set its parameters.  */
	if ((assert = fido_assert_new()) == NULL) {
		warnx("fido_assert_new");
		goto out;
	}
	if ((error = fido_assert_set_rp(assert, S->rp_id)) != FIDO_OK) {
		warnx("fido_assert_set_rp: %s", fido_strerr(error));
		goto out;
	}
	if ((error = fido_assert_set_clientdata_hash(assert,
		    challenge, sizeof(challenge))) != FIDO_OK)
		errx(1, "fido_assert_set_clientdata_hash: %s",
		    fido_strerr(error));

	/* Specify the allowed credential ids.  */
	entry = cbor_map_handle(S->cryptmap);
	for (j = cbor_map_size(S->cryptmap); j --> 0;) {
		const void *credential_id =
		    cbor_bytestring_handle(entry[j].key);
		size_t ncredential_id = cbor_bytestring_length(entry[j].key);
		if ((error = fido_assert_allow_cred(assert, credential_id,
			    ncredential_id)) != FIDO_OK)
			errx(1, "fido_assert_allow_cred: %s",
			    fido_strerr(error));
	}

	DBG("try %s vendor=%04hx (%s) product=%04hx (%s)\n",
	    path,
	    fido_dev_info_vendor(devinfo),
	    fido_dev_info_manufacturer_string(devinfo),
	    fido_dev_info_product(devinfo),
	    fido_dev_info_product_string(devinfo));

	/* Get the assertion.  */
	if ((error = fido_dev_get_assert(dev, assert, NULL)) != FIDO_OK) {
		if (S->verbose && !isdone())
			warnx("fido_dev_get_assert: %s", fido_strerr(error));
		DBG("cancel %s vendor=%04hx (%s) product=%04hx (%s)\n",
		    path,
		    fido_dev_info_vendor(devinfo),
		    fido_dev_info_manufacturer_string(devinfo),
		    fido_dev_info_product(devinfo),
		    fido_dev_info_product_string(devinfo));
		/*
		 * XXX This may block, but it's relatively unlikely
		 * because fido_dev_cancel only issues tx, not rx.
		 */
		if ((error = fido_dev_cancel(dev)) != FIDO_OK)
			warnx("fido_dev_cancel: %s", fido_strerr(error));
		goto out;
	}

	/* Success!  */
	ok = 1;

out:	if (!ok) {
		if (assert)
			fido_assert_free(&assert);
	}
	assert = done(i, assert, devinfo);
	if (assert)
		fido_assert_free(&assert);
	fido_dev_close(dev);
	fido_dev_free(&dev);
	return NULL;		/* pthread return value */
}

static void *
run_thread_per_dev(void *(*start)(void *), const cbor_item_t *cryptmap)
{
	fido_dev_info_t *devlist = NULL;
	size_t ndevs = 0, maxndevs = __arraycount(S->thread);
	struct timespec deadline;
	unsigned i;
	int error;

	/* Get the list of devices.  */
	if ((devlist = fido_dev_info_new(maxndevs)) == NULL)
		errx(1, "fido_dev_info_new");
	if ((error = fido_dev_info_manifest(devlist, maxndevs, &ndevs))
	    != FIDO_OK)
		errx(1, "fido_dev_info_manifest: %s", fido_strerr(error));
	assert(ndevs <= maxndevs);

	if (S->verbose) {
		for (i = ndevs; i --> 0;) {
			const fido_dev_info_t *devinfo;
			const char *path;

			if ((devinfo = fido_dev_info_ptr(devlist, i))
			    == NULL) {
				warnx("fido_dev_info_ptr %u", i);
				continue;
			}
			if ((path = fido_dev_info_path(devinfo)) == NULL) {
				warnx("fido_dev_info_path");
				continue;
			}
			warnx("%s vendor=%04hx (%s) product=%04hx (%s)",
			    path,
			    fido_dev_info_vendor(devinfo),
			    fido_dev_info_manufacturer_string(devinfo),
			    fido_dev_info_product(devinfo),
			    fido_dev_info_product_string(devinfo));
		}
	}

	/* Set up the global state.  */
	S->pending = ndevs;
	S->devlist = devlist;
	S->cryptmap = cryptmap;
	S->result = NULL;
	S->done = false;

	/* Create one thread for each device.  */
	for (i = ndevs; i --> 0;) {
		S->thread[i].exited = false;
		if ((error = pthread_create(&S->thread[i].pt, NULL, start,
			    (void *)(uintptr_t)i)) != 0)
			errc(1, error, "pthread_create");
	}

	/* Determine the deadline -- 15sec from now.  */
	if (clock_gettime(CLOCK_REALTIME, &deadline) == -1)
		err(1, "clock_gettime");
	timespecadd(&deadline, (&(const struct timespec){15, 0}), &deadline);

	/*
	 * Wait for one of the threads to complete.  Then send a signal
	 * to all threads to wake them in case they're still waiting
	 * for I/O that doesn't matter any more.
	 *
	 * We don't simply issue pthread_cancel, causing the threads to
	 * exit immediately at a cancellation point -- we only deliver
	 * a signal with a signal handler that does nothing, so they
	 * have an opportunity to send a cancel command to the device
	 * rather than leave it in a confused lingering state.
	 */
	if ((error = pthread_mutex_lock(&S->mtx)) != 0)
		errc(1, error, "pthread_mutex_lock");
	while (!S->done && S->pending) {
		DBG("wait for first of %u threads\n", S->pending);
		if ((error = pthread_cond_timedwait(&S->cond, &S->mtx,
			    &deadline)) != 0) {
			if (error == ETIMEDOUT) {
				S->done = true;
				break;
			}
			errc(1, error, "pthread_cond_timedwait");
		}
	}
	DBG("threads done\n");
	for (i = ndevs; i --> 0;) {
		if (S->thread[i].exited)
			continue;
		DBG("send signal %d thread=%p\n", SIGUSR1, S->thread[i].pt);
		if ((error = pthread_kill(S->thread[i].pt, SIGUSR1)) != 0)
			errc(1, error, "pthread_kill");
	}
	if ((error = pthread_mutex_unlock(&S->mtx)) != 0)
		errc(1, error, "pthread_mutex_unlock");

	/*
	 * Wait for the threads to actually exit.  Set an alarm in case
	 * something got stuck.
	 */
	alarm(5);
	for (i = 0; i < ndevs; i++) {
		if ((error = pthread_join(S->thread[i].pt, NULL)) != 0)
			errc(1, error, "pthread_join");
	}
	alarm(0);

	/*
	 * We are back to being the sole thread, so no more mutex
	 * needed.
	 */
	if (S->result == NULL)
		errx(1, "no matching devices found");

	/* Free the temporaries.  */
	fido_dev_info_free(&devlist, ndevs);

	return S->result;
}

static int
entry_compare(const void *va, const void *vb)
{
	const struct cbor_pair *a = va;
	const struct cbor_pair *b = vb;
	const void *ap, *bp;
	size_t na, nb, n;

	assert(cbor_isa_bytestring(a->key));
	assert(cbor_isa_bytestring(b->key));
	assert(cbor_bytestring_is_definite(a->key));
	assert(cbor_bytestring_is_definite(b->key));

	ap = cbor_bytestring_handle(a->key);
	bp = cbor_bytestring_handle(b->key);
	na = cbor_bytestring_length(a->key);
	nb = cbor_bytestring_length(b->key);
	n = na < nb ? na : nb;

	/*
	 * RFC 7049, Sec. 3.9 Canonical CBOR: `If two keys have
	 * different lengths, the shorter one sorts earlier.  If two
	 * keys have the same length, the one with the lower value in
	 * (byte-wise) lexical order sorts earlier.'
	 *
	 * XXX Make sure we don't have duplicate keys.
	 */
	if (na < nb)
		return -1;
	if (na > nb)
		return +1;
	return memcmp(ap, bp, n);
}

static void
sort_map(cbor_item_t *map)
{
	struct cbor_pair *entry = cbor_map_handle(map);
	size_t nentry = cbor_map_size(map);

	qsort(entry, nentry, sizeof(*entry), entry_compare);
}

static int
writecrypt(const cbor_item_t *map, const char *path, int flag)
{
	uint8_t *mapbuf = NULL;
	size_t nmap = 0, nmapbuf = 0;
	char tmp[PATH_MAX];
	FILE *fp = NULL;
	const char header[8] = "FIDOCRPT";
	uint32_t crc = 0;
	uint8_t crcbuf[4];
	int error;

	/* Encode the map.  */
	if ((nmap = cbor_serialize_alloc(map, &mapbuf, &nmapbuf)) == 0) {
		error = ENOMEM;
		goto out;
	}

	/* Fail early if it would be too large.  */
	if (nmap > 1024*1024 - sizeof(header) - sizeof(crcbuf))
		errc(1, EFBIG, "setec astronomy");

	/*
	 * If the path is `-', use stdout; otherwise, start writing to a
	 * temporary file, truncating it if it already exists or
	 * creating it if not.
	 */
	if (strcmp(path, "-") == 0) {
		fp = stdout;
	} else {
		if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path)
		    >= sizeof(tmp)) {
			error = ENAMETOOLONG;
			goto out;
		}
		if ((fp = fopen(tmp, "wb")) == NULL) {
			error = errno;
			goto out;
		}
	}

	/* Write the header.  */
	if (fwrite(header, sizeof(header), 1, fp) != 1) {
		error = errno;
		goto out;
	}
	crc = crc32(header, sizeof(header), crc);

	/* Write the map.  */
	if (fwrite(mapbuf, nmap, 1, fp) != 1) {
		error = errno;
		goto out;
	}
	crc = crc32(mapbuf, nmap, crc);

	/* Encode and write the 32-bit CRC.  */
	le32enc(crcbuf, crc);
	if (fwrite(crcbuf, sizeof(crcbuf), 1, fp) != 1) {
		error = errno;
		goto out;
	}

	/*
	 * Make sure it has hit disk before we let the caller proceed;
	 * otherwise the caller might stash some important data with a
	 * key that has been lost if the credential file is eaten by a
	 * power failure.
	 */
	if (fsync_range(fileno(fp), FFILESYNC|FDISKSYNC, 0, 0) == -1) {
		error = errno;
		goto out;
	}

	/* Rename the file to its temporary path, if not stdout.  */
	if (strcmp(path, "-") != 0) {
		if (flag & O_EXCL) {
			if (link(tmp, path) == -1 ||
			    unlink(tmp) == -1) {
				error = errno;
				goto out;
			}
		} else {
			if (rename(tmp, path) == -1) {
				error = errno;
				goto out;
			}
		}
	}

	/* Success!  */
	error = 0;

out:	if (fp && strcmp(path, "-") != 0)
		fclose(fp);
	if (nmapbuf) {
		OPENSSL_cleanse(mapbuf, nmapbuf);
		free(mapbuf);
	}
	return error;
}

static int
readcrypt(cbor_item_t **mapp, const char *path)
{
	FILE *fp = NULL;
	struct stat st;
	char header[8];
	void *blob = NULL;
	size_t nblob = 0;
	uint32_t crc = 0;
	uint8_t crcbuf[4];
	cbor_item_t *map = NULL;
	struct cbor_load_result load;
	const struct cbor_pair *entry;
	unsigned i;
	int error;

	/* If the path is `-', use stdin; otherwise, open for reading.  */
	if (strcmp(path, "-") == 0) {
		fp = stdin;
	} else {
		if ((fp = fopen(path, "rb")) == NULL) {
			error = errno;
			goto out;
		}
	}

	/* Determine the file length, if we can.  */
	if (fstat(fileno(fp), &st) == -1) {
		error = errno;
		goto out;
	}
	if (S_ISREG(st.st_mode)) {
		if ((size_t)st.st_size < sizeof(header) + sizeof(crcbuf)) {
			error = EFTYPE;
			goto out;
		}
		if (st.st_size > 1024*1024) {
			error = EFBIG;
			goto out;
		}
		nblob = st.st_size - sizeof(header) - sizeof(crcbuf);
		blob = malloc(nblob);
		if (blob == NULL) {
			error = errno;
			goto out;
		}
	} else if (S_ISFIFO(st.st_mode)) {
		/*
		 * XXX read incrementally and grow buffer up to a
		 * reasonable limit
		 */
		error = EFTYPE;
		goto out;
	} else {
		/*
		 * Devices, directories, symlinks, and sockets are not
		 * reasonable.
		 */
		error = EFTYPE;
		goto out;
	}

	/* Read and verify the FIDOCRPT header.  */
	if (fread(header, sizeof(header), 1, fp) != 1) {
		error = errno;
		goto out;
	}
	crc = crc32(header, sizeof(header), crc);
	if (memcmp(header, "FIDOCRPT", 8) != 0) {
		error = EFTYPE;
		goto out;
	}

	/* Read the blob.  */
	if (fread(blob, nblob, 1, fp) != 1) {
		error = errno;
		goto out;
	}
	crc = crc32(blob, nblob, crc);

	/* Read the CRC footer.  */
	if (fread(crcbuf, sizeof(crcbuf), 1, fp) != 1) {
		error = errno;
		goto out;
	}
	crc = crc32(crcbuf, sizeof(crcbuf), crc);

	/* Check the CRC.  */
	if (crc != UINT32_C(0x2144df1c)) {
		error = EBADMSG;
		goto out;
	}

	/* Done with the file now.  */
	if (strcmp(path, "-") != 0) {
		fclose(fp);
		fp = NULL;
	}

	/* Parse the CBOR and verify it's a map.  */
	if ((map = cbor_load(blob, nblob, &load)) == NULL ||
	    !cbor_isa_map(map) ||
	    !cbor_map_is_definite(map)) {
		error = EBADMSG;
		goto out;
	}

	/* Verify that every entry is a bytestring->bytestring.  */
	for (entry = cbor_map_handle(map), i = cbor_map_size(map); i --> 0;) {
		if (!cbor_isa_bytestring(entry[i].key) ||
		    !cbor_bytestring_is_definite(entry[i].key) ||
		    !cbor_isa_bytestring(entry[i].value) ||
		    !cbor_bytestring_is_definite(entry[i].value)) {
			error = EBADMSG;
			goto out;
		}
	}

	/* Success!  Return the map.  */
	*mapp = map;
	map = NULL;
	error = 0;

out:	if (map)
		cbor_decref(&map);
	if (blob)
		free(blob);
	if (fp && strcmp(path, "-") != 0)
		fclose(fp);
	return error;
}

static void *
do_get(size_t *nsecretp, const cbor_item_t *map)
{
	fido_assert_t *assert = NULL;
	const void *credential_id;
	size_t ncredential_id;
	const struct cbor_pair *entry;
	const void *ciphertext;
	size_t nciphertext;
	void *secret = NULL;
	size_t nsecret = 0;
	unsigned i;
	int error;

	/* Get an assertion from one of the devices.  */
	assert = run_thread_per_dev(get_thread, map);

	/* Verify that there is at least one assertion.  */
	/* XXX What to do about more than one assertion?  */
	if (fido_assert_count(assert) < 1)
		errx(1, "no assertions");

	/* Get the credential id.  */
	if ((credential_id = fido_assert_id_ptr(assert, 0)) == NULL ||
	    (ncredential_id = fido_assert_id_len(assert, 0)) == 0)
		errx(1, "empty credential id");

	/* Find the matching ciphertext.  */
	for (entry = cbor_map_handle(map), i = cbor_map_size(map); i --> 0;) {
		const void *key = cbor_bytestring_handle(entry[i].key);
		size_t nkey = cbor_bytestring_length(entry[i].key);

		if (nkey == ncredential_id &&
		    consttime_memequal(key, credential_id, nkey))
			goto decrypt;
	}
	errx(1, "no matching credential");

decrypt:
	/*
	 * Verify and decrypt the ciphertext using the `key' derived
	 * from the assertion.
	 */
	ciphertext = cbor_bytestring_handle(entry[i].value);
	nciphertext = cbor_bytestring_length(entry[i].value);
	if (nciphertext < FIDOCRYPT_OVERHEADBYTES)
		errx(1, "corrupt cryptfile");
	nsecret = nciphertext - FIDOCRYPT_OVERHEADBYTES;
	if ((secret = malloc(nsecret)) == NULL)
		err(1, "malloc");
	if ((error = fido_assert_decrypt(assert, 0, COSE_ES256, secret,
		    ciphertext, nciphertext)) != FIDO_OK)
		errx(1, "fido_assert_decrypt: %s", fido_strerr(error));

	/* Success!  Free the assertion and return the secret.  */
	fido_assert_free(&assert);
	*nsecretp = nsecret;
	return secret;
}

static void __dead
usage_enroll(void)
{

	fprintf(stderr,
	    "Usage: %s enroll -N <username> -u <userid> [-s <secretfile>]"
	    " <cryptfile>\n",
	    getprogname());
	exit(1);
}

static void
cmd_enroll(int argc, char **argv)
{
	const char *secretfile = NULL;
	const char *cryptfile = NULL;
	uint8_t secretbuf[32], *secret = NULL;
	size_t nsecret = 0;
	fido_cred_t *cred = NULL;
	const void *credential_id;
	size_t ncredential_id;
	uint8_t *ciphertext;
	size_t nciphertext;
	cbor_item_t *omap = NULL, *nmap = NULL;
	struct cbor_pair entry1;
	const struct cbor_pair *entry;
	unsigned i;
	int ch, error = 0;

	/* Parse arguments.  */
	while ((ch = getopt(argc, argv, "hN:s:u:")) != -1) {
		switch (ch) {
		case 'N':
			if (S->user_name) {
				warnx("specify only one user name");
				error = 1;
				break;
			}
			S->user_name = optarg;
			break;
		case 's':
			if (secretfile) {
				warnx("specify only one secret file");
				error = 1;
				break;
			}
			secretfile = optarg;
			break;
		case 'u':
			if (S->user_id) {
				warnx("specify only one user id");
				error = 1;
				break;
			}
			S->user_id = optarg;
			break;
		case '?':
		case 'h':
		default:
			usage_enroll();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage_enroll();
	cryptfile = *argv++; argc--;

	/* Verify we have all the arguments we need.  */
	if (S->user_name == NULL &&
	    (S->user_name = getenv("FIDOCRYPT_USERNAME")) == NULL) {
		warnx("specify user name (-N or FIDOCRYPT_USERNAME)");
		error = 1;
	}
	if (S->user_id == NULL &&
	    (S->user_id = getenv("FIDOCRYPT_USERID")) == NULL) {
		warnx("specify user id (-u or FIDOCRYPT_USERID)");
		error = 1;
	}

	/* Stop and report usage errors if any.  */
	if (error)
		usage_enroll();

	/* Prevent read/write/execute by anyone but owner.  */
	umask(0077);

	/* Read the existing cryptfile, if there is one.  */
	if ((error = readcrypt(&omap, cryptfile)) != 0 && error != ENOENT)
		errc(1, error, "read cryptfile");

	/*
	 * Determine the secret.
	 * - If specified, use that.
	 * - If already stored, derive it from user interaction.
	 * - Otherwise, generate a 32-byte secret afresh.
	 */
	if (secretfile) {
		/* Secret file specified -- use it.  */
		const size_t nsecret_max = 64*1024;
		FILE *fp;

		/*
		 * Warn the user if we're not doing anything to verify
		 * that the secret stored in the file matches the
		 * secret specified.
		 */
		if (omap)
			warnx("supplied secret may not match stored secrets");

		/* If secretfile is `-', use stdin; otherwise open it.  */
		if (strcmp(secretfile, "-") == 0) {
			fp = stdin;
		} else {
			if ((fp = fopen(secretfile, "rb")) == NULL)
				err(1, "open secret");
		}

		/* Read the secret.  */
		if ((secret = malloc(nsecret_max + 1)) == NULL)
			err(1, "malloc secret");
		if ((nsecret = fread(secret, 1, nsecret_max + 1, fp)) == 0 ||
		    ferror(fp))
			err(1, "read secret");
		if (nsecret >= nsecret_max + 1)
			errc(1, EFBIG, "setec astronomy");

		/* If not stdin, close the secret file.  */
		if (strcmp(secretfile, "-") != 0)
			fclose(fp);
	} else if (omap) {
		/* Existing file -- get the secret from another key.  */
		MSG("tap a key that's already enrolled; waiting...\n");
		secret = do_get(&nsecret, omap);
	} else {
		/* New file -- generate the secret.  */
		if (!RAND_bytes(secretbuf, sizeof(secretbuf)))
			errx(1, "RAND_bytes");
		secret = secretbuf;
		nsecret = sizeof(secretbuf);
	}

	/* Get a credential from one of the devices.  */
	MSG("tap key to enroll; waiting...\n");
	cred = run_thread_per_dev(enroll_thread, omap);

	/* Get the credential id.  */
	if ((credential_id = fido_cred_id_ptr(cred)) == NULL ||
	    (ncredential_id = fido_cred_id_len(cred)) == 0)
		errx(1, "empty credential id");

	/* Allocate a ciphertext buffer.  */
	if (nsecret > SIZE_MAX - FIDOCRYPT_OVERHEADBYTES)
		errx(1, "setec astronomy");
	nciphertext = FIDOCRYPT_OVERHEADBYTES + nsecret;
	if ((ciphertext = malloc(nciphertext)) == NULL)
		err(1, "malloc ciphertext");

	/* Encrypt the secret.  */
	if ((error = fido_cred_encrypt(cred, COSE_ES256, ciphertext, secret,
		    nsecret)) != FIDO_OK)
		errx(1, "fido_cred_encrypt: %s", fido_strerr(error));

	/*
	 * Create a CBOR map from credential id to ciphertext,
	 * incorporating the old map if provided.
	 */
	if ((nmap = cbor_new_definite_map(omap ? 1 + cbor_map_size(omap) : 1))
	    == NULL)
		errx(1, "cbor_new_definite_map");
	if (omap) {
		entry = cbor_map_handle(omap);
		for (i = cbor_map_size(omap); i --> 0;) {
			/* XXX check for and reject duplicate credential id */
			if (!cbor_map_add(nmap, entry[i]))
				errx(1, "cbor_map_add");
		}
	}
	if ((entry1.key = cbor_build_bytestring(credential_id,
		    ncredential_id)) == NULL ||
	    (entry1.value = cbor_build_bytestring(ciphertext,
		    nciphertext)) == NULL)
		errx(1, "cbor_build_bytestring");
	if (!cbor_map_add(nmap, entry1))
		errx(1, "cbor_map_add");

	/* Sort the map to canonicalize it.  */
	sort_map(nmap);

	/* Write the cryptfile.  */
	if ((error = writecrypt(nmap, cryptfile, 0)) != 0)
		errc(1, error, "writecrypt");

	/* Success!  */
	cbor_decref(&nmap);
	if (omap)
		cbor_decref(&omap);
	fido_cred_free(&cred);
	OPENSSL_cleanse(secret, nsecret);
	if (secret != secretbuf)
		free(secret);
}

static void __dead
usage_get(void)
{

	fprintf(stderr, "Usage: %s get -F <format> <cryptfile>\n",
	    getprogname());
	exit(1);
}

static void
cmd_get(int argc, char **argv)
{
	enum { UNSPECIFIED, NONE, RAW, BASE64 } format = UNSPECIFIED;
	const char *cryptfile = NULL;
	cbor_item_t *map = NULL;
	void *secret = NULL;
	size_t nsecret = 0;
	int ch, error = 0;

	/* Parse arguments.  */
	while ((ch = getopt(argc, argv, "F:h")) != -1) {
		switch (ch) {
		case 'F':
			if (format != UNSPECIFIED) {
				warnx("specify only one format");
				error = 1;
				break;
			}
			if (strcmp(optarg, "none") == 0) {
				format = NONE;
			} else if (strcmp(optarg, "raw") == 0) {
				format = RAW;
			} else if (strcmp(optarg, "base64") == 0) {
				format = BASE64;
			} else {
				warnx("invalid format");
				error = 1;
			}
			break;
		case '?':
		case 'h':
		default:
			usage_get();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage_get();
	cryptfile = *argv++; argc--;

	/* Verify we have all the arguments we need.  */
	if (format == UNSPECIFIED) {
		warnx("specify an output format (-F)");
		error = 1;
	}

	/* Stop and report usage errors if any.  */
	if (error)
		usage_get();

	/* Read the cryptfile.  */
	if ((error = readcrypt(&map, cryptfile)) != 0)
		errc(1, error, "readcrypt");

	/* Get the secret.  */
	MSG("tap key; waiting...\n");
	secret = do_get(&nsecret, map);

	/* Print it.  */
	switch (format) {
	case NONE:
		break;
	case RAW:
		if (fwrite(secret, nsecret, 1, stdout) != 1)
			err(1, "fwrite");
		break;
	case BASE64:
		if (!b64write(secret, nsecret, stdout))
			errx(1, "write");
		break;
	default:
		errx(1, "invalid output format");
	}

	/* Success!  */
	cbor_decref(&map);
	OPENSSL_cleanse(secret, nsecret);
	free(secret);
}

static void __dead
usage(void)
{

	fprintf(stderr, "Usage: %s [-dqv] [-r <rpid>] <command> <args>...\n",
	    getprogname());
	fprintf(stderr, "\n");
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "       %s enroll [<options>] <cryptfile>\n",
	    getprogname());
	fprintf(stderr, "       %s get [<options>] <cryptfile>\n",
	    getprogname());
#if 0
	fprintf(stderr, "       %s list [<options>] <cryptfile>\n",
	    getprogname());
	fprintf(stderr, "       %s unenroll [<options>] <cryptfile>\n",
	    getprogname());
#endif
	exit(1);
}

int
main(int argc, char **argv)
{
	int ch, error = 0;

	/* Set the program name for getprogname() later on.  */
	setprogname(argv[0]);

	/* Initialize our signal handlers and thread doohickeys.  */
	signals_init();
	threads_init();

	/* Initialize libfido2 before doing anything else with it.  */
	fido_init(0);

	/* Parse common options.  */
	while ((ch = getopt(argc, argv, "dhqr:v")) != -1) {
		switch (ch) {
		case 'd':
			S->debug = S->verbose = true;
			break;
		case 'q':
			S->quiet = true;
			break;
		case 'r':
			if (S->rp_id) {
				warnx("specify only one relying party id");
				error = 1;
				break;
			}
			S->rp_id = optarg;
			break;
		case 'v':
			S->verbose = true;
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1) {
		warnx("missing command");
		usage();
	}

	/* Verify we have all the arguments we need.  */
	if (S->rp_id == NULL &&
	    (S->rp_id = getenv("FIDOCRYPT_RPID")) == NULL) {
		warnx("specify relying party id (-r or FIDOCRYPT_RPID)");
		error = 1;
	}

	/* Stop and report usage errors if any.  */
	if (error)
		usage();

	/* Open the tty for messages if not quiet.  */
	if (S->quiet) {
		S->ttyfd = -1;
	} else {
		if ((S->ttyfd = open("/dev/tty", O_WRONLY)) == -1)
			err(1, "open tty");
	}

	/*
	 * Verify we have a command and dispatch on it.  Make sure to
	 * reset getopt(3) before parsing the subcommand arguments.
	 */
	optreset = optind = 1;
	if (strcmp(argv[0], "enroll") == 0)
		cmd_enroll(argc, argv);
	else if (strcmp(argv[0], "get") == 0)
		cmd_get(argc, argv);
#if 0
	else if (strcmp(argv[0], "list") == 0)
		cmd_list(argc, argv);
	else if (strcmp(argv[0], "unenroll") == 0)
		cmd_unenroll(argc, argv);
#endif
	else {
		warnx("unknown command");
		usage();
	}

	return 0;
}
