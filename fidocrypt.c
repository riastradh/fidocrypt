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

#include <sys/mman.h>
#include <sys/resource.h>
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
#include <vis.h>

#include <fido.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include "assert_decrypt.h"
#include "cred_encrypt.h"
#include "fidocrypt.h"

static const char *schema[] = {
#include "fidocrypt1.i"
};
static unsigned oldest_compatible_version = 1;

static struct state {
	pthread_mutex_t		mtx;
	pthread_cond_t		cond;

	int			ttyfd;
	bool			quiet;
	bool			verbose;
	bool			debug;
	bool			experimental;

	const char		*rp_id;
	const char		*user_id;
	const char		*user_name;

	struct {
		void			*ptr;
		size_t			nbytes;
	}			*creds;
	size_t			ncreds;

	unsigned		pending;
	const fido_dev_info_t	*devlist;

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
	for (j = 0; j < S->ncreds; j++) {
		if ((error = fido_cred_exclude(cred, S->creds[j].ptr,
			    S->creds[j].nbytes)) != FIDO_OK)
			errx(1, "fido_cred_exclude: %s",
			    fido_strerr(error));
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
	for (j = 0; j < S->ncreds; j++) {
		if ((error = fido_assert_allow_cred(assert, S->creds[j].ptr,
			    S->creds[j].nbytes)) != FIDO_OK)
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
run_thread_per_dev(void *(*start)(void *))
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
db_exec1int(sqlite3 *db, const char *q, int64_t *ret)
{
	sqlite3_stmt *stmt = NULL;
	int error;

	if ((error = sqlite3_prepare_v2(db, q, -1, &stmt, NULL)) != SQLITE_OK)
		goto out;
	if ((error = sqlite3_step(stmt)) != SQLITE_ROW)
		goto out;

	/* Success!  */
	*ret = sqlite3_column_int64(stmt, 0);
	error = 0;

out:	if (stmt) {
		int error1 = sqlite3_finalize(stmt);
		error = error ? error : error1;
	}
	return error;
}

static sqlite3 *
opencrypt(const char *path, int flags)
{
	sqlite3 *db = NULL;
	int64_t appid, ver;
	unsigned i;
	char *errmsg;
	int error;

	/* Open the database.  */
	if ((error = sqlite3_open_v2(path, &db, flags, NULL)) != SQLITE_OK)
		errx(1, "open cryptfile: %s",
		    db ? sqlite3_errmsg(db) : sqlite3_errstr(error));

	/* Get the application id and user schema version.  */
	if (db_exec1int(db, "PRAGMA application_id", &appid) != SQLITE_OK)
		errx(1, "sqlite3 app id: %s", sqlite3_errmsg(db));
	if (db_exec1int(db, "PRAGMA user_version", &ver) != SQLITE_OK)
		errx(1, "sqlite3 user version: %s", sqlite3_errmsg(db));

	/*
	 * Verify the application id -- it will be 0 if this is a newly
	 * created database; otherwise it will be `FCRT'.
	 */
	if (appid != 0 && appid != 0x46435254)
		errx(1, "invalid cryptfile (appid=0x%"PRIx64")", appid);

	/*
	 * If the version is zero. instantiate the schema.  Otherwise,
	 * verify it's not too old, too new, or too experimental.  Do
	 * each schema migration in its own immediate transaction --
	 * exclude other writers but not other readers.
	 */
	if (ver == 0) {
		for (i = 0; i < __arraycount(schema); i++) {
			if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL,
				&errmsg) != SQLITE_OK)
				errx(1, "sqlite3 BEGIN IMMEDIATE: %s", errmsg);
			if (sqlite3_exec(db, schema[i], NULL, NULL, &errmsg)
			    != SQLITE_OK)
				errx(1, "sqlite3 schema %u: %s", i, errmsg);
			if (sqlite3_exec(db, "COMMIT", NULL, NULL, &errmsg)
			    != SQLITE_OK)
				errx(1, "sqlite3 COMMIT: %s", errmsg);
		}
	} else {
		if ((uint64_t)abs(ver) > __arraycount(schema))
			errx(1, "unknown cryptfile format (version=%"PRId64")",
			    ver);
		if ((uint64_t)abs(ver) < oldest_compatible_version)
			errx(1, "schema too old (version=%"PRId64")", ver);
		if (ver < 0) {
			if (S->experimental)
				warnx("WARNING: experimental cryptfile");
			else
				errx(1, "experimental cryptfile"
				    " (set -E to force)");
		}
	}

	/*
	 * If we're opening for read/write, start an immediate
	 * transaction -- allows concurrent reads, but rejects
	 * concurrent writes, and fails immediately if there are
	 * concurrent writes already ongoing.
	 *
	 * Otherwise, if we're opening read-only, just start a deferred
	 * transaction.  If we were in journal_mode=WAL this would
	 * prevent the state from changing under us while we work, but
	 * we don't set that because it makes life more difficult on
	 * read-only media than rollback journals do.  So starting a
	 * transaction here is really only to make it convenient for
	 * closecrypt to just commit it.
	 */
	if ((flags & SQLITE_OPEN_READWRITE) == SQLITE_OPEN_READWRITE) {
		if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &errmsg)
		    != SQLITE_OK)
			errx(1, "%s: sqlite3 BEGIN IMMEDIATE: %s", __func__,
			    sqlite3_errmsg(db));
	} else {
		if (sqlite3_exec(db, "BEGIN", NULL, NULL, &errmsg)
		    != SQLITE_OK)
			errx(1, "%s: sqlite3 BEGIN: %s", __func__,
			    sqlite3_errmsg(db));
	}

	/* Success!  */
	return db;
}

static void
closecrypt(sqlite3 *db)
{
	char *errmsg;

	/* Commit the transaction.  */
	if (sqlite3_exec(db, "COMMIT", NULL, NULL, &errmsg) != SQLITE_OK)
		errx(1, "%s: sqlite3 COMMIT: %s", __func__,
		    sqlite3_errmsg(db));

	/*
	 * If we did anything, vacuum the database to overwrite it with
	 * zeros in case anything we tried to do was deletion.
	 */
	if (sqlite3_total_changes(db) &&
	    sqlite3_exec(db, "VACUUM", NULL, NULL, NULL) != SQLITE_OK)
		errx(1, "sqlite3 vacuum: %s", sqlite3_errmsg(db));

	/* Finally, close the database.  */
	if (sqlite3_close(db) != SQLITE_OK)
		errx(1, "close cryptfile: %s", sqlite3_errmsg(db));
}

static void
set_credentials(sqlite3 *db)
{
	int64_t dv[2], n;
	sqlite3_stmt *stmt;
	unsigned i;
	int error;

top:	/*
	 * Get the data version so we can determine when something is
	 * awry or when the database was merely updated while we were
	 * trying to read from it.
	 */
	if (db_exec1int(db, "PRAGMA data_version", &dv[0]) != SQLITE_OK)
		errx(1, "%s: sqlite3 data version 0: %s", __func__,
		    sqlite3_errmsg(db));

	/* Determine how many entries there are.  */
	if (db_exec1int(db, "SELECT COUNT(*) FROM entry", &n) != SQLITE_OK)
		errx(1, "count credentials: %s", sqlite3_errmsg(db));
	if (n < 0)
		errx(1, "negative credential count: %"PRId64, n);
	if ((uint64_t)n > SIZE_MAX)
		errx(1, "excessive credential count: %"PRId64, n);

	/* Allocate an array of that many credential ids.  */
	S->ncreds = (size_t)n;
	if ((S->creds = calloc(S->ncreds, sizeof(S->creds[0]))) == NULL)
		err(1, "malloc");

	/* Fill up the array.  */
	if (sqlite3_prepare_v2(db, "SELECT credential_id FROM entry", -1,
		&stmt, NULL) != SQLITE_OK)
		errx(1, "%s: sqlite3 prepare: %s", __func__,
		    sqlite3_errmsg(db));
	for (i = 0; i < S->ncreds; i++) {
		const void *ptr;
		int nbytes;

		if ((error = sqlite3_step(stmt)) != SQLITE_ROW) {
			if (error == SQLITE_DONE)
				goto retry;
			errx(1, "list credentials: %s", sqlite3_errmsg(db));
		}
		if ((ptr = sqlite3_column_blob(stmt, 0)) == NULL)
			errx(1, "%s: missing column 0, row %u", __func__, i);
		if ((nbytes = sqlite3_column_bytes(stmt, 0)) <= 0)
			errx(1, "%s: bogus column 0, row %u: %d", __func__, i,
			    nbytes);
		S->creds[i].nbytes = (size_t)nbytes;
		if ((S->creds[i].ptr = malloc(S->creds[i].nbytes)) == NULL)
			err(1, "malloc");
		memcpy(S->creds[i].ptr, ptr, S->creds[i].nbytes);
	}
	if ((error = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (error == SQLITE_ROW)
			goto retry;
		errx(1, "list credentials done: %s", sqlite3_errmsg(db));
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize: %s", __func__,
		    sqlite3_errmsg(db));
	return;

retry:	/*
	 * The count mismatched the number of rows.  Since sqlite3
	 * doesn't provide snapshot isolation[*], the table could have
	 * changed while we were reading it; if this is the case,
	 * data_version will reflect the change, and we need to start
	 * over.  If data_version is unchanged, though, something must
	 * be seriously awry, so just give up.
	 *
	 * [*] See <https://sqlite.org/isolation.html>.  sqlite3 does
	 * provide snapshot isolation when journal_mode=WAL, but with
	 * journal_mode=WAL it is more finicky about read-only media,
	 * and we would like this to work early at boot from read-only
	 * media.
	 */
	if (db_exec1int(db, "PRAGMA data_version", &dv[1]) != SQLITE_OK)
		errx(1, "%s: sqlite3 data version 0: %s", __func__,
		    sqlite3_errmsg(db));
	if (dv[0] == dv[1])
		errx(1, "database corrupt");
	while (i --> 0) {
		OPENSSL_cleanse(S->creds[i].ptr, S->creds[i].nbytes);
		free(S->creds[i].ptr);
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize (retry): %s", __func__,
		    sqlite3_errmsg(db));
	free(S->creds);
	S->creds = NULL;
	S->ncreds = 0;
	goto top;
}

static void *
do_get(size_t *nsecretp, sqlite3 *db)
{
	fido_assert_t *assert = NULL;
	const void *credential_id;
	size_t ncredential_id;
	sqlite3_stmt *stmt = NULL;
	const void *ciphertext;
	int nciphertext;
	void *secret = NULL;
	size_t nsecret = 0;
	int error;

	/* Get an assertion from one of the devices.  */
	assert = run_thread_per_dev(get_thread);

	/* Verify that there is at least one assertion.  */
	/* XXX What to do about more than one assertion?  */
	if (fido_assert_count(assert) < 1)
		errx(1, "no assertions");

	/* Get the credential id.  */
	if ((credential_id = fido_assert_id_ptr(assert, 0)) == NULL ||
	    (ncredential_id = fido_assert_id_len(assert, 0)) == 0)
		errx(1, "empty credential id");
	if (ncredential_id > INT_MAX)
		errx(1, "excessive credential id size: %zu", ncredential_id);

	/* Find the matching ciphertext.  */
	if (sqlite3_prepare_v2(db,
		"SELECT ciphertext FROM entry WHERE credential_id = ?",
		-1, &stmt, NULL) != SQLITE_OK)
		errx(1, "%s: sqlite3 prepare: %s", __func__,
		    sqlite3_errmsg(db));
	if (sqlite3_bind_blob(stmt, 1, credential_id, ncredential_id,
		SQLITE_STATIC) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind: %s", __func__, sqlite3_errmsg(db));
	if ((error = sqlite3_step(stmt)) != SQLITE_ROW) {
		if (error == SQLITE_DONE)
			errx(1, "no matching credential");
		errx(1, "%s: sqlite3: %s", __func__, sqlite3_errmsg(db));
	}
	if ((ciphertext = sqlite3_column_blob(stmt, 0)) == NULL)
		errx(1, "%s: missing column 0", __func__);
	if ((nciphertext = sqlite3_column_bytes(stmt, 0)) <= 0)
		errx(1, "%s: bogus column 0: %d", __func__, nciphertext);

	/*
	 * Verify and decrypt the ciphertext using the `key' derived
	 * from the assertion.
	 */
	if ((size_t)nciphertext < FIDOCRYPT_OVERHEADBYTES)
		errx(1, "corrupt cryptfile");
	nsecret = (size_t)nciphertext - FIDOCRYPT_OVERHEADBYTES;
	if ((secret = malloc(nsecret)) == NULL)
		err(1, "malloc");
	if ((error = fido_assert_decrypt(assert, 0, COSE_ES256, secret,
		    ciphertext, (size_t)nciphertext)) != FIDO_OK)
		errx(1, "fido_assert_decrypt: %s", fido_strerr(error));

	/* Release the sqlite3 statement.  */
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize: %s", __func__,
		    sqlite3_errmsg(db));

	/* Success!  Free the assertion and return the secret.  */
	fido_assert_free(&assert);
	*nsecretp = nsecret;
	return secret;
}

static void
rename_nickname(sqlite3 *db, const char *nickname, const char *newname)
{
	sqlite3_stmt *stmt = NULL;
	int error;

	if (sqlite3_prepare_v2(db,
		"UPDATE entry SET nickname = ? WHERE nickname = ?", -1, &stmt,
		NULL) != SQLITE_OK)
		errx(1, "%s: sqlite3 prepare: %s", __func__,
		    sqlite3_errmsg(db));
	if (sqlite3_bind_text(stmt, 1, newname, (int)strlen(newname),
		SQLITE_STATIC) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind 1: %s", __func__,
		    sqlite3_errmsg(db));
	if (sqlite3_bind_text(stmt, 2, nickname, (int)strlen(nickname),
		SQLITE_STATIC) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind 2: %s", __func__,
		    sqlite3_errmsg(db));
	if ((error = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (error == SQLITE_ROW)
			errx(1, "DELETE unexpectedly returned results");
		errx(1, "%s: sqlite3 step: %s", __func__, sqlite3_errmsg(db));
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize: %s", __func__,
		    sqlite3_errmsg(db));
}

static void
rename_id(sqlite3 *db, int64_t id, const char *newname)
{
	sqlite3_stmt *stmt = NULL;
	int error;

	if (sqlite3_prepare_v2(db,
		"UPDATE entry SET nickname = ? WHERE id = ?", -1, &stmt,
		NULL) != SQLITE_OK)
		errx(1, "%s: sqlite3 prepare: %s", __func__,
		    sqlite3_errmsg(db));
	if (sqlite3_bind_text(stmt, 1, newname, (int)strlen(newname),
		SQLITE_STATIC) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind 1: %s", __func__,
		    sqlite3_errmsg(db));
	if (sqlite3_bind_int64(stmt, 2, id) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind 2: %s", __func__,
		    sqlite3_errmsg(db));
	if ((error = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (error == SQLITE_ROW)
			errx(1, "DELETE unexpectedly returned results");
		errx(1, "%s: sqlite3 step: %s", __func__, sqlite3_errmsg(db));
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize: %s", __func__,
		    sqlite3_errmsg(db));
}

static void
delete_nickname(sqlite3 *db, const char *nickname)
{
	sqlite3_stmt *stmt = NULL;
	int error;

	if (sqlite3_prepare_v2(db, "DELETE FROM entry WHERE nickname = ?", -1,
		&stmt, NULL) != SQLITE_OK)
		errx(1, "%s: sqlite3 prepare: %s", __func__,
		    sqlite3_errmsg(db));
	if (sqlite3_bind_text(stmt, 1, nickname, (int)strlen(nickname),
		SQLITE_STATIC) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind: %s", __func__, sqlite3_errmsg(db));
	if ((error = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (error == SQLITE_ROW)
			errx(1, "DELETE unexpectedly returned results");
		errx(1, "%s: sqlite3 step: %s", __func__, sqlite3_errmsg(db));
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize: %s", __func__,
		    sqlite3_errmsg(db));
}

static void
delete_id(sqlite3 *db, int64_t id)
{
	sqlite3_stmt *stmt = NULL;
	int error;

	if (sqlite3_prepare_v2(db, "DELETE FROM entry WHERE id = ?", -1,
		&stmt, NULL) != SQLITE_OK)
		errx(1, "%s: sqlite3 prepare: %s", __func__,
		    sqlite3_errmsg(db));
	if (sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind: %s", __func__, sqlite3_errmsg(db));
	if ((error = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (error == SQLITE_ROW)
			errx(1, "DELETE unexpectedly returned results");
		errx(1, "%s: sqlite3 step: %s", __func__, sqlite3_errmsg(db));
	}
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize: %s", __func__,
		    sqlite3_errmsg(db));
}

static void __dead
usage_enroll(void)
{

	fprintf(stderr,
	    "Usage: %s enroll -N <username> -u <userid> [-n <nickname>]\n",
	    getprogname());
	fprintf(stderr,
	    "           [-s <secretfile>] <cryptfile>\n");
	exit(1);
}

static void
cmd_enroll(int argc, char **argv)
{
	const char *nickname = NULL;
	const char *secretfile = NULL;
	const char *cryptfile = NULL;
	sqlite3 *db = NULL;
	uint8_t secretbuf[32], *secret = NULL;
	size_t nsecret = 0;
	fido_cred_t *cred = NULL;
	const void *credential_id;
	size_t ncredential_id;
	uint8_t *ciphertext;
	size_t nciphertext;
	sqlite3_stmt *stmt = NULL;
	int ch, error = 0;

	/* Parse arguments.  */
	while ((ch = getopt(argc, argv, "hN:n:s:u:")) != -1) {
		switch (ch) {
		case 'N':
			if (S->user_name) {
				warnx("specify only one user name");
				error = 1;
				break;
			}
			S->user_name = optarg;
			break;
		case 'n':
			if (nickname) {
				warnx("specify only one nickname");
				error = 1;
				break;
			}
			nickname = optarg;
			if (strlen(nickname) > INT_MAX) {
				warnx("excessive nickname length: %zu",
				    strlen(nickname));
				error = 1;
				break;
			}
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

	/* Open the cryptfile if there is one, or create it if not.  */
	db = opencrypt(cryptfile, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE);

	/*
	 * Set the credentials, if specified -- these may be used both
	 * to allow when retrieving the stored secret and to exclude
	 * when enrolling a new device.
	 */
	set_credentials(db);

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
		if (S->ncreds)
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
	} else if (S->ncreds) {
		/* Existing file -- get the secret from another key.  */
		MSG("tap a key that's already enrolled; waiting...\n");
		secret = do_get(&nsecret, db);
	} else {
		/* New file -- generate the secret.  */
		if (!RAND_bytes(secretbuf, sizeof(secretbuf)))
			errx(1, "RAND_bytes");
		secret = secretbuf;
		nsecret = sizeof(secretbuf);
	}

	/* Get a credential from one of the devices.  */
	MSG("tap key to enroll; waiting...\n");
	cred = run_thread_per_dev(enroll_thread);

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
	 * Store the new ciphertext.
	 */

	/* Prepare a statement.  */
	if (sqlite3_prepare_v2(db,
		"INSERT INTO entry (nickname, credential_id, ciphertext)"
		" VALUES (?, ?, ?)",
		-1, &stmt, NULL) != SQLITE_OK)
		errx(1, "%s: sqlite3 prepare: %s", __func__,
		    sqlite3_errmsg(db));

	/* Set the nickname.  */
	if (nickname) {
		if (sqlite3_bind_text(stmt, 1, nickname, (int)strlen(nickname),
			SQLITE_STATIC) != SQLITE_OK)
			errx(1, "%s: sqlite3 bind nickname: %s", __func__,
			    sqlite3_errmsg(db));
	} else {
		if (sqlite3_bind_null(stmt, 1) != SQLITE_OK)
			errx(1, "%s: sqlite3 bind nickname: %s", __func__,
			    sqlite3_errmsg(db));
	}

	/* Set the credential id.  */
	if (ncredential_id > INT_MAX)
		errx(1, "excessive credential id size: %zu", ncredential_id);
	if (sqlite3_bind_blob(stmt, 2, credential_id, (int)ncredential_id,
		SQLITE_STATIC) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind credential id: %s", __func__,
		    sqlite3_errmsg(db));

	/* Set the ciphertext.  */
	if (nciphertext > INT_MAX)
		errx(1, "excessive ciphertext size: %zu", nciphertext);
	if (sqlite3_bind_blob(stmt, 3, ciphertext, (int)nciphertext,
		SQLITE_STATIC) != SQLITE_OK)
		errx(1, "%s: sqlite3 bind ciphertext: %s", __func__,
		    sqlite3_errmsg(db));

	/* Exceute it.  */
	if ((error = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (error == SQLITE_ROW)
			errx(1, "INSERT unexpectedly returned results");
		errx(1, "%s: sqlite3 step: %s", __func__, sqlite3_errmsg(db));
	}

	/* Finalize it.  */
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize: %s", __func__,
		    sqlite3_errmsg(db));

	/* Success!  */
	OPENSSL_cleanse(ciphertext, nciphertext);
	free(ciphertext);
	fido_cred_free(&cred);
	OPENSSL_cleanse(secret, nsecret);
	if (secret != secretbuf)
		free(secret);
	closecrypt(db);
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
	sqlite3 *db = NULL;
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

	/* Open the cryptfile read-only, or fail if it doesn't exist.  */
	db = opencrypt(cryptfile, SQLITE_OPEN_READONLY);

	/* Set the allowed credentials.  */
	set_credentials(db);

	/* Get the secret.  */
	MSG("tap key; waiting...\n");
	secret = do_get(&nsecret, db);

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
	closecrypt(db);
	OPENSSL_cleanse(secret, nsecret);
	free(secret);
}

static void __dead
usage_list(void)
{

	fprintf(stderr, "Usage: %s list <cryptfile>\n", getprogname());
	exit(1);
}

static void
cmd_list(int argc, char **argv)
{
	const char *cryptfile = NULL;
	sqlite3 *db = NULL;
	sqlite3_stmt *stmt = NULL;
	int ch, error = 0;

	/* Parse arguments.  */
	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case '?':
		case 'h':
		default:
			usage_list();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage_list();
	cryptfile = *argv++; argc--;

	/* Stop and report usage errors if any.  */
	if (error)
		usage_list();

	/* Open the cryptfile read-only, or fail if it doesn't exist.  */
	db = opencrypt(cryptfile, SQLITE_OPEN_READONLY);

	/* List the credentials.  */
	if (sqlite3_prepare_v2(db,
		"SELECT id, nickname FROM entry ORDER BY nickname ASC, id ASC",
		-1,
		&stmt, NULL) != SQLITE_OK)
		errx(1, "%s: sqlite3 prepare: %s", __func__,
		    sqlite3_errmsg(db));
	while ((error = sqlite3_step(stmt)) == SQLITE_ROW) {
		int64_t id;
		const char *nickname;
		char *vnickname = NULL;

		/*
		 * Print the id, and then a shell-safe nickname so that
		 * the user can copy & paste it into a shell command
		 * line.
		 */
		id = sqlite3_column_int64(stmt, 0);
		nickname = (const char *)sqlite3_column_text(stmt, 1);
		if (nickname) {
			if (stravis(&vnickname, nickname, VIS_META) == -1)
				err(1, "stravis");
		}
		printf("%"PRId64"%s%s\n", id, nickname ? " " : "",
		    nickname ? vnickname : "");
		free(vnickname);
	}
	if (error != SQLITE_DONE)
		errx(1, "%s: sqlite3 step: %s", __func__, sqlite3_errmsg(db));
	if (sqlite3_finalize(stmt) != SQLITE_OK)
		errx(1, "%s: sqlite3 finalize: %s", __func__,
		    sqlite3_errmsg(db));

	/* Success!  */
	closecrypt(db);
}

static void __dead
usage_rename(void)
{

	fprintf(stderr,
	    "Usage: %s rename [-N <id>] [-n <nickname>] <cryptfile>"
	    " <newname>\n",
	    getprogname());
	exit(1);
}

static void
cmd_rename(int argc, char **argv)
{
	long long id = -1;
	const char *nickname = NULL;
	const char *cryptfile = NULL;
	const char *newname = NULL;
	sqlite3 *db = NULL;
	int nchanges;
	int ch, error = 0;

	/* Parse arguments.  */
	while ((ch = getopt(argc, argv, "hi:n:")) != -1) {
		switch (ch) {
		case 'i': {
			char *end;

			if (id != -1 || nickname) {
				warnx("specify only one id or nickname");
				error = 1;
				break;
			}
			errno = 0;
			id = strtoll(optarg, &end, 0);
			if (end == optarg || *end != '\0' || errno == ERANGE) {
				warnx("invalid id");
				error = 1;
				break;
			}
			break;
		}
		case 'n':
			if (id != -1 || nickname) {
				warnx("specify only one id or nickname");
				error = 1;
				break;
			}
			nickname = optarg;
			if (strlen(nickname) > INT_MAX) {
				warnx("excessive nickname length: %zu",
				    strlen(nickname));
				error = 1;
				break;
			}
			break;
		case '?':
		case 'h':
		default:
			usage_rename();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage_rename();
	cryptfile = *argv++; argc--;
	newname = *argv++; argc--;

	/* Verify we have all the arguments we need.  */
	if (id == -1 && nickname == NULL) {
		warnx("specify an id number (-i) or nickname (-n)");
		error = 1;
	}

	/* Stop and report usage errors if any.  */
	if (error)
		usage_rename();

	/* Open the cryptfile read/write, or fail if it doesn't exist.  */
	db = opencrypt(cryptfile, SQLITE_OPEN_READWRITE);

	/* Rename the specified credential.  */
	if (nickname)
		rename_nickname(db, nickname, newname);
	else
		rename_id(db, id, newname);

	/* Verify that we actually updated one record.  */
	if ((nchanges = sqlite3_changes(db)) != 1) {
		if (nchanges == 0)
			errx(1, "no such key");
		else
			errx(1, "renamed more than expected");
	}

	/* Success!  */
	closecrypt(db);
}

static void __dead
usage_unenroll(void)
{

	fprintf(stderr,
	    "Usage: %s unenroll [-N <id>] [-n <nickname>] <cryptfile>\n",
	    getprogname());
	exit(1);
}

static void
cmd_unenroll(int argc, char **argv)
{
	long long id = -1;
	const char *nickname = NULL;
	const char *cryptfile = NULL;
	sqlite3 *db = NULL;
	int nchanges;
	int ch, error = 0;

	/* Parse arguments.  */
	while ((ch = getopt(argc, argv, "hi:n:")) != -1) {
		switch (ch) {
		case 'i': {
			char *end;

			if (id != -1 || nickname) {
				warnx("specify only one id or nickname");
				error = 1;
				break;
			}
			errno = 0;
			id = strtoll(optarg, &end, 0);
			if (end == optarg || *end != '\0' || errno == ERANGE) {
				warnx("invalid id");
				error = 1;
				break;
			}
			break;
		}
		case 'n':
			if (id != -1 || nickname) {
				warnx("specify only one id or nickname");
				error = 1;
				break;
			}
			nickname = optarg;
			if (strlen(nickname) > INT_MAX) {
				warnx("excessive nickname length: %zu",
				    strlen(nickname));
				error = 1;
				break;
			}
			break;
		case '?':
		case 'h':
		default:
			usage_unenroll();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage_unenroll();
	cryptfile = *argv++; argc--;

	/* Verify we have all the arguments we need.  */
	if (id == -1 && nickname == NULL) {
		warnx("specify an id number (-i) or nickname (-n)");
		error = 1;
	}

	/* Stop and report usage errors if any.  */
	if (error)
		usage_unenroll();

	/* Open the cryptfile read/write, or fail if it doesn't exist.  */
	db = opencrypt(cryptfile, SQLITE_OPEN_READWRITE);

	/* Delete the specified credential.  */
	if (nickname)
		delete_nickname(db, nickname);
	else
		delete_id(db, id);

	/* Verify that we actually deleted one record.  */
	if ((nchanges = sqlite3_changes(db)) != 1) {
		if (nchanges == 0)
			errx(1, "no such key");
		else
			errx(1, "deleted more than expected");
	}

	/* Success!  */
	closecrypt(db);
}

static void __dead
usage(void)
{

	fprintf(stderr, "Usage: %s [-Edqv] [-r <rpid>] <command> <args>...\n",
	    getprogname());
	fprintf(stderr, "\n");
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "       %s enroll [<options>] <cryptfile>\n",
	    getprogname());
	fprintf(stderr, "       %s get [<options>] <cryptfile>\n",
	    getprogname());
	fprintf(stderr, "       %s list [<options>] <cryptfile>\n",
	    getprogname());
	fprintf(stderr, "       %s rename [<options>] <cryptfile> <newname>\n",
	    getprogname());
	fprintf(stderr, "       %s unenroll [<options>] <cryptfile>\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct rlimit rlim;
	int ch, error = 0;

	/* Set the program name for getprogname() later on.  */
	setprogname(argv[0]);

	/* Initialize our signal handlers and thread doohickeys.  */
	signals_init();
	threads_init();

	/* Initialize libfido2 before doing anything else with it.  */
	fido_init(0);

	/* Parse common options.  */
	while ((ch = getopt(argc, argv, "Edhqr:v")) != -1) {
		switch (ch) {
		case 'E':
			S->experimental = true;
			break;
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

	/* Lock all future pages and disable core dumps.  */
	if (mlockall(MCL_FUTURE) == -1)
		err(1, "mlockall");
	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) == -1)
		err(1, "setrlimit(RLIMIT_CORE)");

	/*
	 * Verify we have a command and dispatch on it.  Make sure to
	 * reset getopt(3) before parsing the subcommand arguments.
	 */
	optreset = optind = 1;
	if (strcmp(argv[0], "enroll") == 0)
		cmd_enroll(argc, argv);
	else if (strcmp(argv[0], "get") == 0)
		cmd_get(argc, argv);
	else if (strcmp(argv[0], "list") == 0)
		cmd_list(argc, argv);
	else if (strcmp(argv[0], "rename") == 0)
		cmd_rename(argc, argv);
	else if (strcmp(argv[0], "unenroll") == 0)
		cmd_unenroll(argc, argv);
	else {
		warnx("unknown command");
		usage();
	}

	return 0;
}
