default-target: all
default-target: .PHONY
.PHONY:

LDLIBS = \
	-lcbor \
	-lcrypto \
	-lfido2 \
	-lpthread \
	-lsqlite3 \
	# end of LDLIBS

_CFLAGS = -g -O2 -Wall -Wextra -Werror -std=c99 $(CFLAGS)
_CPPFLAGS = -MD -MF $*.d -D_POSIX_C_SOURCE=200809L $(CPPFLAGS)

.c.o:
	$(CC) $(_CFLAGS) $(_CPPFLAGS) -c $<

# SQL -> C include file, for schema definitions
.SUFFIXES: .sql .i
.sql.i:
	sed -e 's,[\"],\\&,g' -e 's,^,",g' -e 's,$$,\\n",g' < $< > $@.tmp \
	&& mv -f $@.tmp $@

all: .PHONY
all: check
all: fidocrypt
all: fidokdf

clean: .PHONY

test: .PHONY check
check: .PHONY


# fidocrypt tool
#
SRCS_fidocrypt = \
	assert_decrypt.c \
	crc.c \
	cred_encrypt.c \
	dae.c \
	es256_encode.c \
	fidocrypt.c \
	recover.c \
	# end of SRCS_fidocrypt
DEPS_fidocrypt = $(SRCS_fidocrypt:.c=.d)
-include $(DEPS_fidocrypt)
fidocrypt: $(SRCS_fidocrypt:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_fidocrypt:.c=.o) $(LDLIBS)
fidocrypt.o: fidocrypt1.i

clean: clean-fidocrypt
clean-fidocrypt: .PHONY
	-rm -f fidocrypt
	-rm -f fidocrypt.out
	-rm -f $(SRCS_fidocrypt:.c=.o)
	-rm -f $(SRCS_fidocrypt:.c=.d)


# fidokdf tool
#
SRCS_fidokdf = \
	assert_kdf.c \
	crc.c \
	cred_kdf.c \
	es256_encode.c \
	fidokdf.c \
	recover.c \
	# end of SRCS_fidokdf
DEPS_fidokdf = $(SRCS_fidokdf:.c=.d)
-include $(DEPS_fidokdf)
fidokdf: $(SRCS_fidokdf:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_fidokdf:.c=.o) $(LDLIBS)

clean: clean-fidokdf
clean-fidokdf: .PHONY
	-rm -f fidokdf
	-rm -f fidokdf.out
	-rm -f $(SRCS_fidokdf:.c=.o)
	-rm -f $(SRCS_fidokdf:.c=.d)


# assert_decrypt test
#
check: check-assert_decrypt
check-assert_decrypt: .PHONY
check-assert_decrypt: t_assert_decrypt.exp t_assert_decrypt.out
	diff -u t_assert_decrypt.exp t_assert_decrypt.out

t_assert_decrypt.out: t_assert_decrypt
	./t_assert_decrypt > $@.tmp && mv -f $@.tmp $@

SRCS_t_assert_decrypt = \
	assert_decrypt.c \
	dae.c \
	es256_encode.c \
	recover.c \
	t_assert_decrypt.c \
	# end of SRCS_t_assert_decrypt
DEPS_t_assert_decrypt = $(SRCS_t_assert_decrypt:.c=.d)
-include $(DEPS_t_assert_decrypt)
t_assert_decrypt: $(SRCS_t_assert_decrypt:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_assert_decrypt:.c=.o) \
		$(LDLIBS)

clean: clean-assert_decrypt
clean-assert_decrypt: .PHONY
	-rm -f t_assert_decrypt
	-rm -f t_assert_decrypt.out
	-rm -f t_assert_decrypt.out.tmp
	-rm -f $(SRCS_t_assert_decrypt:.c=.o)
	-rm -f $(SRCS_t_assert_decrypt:.c=.d)


# assert_kdf test
#
check: check-assert_kdf
check-assert_kdf: .PHONY
check-assert_kdf: t_assert_kdf.exp t_assert_kdf.out
	diff -u t_assert_kdf.exp t_assert_kdf.out

t_assert_kdf.out: t_assert_kdf
	./t_assert_kdf > $@.tmp && mv -f $@.tmp $@

SRCS_t_assert_kdf = \
	assert_kdf.c \
	es256_encode.c \
	recover.c \
	t_assert_kdf.c \
	# end of SRCS_t_assert_kdf
DEPS_t_assert_kdf = $(SRCS_t_assert_kdf:.c=.d)
-include $(DEPS_t_assert_kdf)
t_assert_kdf: $(SRCS_t_assert_kdf:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_assert_kdf:.c=.o) $(LDLIBS)

clean: clean-assert_kdf
clean-assert_kdf: .PHONY
	-rm -f t_assert_kdf
	-rm -f t_assert_kdf.out
	-rm -f t_assert_kdf.out.tmp
	-rm -f $(SRCS_t_assert_kdf:.c=.o)
	-rm -f $(SRCS_t_assert_kdf:.c=.d)


# cred_encrypt test
#
check: check-cred_encrypt
check-cred_encrypt: .PHONY
check-cred_encrypt: t_cred_encrypt.exp t_cred_encrypt.out
	diff -u t_cred_encrypt.exp t_cred_encrypt.out

t_cred_encrypt.out: t_cred_encrypt
	./t_cred_encrypt > $@.tmp && mv -f $@.tmp $@

SRCS_t_cred_encrypt = \
	cred_encrypt.c \
	dae.c \
	es256_encode.c \
	recover.c \
	t_cred_encrypt.c \
	# end of SRCS_t_cred_encrypt
DEPS_t_cred_encrypt = $(SRCS_t_cred_encrypt:.c=.d)
-include $(DEPS_t_cred_encrypt)
t_cred_encrypt: $(SRCS_t_cred_encrypt:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_cred_encrypt:.c=.o) \
		$(LDLIBS)

clean: clean-cred_encrypt
clean-cred_encrypt: .PHONY
	-rm -f t_cred_encrypt
	-rm -f t_cred_encrypt.out
	-rm -f t_cred_encrypt.out.tmp
	-rm -f $(SRCS_t_cred_encrypt:.c=.o)
	-rm -f $(SRCS_t_cred_encrypt:.c=.d)


# cred_kdf test
#
check: check-cred_kdf
check-cred_kdf: .PHONY
check-cred_kdf: t_cred_kdf.exp t_cred_kdf.out
	diff -u t_cred_kdf.exp t_cred_kdf.out

t_cred_kdf.out: t_cred_kdf
	./t_cred_kdf > $@.tmp && mv -f $@.tmp $@

SRCS_t_cred_kdf = \
	cred_kdf.c \
	es256_encode.c \
	recover.c \
	t_cred_kdf.c \
	# endof SRCS_t_cred_kdf
DEPS_t_cred_kdf = $(SRCS_t_cred_kdf:.c=.d)
-include $(DEPS_t_cred_kdf)
t_cred_kdf: $(SRCS_t_cred_kdf:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_cred_kdf:.c=.o) $(LDLIBS)

clean: clean-cred_kdf
clean-cred_kdf: .PHONY
	-rm -f t_cred_kdf
	-rm -f t_cred_kdf.out
	-rm -f t_cred_kdf.out.tmp
	-rm -f $(SRCS_t_cred_kdf:.c=.o)
	-rm -f $(SRCS_t_cred_kdf:.c=.d)


# recover test
#
check: check-recover
check-recover: .PHONY
check-recover: t_recover.exp t_recover.out
	diff -u t_recover.exp t_recover.out

t_recover.out: t_recover
	./t_recover > $@.tmp && mv -f $@.tmp $@

SRCS_t_recover = \
	recover.c \
	t_recover.c \
	# end of SRCS_t_recover
DEPS_t_recover = $(SRCS_t_recover:.c=.d)
-include $(DEPS_t_recover)
t_recover: $(SRCS_t_recover:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_recover:.c=.o) $(LDLIBS)

clean: clean-recover
clean-recover: .PHONY
	-rm -f t_recover
	-rm -f t_recover.out
	-rm -f t_recover.out.tmp
	-rm -f $(SRCS_t_recover:.c=.o)
	-rm -f $(SRCS_t_recover:.c=.d)


# DAE test
#
check: check-dae
check-dae: .PHONY
check-dae: t_dae.exp t_dae.out
	diff -u t_dae.exp t_dae.out

t_dae.out: t_dae
	./t_dae > $@.tmp && mv -f $@.tmp $@

SRCS_t_dae = \
	dae.c \
	t_dae.c \
	# end of SRCS_t_dae
DEPS_t_dae = $(SRCS_t_dae:.c=.d)
-include $(DEPS_t_dae)
t_dae: $(SRCS_t_dae:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_dae:.c=.o) $(LDLIBS)

clean: clean-dae
clean-dae: .PHONY
	-rm -f t_dae
	-rm -f t_dae.out
	-rm -f t_dae.out.tmp
	-rm -f $(SRCS_t_dae:.c=.o)
	-rm -f $(SRCS_t_dae:.c=.d)
