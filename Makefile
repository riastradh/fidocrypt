default-target: all
default-target: .PHONY
.PHONY:


# Parameters
#
DESTDIR =

prefix = /usr/local

bindir = $(prefix)/bin
includedir = $(prefix)/include
libdir = $(prefix)/lib
mandir = $(prefix)/share/man
man1dir = $(mandir)/man1
man3dir = $(mandir)/man3

INSTALL = install
INSTALL_DATA = $(INSTALL)
INSTALL_DIR = $(INSTALL) -d
INSTALL_LIB = $(INSTALL)
INSTALL_MAN = $(INSTALL)
INSTALL_PROGRAM = $(INSTALL)

MANDOC = mandoc

SHLIB_EXT = so
SHLIB_LDFLAGS = -shared -Wl,-z,defs
SHLIB_NAMEFLAG = -Wl,-soname=
SHLIB_CFLAGS = -fPIC
SHLIB_EXPORT = map
SHLIB_EXPORTFLAG = -Wl,--version-script=
SHLIB_RPATHFLAG = -Wl,-R


# Public targets
#
all: .PHONY
all: check
all: fidocrypt
all: fidocrypt.install
all: fidokdf
all: lib

lib: .PHONY
lib: libfidocrypt.$(SHLIB_EXT)
lib: libfidocrypt.a

clean: .PHONY
check: .PHONY
test: .PHONY check
install: .PHONY
lint: .PHONY


# Installation targets:
# binary tool, run-time libraries, development files, man pages
#
install: install-bin
install-bin: .PHONY
	$(INSTALL_DIR) $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) fidocrypt.install $(DESTDIR)$(bindir)/fidocrypt

install: install-lib
install-lib: .PHONY
install-lib: install-shlib
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_LIB) libfidocrypt.a $(DESTDIR)$(libdir)
	ln -sfn $(LIB_fidocrypt) $(DESTDIR)$(libdir)/libfidocrypt.$(SHLIB_EXT)
	$(INSTALL_DIR) $(DESTDIR)$(includedir)
	$(INSTALL_DATA) fidocrypt.h $(DESTDIR)$(includedir)

install-shlib: .PHONY
	$(INSTALL_DIR) $(DESTDIR)$(libdir)
	$(INSTALL_LIB) $(LIB_fidocrypt).$(MINOR_libfidocrypt) \
		$(DESTDIR)$(libdir)
	ln -sfn $(LIB_fidocrypt).$(MINOR_libfidocrypt) \
		$(DESTDIR)$(libdir)/$(LIB_fidocrypt)

install: install-man
install-man: .PHONY
	$(INSTALL_DIR) $(DESTDIR)$(man1dir)
	$(INSTALL_MAN) fidocrypt.1 $(DESTDIR)$(man1dir)
	$(INSTALL_DIR) $(DESTDIR)$(man3dir)
	$(INSTALL_MAN) fidocrypt.3 $(DESTDIR)$(man3dir)
	ln -sfn fidocrypt.3 $(DESTDIR)$(man3dir)/fido_assert_decrypt.3
	ln -sfn fidocrypt.3 $(DESTDIR)$(man3dir)/fido_cred_encrypt.3


# Suffix rules
#
.SUFFIXES: .c .o .pico
.c.o:
	$(CC) $(_CFLAGS) $(_CPPFLAGS) -c $<
.c.pico:
	$(CC) -o $@ $(SHLIB_CFLAGS) $(_CFLAGS) $(_CPPFLAGS) -DFIDOCRYPT_SHLIB \
		-c $<

_CFLAGS = -g -Og -Wall -Wextra -Werror -std=c99 -fvisibility=hidden $(CFLAGS)
_CPPFLAGS = -MD -MF $@.d -D_POSIX_C_SOURCE=200809L -I. $(CPPFLAGS)

# SQL -> C include file, for schema definitions
.SUFFIXES: .sql .i
.sql.i:
	sed -e 's,[\"],\\&,g' -e 's,^,",g' -e 's,$$,\\n",g' < $< > $@.tmp \
	&& mv -f $@.tmp $@


# Documentation
#
lint: lint-mandoc
lint-mandoc: .PHONY
	$(MANDOC) -Tlint fidocrypt.1 || :
	$(MANDOC) -Tlint fidocrypt.3 || :


# libfidocrypt
#
LIB_fidocrypt = libfidocrypt.so.$(MAJOR_libfidocrypt)
MAJOR_libfidocrypt = 0
MINOR_libfidocrypt = 0

LDLIBS_libfidocrypt = \
	-lcbor \
	-lcrypto \
	-lfido2 \
	# end of LDLIBS_libfidocrypt

SRCS_libfidocrypt = \
	assert_decrypt.c \
	cred_encrypt.c \
	dae.c \
	eddsa_decode.c \
	es256_encode.c \
	recover.c \
	rs256_decode.c \
	# end of SRCS_libfidocrypt
DEPS_libfidocrypt = $(SRCS_libfidocrypt:.c=.o.d) \
	$(SRCS_libfidocrypt:.c=.pico.d)
-include $(DEPS_libfidocrypt)

libfidocrypt.a: $(SRCS_libfidocrypt:.c=.o)
	$(AR) -rcs $@ $(SRCS_libfidocrypt:.c=.o)

$(LIB_fidocrypt).$(MINOR_libfidocrypt): $(SRCS_libfidocrypt:.c=.pico)
$(LIB_fidocrypt).$(MINOR_libfidocrypt): libfidocrypt.$(SHLIB_EXPORT)
	$(CC) -o $@ $(SHLIB_LDFLAGS) $(LDFLAGS) \
		$(SHLIB_NAMEFLAG)$(LIB_fidocrypt) \
		$(SHLIB_EXPORTFLAG)libfidocrypt.$(SHLIB_EXPORT) \
		$(SRCS_libfidocrypt:.c=.pico) $(LDLIBS_libfidocrypt)
$(LIB_fidocrypt): $(LIB_fidocrypt).$(MINOR_libfidocrypt)
	ln -sfn $(LIB_fidocrypt).$(MINOR_libfidocrypt) $@
libfidocrypt.$(SHLIB_EXT): $(LIB_fidocrypt)
	ln -sfn $(LIB_fidocrypt) $@

clean: clean-libfidocrypt
clean-libfidocrypt: .PHONY
	-rm -f $(LIB_fidocrypt)
	-rm -f $(LIB_fidocrypt).$(MINOR_libfidocrypt)
	-rm -f $(LIB_fidocrypt).$(MINOR_libfidocrypt)
	-rm -f $(SRCS_libfidocrypt:.c=.o)
	-rm -f $(SRCS_libfidocrypt:.c=.o.d)
	-rm -f $(SRCS_libfidocrypt:.c=.pico)
	-rm -f $(SRCS_libfidocrypt:.c=.pico.d)
	-rm -f libfidocrypt.$(SHLIB_EXT)
	-rm -f libfidocrypt.a


# fidocrypt tool
#
SRCS_fidocrypt = \
	fidocrypt.c \
	# end of SRCS_fidocrypt
DEPS_fidocrypt = $(SRCS_fidocrypt:.c=.o.d)
-include $(DEPS_fidocrypt)

# Can be run out of build tree.
fidocrypt: $(SRCS_fidocrypt:.c=.o) libfidocrypt.$(SHLIB_EXT)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_fidocrypt:.c=.o) \
		-L. $(SHLIB_RPATHFLAG). -lfidocrypt -pthread -lsqlite3

# Requires libfidocrypt to be installed in order to run.
fidocrypt.install: $(SRCS_fidocrypt:.c=.o) libfidocrypt.$(SHLIB_EXT)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_fidocrypt:.c=.o) \
		-L. $(SHLIB_RPATHFLAG)$(libdir) -lfidocrypt -pthread -lsqlite3

# May be useful for self-contained boot images.
fidocrypt.static: $(SRCS_fidocrypt:.c=.o) libfidocrypt.a
	$(CC) -o $@ -static $(_CFLAGS) $(LDFLAGS) $(SRCS_fidocrypt:.c=.o) \
		-L. -lfidocrypt $(LDLIBS_libfidocrypt) -pthread -lsqlite3 -lm

fidocrypt.o: fidocrypt1.i

clean: clean-fidocrypt
clean-fidocrypt: .PHONY
	-rm -f $(SRCS_fidocrypt:.c=.o)
	-rm -f $(SRCS_fidocrypt:.c=.o.d)
	-rm -f fidocrypt
	-rm -f fidocrypt.install
	-rm -f fidocrypt1.i


# fidokdf toy
#
SRCS_fidokdf = \
	assert_kdf.c \
	crc.c \
	cred_kdf.c \
	es256_encode.c \
	fidokdf.c \
	recover.c \
	# end of SRCS_fidokdf
DEPS_fidokdf = $(SRCS_fidokdf:.c=.o.d)
-include $(DEPS_fidokdf)
fidokdf: $(SRCS_fidokdf:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_fidokdf:.c=.o) \
		$(LDLIBS_libfidocrypt)

clean: clean-fidokdf
clean-fidokdf: .PHONY
	-rm -f $(SRCS_fidokdf:.c=.o)
	-rm -f $(SRCS_fidokdf:.c=.o.d)
	-rm -f fidokdf


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
	eddsa_decode.c \
	es256_encode.c \
	recover.c \
	rs256_decode.c \
	t_assert_decrypt.c \
	# end of SRCS_t_assert_decrypt
DEPS_t_assert_decrypt = $(SRCS_t_assert_decrypt:.c=.o.d)
-include $(DEPS_t_assert_decrypt)
t_assert_decrypt: $(SRCS_t_assert_decrypt:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_assert_decrypt:.c=.o) \
		$(LDLIBS_libfidocrypt)

clean: clean-assert_decrypt
clean-assert_decrypt: .PHONY
	-rm -f $(SRCS_t_assert_decrypt:.c=.o)
	-rm -f $(SRCS_t_assert_decrypt:.c=.o.d)
	-rm -f t_assert_decrypt
	-rm -f t_assert_decrypt.out
	-rm -f t_assert_decrypt.out.tmp


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
DEPS_t_assert_kdf = $(SRCS_t_assert_kdf:.c=.o.d)
-include $(DEPS_t_assert_kdf)
t_assert_kdf: $(SRCS_t_assert_kdf:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_assert_kdf:.c=.o) \
		$(LDLIBS_libfidocrypt)

clean: clean-assert_kdf
clean-assert_kdf: .PHONY
	-rm -f $(SRCS_t_assert_kdf:.c=.o)
	-rm -f $(SRCS_t_assert_kdf:.c=.o.d)
	-rm -f t_assert_kdf
	-rm -f t_assert_kdf.out
	-rm -f t_assert_kdf.out.tmp


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
DEPS_t_cred_encrypt = $(SRCS_t_cred_encrypt:.c=.o.d)
-include $(DEPS_t_cred_encrypt)
t_cred_encrypt: $(SRCS_t_cred_encrypt:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_cred_encrypt:.c=.o) \
		$(LDLIBS_libfidocrypt)

clean: clean-cred_encrypt
clean-cred_encrypt: .PHONY
	-rm -f $(SRCS_t_cred_encrypt:.c=.o)
	-rm -f $(SRCS_t_cred_encrypt:.c=.o.d)
	-rm -f t_cred_encrypt
	-rm -f t_cred_encrypt.out
	-rm -f t_cred_encrypt.out.tmp


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
	# end of SRCS_t_cred_kdf
DEPS_t_cred_kdf = $(SRCS_t_cred_kdf:.c=.o.d)
-include $(DEPS_t_cred_kdf)
t_cred_kdf: $(SRCS_t_cred_kdf:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_cred_kdf:.c=.o) \
		$(LDLIBS_libfidocrypt)

clean: clean-cred_kdf
clean-cred_kdf: .PHONY
	-rm -f $(SRCS_t_cred_kdf:.c=.o)
	-rm -f $(SRCS_t_cred_kdf:.c=.o.d)
	-rm -f t_cred_kdf
	-rm -f t_cred_kdf.out
	-rm -f t_cred_kdf.out.tmp


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
DEPS_t_recover = $(SRCS_t_recover:.c=.o.d)
-include $(DEPS_t_recover)
t_recover: $(SRCS_t_recover:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_recover:.c=.o) \
		$(LDLIBS_libfidocrypt)

clean: clean-recover
clean-recover: .PHONY
	-rm -f $(SRCS_t_recover:.c=.o)
	-rm -f $(SRCS_t_recover:.c=.o.d)
	-rm -f t_recover
	-rm -f t_recover.out
	-rm -f t_recover.out.tmp


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
DEPS_t_dae = $(SRCS_t_dae:.c=.o.d)
-include $(DEPS_t_dae)
t_dae: $(SRCS_t_dae:.c=.o)
	$(CC) -o $@ $(_CFLAGS) $(LDFLAGS) $(SRCS_t_dae:.c=.o) \
		$(LDLIBS_libfidocrypt)

clean: clean-dae
clean-dae: .PHONY
	-rm -f $(SRCS_t_dae:.c=.o)
	-rm -f $(SRCS_t_dae:.c=.o.d)
	-rm -f t_dae
	-rm -f t_dae.out
	-rm -f t_dae.out.tmp
