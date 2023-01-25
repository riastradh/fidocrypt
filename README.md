Fidocrypt -- FIDO-based key derivation and encapsulation
========================================================

Taylor ‘Riastradh’ Campbell <campbell+fidocrypt@mumble.net>

**Fidocrypt** is a technique by which a server can store a secret in
the credential during U2F/FIDO/webauthn registration, and retrieve it
again during signin.  As long as the server erases its copy of the
secret, and as long as the U2F device isn't badly designed (see below
on security), the secret cannot be retrieved again except by
U2F/FIDO/webauthn signin with the device.

- **WARNING: Fidocrypt is new and has had little scrutiny.  There may
  be security issues.  Caveat lector.**

For example, if a server holds the share of a key to encrypt a user's
password vault, you might store this share as the fidocrypt secret --
and store the _same_ share with every credential registered by the
user, so any one of their U2F keys not only serves to sign in but also
serves to decrypt the share.

The server-side credential storage of fidocrypt is necessarily slightly
different from standard webauthn credential storage.  Signin with
fidocrypt provides the same authentication guarantee as standard
webauthn -- it just also lets you retrieve a secret at the same time.

Fidocrypt works with:
- any U2F key
- any FIDO2 key using ECDSA over NIST P-256 (i.e., `ES256`/`P-256`,
  in terms of [RFC 8152](https://tools.ietf.org/html/rfc8152))
- any FIDO2 key with the hmac-secret extension

This should cover essentially every U2F/FIDO key ever made as of 2020;
the vast majority support ECDSA over NIST P-256 anyway.

This C implementation of fidocrypt is based on Yubico's
[libfido2](https://github.com/Yubico/libfido2) library.  This
implemention is limited to ECDSA over NIST P-256 and Ed25519 -- it does
not (yet) support any other credential types, but this covers the vast
majority of U2F/FIDO models already.

#### [Protocol description](PROTOCOL.md)

Credit: I first learned about the technique to derive secrets with U2F
from Joseph Birr-Paxton's blog post on [abusing U2F to ‘store’
keys](https://jbp.io/2015/11/23/abusing-u2f-to-store-keys.html).

I tweaked it to store a secret with the credential that can be
decrypted with a key derived from the device, rather than just exposing
the key directly, so that you can easily store the _same_ secret
encrypted differently with many U2F devices.  Then I added support for
the hmac-secret extension so it is less of an abuse of the protocol.

Other implementations of the same basic idea:

- https://github.com/ctz/u2f-secret-storage
- https://github.com/darkskiez/u2f-luks


Usage
-----

The following `make` targets are included:

- `make` or `make all` -- build library and example program and run tests
- `make install` -- install library, example program, and man pages
- `make check` -- build and run tests
- `make lib` -- build library
- `make install-lib` -- install library
- `make install-shlib` -- install just the shared library, no soname
  link or header files

The makefile respects the variables `prefix`, `bindir`, `includedir`,
`libdir`, `mandir`, `man1dir`, `man3dir`, and, for staged installation,
`DESTDIR`.  The `libdir` (default `$(prefix)/lib`) must match during
build and install; otherwise the shared library will not be found at
run-time.

The following C preprocessor macros may be set in `CPPFLAGS`, with,
e.g., `CPPFLAGS=-DHAVE_FIDO_DEV_SET_SIGMASK`, to enable use of newer
features or bug fixes in libfido2:

- `HAVE_FIDO_ASSERT_SET_HMAC_SECRET` (libfido2 >=1.7.0, https://github.com/Yubico/libfido2/issues/256)
- `HAVE_FIDO_CRED_AUTHDATA_RAW_PTR` (libfido2 >=1.6.0, https://github.com/yubico/libfido2/issues/212)
- `HAVE_FIDO_DEV_SET_SIGMASK` (libfido2 >=1.7.0, https://github.com/Yubico/libfido2/issues/251, but broken on macOS, https://github.com/Yubico/libfido2/issues/650)
- `HAVE_FIDO_ED25519` (libfido2 >=1.4.0)
- `HAVE_FIDO_ES256_PK_FROM_EC_KEY_FIX` (libfido2 >=1.11.0, https://github.com/yubico/libfido2/issues/546)
- `HAVE_FIDO_RSA` (libfido2 >=1.4.0)

[fidocrypt.c](fidocrypt.c) implements a command that stores a short
secret in a file encrypted with any one of a set of enrolled security
keys in a file.

Example:

```none
$ export FIDOCRYPT_RPID=fidocrypt.example.com
$ fidocrypt enroll -N Falken -u falken -n yubi5nano example.crypt
tap key `yubi5nano' key to enroll; waiting...
tap key `yubi5nano' again to verify; waiting...
$ fidocrypt list example.crypt
1 yubi5nano
$ fidocrypt get example.crypt
fidocrypt: specify an output format (-F)
Usage: fidocrypt get -F <format> <cryptfile>
$ fidocrypt get -F base64 example.crypt
tap key; waiting...
yTpyXp1Hk3F48Wx3Mp7B2gNOChPyPW0VOH3C7l5AM9A=
$ fidocrypt enroll -N Falken -u falken -n redsolokey example.crypt
tap a key that's already enrolled; waiting...
tap key `redsolokey' to enroll; waiting...
tap key `redsolokey' again to verify; waiting...
$ fidocrypt get -F base64 example.crypt
tap key; waiting...
yTpyXp1Hk3F48Wx3Mp7B2gNOChPyPW0VOH3C7l5AM9A=
$ fidocrypt rename -n redsolokey example.crypt blacksolokey
$ fidocrypt list example.crypt
2 blacksolokey
1 yubi5nano
```

The fidocrypt command is implemented in terms of the following
[libfidocrypt functions](fidocrypt.3) extending the libfido2 API:

- [`fido_cred_encrypt(cred, assert, idx, payload, payloadlen, &ciphertext, &ciphertextlen)`](cred_encrypt.c)

  Given a credential, such as one obtained with `fido_dev_make_cred` or
  derived from webauthn `navigator.credential.create`, encrypt the
  payload and return a ciphertext.  Providing nonnull `assert` allows
  use of the [hmac-secret extension][hmac-secret].

  You should then store `ciphertext` alongside the credential id of
  `cred` -- and _not_ the public key of `cred` -- so you can later pass
  it to `fido_assert_decrypt` to verify an authenticator and recover
  the payload.

- [`fido_assert_decrypt(assert, idx, ciphertext, ciphertextlen, &payload, &payloadlen)`](assert_decrypt.c)

  Given an assertion, such as one obtained with `fido_dev_get_assert`
  or derived from webauthn `navigator.credential.get`, verify the
  assertion and decrypt the ciphertext, or fail if the assertion does
  not match the credential.

  `fido_assert_decrypt` implies the same authentication security as
  `fido_assert_verify` against a known public key.  **You must _only_
  use `fido_assert_decrypt`, and not `fido_assert_verify`**, if you are
  using fidocrypt, since for fidocrypt's secrecy properties the ‘public
  key’ must be kept secret.


  [hmac-secret]: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#sctn-hmac-secret-extension


Security
--------

### Device security

On most U2F devices, the public key is effectively a pseudorandom
function (with nonuniform distribution) of the credential id.
Typically, the credential id (or key handle, in the older U2F
nomenclature) is either

1. an authenticated ciphertext containing a private key generated on
   the device, under a symmetric secret key stored on the device, as in
   [current Yubico models][yubico-keygen]; or

2. a random input to a PRF which is used to derive the private key from
   it, along with an authenticator on the random input under a
   symmetric key stored on the device, as in [past Yubico
   models][yubico-keygen-old], SoloKeys (key generation:
   [(1)][solokeys-keygen1], [(2)][solokeys-keygen2]; key loading:
   [(1)][solokeys-keyload1], [(2)][solokeys-keyload2]), and likely
   other devices too.

In principle, a badly designed U2F device could expose the public key
in the credential id.  I don't know of any that do this, and it would
be quite a waste of space -- the credential id already has to determine
a ~256-bit private key, and usually has a ~128-bit authenticator on it;
on top of that, a public key is usually at least 32 bytes long.

That said, like all U2F-based systems, you should use fidocrypt as one
factor in multi-factor authentication -- use it to encrypt a single
share of a key to decrypt a password vault or laptop disk, not the
whole key, and combine it with another key derived from a password or
software storage device or similar.


  [yubico-keygen]: https://developers.yubico.com/U2F/Protocol_details/Key_generation.html
  [yubico-keygen-old]: https://web.archive.org/web/20190712075231/https://developers.yubico.com/U2F/Protocol_details/Key_generation.html
  [solokeys-keygen1]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/u2f.c#L180-L187
  [solokeys-keygen2]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/crypto.c#L273-L284
  [solokeys-keyload1]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/u2f.c#L250-L252
  [solokeys-keyload2]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/u2f.c#L164-L168
  [solokeys-keyload3]: https://github.com/solokeys/solo/blob/8b91ec7c538d0d071842e0b86ef94266936ab1d7/fido2/crypto.c#L210-L216


### Transport security

- _Without_ the hmac-secret extension, an eavesdropper or MITM on the
  channel between the authenticator and the server can recover the
  encryption key that will decrypt the ciphertext on the server.  (The
  adversary would still need the ciphertext on the server, of course.)

  Normally this threat model is not relevant -- typically, the channel
  goes through a browser talking to the server over TLS; the browser is
  trusted anyway, and TLS should defeat any eavesdropper and MITM on
  the network.  However, it might be relevant for NFC devices that
  implement only U2F or FIDO2 without the hmac-secret extension.

- _With_ the hmac-secret extension, fidocrypt defends against such an
  eavesdropper or MITM.


### Side channels

All arithmetic to compute ECDSA public key recovery is done in OpenSSL.
Any side channel attacks on OpenSSL, such as on OpenSSL's generic
bignum arithmetic, may carry over to fidocrypt.  There are two weak
mitigations for timing side channel attacks:

1. The vulnerable arithmetic is computed only once at registration time
   and once at each signin.  Thus, an adversary not in control of the
   user's device has limited opportunities to repeat measurements to
   refine a statistical model of the secrets -- it's only when the user
   chooses to sign in.

2. The key derived by the vulnerable arithmetic is used for only one
   purpose -- to verify and decrypt a ciphertext stored on the server.
   So it is useful to an adversary only if they also compromise the
   ciphertext on the server.

Timing side channel attacks are serious, and you might rightly choose a
different implementation of fidocrypt on the basis of them.
Nevertheless, you can still use fidocrypt as a factor in a multifactor
system, combining the secret with others (say) derived from the user's
password, to raise the difficulty for the adversary -- especially if
users are already using U2F as a second factor to sign in anyway.
