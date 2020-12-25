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

Fidocrypt works only with ECDSA over NIST P-256 (i.e., `ES256`/`P-256`,
in terms of [RFC 8152](https://tools.ietf.org/html/rfc8152)) -- it
could easily be extended to ECDSA over NIST P-384 or NIST P-521, but it
cannot be made to work with EdDSA (Ed25519 or Ed448) or RSASSA-PSS.

This C implementation of fidocrypt is based on Yubico's
[libfido2](https://github.com/Yubico/libfido2) library.

#### [Protocol description](PROTOCOL.md)

Credit: I first learned about this technique from Joseph Birr-Paxton's
blog post on [abusing U2F to ‘store’
keys](https://jbp.io/2015/11/23/abusing-u2f-to-store-keys.html).

I tweaked it to store a secret with the credential that can be
decrypted with a key derived from the device, rather than just exposing
the key directly, so that you can easily store the _same_ secret
encrypted differently with many U2F devices.

Other implementations of the same basic idea:

- https://github.com/ctz/u2f-secret-storage
- https://github.com/darkskiez/u2f-luks


Usage
-----

Type `make check` to run the tests, or `make` to also build the example
programs.

[fidocrypt.c](fidocrypt.c) implements a command that stores a short
secret in a file encrypted with any one of a set of enrolled security
keys in a file.  (Tested on NetBSD 9.1; fidocrypt.c itself may require
tweaks for other systems, but the rest should not.)

- N.B.: fidocrypt.c depends on a new function `fido_dev_set_sigmask` in
  order to query all U2F/FIDO devices at the same time and, once one is
  chosen, reliably interrupt queries to all the other ones.  See
  https://github.com/Yubico/libfido2/issues/251 for details.

Example:

```none
% export FIDOCRYPT_RPID=fidocrypt.example.com
% fidocrypt enroll -N Falken -u falken -n yubi5nano example.crypt
tap key to enroll; waiting...
% fidocrypt list example.crypt
1 yubi5nano
% fidocrypt get example.crypt
fidocrypt: specify an output format (-F)
Usage: fidocrypt get -F <format> <cryptfile>
% fidocrypt get -F base64 example.crypt
tap key; waiting...
yTpyXp1Hk3F48Wx3Mp7B2gNOChPyPW0VOH3C7l5AM9A=
% fidocrypt enroll -N Falken -u falken -n redsolokey example.crypt
tap a key that's already enrolled; waiting...
tap key to enroll; waiting...
% fidocrypt get -F base64 example.crypt
tap key; waiting...
yTpyXp1Hk3F48Wx3Mp7B2gNOChPyPW0VOH3C7l5AM9A=
% fidocrypt rename -n redsolokey example.crypt blacksolokey
% fidocrypt list example.crypt
2 blacksolokey
1 yubi5nano
```

The fidocrypt command is implemented in terms of the following
functions extending the libfido2 API:

- [`fido_cred_encrypt(cred, cose_alg, ciphertext, payload, n)`](cred_encrypt.c)

  Given a credential, such as one obtained with `fido_dev_make_cred` or
  derived from webauthn `navigator.credential.create`, encrypt the
  `n`-byte `payload` and store it in `ciphertext`.  `ciphertext` must
  be a buffer of at least `FIDOCRYPT_OVERHEADBYTES` more bytes than
  `payload`; exactly `FIDOCRYPT_OVERHEADBYTES + n` bytes will be
  stored.

  You should then store `ciphertext` alongside the credential id of
  `cred` so you can later pass it to `fido_assert_decrypt` to verify an
  authenticator and recover the payload.  You must make sure to _erase_
  the ‘public key’ in the credential, since for fidocrypt's secrecy
  properties it must be kept secret; `fido_assert_decrypt` will verify
  an assertion using the ciphertext instead of the public key.

  Callers concerned with device attestation are responsible for calling
  `fido_cred_verify`; `fido_cred_encrypt` does nothing to verify device
  attestations.

- [`fido_assert_decrypt(assert, idx, cose_alg, payload, ciphertext, n)`](assert_decrypt.c)

  Given an assertion, such as one obtained with `fido_dev_get_assert`
  or derived from webauthn `navigator.credential.get`, and `n`-byte
  `ciphertext` associated with the credential id in the assertion as
  obtained with `fido_cred_encrypt`, verify and decrypt the ciphertext
  and store the plaintext in `payload`, or fail if the assertion does
  not match.  `n` must be at least `FIDOCRYPT_OVERHEADBYTES`; exactly
  `FIDOCRYPT_OVERHEADBYTES - n` bytes will be written to `payload`.

  `fido_assert_decrypt` implies the same authentication security as
  `fido_assert_verify` against a known public key.  You must _only_ use
  `fido_assert_decrypt`, and not `fido_assert_verify`, if you are using
  fidocrypt, since for fidocrypt's secrecy properties the ‘public key’
  must be kept secret.


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
