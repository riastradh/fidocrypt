Fidocrypt protocol
==================

The fidocrypt protocol is purely server-side; there are no changes to
the client side.

### Registration

Registration starts as in standard webauthn.  When the client returns a
registration response:

Given

- a server-chosen challenge (and any other registration state),
- a server-chosen payload (an arbitrary byte string),
- a client-furnished `client_data` (a
  [client data](https://www.w3.org/TR/webauthn-1/#client-data) object),
- a client-furnished `attestation_object` (an
  [attestation object](https://www.w3.org/TR/webauthn-1/#attestation-object)),
  and
- optionally, a 32- or 64-byte `hmac_secret` (with the
  [hmac-secret extension](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#sctn-hmac-secret-extension);
  note that this requires getting an attestation from the client with
  the credential),

first verify the client data and attestation object using the challenge
as in standard webauthn registration, yielding `auth_data`, an
[authenticator data](https://www.w3.org/TR/webauthn-1/#authenticator-data)
object.

Then, let `credential_id` and `public_key` be the parts of the
`auth_data` object's attested credential data as byte strings.  Verify
that `public_key` is the CBOR encoding, in
[CTAP2 canonical CBOR encoding
form](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#ctap2-canonical-cbor-encoding-form),
of a COSE public key.

Next, compute a 32-byte string `key` by the SHA-256 hash of the
concatenation of:

- the US-ASCII encoding of the string `FIDOKDF0`,
- the bytes of `public_key`, and
- if `hmac_secret` is provided, the CBOR encoding of `hmac_secret` as a
  bytestring.

Let `pk_strip` be `public_key`, if it is not an ECDSA public key, or if
it is an ECDSA public key, then the canonical CBOR encoding of the map

- 1 (kty): 2 (verify)
- 3 (alg): (the algorithm, e.g. -7 for ES256)
- -1 (crv): (the curve, e.g. 1 for NIST P-256)

Note that this excludes the coordinates of the point on the curve; call
this a `stripped public key'.

Let `ciphertext` be `pk_strip` prepended to the authenticated
encryption of the payload under `key` with associated data `public_key`
using the deterministic authenticated cipher ChaCha20-HMACSHA256-SIV
defined below.

Finally, erase `client_data`, `attestation_object`, `auth_data`, and
`public_key`, and return a dictionary mapping `credential_id` to
`ciphertext` as a set of registered credentials.

### Signin

Signin starts as in standard webauthn.  When the client returns an
authentication response:

Given

- a server-chosen challenge (and any other signin state)
- a server-chosen set of registered credentials mapping credential ids
  to ciphertexts,
- a client-furnished credential id,
- a client-furnished `client_data` (a
  [client data](https://www.w3.org/TR/webauthn-1/#client-data) object),
- a client-furnished `auth_data` (an
  [authenticator data](https://www.w3.org/TR/webauthn-1/#authenticator-data)
  object), and
- a client-furnished signature,

first verify that the credential id is registered and retrieve the
ciphertext associated with it.  The ciphertext begins with the CTAP2
canonical CBOR encoding of either a stripped ECDSA public key, or a
normal public key; decode it.  Discriminate on the resulting public
key:

- If it is a stripped ECDSA public key as above (only kty, alg, and
  crv, no coordinates): Let `message` be the concatenation of
  `auth_data` and the SHA-256 hash of `client_data`.  Apply ECDSA
  public key recovery to the signature and message, yielding two
  candidate ECDSA public keys (curve points).

  Next, for each of the two ECDSA public keys in any order:
  Let `public_key` be its COSE representation's CTAP2 canonical CBOR
  encoding, and compute a 32-byte string `key` by the SHA-256 hash of
  the concatenation of:

  - the US-ASCII encoding of the string `FIDOKDF0`,
  - the bytes of `public_key`, and
  - if `hmac_secret` is provided, the CBOR encoding of `hmac_secret` as
    a bytestring.

  Let `payload` be the authenticated decryption of the rest of the
  ciphertext under `key` with associated data `public_key` using the
  deterministic authenticated cipher ChaCha-HMACSHA256-SIV defined
  below, or reject this public key if it fails.  If both public keys
  fail, and refuse signin.

  Finally, using the public key for which decryption succeeded, proceed
  to standard webauthn authentication completion (verifying the
  signature, &c.), and return `payload` if it succeeds.

- Otherwise, if it is a normal public key, call its stored encoding
  `public_key`.  Apply standard webauthn authentication completion
  (verify the signature, &c.) under the public key.  Then compute a
  32-byte string `key` by the SHA-256 hash of the concatenation of:

  - the US-ASCII encoding of the string `FIDOKDF0`,
  - the bytes of `public_key`, and
  - if `hmac_secret` is provided, the CBOR encoding of `hmac_secret` as
    a bytestring.

  Finally, let `payload` be the authenticated decryption of the rest of
  the ciphertext under `key` with associated data `public_key` using
  the deterministic authenticated cipher ChaCha-HMACSHA256-SIV defined
  below and return `payload` if it succeeds, or refuse signin if it
  fails.


ECDSA public key recovery
-------------------------

An ECDSA public key is a point A on an elliptic curve with standard
base point B.  An ECDSA signature under A on a message m is an encoding
of two integers r and s satisfying the equation

        r = x(H(m) s^{-1} * B + r s^{-1} * A),

where s^{-1} and the equation are taken modulo the order of the curve,
and where H is a hash function mapping messages into integers.

Given r, s, and m, we can solve for either of two candidate public keys
by choosing a point R such that x(R) = r, and computing

        r^{-1} s * (R - H(m) s^{-1} * B),
        r^{-1} s * (-R - H(m) s^{-1} * B)

as the two candidates for the public key A.  Both of them will verify
the signature by construction; nothing can be inferred from verifying
the signature under them other than that the key recovery software is
functioning correctly.  For public key recovery to be useful, the
caller must have some way to verify the recovered public key (as it
does in fidocrypt).


ChaCha20-HMACSHA256-SIV
-----------------------

ChaCha20-HMACSHA256-SIV is a deterministic authenticated cipher defined
in terms of HMAC-SHA256 and ChaCha20 in an
[SIV-like](https://web.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf)
construction.

### Encryption

Given

- a 32-byte key `k`,
- a byte string `header` (associated data), and
- a byte string `payload` (plaintext),

compute `t = HMAC-SHA256_k(header || payload || len || 0)`, where `0`
denotes a single zero byte, and `len` is `le64(nbytes(header)) ||
le64(nbytes(payload))`.  Here `le64` means the 8-byte little-endian
encoding of an integer in the interval [0, 2^64), and `nbytes` means
the number of bytes in a byte string.

Next, compute `k' = HMAC-SHA256_k(t || 1)`, where `1` denotes a single
one byte, and encrypt `payload` with ChaCha20 under the key `k'` and a
nonce of all bytes zero.

Finally, return the concatenation of `t` and the ChaCha20 ciphertext of
`payload`.

### Decryption

Given

- a 32-byte key `k`,
- a byte string `header` (associated data), and
- a byte string of alleged authenticated ciphertext,

first verify that the alleged authenticated ciphertext is at least 32
bytes long, and let `t` be the first 32 bytes.

Compute `k' = HMAC-SHA256_k(t || 1)`, where `1` denotes a single one
byte, and decrypt the remainder of the alleged authenticated ciphertext
with ChaCha20 under the key `k'` and a nonce of all zero bytes; let
`payload` be the result.

Next, compute `t' = HMAC-SHA256(header || payload || len || 0)`, where
`0` denotes a single zero byte, and `len` is `le64(nbytes(header)) ||
le64(nbytes(payload))`.

Verify in constant time that `t' = t`; if not, erase `payload` and
report a forgery.  Otherwise, return `payload`.
