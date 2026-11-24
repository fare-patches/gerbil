# One-Time Passwords: HOTP, TOTP and otpauth URIs

The `:std/crypto/otp/core` module computes and validates HMAC-based one-time
passwords and reads and writes `otpauth://` key URIs, as used by Google
Authenticator and compatible apps and by `oathtool`.

```scheme
(import :std/crypto/otp/core)
```

Specifications:

- RFC 4226, HOTP: <https://www.rfc-editor.org/rfc/rfc4226>
- RFC 6238, TOTP: <https://www.rfc-editor.org/rfc/rfc6238>
- RFC 2104, HMAC: <https://www.rfc-editor.org/rfc/rfc2104>
- RFC 4648 §6, Base32: <https://www.rfc-editor.org/rfc/rfc4648#section-6>
- RFC 3986, URI: <https://www.rfc-editor.org/rfc/rfc3986>
- Key Uri Format: <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
- oathtool(1), the reference behavior for tests: <https://www.nongnu.org/oath-toolkit/oathtool.1.html>

HMACs come from `:std/crypto/hmac` (OpenSSL); Base32 from
`:std/encoding/base32`; percent-encoding from `:std/net/uri`.

## Common parameters

| Parameter   | Values | Default |
|-------------|--------|---------|
| `key`, `secret` | the shared secret, a `u8vector` of any length | |
| `counter`   | exact integer in [0, 2^64^) | `0` |
| `digits`    | fixnum 6 to 10 | `6` |
| `algorithm` | `'sha1`, `'sha256` or `'sha512`, lowercase only | `'sha1` |
| `time`      | finite real, seconds since the Unix epoch | `(current-time-seconds)` |
| `period`    | positive exact integer, the time step _X_ in seconds | `30` |
| `start`     | exact integer, the epoch _T0_ in seconds | `0` |
| `window`    | nonnegative fixnum | `0` |

Out-of-range values raise `ContractViolation` (via `raise-bad-argument`)
with the public procedure as the error location and the offending value as an
irritant; wrong types are caught by the declared contracts. Secrets never
appear in irritants.

## Algorithm

`HOTP(K, C) = Truncate(HMAC(K, C)) mod 10^digits^`, where the counter _C_ is
an 8-byte big-endian integer. Dynamic truncation (RFC 4226 §5.3) takes the low
four bits of the _last_ HMAC byte as an offset and reads the four bytes there
as a big-endian integer with the top bit cleared, giving a 31-bit value. Using
the last byte makes it work unchanged for the 32- and 64-byte SHA-256 and
SHA-512 MACs of RFC 6238. The code is the last `digits` decimal digits of that
value, zero-padded; with 10 digits it is the whole value, so the first digit
is 0, 1 or 2.

`TOTP = HOTP(K, T)` with `T = floor((time - start) / period)` (RFC 6238 §4),
computed with exact integers so that times past 2038 (e.g. `20000000000`)
work. A real `time` is floored first, which gives the same `T` because `start`
and `period` are integers.

## hotp

```text
(hotp (key     : :u8vector)
      (counter : :integer)
      digits:    (digits    : :fixnum := 6)
      algorithm: (algorithm : :symbol := 'sha1))
  => :string
```

Returns the HOTP code of `key` at `counter`, a string of exactly `digits`
decimal digits.

## totp-counter

```text
(totp-counter (time : :real)
              period: (period : :integer := 30)
              start:  (start  : :integer := 0))
  => :integer
```

Returns the exact time step `floor((time - start) / period)`. Before `start`
the result is negative, e.g. `(totp-counter 39 start: 40)` is `-1`.

## totp

```text
(totp (key : :u8vector)
      time:      (time      : :real    := (current-time-seconds))
      period:    (period    : :integer := 30)
      start:     (start     : :integer := 0)
      digits:    (digits    : :fixnum  := 6)
      algorithm: (algorithm : :symbol  := 'sha1))
  => :string
```

Returns `(hotp key (totp-counter time period: period start: start) ...)`.
A time step outside [0, 2^64^), i.e. a time before `start`, raises
`ContractViolation`.

## hotp-validate

```text
(hotp-validate (key  : :u8vector)
               (code : :string)
               counter:   (counter   : :integer := 0)
               window:    (window    : :fixnum  := 0)
               digits:    (digits    : :fixnum  := 6)
               algorithm: (algorithm : :symbol  := 'sha1))
  => (Maybe :integer)
```

Tries counters `counter`, `counter + 1`, ..., `counter + window` in that
order (stopping at 2^64^ - 1) and returns the first counter whose code is
`code`, or `#f`. Like `oathtool -w`, the window only looks ahead. A `code`
that is not exactly `digits` ASCII decimal digits never matches. The caller
must store the returned counter plus one as the next counter, so the same code
cannot be replayed.

## totp-validate

```text
(totp-validate (key  : :u8vector)
               (code : :string)
               time:      (time      : :real    := (current-time-seconds))
               period:    (period    : :integer := 30)
               start:     (start     : :integer := 0)
               window:    (window    : :fixnum  := 0)
               digits:    (digits    : :fixnum  := 6)
               algorithm: (algorithm : :symbol  := 'sha1))
  => (Maybe :fixnum)
```

With `T = (totp-counter time period: period start: start)`, tries the time
steps `T + offset` for offsets `0, -1, +1, -2, +2, ..., -window, +window`, in
that order, and returns the first matching _offset_ (not the step), or `#f`.
Steps outside [0, 2^64^) are skipped rather than raising, so validating near
`start` works. Nearer steps are tried first, past before future, since
clients usually lag.

## OtpKey

```text
(defstruct OtpKey
  ((issuer    :? :string)
   (account   : :string)
   (secret    : :u8vector)
   (type      : :symbol)
   (algorithm : :symbol)
   (digits    : :fixnum)
   (period    : :integer)
   (counter   : :integer))
  transparent: #t
  constructor: :init!
  print: (issuer account type algorithm digits period counter)
  final: #t)
```

An OTP key as described by an `otpauth://` URI. `type` is `'totp` or
`'hotp`. Both kinds keep both `period` and `counter`: `period` is unused by
hotp keys and `counter` by totp keys. The struct is transparent for `equal?`,
which compares keys field by field, secret included; printing a key shows
every field but the secret. The struct is final.
The exported bindings are the type `OtpKey`, the predicate `OtpKey?` and
the accessors `OtpKey-issuer`, `OtpKey-account`, `OtpKey-secret`,
`OtpKey-type`, `OtpKey-algorithm`, `OtpKey-digits`, `OtpKey-period` and
`OtpKey-counter`. The positional constructor validates the same fields as `new-otp-key`.

## new-otp-key

```text
(new-otp-key (secret : :u8vector)
             issuer:    (issuer    :? :string := #f)
             account:   (account   : :string  := "")
             type:      (type      : :symbol  := 'totp)
             algorithm: (algorithm : :symbol  := 'sha1)
             digits:    (digits    : :fixnum  := 6)
             period:    (period    : :integer := 30)
             counter:   (counter   : :integer := 0))
  => OtpKey
```

Returns a validated key. Besides the common parameter ranges, `secret` must be
nonempty, as for `otpauth->otp-key`, so that every key has a URI that imports
back; `type` must be `'totp` or `'hotp` (lowercase), and `issuer` must not
contain a colon, since it becomes the label prefix of the URI. Without an
issuer, an account containing a colon is ambiguous. With an issuer (including
`""`), leading ASCII spaces in the account would be lost. Both constructors
reject these labels. The key shares `secret` with the caller, without copying
it: do not mutate it afterwards.

## otp-key-code

```text
(otp-key-code (key : OtpKey)
              time: (time : :real := (current-time-seconds)))
  => :string
```

For a hotp key, the HOTP code at the key's counter; `time` is ignored and
the caller is responsible for advancing the counter. For a totp key, the TOTP
code at `time` with the key's period and `start` 0.

## otpauth->otp-key

```text
(otpauth->otp-key (uri : :string))
  => OtpKey
```

Parses `otpauth://TYPE/LABEL?PARAMETERS` into a validated key:

- The scheme `otpauth://` and `TYPE` (`totp` or `hotp`) are matched
  case-insensitively. A `#fragment` is ignored.
- `LABEL` (up to `?`) is percent-decoded, _then_ split at its first colon, so
  a literal `:` and `%3A` are equivalent. Before the colon is the issuer
  prefix; after it is the account, with leading spaces (literal or `%20`)
  removed. Without a colon the whole label is the account.
- `PARAMETERS` are split at `&` and each at its first `=`; name and value
  are then percent-decoded (`+` stays `+`). A parameter without `=` has an
  empty value. Names are case-sensitive, unknown names (such as `image`) are
  ignored, and a repeated name keeps its last value.
- `secret` is required and decoded with `base32-decode-lenient` (any case,
  separators, optional canonical padding and zero unused bits); it must not be empty.
- `issuer`, if present, is the issuer, silently overriding a different label
  prefix; otherwise the label prefix (if any) is. It must not contain a colon.
- `algorithm` is `SHA1`, `SHA256` or `SHA512` in any case; default `SHA1`.
- `digits` (6 to 10, default 6), `period` (positive, default 30) and
  `counter` (below 2^64^) are plain ASCII decimal integers: no sign, radix
  prefix, fraction or exponent.
- `counter` is required for hotp and ignored for totp (which gets 0).

The Key Uri Format only specifies 6 or 8 digits; this module accepts 6 to 10,
as `hotp` does.

Every problem raises `ContractViolation` with `otpauth->otp-key` as the error
location: wrong scheme, missing `/`, unsupported type or algorithm, malformed
percent-encoding (reported by component and index), missing or invalid
parameters, and invalid Base32. Base32 errors report the decoder's reason and
the secret's length only, not its characters.

## otp-key->otpauth

```text
(otp-key->otpauth (key : OtpKey))
  => :string
```

Returns the canonical URI:

```text
otpauth://TYPE/[ISSUER:]ACCOUNT?secret=BASE32[&issuer=ISSUER]&algorithm=ALG&digits=N(&period=P|&counter=C)
```

Issuer and account are UTF-8 percent-encoded, keeping only RFC 3986
unreserved characters (so `@` becomes `%40` and a space `%20`); the label
colon is literal. The secret is uppercase unpadded Base32 and the algorithm
uppercase. Totp keys end with `period`, hotp keys with `counter`; an hotp
key's period is not emitted and so does not survive a round trip.

Issuer and account round-trip exactly. The URI only records the moving
factor for its key type. A HOTP key imports with period 30, and a TOTP
key imports with counter 0.

## Examples

```scheme
(def key (string->bytes "12345678901234567890"))  ; RFC 4226 Appendix D
(hotp key 0)                                      ; => "755224"
(hotp key 0 digits: 8)                            ; => "84755224"
(totp key time: 59 digits: 8)                     ; => "94287082", RFC 6238 Appendix B
(totp-counter 1111111109)                         ; => #x23523EC
(hotp-validate key "969429" window: 10)           ; => 3, like oathtool -w 10
(totp-validate key "755224" time: 59 window: 1)   ; => -1

(def k (otpauth->otp-key
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co"))
(OtpKey-issuer k)                                ; => "ACME Co"
(otp-key-code k)                                  ; => the current 6-digit code
(otp-key->otpauth k)
; => "otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
```

## Security notes

- _Secrets in memory._ Secrets are ordinary `u8vector`s in the garbage
  collected heap. HMAC, Base32 decoding and URI decoding make copies, and
  nothing is wiped; moving GC, swap and crash dumps can retain them. Printing
  an `OtpKey` omits its secret; the accessor `OtpKey-secret` and
  `otp-key->otpauth` still expose it.
- _Code comparison._ Validation parses the candidate code into an integer
  once and compares it with each computed value using a single `fx=`, so
  there is no character-by-character early exit revealing how many leading
  digits matched. Rejecting a code of the wrong length or with non-digits
  early only reveals the code's syntax, which the caller already knows. The
  window scan stops at the first match, which reveals the matched position by
  timing, but that position is the result anyway. HMAC timing does not depend
  on the code.
- _Brute force and replay._ A 6-digit code has a million values and a window
  of _w_ multiplies the acceptance probability per guess by up to 2_w_+1 for
  TOTP (_w_+1 for HOTP). Callers must throttle failed attempts (RFC 4226
  §7.3), keep windows small, and reject reuse: store the HOTP counter after a
  match, and remember the last accepted TOTP step.
- _Secret length._ RFC 4226 §4 requires at least 128 bits and recommends
  160. This module does not enforce a minimum, so that test vectors and
  existing short secrets work.

Dynamic truncation yields 31 bits. A ten-digit code starts with 0, 1, or 2.
