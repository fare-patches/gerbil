# One-Time Passwords

The `:std/crypto/otp` library computes and validates HOTP and TOTP one-time
passwords, reads and writes `otpauth://` key URIs, keeps keyrings of such
keys, and turns a short user script into an `otp` command, with commands to generate and verify codes. It is a native replacement for the old
gerbil-utils `otp` tool.

```scheme
(import :std/crypto/otp)
```

Specifications:

- RFC 4226, HOTP: <https://www.rfc-editor.org/rfc/rfc4226>
- RFC 6238, TOTP: <https://www.rfc-editor.org/rfc/rfc6238>
- RFC 2104, HMAC: <https://www.rfc-editor.org/rfc/rfc2104>
- RFC 4648 §6, Base32: <https://www.rfc-editor.org/rfc/rfc4648#section-6>
- RFC 3986, URI: <https://www.rfc-editor.org/rfc/rfc3986>
- Key Uri Format: <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
- oathtool(1): <https://www.nongnu.org/oath-toolkit/oathtool.1.html>

## Modules

- `:std/crypto/otp/core` ([core.md](otp/core.md)): the algorithms. `hotp`,
  `totp-counter`, `totp`, `hotp-validate` and `totp-validate` compute and check
  codes from a `u8vector` secret, with SHA-1, SHA-256 or SHA-512 HMACs (from
  `:std/crypto/hmac`) and 6 to 10 digits. The `OtpKey` struct holds the
  parameters of an `otpauth://` URI; `new-otp-key`, `otp-key-code`,
  `otpauth->otp-key` and `otp-key->otpauth` build keys, compute their current
  code, and parse and print the URIs.
- `:std/crypto/otp/keyring` ([keyring.md](otp/keyring.md)): the
  `OtpKeyring` interface, a collection of `OtpKey`s identified by issuer and
  account, kept in insertion order, searched with case-insensitive glob
  patterns, with HOTP counter advancement. `new-memory-otp-keyring` is the only
  implementation so far. `current-otp-keyring`, `otp-keyring-register!` and
  `register-otp-keys` register keys from a script, as `otpauth://` URIs or as
  issuer, account, Base32 secret triples, all or nothing.
- `:std/crypto/otp/cli` ([cli.md](otp/cli.md)): `:std/cli/multicall` entry
  points `keys` (show codes, the default), `otpauth`, `generate` and `verify`, the `parse-otp-time` and
  `ll1-otp-duration` argument parsers, `register-otp-entry-points!`, and
  `define-otp-main`, which registers the entry points and defines `main` with
  `keys` as the default entry point. Importing registers no entry point.
- `:std/crypto/otp` (this facade): re-exports the public API of the three
  modules above, and nothing else.

Base32 secrets are decoded by `base32-decode-lenient` from
`:std/encoding/base32`, which is not re-exported: import it separately to
decode secrets yourself.

## Quick start

### A personal otp script

```scheme
#!/usr/bin/env gxi
(import :std/crypto/otp)
(define-otp-main)
(register-otp-keys
  "gmail.com" "myaccount" "abcd efgh ijkl mnop qrst uvwx yz23 4567"
  "otpauth://totp/GitHub:fare?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
```

Make it executable and readable only by you, and name it `otp`. Then `otp`
shows every code, `otp git` the codes of the keys matching `*git*`, and
`otp help`, `otp otpauth gmail` and `otp verify ...` run the
other subcommands. See [cli.md](otp/cli.md).

### Library use

```scheme
(import :std/crypto/otp
        :std/encoding/base32)

(totp (base32-decode-lenient "JBSW Y3DP EHPK 3PXP"))  ; current 6-digit code
(totp-validate (base32-decode-lenient "JBSW Y3DP EHPK 3PXP") "123456" window: 1)
  ; => the matching time step offset, or #f
(otp-key-code (otpauth->otp-key "otpauth://totp/GitHub:fare?secret=JBSWY3DPEHPK3PXP"))
```

## Security notes

- _Secrets in memory._ Secrets are ordinary `u8vector`s in the garbage
  collected heap; HMAC, Base32 and URI decoding copy them and nothing is
  wiped. Moving GC, swap and crash dumps can retain them. Printing an
  `OtpKey` omits its secret, but `otp-key->otpauth` includes it. See [core.md](otp/core.md).
- _Secrets in scripts._ A personal script holds its secrets in clear text;
  keep it readable only by you.
- _Process list._ `generate` and `verify` read KEY from its arguments, visible in the process list, unless given as `-` (stdin) or `@FILE`.
- _No persistence yet._ Keyrings live in memory only. Scripts re-register
  their keys at each run, so HOTP counters are not consumed: `keys` shows the
  same HOTP code every time.
- _Validation._ Callers that validate codes must throttle failed attempts,
  keep windows small, and reject replays (RFC 4226 §7.3).
