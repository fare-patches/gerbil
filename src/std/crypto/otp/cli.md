# OTP command line

The `:std/crypto/otp/cli` module defines `:std/cli/multicall` entry points
that show the one-time passwords of the keys in the current keyring (see
`keyring.md`), print their `otpauth://` URIs, and generate or
validate codes for one-off secrets. `define-otp-main` turns a user script into an
`otp` command. Importing the module registers no entry point:
`define-otp-main` or `register-otp-entry-points!` does.

```scheme
(import :std/crypto/otp/cli)
```

Specifications:

- Key Uri Format: <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
- RFC 4226 HOTP: <https://www.rfc-editor.org/rfc/rfc4226>
- RFC 6238 TOTP: <https://www.rfc-editor.org/rfc/rfc6238>

## A personal otp script

```scheme
#!/usr/bin/env gxi
(import :std/crypto/otp)
(define-otp-main)
(register-otp-keys "gmail.com" "myaccount" "abcd efgh ijkl mnop qrst uvwx yz23 4567")
```

The `:std/crypto/otp` facade re-exports core, keyring and cli (see `../otp.md`),
which is all such a script needs. Make the script executable and readable only
by you, since it holds the secrets. Then `otp` shows every code, `otp gmail` the
codes of the matching keys, and `otp help`, `otp otpauth gmail`,
`otp generate ...` run the subcommands. A key whose pattern is a subcommand name
must be selected explicitly, as in `otp keys help`.

## Entry points

Each entry point returns `(void)` on success and `(values)` on failure, so
that `call-entry-point` exits with status 0 or 1 (see `:std/cli/print-exit`).
Invalid arguments raise `ContractViolation`, a `ParseError` for TIME and
DURATION values (see `parse-error?` in `:std/text/parser/base`), or a getopt
error, which the `main` of `define-otp-main` prints, exiting with status 2.
Success writes nothing to the standard error.

Options come before the positional arguments: the first word that does not
start with `-` ends the options.

### keys

```text
keys [-w N | --window N] [-N TIME | --time TIME] [-m GLOB | --match GLOB]... [word ...]
```

The default entry point of `define-otp-main`. Each `-m` supplies one pattern.
Trailing words joined with spaces supply one final pattern. With no patterns,
show every key. Matching uses case-insensitive globs with implicit surrounding
wildcards (see `keyring.md`).

For example, `otp keys -m github --match gmail` shows GitHub matches first,
then Gmail matches. Each pattern visits keys in keyring order, and each key
appears only on its first match. Each output line has the form

```text
CODE[ CODE ...] issuer account
```

or `CODE ... account` for a key without issuer. A totp key shows its code at
TIME (default: now) and, with `-w N`, the codes of the next N time steps; an
hotp key shows the code at its counter and at the next N counters. hotp
counters are _not_ consumed: the keyring is in memory, and the same code is
shown every time.

With no match (including an empty keyring), print `No matching OTP key` to the
standard error and fail.

### otpauth

```text
otpauth [pattern ...]
```

Print the canonical `otpauth://` URI of each matching key, one per line, as
`otp-key->otpauth` emits it. The URIs contain the secrets. No match fails as
for `keys`.

### generate and verify

```text
otp generate [OPTIONS] KEY
otp verify [OPTIONS] KEY CODE
```

Generate prints one code per line. With `--window N`, it prints the current
code and the next N codes. Verify prints the absolute counter for an HOTP
match or the signed step offset for a TOTP match. A mismatch exits 1.

KEY is a literal secret, `-` for the first line of stdin, or `@FILE` for
the first line of a file. Prefer stdin or a file to keep secrets out of argv.
These commands operate independently of the keyring.

| Option | Meaning and default |
| --- | --- |
| `--mode hotp\|totp` | Default TOTP |
| `--encoding base32\|hex` | Default Base32 |
| `--hash sha1\|sha256\|sha512` | HMAC digest, default SHA1 |
| `--counter N` | First HOTP counter, default 0 |
| `--period D` | TOTP step duration, default 30s |
| `--start TIME` | TOTP epoch, default Unix epoch |
| `--time TIME` | Current TOTP time, default now |
| `--digits N` | Code length, 6 to 10, default 6 |
| `--window N` | Extra counters forward (HOTP) or steps each way for TOTP verification, default 0 |
| `--verbose` | Print the parameters, including key length, before the result |

For example, given a file containing the RFC 4226 test key in Base32:

```sh
otp generate --mode hotp @test.key                 # 755224
otp verify --mode hotp --window 3 @test.key 969429 # 3
```

## Helpers

### otp-code-command

```scheme
(otp-code-command key (otp #f)
  mode: mode algorithm: algorithm encoding: encoding counter: counter
  step: step start: start now: now digits: digits window: window verbose: verbose?)
```

The procedure behind `generate` and `verify`. Supply a code to verify it,
or omit it to generate. The keyword arguments are optional and use the CLI
defaults above. Mode, algorithm and encoding are symbols. Step, start and
now are seconds. It writes the CLI output and returns `(void)` on success
or zero values on a mismatch. Command-line adapters can call it directly.


### parse-otp-time

```scheme
(parse-otp-time (text : :string)) => :integer
```

Parse a complete TIME argument for `--time` or `--start`
as whole Unix epoch seconds. Use `now`, an optionally negative integer
prefixed with `@` (such as `@-1`), or a calendar date in `YYYY-MM-DD` form.

A date alone means midnight. Append a space, `T` or `t` and `HH:MM` or
`HH:MM:SS` to specify a time. The default zone is UTC. A date or date-time
may end with the literal ` UTC`; a date-time may instead end with `Z`, `z`,
or a numeric offset in `±HH:MM` or `±HHMM` form. For example,
`1970-01-01 UTC` and `1969-12-31T19:00:00-0500` both denote epoch zero.

Calendar conversion uses `:std/time/date`. Invalid dates, out-of-range
offsets and unsupported spellings raise a `ParseError`. The grammar uses
whole seconds (00–59) and excludes bracketed zone names and annotations.

### ll1-otp-duration

```text
(ll1-otp-duration (reader : BufferedReader)) => :integer
```

Parse a positive DURATION argument as seconds: decimal digits optionally
followed by a unit `s` (default), `m` or `h`: `30`, `30s`, `1m`, `24h`. Zero,
signs, fractions, spaces and other units raise a `ParseError` through `ll1`.

### register-otp-entry-points!

```text
(register-otp-entry-points!) => :void
```

Register the `keys`, `otpauth`, `generate` and `verify` entry points in the global
`:std/cli/multicall` registry, replacing any entry points of the same names.
Use it to add the OTP commands to a multicall program with its own `main`.

### define-otp-main

```text
(define-otp-main)
```

Call `register-otp-entry-points!`, define `main` as `define-multicall-main`
does, and make `keys` the default entry point: with no arguments, or when the
first argument is not a registered entry point, all the arguments go to `keys`.
