# OTP keyrings

The `:std/crypto/otp/keyring` module keeps collections of `OtpKey`s (see
`core.md`), searches them, advances HOTP counters, and registers keys from
user scripts given as `otpauth://` URIs or as issuer, account, secret triples.

```scheme
(import :std/crypto/otp/keyring)
```

Specifications:

- Key Uri Format: <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>
- POSIX fnmatch, for the `*` and `?` of search patterns:
  <https://pubs.opengroup.org/onlinepubs/9799919799/functions/fnmatch.html>

Keys come from `:std/crypto/otp/core`; Base32 from `:std/encoding/base32`
(`base32-decode-lenient`); glob patterns from `:std/text/glob`.

## Identity and order

A keyring identifies each key by its (issuer, account) pair, compared
exactly: case matters, and a key without issuer (`#f`) is distinct from a key
with the empty issuer `""`. Keys are kept in insertion order. Adding a key
whose identity is already present replaces the old key _in place_; a removed
identity added again goes at the end.

A keyring shares its keys with its callers, without copying them: do not
mutate a key or its secret after adding it, nor the keys a keyring returns.

## OtpKeyring

```text
(interface OtpKeyring
  (list-keys) => :list
  (find-keys (pattern : :string)) => :list
  (add-key! (key : OtpKey)) => :void
  (remove-key! (issuer :? :string) (account : :string)) => :boolean
  (next-hotp-counter! (key : OtpKey)) => :integer)
```

Call the methods as `(OtpKeyring-list-keys keyring)` etc., or `keyring.list-keys`
on a binding typed `OtpKeyring`.

- `list-keys` returns all the keys, in insertion order, as a fresh list.
- `find-keys` returns the keys matching `pattern`, in insertion order; see
  "Matching" below.
- `add-key!` adds `key`, replacing in place any key with the same identity.
- `remove-key!` removes the key with exactly that identity and returns
  whether there was one.
- `next-hotp-counter!` looks up the stored key with the identity of `key`
  (the other fields of `key` are ignored), returns its counter, and stores in
  its place a copy whose counter is one more. The caller's `key` is not
  modified. If the identity is absent or the stored key is a `'totp` key, it
  raises `ContractViolation` and the keyring is unchanged. Use it to get the
  counter for the next HOTP code: the counter is consumed before the code is
  shown, so a code is never reused.

## Matching

`(find-keys keyring pattern)` matches each key's _search text_ against the
glob pattern `*pattern*`:

- the search text is `"issuer account"` (one space), or just `"account"` for a
  key without issuer;
- both the pattern and the search text are downcased, so matching is
  case-insensitive;
- `*` matches any string, `?` any one character; every other character,
  including `.`, `[` and `\`, matches itself;
- the surrounding `*`s make it a substring search; the empty pattern matches
  every key.

The pattern is compiled once per call, then matched against every key.

```scheme
;; keys: github.com fare, GitLab fare@example.org, alice@google.com (no issuer)
(find-keys kr "git")        ; => the github.com and GitLab keys
(find-keys kr "com fare")   ; => the github.com key: spans issuer and account
(find-keys kr "git???.com") ; => the github.com key
(find-keys kr " alice")     ; => none: no issuer means no leading space
```

## new-memory-otp-keyring

```text
(new-memory-otp-keyring) => OtpKeyring
```

Returns a fresh, empty in-memory keyring. Keys live in a vector, in insertion
order, with a hash table from identity to position: lookup, replacement and
appending are O(1) (amortized), `list-keys` and `find-keys` O(n), and removal
O(n) since later keys shift down. A memory keyring is _not_ thread-safe:
threads sharing one must serialize access themselves.

## current-otp-keyring

```text
(current-otp-keyring) => OtpKeyring
```

A parameter holding the keyring `register-otp-keys` registers into. Its
initial value is a process-wide memory keyring, initially empty. Use
`parameterize` to register into another keyring.

## otp-keyring-register!

```text
(otp-keyring-register! (keyring : OtpKeyring)
                       (items   : :list))
  => :void
```

Registers `items` into `keyring`, in order. The items form a sequence of:

- an `otpauth://` URI, a single string whose scheme is in any case, parsed by
  `otpauth->otp-key`;
- or a triple _issuer account secret_ of strings, symbols or keywords, each
  standing for its name (`github.com:`, `'github.com` and `"github.com"` are
  the same). The secret is lenient Base32 (any case, spaces, hyphens and
  optional canonical padding allowed) and must not be empty. The key
  takes the `new-otp-key` defaults: `'totp`, `'sha1`, 6 digits, 30 seconds.
  The issuer is kept even when empty; it must not contain a colon.

Only a string item can be a URI, and only at the start of a group: an item
that is not a URI starts a triple. A trailing group of 1 or 2 items, an item
that is not a string, symbol or keyword, an invalid URI, an invalid secret or
an issuer with a colon raises `ContractViolation`. Secrets never appear in
irritants. A repeated identity replaces the earlier key in place, as
`add-key!` does.

_Atomicity._ All items are parsed and validated before any key is added: if
any item is invalid, nothing is added. With the memory keyring, adding cannot
fail, so registration is all or nothing.

## register-otp-keys

```text
(register-otp-keys item ...) => :void
```

Same as `(otp-keyring-register! (current-otp-keyring) [item ...])`. Keywords
are ordinary values in a rest list, so `github.com:` works as an item.

## Example user script

A personal script, in the style of the old gerbil-utils `otp` tool, lists the
user's keys; a command-line tool then searches the keyring and prints codes.

```scheme
(import :std/crypto/otp/keyring)

(register-otp-keys
  "gmail.com" "myaccount" "abcd efgh ijkl mnop qrst uvwx yz23 4567"
  "otpauth://totp/GitHub:fare?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
  bank.example: myname: "JBSW Y3DP EHPK 3PXP")
```

Then, e.g., with `:std/crypto/otp/core`:

```scheme
(for-each (lambda (key)
            (displayln (OtpKey-issuer key) " " (OtpKey-account key) " "
                       (otp-key-code key)))
          (OtpKeyring-find-keys (current-otp-keyring) "git"))
```

For an hotp key, take the code at `(OtpKeyring-next-hotp-counter! kr key)`
rather than at `(OtpKey-counter key)`, so the stored counter advances.
