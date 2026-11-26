# Base32 Encoding

The `:std/encoding/base32` module implements the standard RFC 4648 Base32
alphabet (`A-Z2-7`), not Base32hex or Crockford Base32.

## base32-encode

```text
(base32-encode (bytes : :u8vector)
               padding: (padding? : :boolean := #t)
               lowercase: (lowercase? : :boolean := #f))
  => :string
```

Returns a new string encoding all input bytes, preserving leading zero bytes.
The default is uppercase with `=` padding to a multiple of eight characters.
`padding: #f` omits padding; `lowercase: #t` uses `a-z2-7`. No line breaks or
prefixes are inserted. Empty input returns an empty string.

For `n` input bytes the output length is `8 * ceiling(n / 5)` with padding,
or `ceiling(8 * n / 5)` without it. An output length outside the fixnum range
raises `ContractViolation`; allocation failures propagate from the runtime.

## base32-decode

```text
(base32-decode (str : :string)
               no-padding: (no-padding? : :boolean := #f))
  => :u8vector
```

Returns a new byte vector. Uppercase, lowercase and mixed-case letters are
accepted. By default, complete padding is required for partial eight-character
groups. Complete groups need no padding. `no-padding: #t` additionally permits
correct unpadded input; it still accepts correctly padded input and does not
relax any other validation. Empty input is valid in either mode.

The decoder rejects:

- Characters outside `A-Z`, `a-z`, `2-7`, and terminal padding, including
  whitespace, non-ASCII characters, `0`, `1`, `8`, and `9`.
- Data lengths congruent to 1, 3, or 6 modulo 8.
- Interior, missing (unless permitted), excessive, or incorrect padding.
  Data-length residues 2, 4, 5, and 7 require respectively 6, 4, 3, and 1
  padding characters when padding is present. Complete groups take none.
- Nonzero unused low bits in the last data character, even without padding.

Malformed encodings raise `ContractViolation` with `base32-decode` as the
error location and diagnostic irritants: input `length`, plus `data-length`
for impossible lengths, `index` and `padding` for padding errors, or `index`
and `char` for invalid characters and pad bits. Indexes are zero-based;
padding errors report the start of trailing padding (or the input length
when required padding is missing). If several rules are violated, length
and padding validation can report an error before character validation.
Argument types and boolean options are checked by the declared contracts.

## base32-decode-lenient

```text
(base32-decode-lenient (str : :string))
  => :u8vector
```

Returns a new byte vector decoded from human-entered Base32, such as OTP
secrets copied from a setup page or an `otpauth://` URI.
It accepts every canonically encoded key accepted by `oathtool --base32`.
Both decoders in this module accept either letter case. The lenient
decoder also ignores spaces, tabs, CR, LF and dashes anywhere in the
input, including between pad characters. Other whitespace is invalid.

After removing separators, the input must be valid Base32 with either
canonical padding or no padding. For example, `MY` and `MY= = = = = =`
both decode to byte 102. `MY==` has too little padding, and `MZ` has
nonzero unused bits. Empty input and separators alone decode to an empty
vector. Padding alone is invalid.

Malformed input raises `ContractViolation`. Indexes refer to the original
string. For incorrect padding, the error reports the first pad index,
input length and pad count. For nonzero unused bits, it reports the last
data character, its index and the input length. An invalid character or a
data character after padding is reported with its character, index and
input length. An impossible data length reports the input length and the
number of data characters.

A validating counting pass sizes the result and a second pass decodes it,
skipping ignored characters in place; no cleaned copy of the input is made.

## DNS-Safe Labels

```scheme
(import :std/encoding/base32)

(base32-encode #u8(102 111 111) padding: #f lowercase: #t)
;; => "mzxw6"
(base32-decode "mzxw6" no-padding: #t)
;; => #u8(102 111 111)
```

Lowercase unpadded output uses only DNS-safe letters and digits. The codec
does not enforce DNS label or hostname limits, add DID prefixes, or split
labels. A single DNS label must be nonempty and at most 63 octets; without
additional prefixes, at most 39 input bytes fit in one Base32 label.

All operations run in linear time with a bounded accumulator of at most
12 bits and constant auxiliary space besides the result. Decoding validates
without re-encoding and allocates exactly `floor(5 * d / 8)` bytes for `d`
data characters. Inputs are not modified. There is no application-specific
size limit beyond runtime string/vector capacity, the encoding fixnum-size
check, and available memory.
