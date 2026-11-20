# UTF-8

```scheme
(import :std/encoding/utf8)
```

Conversions between strings and UTF-8 without intermediate ports, with exact error offsets, and the unchecked primitives they are built from, for scanners and serializers that establish their own bounds.

The names differ from the core `string->utf8` and `utf8->string` on purpose: importing this module leaves every existing call of the core procedures as it was. Core `utf8->string` raises Gambit's own exception, without an offset, for invalid input; core `string->utf8` writes a lone surrogate as the ill-formed `ED A0 80`. These raise `UTF8Error`. `utf8-encode` and `utf8-decode` keep the names the prior `:std/text/utf8` gave its encoder and decoder.

## Checked conversions

```scheme
(utf8-encode str (start 0) (end (string-length str))) -> u8vector
(utf8-decode bytes (start 0) (end (u8vector-length bytes))) -> string
(utf8-decoded-length bytes (start 0) (end (u8vector-length bytes))) -> fixnum
(string-utf8-length str (start 0) (end (string-length str))) -> fixnum
```

- `utf8-encode`: the UTF-8 encoding of `str[start, end)` as a fresh u8vector. A Gambit string can hold a lone surrogate (its port decoders return one for an encoded surrogate), which UTF-8 cannot encode: `utf8-encode` raises `UTF8Error` at its index in `str`.
- `utf8-decode`: the string of the UTF-8 in `bytes[start, end)`. Ill-formed UTF-8 (Unicode Table 3-7: overlong forms, encoded surrogates, code points above U+10FFFF, stray continuation bytes, sequences truncated by a byte or by `end`) raises `UTF8Error` at the index in `bytes` of the first byte of the first ill-formed sequence.
- `utf8-decoded-length`: the number of characters `bytes[start, end)` decodes to; it checks the UTF-8 as `utf8-decode` does, raising at the same offset. This is the validator: `utf8-decode` is `utf8-decoded-length` followed by the unchecked decoder. Unlike `base64-decoded-length`, which returns `#f` for invalid input, it raises, so that the error carries the offset.
- `string-utf8-length`: the byte length of the encoding of `str[start, end)`; it counts a lone surrogate as 3 bytes, although `utf8-encode` raises on it. It is the binding of `:std/string/utf8`, re-exported for convenience.

Ranges are checked: `start` and `end` must satisfy `0 <= start <= end <= length`, or `ContractViolation` is raised. Offsets index the whole string or u8vector, not the range.

```scheme
(utf8-decode (u8vector #x61 #xc3 #xa9)) ;; => "aé"
(with-catch UTF8Error-offset (cut utf8-decode (u8vector #x61 #x62 #xe0 #x80 #x80))) ;; => 2
```

## Errors

```scheme
(deferror-class (UTF8Error IOError) (offset) utf8-error?)
```

`UTF8Error` is an `IOError` whose `offset` (`UTF8Error-offset`) is the index of the invalid input: a byte index for decoding, a character index for encoding.

## Unchecked primitives

These take no optional arguments and check no bounds or well-formedness: out-of-range indexes or ill-formed input are undefined behaviour, as for the `&` accessors of `:std/vector/u8vector`. They exist for code that already knows its bounds and validity, such as a scanner over a buffer ending with a sentinel byte.

```scheme
(&put-utf8! buf j c) -> fixnum                         ; inline
(&utf8-encode str start end tail) -> u8vector
(&utf8-sequence-length bytes k) -> fixnum              ; inline
(&utf8-code-at bytes k) -> fixnum                      ; inline
(&utf8-check-run bytes k end count fail resume)        ; macro
(&utf8-count-continuations bytes start end) -> fixnum  ; inline
(&utf8-decode bytes start end n) -> string             ; inline
```

The inline primitives are `definline`: a call expands in place.

- `&put-utf8!`: stores the encoding of code point `c`, not a surrogate, at `buf[j]` and returns the index after it; `buf` must have room for 4 bytes.
- `&utf8-encode`: the encoding of `str[start, end)` followed by `tail` zero bytes (a sentinel for a scanner); a lone surrogate raises `UTF8Error` at its index, as in `utf8-encode`. ASCII text is encoded in one pass.
- `&utf8-sequence-length`: the length of the well-formed sequence at `bytes[k]`, whose first byte is at least `#x80`, or 0 when it is ill-formed. It reads a byte only after the previous one proved to be a continuation byte, so `bytes` must hold a byte below `#x80` somewhere after `k`, as a 0 sentinel is.
- `&utf8-code-at`: the code point of the well-formed sequence at `bytes[k]`.
- `&utf8-check-run`: checks the sequences from `bytes[k]` up to the next byte below `#x80` or `end`, then evaluates `(resume i n)` at that index `i`, `n` being `count` plus their continuation bytes; at an ill-formed sequence `i` it evaluates `(fail i)` instead. It reads no byte at or past `end`. A macro, for scanning loops: `fail` and `resume` name the caller's macros or procedures. `utf8-decoded-length` is a loop over it.
- `&utf8-count-continuations`: the number of continuation bytes (`#x80` to `#xbf`) in `bytes[start, end)`.
- `&utf8-decode`: the string of the well-formed `bytes[start, end)`, which holds `n` characters: `(- end start)` less its continuation bytes. When `n` is `(- end start)` the bytes are ASCII and are copied four at a time.

## Performance

The checked conversions are two passes, like Gambit's: `utf8-decode` validates and counts, then decodes into a string of the exact length; `utf8-encode` copies ASCII until the first non-ASCII character, then sizes the rest and encodes it. The unchecked primitives let a scanner validate while it scans, with exact offsets, and decode spans whose length it already knows without validating them again.
