# CSV

```scheme
(import :std/encoding/csv)
```

## Reading and writing

```scheme
(read-csv source [options])              ; list of rows
(read-csv-line source [options])         ; one row
(write-csv sink rows [options])
(write-csv-line sink fields [options])
```

A row is a list of fields. The reader returns strings. The writer accepts
strings, symbols (by name), numbers (using `number->string`), and `#f`
(an empty field). It applies the dialect's quoting rules after conversion.

A string input contains CSV text. Use an input port to read a file.
An output port writes to that port, a pathname string writes a file,
and the sink `'string` returns the encoded CSV text.

```scheme
(read-csv "a,b\r\n")                    ; => (("a" "b"))
(write-csv-line 'string '("a,b" "c"))   ; => "\"a,b\",c\r\n"
(call-with-input-file "data.csv" read-csv)
```

A blank record has zero fields. With the built-in dialects, `""` on a line
of its own represents one empty field, and a comma alone represents two.
At end of input, `read-csv-line` also returns the empty list. Use `read-csv`
to collect all records including blank ones.

## Dialects

The optional final argument defaults to `(current-csv-options)`.
The presets are `creativyst-csv-options` (the default), `rfc4180-csv-options`,
and `strict-rfc4180-csv-options`. To bind a preset for a body, use
`with-creativyst-csv-syntax`, `with-rfc4180-csv-syntax`, or
`with-strict-rfc4180-csv-syntax` with an empty argument list.
Each also has a `call-with-…-csv-syntax` variant taking a thunk.

Copy a preset before customizing it. For example, a slash can separate fields
even when the printed form of a number contains a slash.

```scheme
(let (opts (struct-copy creativyst-csv-options))
  (csv-options-separator-set! opts #\/)
  (write-csv-line 'string '(1/2 3) opts)) ; => "\"1/2\"/3\r\n"
```

The option fields are `separator`, `quote`, `unquoted-quotequote?`,
`loose-quote?`, `allow-binary?`, `eol`, `accept-lf?`, `accept-cr?`,
`accept-crlf?`, and `skip-whitespace?`. Use the corresponding
`csv-options-…` accessors and `csv-options-…-set!` setters.

* With `unquoted-quotequote?` enabled, two initial quotes encode one literal
  quote. A singleton empty field has no spelling. With loose quoting disabled,
  a field starting with a quote and containing the separator also has no
  spelling. The writer signals an I/O error in these cases. Loose quoting lets
  the writer quote the suffix after the initial literal quotes.
* With `allow-binary?` disabled, both directions accept printable ASCII, CR,
  and LF as field data. Other characters signal an I/O error.
* With CRLF as the only record ending, an unquoted lone CR or LF is an error.
  Quoted fields may contain either character. A CR-only or LF-only dialect
  can carry the other character as ordinary field data.

The public readers and writers check the options before processing any rows,
including an empty input or row list. Enable at least one input line ending.
The separator and quote must be distinct and must not collide with an enabled
input line ending or the first character of the output line ending.
A space or tab used as the separator or quote retains its CSV meaning when
`skip-whitespace?` is enabled.

The writer's `eol` and the reader's accepted line endings are independent.
For a round trip, the reader must consume the writer's `eol` as one record
ending. For example, disabling only `accept-crlf?` on the default preset
leaves the writer emitting CRLF. The reader then treats CR and LF as two
endings, adding a blank record after each row.

For interchange with Common Lisp's `fare-csv`, supply strings when the precise
spelling matters. Each implementation uses its own number printer and symbol
names when converting other values to text.
