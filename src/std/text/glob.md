# Glob Patterns

The `:std/text/glob` module matches strings against shell-style glob
patterns.

```scheme
(import :std/text/glob)
```

## Pattern syntax

| Pattern | Matches |
|---------|---------|
| `*`     | any sequence of characters, including the empty one, `/` and newlines |
| `?`     | exactly one character, including newline and `/` |
| any other character | itself, case-sensitively |

Both wildcards can match a slash, a newline, or a leading period.
Brackets, braces and backslashes match literally. For example, `[ab]`
matches the four-character string `[ab]`, and `a\*` matches a literal
`a` and backslash followed by any suffix.

## glob-match?

```text
(glob-match? (pattern : :string)
             (str     : :string))
  => :boolean
```

Returns `#t` if the whole of `str` matches `pattern`, `#f` otherwise.

## Examples

```scheme
(glob-match? "*.ss" "glob.ss")             ; => #t
(glob-match? "*.ss" "glob.ssi")            ; => #f
(glob-match? "a?c" "a\nc")                 ; => #t
(glob-match? "a.c" "abc")                  ; => #f, `.` is literal
(glob-match? "[ab]" "a")                   ; => #f, brackets are literal
```

## Performance

For a pattern of length _m_ and input of length _n_, `glob-match?` takes
O((_n_ + 1)(_m_ + 1)) time and constant auxiliary space. It retries only
the most recent star.
