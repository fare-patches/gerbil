# Printing results and setting the exit status

Import `:std/cli/print-exit` to turn the values returned by a command into
output and a process exit status. For example, a command that has already
printed its search results can exit successfully if it found any matches:

```scheme
(import :std/cli/print-exit)

(def (main . patterns)
  (begin-print-exit
    (silent-exit (show-matches patterns))))
```

| Command result | Output with the default printer | Exit status |
| --- | --- | --- |
| One void value, `(void)` | Nothing | 0 |
| Zero values, `(values)` | Nothing | 1 |
| One false value, `#f` | `#f` | 1 |
| Any other result | Each value in order | 0 |

## value-printer

`value-printer` is a parameter whose default is `write`. The printer takes
one argument. By default strings appear in quotes and successive values
have no separator or trailing newline.

## print-values and print-exit

`(print-values . vs)` prints the supplied values as described above,
attempts to flush the current output and error ports independently, and
returns `(void)`. A flush error on either port is ignored.

`(print-exit . vs)` calls `print-values` and exits with the status in the
table. For example, `(print-exit #f 42)` writes `#f42` and exits 0.

## silent-exit

`(silent-exit [success?])` returns one void value if its argument is true
and zero values if it is false. The argument defaults to true. Pass those
values to `print-exit` to exit silently. Calling `silent-exit` itself
returns to the caller.

## call-print-exit and begin-print-exit

`(call-print-exit thunk)` calls a zero-argument procedure and passes all
its returned values to `print-exit`. An uncaught error goes through
`exit-with-error`, which attempts to flush pending output, reports the
error on the current error port, and exits 2.

`(begin-print-exit body ...)` is shorthand for
`(call-print-exit (lambda () body ...))`.
