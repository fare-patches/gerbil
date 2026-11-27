# Command-Line Option and Argument Parsing

The `:std/cli/getopt` module parses command lines into a hash table, from a
specification of flags, options, positional arguments and subcommands, and
displays help from the same specification.

```scheme
(import :std/cli/getopt)
```

For changes affecting existing callers, see the [migration notes](#migrating-from-the-previous-getopt).

## Overview

A specification is built with `getopt` from _specifiers_: `flag`, `option`,
`argument`, `optional-argument`, `rest-arguments`, and `command` for
subcommands, each with its own specifiers.
`getopt-parse` parses a list of strings into a hash table indexed by the
specifiers' ids (symbols).

```scheme
(def gopt
  (getopt (flag 'verbose "-v" "--verbose" help: "be verbose")
          (option 'digits "-d" "--digits" default: "6" parse: string->number)
          (argument 'key help: "the secret key")))

(getopt-parse gopt ["-v" "--digits=8" "K"])
;; => table with verbose: #t, digits: 8, key: "K"
(getopt-parse gopt ["K"])
;; => table with digits: "6" (a default is not parsed), key: "K"; no verbose
```

## Command-line syntax

Flags and options are recognized at the start of the command line (or of a
command's arguments), until `--`, which is dropped, or the first word that
does not start with `-`, or a lone `-` (conventionally standard input),
which is kept as a positional argument. Empty words are skipped. Then the positional arguments
are matched in order.

An option takes a value in one of these forms:

- the next word, whatever it looks like: `-c 5`, `--counter 5`, `-c -1`;
- attached to its long name after the _first_ `=`: `--counter=5`,
  `--window=a=b` (value `a=b`), `--window=` (value `""`);
- attached to a two-character short name: `-c5`, `-d-1` (value `-1`),
  `-d=8` (value `=8`).

A word that exactly matches a registered name always takes precedence over
these splits: with `(flag 'cv "-cv")` and `(option 'c "-c")`, `-cv` is the flag.
Help shows a multi-character single-dash alias such as `-color` bare.
A registered alias such as `--mode=plain` also matches exactly, even when
`--mode` accepts an attached value.
An attached value given to a flag (`--verbose=x`, `-v5`) is an error, as is an
unknown name. Short flags cannot be clustered: `-vc` is an error, not `-v -c`.

An option with an `optional-value:` never consumes the next word: a bare
`--totp` or `-m` yields the optional value as given (it is not parsed), and an
explicit value must be attached, as in `--totp=SHA256` or `-mfoo`; it is parsed.

If parsing fails, a getopt error is raised (see `getopt-error?`).

## Parsing and defaults

Every specifier takes `parse:`, a procedure that converts the value of each
occurrence: the string given on the command line, or `#t` for a flag.
It defaults to `identity`, so a flag stores `#t` and an option a string.
`value:` is a compatible alias of `parse:`; passing both is an error
when the specifier is created, as is passing an unknown keyword.

A keyword counts as supplied whenever it is passed, whatever its value:
`default: #f` supplies the default `#f`, and `optional-value: #f` makes `#f`
the optional value. Not passing the keyword at all is what "no default" or
"no optional value" means.

A repeated flag or ordinary option keeps its last value. An omitted one
has no entry unless a specifier supplies a `default:`. Use `hash-key?` to
test presence and `hash-get` when absence should yield `#f`.

Use `multioption` to collect parsed values in command-line order across the selected
command path.
For example, `(multioption 'include "-I" "--include")` gives
`("a" "b")` for `-Ia --include b`, and the empty list when omitted.

## Shared ids

Distinct option names can share an id. Each occurrence uses the parser
for its spelling. At most one scalar specifier per id may supply a
default. A multioption may share its id only with other multioptions
at the same level.

oathtool-style mode and key encoding:

```scheme
(def gopt
  (getopt (flag 'mode #f "--hotp" parse: (lambda (_) 'hotp))
          (option 'mode #f "--totp" optional-value: '(totp . sha1)
                  parse: (lambda (s) (cons 'totp (string->symbol s))))
          (flag 'encoding "-b" "--base32" parse: (lambda (_) 'base32))
          (flag 'encoding #f "--hex" parse: (lambda (_) 'hex))
          (rest-arguments 'args)))
```

| command line                  | mode               | encoding     | args      |
|-------------------------------|--------------------|--------------|-----------|
| (none)                        | (not stored)               | (not stored) | `()`      |
| `--hotp`                      | `hotp`             | (not stored) | `()`      |
| `--totp KEY`                  | `(totp . sha1)`    | (not stored) | `("KEY")` |
| `--hotp --totp=SHA256 -b KEY` | `(totp . SHA256)`  | `base32`     | `("KEY")` |
| `--hex -b`                    | `#f`               | `base32`     | `()`      |

## Example: subcommands

The command line of a package manager, with `call-with-getopt` adding a `help`
command:

```scheme
(def (main . args)
  (call-with-getopt pkg-main args
    program: "gxpkg"
    help: "The Gerbil Package Manager"
    (command 'install help: "install one or more packages"
             (rest-arguments 'pkg help: "package to install"))
    (command 'uninstall help: "uninstall one or more packages"
             (flag 'force "-f" help: "force uninstall even if there are orphaned dependencies")
             (rest-arguments 'pkg help: "package to uninstall"))
    (command 'link help: "link a local development package"
             (argument 'pkg help: "package to link")
             (argument 'src help: "path to package source directory"))
    (command 'list help: "list installed packages")))

(def (pkg-main cmd opt)
  (let-hash opt
    (case cmd
      ((install) (install-pkgs .pkg))
      ((uninstall) (uninstall-pkgs .pkg .?force))
      ((link) (link-pkg .pkg .src))
      ((list) (list-pkgs)))))
```

## Nested commands and dispatch

```scheme
(defgetopt-dispatch handlers
  (version => show-version)
  (client
    (inspect => do-inspect)
    (status => do-status)))

(def (main . argv)
  (call-with-getopt-dispatch handlers argv
    program: "demo"
    (option 'profile "-p")
    (command 'version)
    (command 'client
      (flag 'verbose "-v")
      (command 'inspect (argument 'server))
      (command 'status))))
```

The required `program:` argument supplies the root name for help and error
usage. Here `program: "demo"` gives `Usage: demo client inspect` even if the
executable was invoked under another name. To display the invocation name,
pass the caller's argv[0] (the shell's `$0`) as `program:`. The `argv` list
passed to getopt starts with the first argument after the program name.

`demo -p home client -v inspect dev` selects `(client inspect)` and calls `do-inspect` with one table containing `profile` → `"home"`, `verbose` → `#t`, and `server` → `"dev"`. Each option is read at the level that declares it. Only the selected branch contributes defaults. A later explicit value for the same key replaces an earlier value. A default never replaces an existing option value.

A grammar with a single command level keeps returning a symbol. If any command has children, all selected commands return list paths, including a top-level leaf. Required, optional, and rest arguments are legal only on nodes that have no child commands.

`demo client help` and `demo client -h` both print the summary for `client` and list its immediate subcommands with their descriptions. The flag takes no arguments. The `help` command accepts an optional topic relative to the selected group. For example, `demo client help inspect`, `demo help client inspect`, and `demo client inspect -h` show the leaf's usage without requiring a server argument. These automatic forms belong to `call-with-getopt` and `call-with-getopt-dispatch`. The lower-level `getopt-parse` parses exactly the grammar supplied.

## Interface

### getopt

```text
(getopt help: (help #f) specifier ...) => getopt

specifier:
 (flag id short [long] help: parse: value: default:)
 (option id short [long] help: parse: value: default: optional-value:)
 (multioption id short [long] help: parse: value: optional-value:)
 (argument id help: parse: value:)
 (optional-argument id help: parse: value: default:)
 (rest-arguments id help: parse: value:)
 (command id help: specifier ...)
```

Creates a parser from the specifiers. Flags and options may appear anywhere.
Positional arguments are required arguments, then optional arguments, then
at most one rest argument. A parser has either positional arguments or
commands. A command may contain nested commands. See [nested commands and dispatch tables](#nested-commands-and-dispatch).

### flag

```text
(flag id short (long #f)
      help:      (help #f)
      parse:     (parse identity)       ; alias: value:
      default:   (default <not passed: not stored when absent>))
```

A flag `id` without value, named by the strings `short` and/or `long` (either
may be `#f`), e.g. `"-v"` and `"--verbose"`. Each occurrence yields
`(parse #t)`. See [Parsing and defaults](#parsing-and-defaults) and
[Shared ids](#shared-ids).

### option

```text
(option id short (long #f)
        help:           (help #f)
        parse:          (parse identity)       ; alias: value:
        default:        (default <not passed: not stored when absent>)
        optional-value: (optional-value <not passed: a value is required>))
```

An option `id` with a value (see [Command-line syntax](#command-line-syntax)).
If `optional-value:` is passed, its value, of any type (`#f` and `""` included),
is yielded as given, without `parse:`, by a bare option, which then never
consumes the next word. Without it, a value is required.
The help shows such an option as `-s[<id>]` and `--long[=<id>]`.

### multioption

```scheme
(multioption 'match "-m" "--match" help: "Glob to match (repeatable)")
```

Each occurrence contributes one element to a list, including duplicates.
It accepts the same value syntax and per-occurrence conversion as
`option`. With zero occurrences its value is `()`. To aggregate the list
in any other way, process it in the command handler.

### argument, optional-argument and rest-arguments

```text
(argument id help: (help #f) parse: (parse identity))
(optional-argument id help: (help #f) parse: (parse identity) default: (default #f))
(rest-arguments id help: (help #f) parse: (parse identity))
```

A required positional argument, an optional one (its unparsed `default:` when
absent), and the list of all remaining arguments, each element parsed.
`value:` is accepted as an alias of `parse:`. Extra arguments are an error.

### command

```text
(command id help: (help #f) specifier ...)
```

A subcommand named by the symbol `id`, with its own flags, options and
positional arguments or child commands. Options before a child command belong
to its parent.

### getopt->specifiers

```text
(getopt->specifiers getopt) => list
```

Returns the options followed by the commands or positional arguments, preserving
the order within each group. Multicall uses these specifiers to include an
entry's parser tree in its help display.

### call-with-getopt-topic

`(call-with-getopt-topic parser topic program proc)` walks the command names in
`topic` and calls `proc` with the deepest recognized parser, its full program
name, and the remaining topic symbols. An empty remainder means the entire
topic matched.

### getopt-parse

```text
(getopt-parse getopt args) => hash-table
                           => (values command-id hash-table)  ; flat command grammar
                           => (values command-path hash-table) ; nested grammar
```

Parses the list of strings `args`. In a nested grammar the command path is a
list of symbols, even for a top-level leaf. The table includes the options
from each selected command level. Raises a getopt error on failure.

### getopt-error?

```text
(getopt-error? obj) => boolean
```

Recognizes the errors raised by `getopt-parse`: unknown option or command,
missing or unexpected value, missing or unexpected arguments.

### getopt? and getopt-object?

```text
(getopt? obj) => boolean
(getopt-object? obj) => boolean
```

`getopt?` recognizes parsers made by `getopt`; `getopt-object?` recognizes
specifiers (commands, flags, options and positional arguments).

### getopt-display-help

```text
(getopt-display-help obj program (port (current-output-port)))
```

Displays the usage and help of a parser or a command for the program named
`program`; for a getopt error, displays the error, then the help of the parser
or command that raised it.

### getopt-display-help-topic

```text
(getopt-display-help-topic getopt topic program (port (current-output-port)))
```

Displays help for a command symbol or a list of command symbols. An empty
path shows root help. An unknown component reports the recognized path and the offending name, then shows help for its parent. Both go to `port`, which defaults to the current output port.

### call-with-getopt

```text
(call-with-getopt proc args
                  program: program
                  help: (help #f)
                  exit-on-error: (exit-on-error? (exit-on-error?))
                  specifier ...)
```

The required `program:` string begins each usage line.
Creates a parser from the specifiers, adding a `-h`/`--help` flag at each level
and a `help [command ...]` command at each branch, and parses `args`.
On help, displays it; otherwise calls `(proc table)`, or `(proc command-id
table)` with commands. On a getopt error, if `exit-on-error?` is true, displays
the error and help on the current error port and exits with status 2;
otherwise the error is raised.

### getopt-parse->function-arguments

```text
(getopt-parse->function-arguments getopt table) => list
```

Converts a parse table into arguments for a Scheme function with an analogous
calling convention: the positional arguments in order, then the rest
arguments, then the remaining entries as keyword arguments, sorted by name.
Each stored id yields one parameter, even when several specifiers share it.
An absent flag or option with no `default:` yields no keyword argument,
so the called function's own keyword default applies.
`table` is modified: positional and rest entries are removed; use `hash-copy`
to preserve it.

### call-with-getopt-parse

```text
(call-with-getopt-parse getopt table function) => result
```

`(apply function (getopt-parse->function-arguments getopt table))`.
See also `call-with-processed-command-line` and `define-entry-point` in
`:std/cli/multicall`.

### defgetopt-dispatch

`(defgetopt-dispatch name entry ...)` defines a dispatch table for a separate getopt grammar. Write each leaf as `(command => handler)` and each group as `(command entry ...)`. The same syntax applies at every depth, and leaves and groups can be siblings. Keys are literal command symbols. Each handler takes the merged option table. Tables are built on first use, so handler definitions can follow the declaration.

### getopt-dispatch

`(getopt-dispatch table command options)` follows a parsed symbol or nonempty command path and returns the leaf handler's result. An empty path, a missing handler, or a path that ends at a subtable raises an exception recognized by `getopt-error?`. Its irritants include the requested command.

### call-with-getopt-dispatch

`(call-with-getopt-dispatch table argv program: name spec ...)` parses a grammar containing commands and invokes the selected leaf handler. It accepts the same `help:` and `exit-on-error:` keywords as `call-with-getopt`. With `exit-on-error: #t`, a parse or dispatch error prints the diagnostic and the selected command’s help to stderr and exits with status 2. With `exit-on-error: #f`, the caller receives the exception. Exceptions raised by the leaf handler propagate to its caller in either mode.

## Future work

- Clustering short flags, as in `-bv` for `-b -v`.
- Opt-in GNU-style permutation, accepting options after positional arguments.

## Migrating from the previous getopt

Gerbil v0.19 removes the old `:std/getopt` module name. Update imports to `:std/cli/getopt`.

- Previously, omitting an option without a default inserted its id with `#f`.
  Now flags and options both omit the entry unless a specifier for the id supplies
  `default:`. Use `hash-get` for a `#f` fallback, or declare
  `default: #f` to keep the key present. When forwarding keywords to a function,
  omission now lets that function's keyword default apply.
- Two specifiers at the same command level claiming the same option name used
  to silently select the later one. The grammar now rejects the collision.
  Distinct spellings can still share an id. Automatic help reserves `-h` and
  `--help` at each level in the high-level entry points.
- A lone `-` now starts positional arguments. Attached option values such as
  `--count=3` and `-c3` are accepted. An exact registered spelling takes priority.
- Flat command grammars still return a command symbol. Introducing nested
  commands changes that result to a list of symbols for every selected command.
- With `exit-on-error: #t`, a getopt error in `call-with-getopt` now exits
  with status 2 (previously 1). Help for an unknown topic includes a diagnostic
  and the recognized parent's usage, both on the selected help port.
- Help prints default and optional values using Scheme syntax, including quotes
  around strings.
