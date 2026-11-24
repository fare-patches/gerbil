# Multicall Binaries

The `:std/cli/multicall` module builds a single binary whose first command-line
argument selects one of several registered _entry points_ (subcommands),
like the `gerbil` binary itself, `git`, or `busybox`.
An entry point can supply a help string and a `:std/cli/getopt` specification
for parsing its arguments and displaying help.

```scheme
(import :std/cli/multicall)
```

Entry points are registered in a single global table, `entry-points`,
indexed by symbol. The module itself registers `help`, `meta` and `version`.

## Dispatch

`(dispatch-entry-point arg ...)` selects an entry point as follows:

1. With no arguments, call the `multicall-default` entry point with no arguments.
2. If the first argument names a registered entry point, call it with the
   remaining arguments.
3. If the default is `help`, report the unrecognized first argument on stderr and show general help.
4. If the application passed `fallback: #t`, call the `multicall-default` entry point with _all_ the
   arguments, as if its name had been typed first.
   This includes a first argument that looks like an option, such as `-w`.
5. Otherwise, raise an unknown-command error.

An unregistered `multicall-default` raises an "Unknown command" error naming it.
In every case the selected entry point's name is pushed, as a string,
onto `current-program` while it runs.
A registered command always takes precedence over the default: to pass a
registered command name to the default, name the default explicitly.

With the stock default, `prog` and `prog help` show general help and exit 0.
`prog typo extra` reports the typo on stderr, shows general help on stdout,
and exits 1. A non-help default rejects the typo unless fallback is enabled.
`prog help a b` follows the registered topic path without running the command.

## Example

An `otp` command where `otp github` shows codes for keys matching `github`,
while `otp help`, `otp version` and `otp add ...` remain subcommands:

```scheme
(import :std/cli/multicall :std/cli/getopt)
(export main)

(define-entry-point (keys . patterns)
  (help: "Show codes for keys matching the patterns"
   getopt: [(rest-arguments 'patterns help: "key name patterns")])
  ...)

(define-entry-point (add name secret)
  (help: "Add a key"
   getopt: [(argument 'name) (argument 'secret)])
  ...)

;; `otp` alone = `otp keys`, showing all codes; `otp github` = `otp keys github`.
(set-default-entry-point! 'keys fallback: #t)
(define-multicall-main)
```

`otp help` still runs the `help` subcommand. A key literally named like a
subcommand must be selected explicitly, as in `otp keys help`.

## Interface

### Entry point registry

`entry-points` maps each registered name (a symbol) to an
`(entry-point name function help getopt)` record. The fields hold the command
name, handler procedure, help string and argument specification.
`(entry-points-getopt-spec [table])` returns a list of command specifiers
sorted by name. It uses the global registry when called without a table.

### define-entry-point

```text
(define-entry-point (id . formals) (option ...) body ...)
```

Defines the procedure `id` with the given formals and body, and registers it
as an entry point via `register-entry-point` with `id: 'id` and the options,
typically `help: string` and `getopt: spec`.
The getopt results are passed to the procedure as positional and keyword arguments.

### register-entry-point

```text
(register-entry-point function
                      id:     (id     #f)
                      name:   (name   #f)
                      help:   (help   #f)
                      getopt: (getopt #f))
```

Registers `function` as the entry point named `(make-symbol name)`, or if no
`name` is given, the symbol made of the `easy-shell-character?` characters
(from `:std/cli/shell`) of `id`.
`getopt` is any spec accepted by `->getopt-spec`: a list of getopt specifiers,
a `getopt` parser, a natural number, or `#f` (the default) to pass the command
line to `function` unparsed. It parses the command line for dispatch and
describes the entry point in `help`.

### multicall-default and set-default-entry-point!

```text
multicall-default => :symbol                      ; initially 'help
(set-default-entry-point! (name : :symbol) fallback: (fallback? : :boolean := #f))
```

The name of the entry point called with no arguments when no arguments are
given, and, with `fallback: #t`, with all arguments when the first argument isn't a registered
entry point (see [Dispatch](#dispatch)).

### dispatch-entry-point

```text
(dispatch-entry-point arg ...) => result
```

Dispatches the string arguments as described in [Dispatch](#dispatch) and returns the
entry point's result. Errors, including getopt errors, propagate to the caller.
Use this to call the dispatcher from your own `main` or from tests.

### call-entry-point

```text
(call-entry-point arg ...)
```

`(begin-print-exit (apply dispatch-entry-point args))`: dispatches, then prints
the result and exits with a status reflecting it, printing any error and
exiting with status 2 (see `:std/cli/print-exit`).

### define-multicall-main

```text
(define-multicall-main)
```

Defines `main` as `call-entry-point` in the current module.

### current-program and current-program-string

```text
current-program => parameter of (:list :string)   ; initially [(car (command-line))]
(current-program-string (program (current-program))) => :string
```

`current-program` holds the program name and the successive subcommands used
to invoke the current entry point, most recent first; the dispatcher pushes the
selected entry point's name. `current-program-string` returns them in order,
separated by spaces, for usage and help messages.

### call-with-processed-command-line

```text
(call-with-processed-command-line processor command-line function) => result
```

Parses the list of strings `command-line` with `processor` and calls
`function` with the corresponding arguments, as `call-with-getopt-parse` does
(see [getopt](getopt.md)). `processor` is a getopt parser, or a spec for
`->getopt-spec` to make one from, except that `#f` calls `function` with
`command-line` itself, unparsed, options included.

### ->getopt-spec

```text
(->getopt-spec spec) => list
```

The list of getopt specifiers for the `getopt:` of an entry point, to
`(apply getopt ...)` or `(apply command ...)`: a list is flattened; a getopt
parser without commands gives its specifiers (see `getopt->specifiers`); a
natural number `n` gives `n` positional `argument`s `arg1` ... `argn`; `#f`
gives a `rest-arguments` named `rest`, which describes the unparsed arguments
in `help`. Anything else is an error.

### help, meta and version

```text
(help . topics)
(meta)
(version all?: (all? #f) layer: (layer #f))
```

Predefined entry points: `help` prints the build manifest and help for all
entry points or the deepest recognized command in the topic path. An unknown
first topic raises an "Unknown command" error; `meta` prints the space-separated names of all
entry points, for shell completion; `version` prints the build manifest head,
all layers (`-a`), or the given layer (`-l`).
