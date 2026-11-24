# Nested commands and dispatch

Import `:std/cli/getopt` to define a command grammar and dispatch a parsed command to a handler.

## Exports

| Bindings | Reference |
| --- | --- |
| `getopt`, `getopt?`, `getopt-object?`, `flag`, `option`, `command`, `argument`, `optional-argument`, `rest-arguments` | [Grammar](../../../doc/reference/std/cli/getopt.md#getopt) |
| `getopt-parse`, `getopt-error?`, `getopt-display-help`, `getopt-display-help-topic`, `call-with-getopt` | [Parsing and help](../../../doc/reference/std/cli/getopt.md#getopt-parse) |
| `getopt-parse->function-arguments`, `call-with-getopt-parse` | [Function arguments](../../../doc/reference/std/cli/getopt.md#getopt-parse-function-arguments) |
| `defgetopt-dispatch` | [Define a dispatch table](#defgetopt-dispatch) |
| `getopt-dispatch` | [Dispatch a parsed command](#getopt-dispatch) |
| `call-with-getopt-dispatch` | [Parse and dispatch](#call-with-getopt-dispatch) |

## Example

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

`demo -p home client -v inspect dev` selects `(client inspect)` and calls `do-inspect` with one table containing `profile` → `"home"`, `verbose` → `#t`, and `server` → `"dev"`. Each option is read at the level that declares it. Only the selected branch contributes defaults. A later explicit value for the same key replaces an earlier value. A default never replaces an existing option value.

A grammar with a single command level keeps returning a symbol. If any command has children, all selected commands return list paths, including a top-level leaf. Required, optional, and rest arguments are legal only on nodes that have no child commands.

`demo client help` and `demo client -h` both print the summary for `client` and list its immediate subcommands with their descriptions. The flag takes no arguments. The `help` command accepts an optional topic relative to the selected group. For example, `demo client help inspect`, `demo help client inspect`, and `demo client inspect -h` show the leaf's usage without requiring a server argument. These automatic forms belong to `call-with-getopt` and `call-with-getopt-dispatch`. The lower-level `getopt-parse` parses exactly the grammar supplied.

## Reference

### defgetopt-dispatch

`(defgetopt-dispatch name entry ...)` defines a dispatch table for a separate getopt grammar. Write each leaf as `(command => handler)` and each group as `(command entry ...)`. The same syntax applies at every depth, and leaves and groups can be siblings. Keys are literal command symbols. Each handler takes the merged option table. Tables are built on first use, so handler definitions can follow the declaration.

### getopt-dispatch

`(getopt-dispatch table command options)` follows a parsed symbol or nonempty command path and returns the leaf handler's result. An empty path, a missing handler, or a path that ends at a subtable raises an exception recognized by `getopt-error?`. Its irritants include the requested command.

### call-with-getopt-dispatch

`(call-with-getopt-dispatch table argv program: name spec ...)` parses a grammar containing commands and invokes the selected leaf handler. It accepts the same `help:` and `exit-on-error:` keywords as `call-with-getopt`. With `exit-on-error: #t`, a parse or dispatch error prints the diagnostic and the selected command’s help to stderr and exits with status 1. With `exit-on-error: #f`, the caller receives the exception. Exceptions raised by the leaf handler propagate to its caller in either mode.

### getopt->specifiers

```text
(getopt->specifiers getopt) => list
```

Returns the options followed by the commands or positional arguments, preserving
the order within each group. Multicall uses these specifiers to include an
entry's parser tree in its help display.
