# Testing

Gerbil comes with a testing library and a testing tool that can be used to run your tests
in the command line.

## Running tests with gxtest

Test files by convention have the `-test.ss` suffix and are generally not compiled.
Each test file is a module that should export one or more _test suites_, with a name that
ends in `-test`. See below for definition of test suites and test cases.

Tests can also optionally export `test-setup!` and `test-cleanup!` thunks:
- `test-setup!` will be executed before any test-suite in the file has run.
- `test-cleanup!` will be executed (with unwind protection) when all the test suites in the
  file have run.

Once your tests are in place, you can run them using `gerbil test` or just `gxtest`.
If you invoke it without arguments it will run all the test files in the current directory.
You can also explicitly pass files or directories to be run, and if you want to run tests
in a directory recursively you can append `/...` in the directory.

For instance, the following will recursively run all tests in the current directory:
```
gerbil test ./...
```

Use `--isolate` to run each test module in a fresh subprocess. This releases its
loaded modules, test state, and heap when the module finishes:

```sh
gerbil test --isolate ./...
```

Use `--parallel N` to run up to N test module subprocesses concurrently. It implies
isolation; N must be a positive integer. For example, to use up to four cores:

```sh
gerbil test --parallel 4 ./...
```

The default remains a single process. In isolated mode, each child inherits the
working directory and environment, and receives the suite filter (`-r`), feature
flags (`-D`), verbosity (`-v`), and global environment option (`-g`). The parent
reads each child's combined stdout and stderr one line at a time, prefixes it with
`[module-path]`, and prints the complete line under a shared lock. Lines from
different modules can alternate, but their contents do not interleave. A final
unterminated line is printed when the parent reaches EOF. The runner splits output on
newline bytes and preserves the bytes of each line, including incomplete UTF-8.

In isolated mode, `gxexec` supervises each module in its own process group.
When the module exits, the monitor kills remaining group members. A helper
that starts a separate session or moves to a different process group can
outlive the module. Such a helper must close or redirect both stdout and
stderr, or its inherited pipe will keep the worker waiting for EOF.

On Linux, `--cgroup DIR` runs each module in a separate cgroup under a writable,
delegated cgroup v2 directory. It implies isolation and works with `--parallel`.
The monitor kills remaining processes in the module's cgroup, including helpers
that changed sessions, and removes the empty cgroup before reporting the result.
If the supplied directory cannot support this operation, the module fails to start.

The parent uses the child process's exit status as the module result. A test
that explicitly calls `(exit 0)` marks its module as passed, even if an
earlier check failed. Return from the test to let the harness report those
failures.

Failed or abnormally terminated children do not prevent the remaining modules
from running. The runner lists failed modules and their process status or launch
error at the end, and exits nonzero if any module fails. Tests within a module
still run sequentially and share that module's setup and cleanup.

## Test suites

A test suite is created using the `test-suite` special form from `:std/test` and contains one
or more _test cases_ created with the `test-case` special form.

Test cases contain code executed by the test runner, and in general contain one or more _checks_ with the `check` family of special forms which perform assertions.


## Example
Here is a small example for unit testing a trivial module:

```
$ cat gerbil.pkg
(package: tmp)

$ cat mylib.ss
(export myadd)

(def (myadd x y)
 (+ x y))

$ cat mylib-test.ss
(import :std/test
        ./mylib)
(export mylib-test test-setup! test-cleanup!)

(def (test-setup!)
  (displayln "setting up..."))

(def (test-cleanup!)
  (displayln "cleaning up..."))

(def mylib-test
  (test-suite "test mylib"
    (test-case "test myadd"
      (check (myadd 1 2) => 3))))

$ gxc -O mylib.ss
$ gerbil test
=== ./mylib-test.ss
>>> setup
setting up...
>>> run mylib-test
Test suite: test mylib
Test case: test myadd
... 1 checks OK
... All tests OK
>>> cleanup
cleaning up...
OK
$ echo $?
0
```

## The standard testing library

See [:std/test](/reference/std/test.md) for the api of the testing library.
