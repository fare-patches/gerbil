# Owned native processes

Use `:std/os/process` to launch an executable, read its output, and wait for its exit. Set `gxexec: #t` to give a native monitor responsibility for cleaning up the payload’s process group.

```scheme
(import :std/os/process)

(using (child (start-process! "/bin/sh" ["sh" "-c" "exit 7"]) : Process)
  (unwind-protect!
    (using (result (child.wait) : ProcessExit)
      result.code)                      ; => 7
    (child.close)))
```

## Exports

| Export and generated bindings | Reference |
| --- | --- |
| `Process` | [Process interface](#process) |
| `ProcessExit` | [Exit information](#processexit) |
| `start-process!` | [Construction](#start-process) |

## Reference

### start-process!

```scheme
(def (start-process! (path : :string)
                     (argv :~ (list-of? string?) :- :list)
                     environment: (environment :~ (list-of? string?) :- :list :=
                                  (map (lambda (entry) (string-append (car entry) "=" (cdr entry)))
                                       (get-environment-variables)))
                     directory: (directory : :string := (current-directory))
                     terminal: (terminal? : :boolean := #f)
                     stdin-redirection: (pipe-in? : :boolean := #t)
                     stderr-to-stdout: (merged? : :boolean := #f)
                     rows: (rows :~ (in-range-inclusive? 0 65535) :- :fixnum := 24)
                     columns: (columns :~ (in-range-inclusive? 0 65535) :- :fixnum := 80)
                     grace: (grace :~ process-grace? :- :real := 5)
                     gxexec: (gxexec? : :boolean := #f)
                     cgroup: (cgroup :? :string := #f)
                     helper: (helper : :string := "~~bin/gxexec"))
  => Process
  ...)
```

`path` names the executable, and relative paths resolve against `directory:`. Supply a nonempty argument list including the program’s `argv[0]`. The launcher calls `execve` directly. For shell command parsing or lookup on `PATH`, launch a shell explicitly. The default environment is a snapshot of the caller’s environment. An explicit environment is a list of `"NAME=value"` strings. Environment entries containing an embedded NUL are rejected at the native boundary.

| Option | Behavior |
| --- | --- |
| `terminal: #f` (default) | Uses pipes. By default, stdin has a writer, and stdout and stderr have separate readers. With `stdin-redirection: #f` the child inherits fd 0, which must be open or launch raises `OSError` with `EBADF`. With `stderr-to-stdout: #t` both output descriptors write to the stdout pipe in write order. |
| `terminal: #t` | Connects all three descriptors to one controlling PTY. Its initial size is 24 rows by 80 columns. Supply `rows:` and `columns:` to override either value. Both accept fixnums from 0 through 65535. These arguments are checked in both modes and only affect PTY mode. The `terminal:` argument accepts only `#f` or `#t`. |
| `gxexec: #f` (default) | Launches the payload directly. The returned handle manages its PID. Pipe children inherit the caller’s process group. PTY children create a session and acquire the slave as their controlling terminal. |
| `gxexec: #t` | Starts one native monitor using `helper:`, which defaults to `~~bin/gxexec`. A missing or unexecutable helper raises a startup error. A standalone deployment can specify another absolute path. |
| `grace:` | Seconds between requesting shutdown and escalating to `SIGKILL`. Accepts a real number from 0 through 2147483 and defaults to 5. The monitor measures elapsed time with a monotonic clock at millisecond resolution. |
| `cgroup:` | With `gxexec: #t` on Linux, supply a delegated cgroup v2 directory to contain descendants that change sessions or process groups. The default is `#f`. An unsupported platform, invalid directory, or insufficient delegation raises a startup error. |

The caller receives a `Process` after successful exec. If the child cannot enter its directory or execute its program, `start-process!` raises a startup error. A program that starts and exits with status 127 returns that status through `(child.wait)`. Application-level readiness requires its own signal.

### Process

```scheme
(interface (Process Closer)
  (pid)
  => :fixnum
  (stdin)
  => (Maybe Writer)
  (stdout)
  => Reader
  (stderr)
  => (Maybe Reader)
  (terminal?)
  => :boolean
  (wait timeout: (timeout : :t := #f))
  => ProcessExit
  (signal (signo :~ (in-range? 1 SIGMAX) :- :fixnum)
          group: (group? : :boolean := #t))
  => :void
  (stop)
  => :void
  (resize (rows :~ (in-range-inclusive? 0 65535) :- :fixnum)
          (columns :~ (in-range-inclusive? 0 65535) :- :fixnum))
  => :void)
```

The following calls use the typed `child` binding in the opening example.

- `(child.pid)` returns the payload PID. `(child.terminal?)` reports whether it has a controlling PTY.
- `(child.stdin)`, `(child.stdout)`, and `(child.stderr)` return borrowed streams. Inherited stdin and combined stderr each return `#f` for their respective stream. Closing a pipe writer delivers EOF to the child. A PTY is bidirectional, so terminal EOF depends on its mode and the control bytes sent. The PTY reader translates Linux slave hangup (`EIO`) into EOF.
- Read separate stdout and stderr concurrently if the child can fill both pipes. A PTY exposes one byte stream. Use `io-copy!` to relay it and `(child.resize 40 100)` to set its window size. Resizing a pipe raises a contract error. An interactive client can restore its own terminal settings with the [PTY utilities](pty.md#call-with-terminal-raw-mode).
- `(child.wait)` returns the retained `ProcessExit` and leaves output available to drain. Concurrent callers can wait independently. For example, `(child.wait timeout: 2)` raises `Timeout` after two seconds if the payload is still running.
- `(child.signal SIGTERM)` signals the payload PID in direct mode and its process group in monitored mode. Use `(child.signal SIGTERM group: #f)` to select just the monitored leader. Wait for the result to observe termination or a monitor error.
- `(child.stop)` requests shutdown and leaves the streams available. The owner must call `(child.close)` to request cleanup, close its streams and join exit observation. Closing is repeatable and propagates monitor errors. After the handle has been returned it can be transferred between Gerbil thread groups. The exit observer and shutdown timer run in a detached group.

### ProcessExit

```scheme
(defstruct ProcessExit
  ((code   :? :fixnum := #f)
   (signal :? :fixnum := #f))
  final: #t)
```

Exactly one field contains a fixnum. For a normal exit, `code` contains the exit status, including zero. For signal termination, `signal` contains the signal number. Both describe the payload.

## Process groups and cleanup

In direct mode, stop sends TERM and CONT to the payload PID and escalates to KILL after the grace period. Descendants can survive the payload. The Gambit process-device implementation assumes one native thread eligible to receive SIGCHLD while registering, checking, and signaling the child. See the [native launch details](process-native.md#direct-launch).

In monitored mode, `gxexec` runs in its own process group. It starts with an empty environment and receives the payload’s environment over the owner channel. Loader settings such as `LD_PRELOAD` therefore apply only to the payload. The payload inherits its standard descriptors. The monitor keeps the owner and event channels private. Closing the owner channel, including when the owner process dies, makes the monitor send TERM and CONT to the payload group. At the grace deadline it escalates to KILL. When the leader exits first, the monitor signals the remaining group members while the leader’s PID is still reserved, then reaps the leader. The reported result confirms the leader was reaped and cleanup was requested.

POSIX process groups are flat. A descendant that starts another group or session can survive a signal to the original group. If that descendant has its own surviving `gxexec` monitor, its immediate owner’s death closes that monitor’s owner pipe and triggers independent cleanup. Startup reports success to the immediate owner. Ancestors receive no recursive registration or acknowledgement.

### Linux cgroup cleanup

The monitor creates a leaf named `gxexec-<monitor-pid>` under the delegated root and stays outside that leaf. Before exec, the child writes itself to `cgroup.procs`. Its descendants inherit membership across fork, process-group changes, and session changes. The leaf sets `cgroup.max.descendants` to zero.

At the grace deadline the monitor writes to `cgroup.kill`. When the leader exits, including after a successful run, it kills remaining leaf members, waits for `cgroup.events` to report `populated 0`, and removes the leaf before reporting the result. This requires a surviving monitor and permission to create, populate, kill, and remove the leaf. A deployment enforcing containment must also restrict the payload’s ability to migrate processes out of the leaf. Separate leaves created under a shared delegated root are siblings and have independent lifetimes.
