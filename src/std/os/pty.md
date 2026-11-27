# POSIX terminal utilities

`:std/os/pty` supplies reusable pseudoterminal and terminal-mode operations.

## Exports

| Export | Reference |
| --- | --- |
| `open-pty` | [Pseudoterminals](#open-pty) |
| `terminal-size` | [Size](#terminal-size) |
| `terminal-resize!` | [Resize](#terminal-resize) |
| `call-with-terminal-raw-mode` | [Raw mode](#call-with-terminal-raw-mode) |

## Reference

### open-pty

```scheme
(def (open-pty rows: (rows :~ terminal-dimension? :- :fixnum := 24)
               columns: (columns :~ terminal-dimension? :- :fixnum := 80))
  => :values
  ...)
```

Returns the master and slave as two `FileDevice` values, in that order.
The caller owns and must close both. The master is nonblocking. The slave stays
blocking for use as child standard IO. Both descriptors have close-on-exec set.
Dimensions are fixnums in 0..65535. Errors close any partially acquired resources.
The child launcher creates the session and acquires the slave as its controlling terminal. Direct reads on a Linux master may report `EIO` on hangup. The `Process` interface presents this as EOF.

### terminal-size

```scheme
(def (terminal-size (fd : :fixnum))
  => :values
  ...)
```

Returns the current row and column counts as two values. It raises OSError for
an invalid descriptor or a descriptor that does not refer to a terminal.

### terminal-resize!

```scheme
(def (terminal-resize! (fd      : :fixnum)
                       (rows    :~ terminal-dimension? :- :fixnum)
                       (columns :~ terminal-dimension? :- :fixnum))
  => :void
  ...)
```

Sets the window size of the terminal referred to by `fd`. Dimensions
use the same contract as `open-pty`. OS errors propagate.

### call-with-terminal-raw-mode

```scheme
(def (call-with-terminal-raw-mode (fd   : :fixnum)
                                  (proc : :procedure))
  => :t
  ...)
```

Saves the terminal settings, enables raw mode, and calls the zero-argument procedure.
`dynamic-wind` restores the saved settings on normal return, exceptions and continuation escape, and reapplies raw mode on
continuation reentry. The caller retains the fd and must keep it open throughout.
The caller must serialize changes when multiple clients share the same terminal.
