# Native process implementation boundary

`:std/os/process-native` is internal to `:std/os/process`. It prepares the IO endpoints for both launch modes. Direct execution uses a Gambit
process device. Monitored execution uses POSIX spawn file actions to start `gxexec`.

## Exports

| Export and generated bindings | Reference |
| --- | --- |
| `process_fds` | [Descriptor ownership](#process_fds) |
| `native-process-prepare!`, `native-process-close-child-fds!` | [Descriptor ownership](#process_fds) |
| `native-raw-spawn!`, `native-process-exit-value` | [Direct launch](#direct-launch) |
| `native-spawn-monitor!`, `ffi-spawn-monitor` | [Monitor launch](#monitor-launch) |
| `native-process-take-device!`, `native-process-take-fd!` | [Transfer](#transfer) |
| `native-process-discard!` | [Discard](#native-process-discard) |

## Reference

### process_fds

Native descriptor bundle initialized by `native-process-prepare!` with stdin, stdout,
optional stderr, a startup event pipe, and an owner command pipe for monitored launches. Empty/transferred slots are -1. Parent descriptors are
nonblocking and close-on-exec. The high-level Process adopts them before spawn. The native launcher borrows the child descriptors during fork or spawn. Close the parent copies immediately
afterward with `native-process-close-child-fds!` so readers can observe EOF.

### Direct launch

`native-raw-spawn!` supplies the child endpoints, explicit executable, argv,
environment and directory to its native exec callback. Gambit allocates the
process device and forks. In the child the callback connects stdio, acquires the
controlling terminal when requested, resets signals and calls `execve`. Closing
the report pipe on exec signals success to the parent. A setup or exec failure
sends errno over the same pipe. The caller waits on its nonblocking Gerbil reader,
so other Gerbil threads can run while the child is entering the executable.
Gambit supplies the native fork entry point as a foreign function pointer.
This works in a standalone binary and in a dynamically loaded module.
`native-process-exit-value` decodes the native wait status as an exit code
or negative signal number.

### Monitor launch

Starts the helper with explicitly mapped descriptors, reset signal state and its
own process group through POSIX_SPAWN_SETPGROUP.
Sources are first duplicated above all destination descriptors to prevent dup2
aliasing. Every failed preparation/spawn closes its temporary descriptors.
Arguments cross the FFI using Gambit's UTF-8 conversions. The monitor receives an
empty environment; payload environment is sent later through its owner channel.

### Transfer

`native-process-take-fd!` transfers one descriptor and clears its bundle slot.
`native-process-take-device!` wraps it as FileDevice, closing it if wrapping fails.
The latter returns false for an empty slot. Index/direction are internal contracts.

### native-process-discard!

Closes remaining bundle descriptors. In particular, discarding an unadopted owner
endpoint requests monitor cleanup. Already transferred descriptors are untouched.
