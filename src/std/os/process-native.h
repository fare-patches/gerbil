/* Copyright Gerbil contributors. POSIX descriptors and native process launch. */
#include <spawn.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
struct process_fds { int fd[5], child[5]; };
static int gerbil_process_pipe(int fd[2]) {
#if !defined(__APPLE__)
  return pipe2(fd, O_CLOEXEC);
#else
  if (pipe(fd) < 0) return -1;
  if (fcntl(fd[0], F_SETFD, FD_CLOEXEC) < 0 || fcntl(fd[1], F_SETFD, FD_CLOEXEC) < 0) {
    int error = errno; close(fd[0]); close(fd[1]); errno = error; return -1;
  }
  return 0;
#endif
}
static int gerbil_prepare_process(struct process_fds *result, int monitored,
                                  int terminal, int merged, int pipe_stdin, int rows, int columns) {
  int channels[5][2], high[5], error = 0;
  struct pty_fds pty = {-1, -1};
  for (int i = 0; i < 5; ++i) { result->fd[i] = result->child[i] = -1; channels[i][0] = channels[i][1] = high[i] = -1; }
  /* Snapshot inherited stdin before pipe() can reuse a closed descriptor 0. */
  if (!terminal && !pipe_stdin) {
    high[0] = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 10);
    if (high[0] < 0) return -errno;
  }
  /* 0: owner command; 1: events; 2: stdin; 3: stdout; 4: stderr. */
  for (int i = monitored ? 0 : 1; i < (terminal ? 2 : merged ? 4 : 5); ++i)
    if ((i != 2 || pipe_stdin) && gerbil_process_pipe(channels[i]) < 0) { error = errno; goto done; }
  if (terminal) {
    error = -gerbil_open_pty(&pty, rows, columns);
    if (error) goto done;
  }
  int child[5] = {terminal ? pty.slave : channels[2][0],
                  terminal ? pty.slave : channels[3][1],
                  terminal ? pty.slave : channels[merged ? 3 : 4][1], channels[0][0], channels[1][1]};
  /* Relocate before dup2 actions: source fds must not alias target slots. */
  for (int i = 0; i < 5; ++i) {
    if (child[i] < 0) continue;
    high[i] = fcntl(child[i], F_DUPFD_CLOEXEC, 10);
    if (high[i] < 0) { error = errno; goto done; }
  }
  /* Prepare parent endpoints before spawning, so failure cannot orphan a child. */
  if (terminal) {
    channels[2][1] = fcntl(pty.master, F_DUPFD_CLOEXEC, 10);
    if (channels[2][1] < 0) { error = errno; goto done; }
    channels[3][0] = pty.master; pty.master = -1;
  }
  int parent[5] = {channels[0][1], channels[1][0], channels[2][1], channels[3][0], channels[4][0]};
  for (int i = 0; i < 5; ++i)
    if (parent[i] >= 0 && fcntl(parent[i], F_SETFL, O_NONBLOCK) < 0) { error = errno; goto done; }
  for (int i = 0; i < 5; ++i) {
    result->fd[i] = parent[i];
    result->child[i] = high[i]; high[i] = -1;
  }
  channels[0][1] = channels[1][0] = channels[2][1] = channels[3][0] = channels[4][0] = -1;
done:
  for (int i = 0; i < 5; ++i) {
    if (high[i] >= 0) close(high[i]);
    for (int j = 0; j < 2; ++j) if (channels[i][j] >= 0) close(channels[i][j]);
  }
  if (pty.master >= 0) close(pty.master);
  if (pty.slave >= 0) close(pty.slave);
  return -error;
}

static int gerbil_spawn_monitor(struct process_fds *fds, const char *helper, char **argv) {
  int error, actions_ready = 0, attr_ready = 0;
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attr;
  if ((error = posix_spawn_file_actions_init(&actions))) goto done;
  actions_ready = 1;
  for (int i = 0; i < 5; ++i)
    if ((error = posix_spawn_file_actions_adddup2(&actions, fds->child[i], i))) goto done;
  if ((error = posix_spawnattr_init(&attr))) goto done;
  attr_ready = 1;
  sigset_t signals;
  sigfillset(&signals);
  if ((error = posix_spawnattr_setsigdefault(&attr, &signals))) goto done;
  sigemptyset(&signals);
  if ((error = posix_spawnattr_setsigmask(&attr, &signals))) goto done;
  if ((error = posix_spawnattr_setpgroup(&attr, 0))) goto done;
  /* A signal to the owner's foreground group must not kill its monitor. */
  short flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETPGROUP;
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
  flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
#endif
  if ((error = posix_spawnattr_setflags(&attr, flags))) goto done;
  pid_t monitor;
  char *env[] = {NULL};
  error = posix_spawn(&monitor, helper, &actions, &attr, argv, env);
done:
  if (actions_ready) posix_spawn_file_actions_destroy(&actions);
  if (attr_ready) posix_spawnattr_destroy(&attr);
  return -error;
}

static void gerbil_close_child_fds(struct process_fds *fds) {
  for (int i = 0; i < 5; ++i)
    if (fds->child[i] >= 0) { close(fds->child[i]); fds->child[i] = -1; }
}

/* Gambit retains the process device before fork and publishes the PID before
 * letting its SIGCHLD handler collect the child. The IO endpoints are ours. */

#ifdef __linux__
#include <sys/syscall.h>
#endif

struct gerbil_exec_args {
  int stdio[3];
  char *path, **argv, **env, *directory;
  int terminal;
  int report_fd;
  long max_fd;
};

static void gerbil_exec_child(void *context) {
  struct gerbil_exec_args *args = context;
  int report = args->report_fd;
  /* All sources were relocated above stdio before fork. */
  for (int i = 0; i < 3; ++i)
    if (dup2(args->stdio[i], i) < 0) goto fail;
  if (dup2(report, 3) < 0) goto fail;
  report = 3;
  if (fcntl(report, F_SETFD, FD_CLOEXEC) < 0) goto fail;
#ifdef SYS_close_range
  if (syscall(SYS_close_range, 4, ~0U, 0) < 0)
#endif
    for (long fd = 4; fd < args->max_fd; ++fd) close((int)fd);
  if (args->terminal && (setsid() < 0 || ioctl(STDIN_FILENO, TIOCSCTTY, 0) < 0))
    goto fail;
  if (chdir(args->directory) < 0) goto fail;
  struct sigaction action = {0};
  action.sa_handler = SIG_DFL;
  sigemptyset(&action.sa_mask);
  for (int i = 1; i < NSIG; ++i) sigaction(i, &action, NULL);
  sigprocmask(SIG_SETMASK, &action.sa_mask, NULL);
  execve(args->path, args->argv, args->env);
fail: {
    int32_t error = errno;
    while (write(report, &error, sizeof error) < 0 && errno == EINTR) {}
    _exit(127);
  }
}

typedef ___SCMOBJ (*gerbil_process_fork_fn)(void (*)(void *), void *);
static ___SCMOBJ gerbil_raw_spawn(gerbil_process_fork_fn fork_device,
                                  struct process_fds *fds, char *path,
                                  char **argv, char **env, char *directory,
                                  int terminal) {
  struct gerbil_exec_args args = {
    .stdio = {fds->child[0], fds->child[1], fds->child[2]},
    .path = path, .argv = argv, .env = env, .directory = directory,
    .terminal = terminal, .report_fd = fds->child[4], .max_fd = sysconf(_SC_OPEN_MAX)
  };
  if (args.max_fd < 0) return ___FIX(-EINVAL);
  ___SCMOBJ dev = fork_device(gerbil_exec_child, &args);
  if (!___FIXNUMP(dev)) ___EXT(___release_scmobj)(dev);
  return dev;
}
