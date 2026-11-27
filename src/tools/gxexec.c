/* Copyright Gerbil contributors.
 * Single-threaded monitor. Spawned as a fresh executable, never forked from
 * the Scheme runtime. fd 3 is the owner channel; fd 4 carries status records.
 * The payload inherits only stdin/stdout/stderr, never either control endpoint.
 */
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#ifdef __linux__
#include <linux/magic.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#endif

static int wake_fd = -1;
static void wake_child(int signo) {
  int saved = errno;
  unsigned char byte = 0;
  (void)signo;
  if (wake_fd >= 0) (void)write(wake_fd, &byte, 1);
  errno = saved;
}

static int send_event(int kind, int value) {
  int32_t event[2] = {kind, value};
  const char *p = (const char *)event;
  size_t left = sizeof event;
  while (left) {
    ssize_t n = write(4, p, left);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    p += n; left -= (size_t)n;
  }
  return 0;
}

static int read_exact(int fd, void *buffer, size_t length) {
  char *p = buffer;
  while (length) {
    ssize_t n = read(fd, p, length);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { if (n == 0) errno = EPIPE; return -1; }
    p += n; length -= (size_t)n;
  }
  return 0;
}

/* Private startup message: native uint32 count, then length + UTF-8 bytes for
 * each entry. Reading happens before any payload exists. */
static char **read_environment(void) {
  uint32_t count, length;
  if (read_exact(3, &count, sizeof count) < 0) return NULL;
  if ((uint64_t)count + 1 > SIZE_MAX / sizeof(char *)) { errno = E2BIG; return NULL; }
  char **env = calloc((size_t)count + 1, sizeof(char *));
  if (!env) return NULL;
  for (uint32_t i = 0; i < count; ++i) {
    if (read_exact(3, &length, sizeof length) < 0) goto failed;
    if ((uint64_t)length + 1 > SIZE_MAX) { errno = E2BIG; goto failed; }
    env[i] = malloc((size_t)length + 1);
    if (!env[i]) goto failed;
    if (read_exact(3, env[i], length) < 0) goto failed;
    env[i][length] = 0;
  }
  return env;
failed: {
    int error = errno;
    for (uint32_t i = 0; i < count; ++i) free(env[i]);
    free(env); errno = error; return NULL;
  }
}

static int64_t milliseconds(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) _exit(125);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void close_extra(void) {
  /* Run only in the fresh, single-threaded helper. */
#if defined(__linux__) && defined(SYS_close_range)
  if (syscall(SYS_close_range, 5, ~0U, 0) == 0) return;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  closefrom(5);
  return;
#endif
  struct rlimit limit;
  if (getrlimit(RLIMIT_NOFILE, &limit) < 0) _exit(125);
  for (rlim_t fd = 5; fd < limit.rlim_cur; ++fd) close((int)fd);
}

static void child_error(int fd) {
  int error = errno;
  (void)write(fd, &error, sizeof error);
  _exit(127);
}

/* Only the monitor owns the leaf. Its child joins by writing 0 (self) before
 * exec. The monitor stays outside so it can finish cleanup after owner EOF. */
#ifdef __linux__
static int group_root = -1, group_procs = -1, group_kill = -1, group_events = -1;
static char group_name[48];

static int write_setting(int fd, char value) {
  ssize_t n;
  do { n = pwrite(fd, &value, 1, 0); } while (n < 0 && errno == EINTR);
  if (n == 1) return 0;
  if (n == 0) errno = EIO;
  return -1;
}

static int prepare_cgroup(const char *root) {
  group_root = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (group_root < 0) return -1;
  struct statfs fs;
  if (fstatfs(group_root, &fs) < 0) return -1;
  if (fs.f_type != CGROUP2_SUPER_MAGIC) { errno = ENODEV; return -1; }
  snprintf(group_name, sizeof group_name, "gxexec-%ld", (long)getpid());
  if (mkdirat(group_root, group_name, 0755) < 0) return -1;
  int dir = openat(group_root, group_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir >= 0) {
    /* This is a leaf for one incarnation. Descendant processes can fork and
     * change sessions, but need no nested cgroup directories. */
    int limit = openat(dir, "cgroup.max.descendants", O_WRONLY | O_CLOEXEC);
    if (limit >= 0 && write_setting(limit, '0') == 0 &&
        (group_procs = openat(dir, "cgroup.procs", O_WRONLY | O_CLOEXEC)) >= 0 &&
        (group_events = openat(dir, "cgroup.events", O_RDONLY | O_CLOEXEC)) >= 0 &&
        (group_kill = openat(dir, "cgroup.kill", O_WRONLY | O_CLOEXEC)) >= 0) {
      close(limit);
      close(dir);
      return 0;
    }
  }
  int error = errno;
  unlinkat(group_root, group_name, AT_REMOVEDIR);
  errno = error;
  return -1;
}

static int join_cgroup(void) {
  return group_procs < 0 ? 0 : write_setting(group_procs, '0');
}

static int kill_cgroup(void) {
  return group_kill < 0 ? 0 : write_setting(group_kill, '1');
}

static int remove_cgroup(void) {
  if (group_kill < 0) return 0;
  if (kill_cgroup() < 0) return -1;
  struct pollfd event = {group_events, POLLPRI, 0};
  for (;;) {
    char data[512];
    ssize_t n = pread(group_events, data, sizeof data - 1, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) return -1;
    data[n] = 0;
    if (strstr(data, "populated 0\n")) break;
    if (!strstr(data, "populated 1\n")) { errno = EIO; return -1; }
    if (poll(&event, 1, -1) < 0 && errno != EINTR) return -1;
  }
  return unlinkat(group_root, group_name, AT_REMOVEDIR);
}
#else
static int prepare_cgroup(const char *root) { (void)root; errno = ENOTSUP; return -1; }
static int join_cgroup(void) { return 0; }
static int kill_cgroup(void) { return 0; }
static int remove_cgroup(void) { return 0; }
#endif

int main(int argc, char **argv) {
  /* Version 2 inserts the delegated cgroup root before the executable. */
  if (argc < 7) return 125;
  int grouped = !strcmp(argv[1], "2");
  if (grouped ? argc < 8 : strcmp(argv[1], "1") != 0) return 125;
  char **program = &argv[grouped ? 6 : 5];
  int terminal = !strcmp(argv[2], "pty");
  char *end;
  long grace = strtol(argv[3], &end, 10);
  if (*end || grace < 0 || grace > 2147483647L) return 125;
  close_extra();
  signal(SIGPIPE, SIG_IGN);
  char **environment = read_environment();
  if (!environment) { send_event(3, errno); return 125; }
  int wake[2], error_pipe[2];
  if (pipe(wake) < 0) { send_event(3, errno); return 125; }
  if (pipe(error_pipe) < 0) { send_event(3, errno); return 125; }
  fcntl(error_pipe[1], F_SETFD, FD_CLOEXEC);
  fcntl(wake[0], F_SETFL, O_NONBLOCK);
  fcntl(wake[1], F_SETFL, O_NONBLOCK);
  wake_fd = wake[1];
  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = wake_child;
  sigemptyset(&action.sa_mask);
  sigaction(SIGCHLD, &action, NULL);

  if (grouped && prepare_cgroup(argv[5]) < 0) { send_event(3, errno); return 125; }
  pid_t child = fork();
  if (child < 0) {
    int error = errno;
    remove_cgroup();
    send_event(3, error);
    return 125;
  }
  if (child == 0) {
    close(3); close(4); close(wake[0]); close(wake[1]); close(error_pipe[0]);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);
    if (join_cgroup() < 0) child_error(error_pipe[1]);
    if (setsid() < 0) child_error(error_pipe[1]);
    if (terminal && ioctl(0, TIOCSCTTY, 0) < 0) child_error(error_pipe[1]);
    if (chdir(argv[4]) < 0) child_error(error_pipe[1]);
    execve(program[0], program + 1, environment);
    child_error(error_pipe[1]);
  }
  for (char **entry = environment; *entry; ++entry) free(*entry);
  free(environment);
  close(error_pipe[1]);
  close(0); close(1); close(2);
  int error = 0;
  ssize_t n;
  do { n = read(error_pipe[0], &error, sizeof error); } while (n < 0 && errno == EINTR);
  close(error_pipe[0]);
  if (n != 0) {
    if (n < 0) error = errno;
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    if (remove_cgroup() < 0) error = errno;
    send_event(3, error);
    return 125;
  }

  int stopping = 0, killed = 0, owner = 1;
  int64_t deadline = 0;
  if (send_event(1, (int)child) < 0) owner = 0;
  int32_t command[2];
  size_t have = 0;
  for (;;) {
    siginfo_t info;
    memset(&info, 0, sizeof info);
    if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT) < 0) {
      error = errno;
      if (error == EINTR) continue;
      break;
    }
    if (info.si_pid) {
      /* Keep the leader unreaped while signaling: its PID cannot be reused.
       * No delayed signal is ever sent after waitpid releases that identity.
       */
      if (kill(-child, SIGKILL) < 0 && errno != ESRCH) { error = errno; break; }
      int status;
      do { n = waitpid(child, &status, 0); } while (n < 0 && errno == EINTR);
      if (n < 0) { error = errno; break; }
      if (remove_cgroup() < 0) { send_event(3, errno); return 125; }
      send_event(2, WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status));
      return 0;
    }
    if (!owner && !stopping) {
      stopping = 1;
      deadline = milliseconds() + grace;
      if (kill(-child, SIGTERM) < 0 && errno != ESRCH) { error = errno; break; }
      /* A stopped job must be allowed to handle TERM. */
      kill(-child, SIGCONT);
    }
    int timeout = -1;
    if (stopping && !killed) {
      int64_t left = deadline - milliseconds();
      if (left <= 0) {
        if (kill(-child, SIGKILL) < 0 && errno != ESRCH) { error = errno; break; }
        if (kill_cgroup() < 0) { error = errno; break; }
        killed = 1;
      } else timeout = (int)left;
    }
    struct pollfd fds[2] = {{owner ? 3 : -1, POLLIN, 0}, {wake[0], POLLIN, 0}};
    int ready = poll(fds, 2, timeout);
    if (ready < 0) { if (errno == EINTR) continue; error = errno; break; }
    if (fds[1].revents & POLLIN) {
      unsigned char bytes[64];
      while (read(wake[0], bytes, sizeof bytes) > 0) {}
    }
    if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
      n = read(3, (char *)command + have, sizeof command - have);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) { owner = 0; continue; }
      have += (size_t)n;
      if (have == sizeof command) {
        have = 0;
        if (command[0] == 3) { owner = 0; continue; }
        if (command[0] != 1 && command[0] != 2) { error = EINVAL; break; }
        if (kill(command[0] == 1 ? child : -child, command[1]) < 0 && errno != ESRCH) {
          error = errno; break;
        }
      }
    }
  }
  /* A monitor/control error is terminal for this incarnation. */
  kill(-child, SIGKILL);
  kill(child, SIGKILL);
  while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
  if (remove_cgroup() < 0) error = errno;
  send_event(3, error);
  return 125;
}
