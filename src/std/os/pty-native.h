/* Copyright Gerbil contributors. Shared POSIX terminal primitives. */
#ifndef GERBIL_PTY_NATIVE_H
#define GERBIL_PTY_NATIVE_H
#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#if defined(__APPLE__)
#include <util.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <libutil.h>
#elif defined(__OpenBSD__) || defined(__NetBSD__)
#include <util.h>
#else
#include <pty.h>
#endif
struct pty_fds { int master, slave; };
struct terminal_state { struct termios attributes; };
static int gerbil_open_pty(struct pty_fds *p, int rows, int columns) {
  struct winsize size = {0};
  size.ws_row = rows; size.ws_col = columns;
  p->master = p->slave = -1;
  if (openpty(&p->master, &p->slave, NULL, NULL, &size) < 0) return -errno;
  if (fcntl(p->master, F_SETFD, FD_CLOEXEC) < 0 ||
      fcntl(p->slave, F_SETFD, FD_CLOEXEC) < 0) {
    int error = errno;
    close(p->master); close(p->slave); p->master = p->slave = -1;
    return -error;
  }
  return 0;
}
static int gerbil_terminal_size(int fd, struct winsize *size) {
  return ioctl(fd, TIOCGWINSZ, size) < 0 ? -errno : 0;
}
static int gerbil_terminal_resize(int fd, int rows, int columns) {
  struct winsize size = {0};
  size.ws_row = rows; size.ws_col = columns;
  return ioctl(fd, TIOCSWINSZ, &size) < 0 ? -errno : 0;
}
#endif
