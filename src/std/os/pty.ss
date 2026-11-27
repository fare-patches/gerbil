;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; POSIX pseudoterminals and terminal settings
(import :std/error
        :std/ffi
        ./error
        ./device
        ./file
        ./fcntl)
(export open-pty
        terminal-size
        terminal-resize!
        call-with-terminal-raw-mode)

(C-ffi-macrology)
(C-include-file "pty-native.h")
(def-C-struct pty_fds)
(def-C-struct terminal_state)
(def-C-struct winsize)

(defrule (terminal-dimension? x)
  (and (fixnum? x) (fx<= 0 x 65535)))

;; Both devices belong to the caller. Only the master is nonblocking; the slave
;; remains suitable for duplication onto a child's standard descriptors.
(def (open-pty rows: (rows :~ terminal-dimension? :- :fixnum := 24)
               columns: (columns :~ terminal-dimension? :- :fixnum := 80))
  => :values
  (let ((fds (make-pty_fds)) (master #f) (slave #f) (owned? #f))
    (do-syscall (__open-pty-fds fds rows columns))
    (unwind-protect!
      (begin
        (fcntl-setfl! (__pty-master fds) O_NONBLOCK)
        (set! master (FileDevice (__open-raw-device 'pty (__pty-master fds) DIRECTION-INOUT)
                                 (__pty-master fds) DIRECTION-INOUT "pty-master"))
        (set! slave (FileDevice (__open-raw-device 'pty (__pty-slave fds) DIRECTION-INOUT)
                                (__pty-slave fds) DIRECTION-INOUT "pty-slave"))
        (set! owned? #t)
        (values master slave))
      (unless owned?
        (if master (device-close master) (__close-fd (__pty-master fds)))
        (if slave (device-close slave) (__close-fd (__pty-slave fds)))))))

(def (terminal-size (fd : :fixnum))
  => :values
  (let (size (make-winsize))
    (do-syscall (__terminal-size-syscall fd size))
    (values (__terminal-rows size) (__terminal-columns size))))

(def (terminal-resize! (fd      : :fixnum)
                       (rows    :~ terminal-dimension? :- :fixnum)
                       (columns :~ terminal-dimension? :- :fixnum))
  => :void
  (do-syscall (__terminal-resize fd rows columns))
  (void))

;; A public callback can escape through a continuation: use dynamic-wind cleanup.
(def (call-with-terminal-raw-mode (fd   : :fixnum)
                                  (proc : :procedure))
  => :t
  (let (saved (make-terminal_state))
    (do-syscall (__terminal-save fd saved))
    (dynamic-wind
      (lambda () (do-syscall (__terminal-raw fd saved)))
      proc
      (lambda () (do-syscall (__terminal-restore fd saved))))))

(def-C (__open-pty-fds (fds :- pty_fds) (rows :- :fixnum) (columns :- :fixnum))
  => :fixnum
  "gerbil_open_pty(___arg1, ___arg2, ___arg3)")
(def-C (__pty-master (fds :- pty_fds)) => :fixnum "___arg1->master")
(def-C (__pty-slave (fds :- pty_fds)) => :fixnum "___arg1->slave")
(def-C (__terminal-size-syscall (fd :- :fixnum) (size :- winsize))
  => :fixnum
  "gerbil_terminal_size(___arg1, ___arg2)")
(def-C (__terminal-rows (size :- winsize)) => :fixnum "___arg1->ws_row")
(def-C (__terminal-columns (size :- winsize)) => :fixnum "___arg1->ws_col")
(def-C (__terminal-resize (fd :- :fixnum) (rows :- :fixnum) (columns :- :fixnum))
  => :fixnum
  "gerbil_terminal_resize(___arg1, ___arg2, ___arg3)")
(def-C (__terminal-save (fd :- :fixnum) (saved :- terminal_state))
  => :fixnum
  "tcgetattr(___arg1, &___arg2->attributes) < 0 ? -errno : 0")
(def-C (__terminal-restore (fd :- :fixnum) (saved :- terminal_state))
  => :fixnum
  "tcsetattr(___arg1, TCSANOW, &___arg2->attributes) < 0 ? -errno : 0")
(def-C (__terminal-raw (fd :- :fixnum) (saved :- terminal_state))
  => :fixnum
  "({ struct termios raw = ___arg2->attributes;
      cfmakeraw(&raw);
      tcsetattr(___arg1, TCSANOW, &raw) < 0 ? -errno : 0; })")
