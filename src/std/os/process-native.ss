;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Internal native process launch boundary
(import :std/ffi
        ./error
        ./device
        ./file)
(export #t)

(C-ffi-macrology)
(C-include-file "pty-native.h")
(C-include-file "process-native.h")
(def-C-struct process_fds)

(def (native-spawn-monitor! (fds    : process_fds)
                            (helper : :string)
                            (argv   : :list))
  => :void
  (let (result (ffi-spawn-monitor (raw-c-struct-body fds) helper argv))
    (when (fxnegative? result)
      (raise-os-error start-process! result helper: helper)))
  (void))

(def fork-process-device-function (##os-device-process-fork-function))

;; The device records the exit status independently of the three IO streams.
(def (native-raw-spawn! (fds         : process_fds)
                        (path        : :string)
                        (argv        : :list)
                        (environment : :list)
                        (directory   : :string)
                        (terminal?   : :boolean))
  => :foreign
  (let (dev (ffi-raw-spawn fork-process-device-function (raw-c-struct-body fds)
                           path argv environment directory terminal?))
    (when (fixnum? dev)
      (raise-os-error start-process! dev path: path))
    (: dev :foreign)))

;; Transfer each descriptor once; a failed device wrapper still closes its fd.
(def (native-process-take-device! (fds       : process_fds)
                                  (index     : :fixnum)
                                  (direction : :fixnum))
  => (Maybe FileDevice)
  (let (fd (native-process-take-fd! fds index))
    (and (fx>= fd 0)
         (FileDevice
          (with-error (__close-fd fd)
            (__open-raw-device 'process fd direction))
          fd direction "process"))))

(def (native-process-discard! (fds : process_fds))
  => :void
  (native-process-close-child-fds! fds)
  (let loop ((index 0))
    (when (fx< index 5)
      (let (fd (native-process-take-fd! fds index))
        (when (fx>= fd 0) (__close-fd fd)))
      (loop (fx1+ index)))))

(def-C (native-process-take-fd! (fds :- process_fds) (index :- :fixnum))
  => :fixnum
  "({ int fd = ___arg1->fd[___arg2]; ___arg1->fd[___arg2] = -1; fd; })")

(def-C (native-process-prepare! (fds       :- process_fds)
                                (monitored :- :fixnum)
                                (terminal  :- :fixnum)
                                (merged    :- :fixnum)
                                (pipe-in   :- :fixnum)
                                (rows      :- :fixnum)
                                (columns   :- :fixnum))
  => :fixnum
  "gerbil_prepare_process(___arg1, ___arg2, ___arg3, ___arg4, ___arg5, ___arg6, ___arg7)")

(def-C (native-process-close-child-fds! (fds :- process_fds))
  => :void
  "gerbil_close_child_fds(___arg1)")

(def-C (native-process-exit-value (status :- :fixnum))
  => :fixnum
  "WIFEXITED(___arg1) ? WEXITSTATUS(___arg1) : -WTERMSIG(___arg1)")

(def-C-lambda (ffi-raw-spawn (fork      : scheme-object)
                             (fds       : scheme-object)
                             (path      : nonnull-UTF-8-string)
                             (argv      : nonnull-UTF-8-string-list)
                             (env       : nonnull-UTF-8-string-list)
                             (directory : nonnull-UTF-8-string)
                             (terminal  : bool))
  => scheme-object
  "___result = gerbil_raw_spawn((gerbil_process_fork_fn)___FOREIGN_PTR_FIELD(___arg1),
                                ___U8VECTOR_AS(struct process_fds*, ___arg2),
                                ___arg3, ___arg4, ___arg5, ___arg6, ___arg7);")

(def-C-lambda (ffi-spawn-monitor (fds    : scheme-object)
                                (helper : nonnull-UTF-8-string)
                                (argv   : nonnull-UTF-8-string-list))
  => int
  "___result = gerbil_spawn_monitor(___U8VECTOR_AS(struct process_fds*, ___arg1), ___arg2, ___arg3);")
