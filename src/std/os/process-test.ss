;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        :std/io
        :std/format
        :std/sync/threads
        :std/time/time
        ./process
        ./signal
        ./error)
(export process-test)

(def (process-output (reader : Reader))
  => :string
  (utf8->string (read-all-from-reader reader)))

(def (process-gone? (pid : :fixnum))
  => :boolean
  (try (kill pid 0) #f
       (catch (e)
         (if (and (os-error? e) (fx= (OSError-errno e) ESRCH)) #t (raise e)))))

(def (await-process-gone (pid : :fixnum))
  => :void
  (let (deadline (+ (current-time-seconds) 5))
    (let loop ()
      (unless (process-gone? pid)
        (when (> (current-time-seconds) deadline)
          (error "process survived ownership loss" pid))
        (thread-sleep! .02)
        (loop)))))

(def process-test
  (test-suite "Owned native processes"
    (test-case "argv, environment, directory and separate output streams"
      (call-with-temporary-directory "native-process-"
        (lambda (directory)
          (using (child (start-process! "/bin/sh"
                          ["named-shell" "-c" "printf '%s\\n' \"$0\" \"$1\" \"$VALUE\"; pwd; printf error >&2"
                                         "named-shell" "a b λ"]
                          helper: "/no/such/gerbil-helper"
                          directory: directory environment: ["VALUE=explicit"])
                        : Process)
            (unwind-protect!
              (begin
                (check (process-output (child.stdout))
                       => (string-append "named-shell\na b λ\nexplicit\n" (path-strip-trailing-directory-separator directory) "\n"))
                (check (process-output (child.stderr)) => "error")
                (using (result (child.wait timeout: 5) : ProcessExit)
                  (check result.code => 0)
                  (check result.signal => #f)))
              (child.close))))))

    (test-case "stderr can share the stdout pipe"
      (for-each
        (lambda (monitored?)
          (using (child (start-process! "/bin/sh"
                          ["sh" "-c" "printf out; printf err >&2"]
                          stderr-to-stdout: #t gxexec: monitored?) : Process)
            (unwind-protect!
              (begin
                (check (child.stderr) => #f)
                (check (process-output (child.stdout)) => "outerr")
                (using (result (child.wait) : ProcessExit)
                  (check result.code => 0)))
              (child.close))))
        '(#f #t)))

    (test-case "stdin EOF is independent from output and exit observation"
      (using (child (start-process! "/bin/sh" ["sh" "-c" "exec cat"]) : Process)
        (unwind-protect!
          (using (input (child.stdin) : Writer)
            (input.write (string->utf8 "hello\n"))
            (input.close)
            (check (process-output (child.stdout)) => "hello\n")
            (using (result (child.wait timeout: 5) : ProcessExit)
              (check result.code => 0)))
          (child.close))))

    (test-case "inheriting closed stdin reports EBADF in both launch modes"
      ;; Close fd 0 only inside a disposable Gerbil process.
      (let ((runtime (path-expand "~~bin/gerbil"))
            (probe '(begin
                      (import :std/os/device :std/os/error :std/os/process)
                      (__close-fd 0)
                      (for-each
                       (lambda (monitored?)
                         (try
                          (using (child (start-process! "/bin/sh" ["sh" "-c" "exit 0"]
                                          stdin-redirection: #f gxexec: monitored?) : Process)
                            (child.close)
                            (exit 1))
                          (catch (os-error? e)
                            (unless (eqv? (OSError-errno e) EBADF) (raise e)))))
                       '(#f #t)))))
        (using (owner (start-process! runtime [runtime "-e" (format "%s" probe)]) : Process)
          (unwind-protect!
            (using (result (owner.wait timeout: 5) : ProcessExit)
              (check result.code => 0))
            (owner.close)))))

    (test-case "nonzero exit and startup failures stay distinct"
      (using (child (start-process! "/bin/sh" ["sh" "-c" "exit 17"]) : Process)
        (unwind-protect!
          (using (result (child.wait timeout: 5) : ProcessExit)
            (check result.code => 17)
            (check result.signal => #f))
          (child.close)))
      (check-exception (start-process! "/no/such/gerbil-executable" ["missing"]) os-error?)
      (check-exception (start-process! "/bin/sh" ["sh" "-c" "exit 0"] directory: "/no/such/gerbil-directory") os-error?)
      (check-exception (start-process! "/bin/sh" ["sh" "-c" "exit 0"] gxexec: #t helper: "/no/such/gerbil-helper") os-error?))

    (test-case "environment startup can exceed the control pipe capacity"
      (using (child (start-process! "/bin/sh"
                      ["sh" "-c" "test ${#PAYLOAD} -eq 50000"]
                      gxexec: #t environment: [(string-append "PAYLOAD=" (make-string 50000 #\x))])
                    : Process)
        (unwind-protect!
          (using (result (child.wait timeout: 5) : ProcessExit)
            (check result.code => 0))
          (child.close))))

    (cond-expand
      (linux
       (test-case "payload loader environment does not configure the monitor"
         (using (child (start-process! "/bin/sh" ["sh" "-c" "exit 0"]
                         gxexec: #t environment: ["LD_TRACE_LOADED_OBJECTS=1"])
                       : Process)
           (unwind-protect!
             (begin
               (check (string-empty? (process-output (child.stdout))) => #f)
               (using (result (child.wait timeout: 5) : ProcessExit)
                 (check result.code => 0)))
             (child.close)))))
      (else (void)))

    (test-case "cgroup setup failure never launches the payload"
      (call-with-temporary-directory "process-cgroup-"
        (lambda (directory)
          (let (marker (path-expand "started" directory))
            (check-exception
             (start-process! "/bin/sh" ["sh" "-c" "touch \"$1\"" "sh" marker]
                             gxexec: #t cgroup: directory)
             (cond-expand (linux os-error?) (else Error?)))
            (check (file-exists? marker) => #f)
            (check (directory-files directory) => [])))))

    (cond-expand
      (linux
       ;; Supply a writable delegated subtree to exercise the kernel backend.
       (when (getenv "GERBIL_TEST_CGROUP_ROOT" #f)
         (test-case "a new session stays in the execution cgroup until cleanup"
           (let (root (getenv "GERBIL_TEST_CGROUP_ROOT"))
             (using (child (start-process! "/bin/sh"
                             ["sh" "-c" "setsid sh -c 'cat /proc/self/cgroup; exec sleep 60' & wait"]
                             gxexec: #t cgroup: root grace: .05)
                           : Process)
               (unwind-protect!
                 (call-with-buffered-reader (child.stdout)
                   (lambda ((out : BufferedReader))
                     (let* ((leaf (path-strip-directory (out.read-line-utf8)))
                            (path (path-expand leaf root)))
                       (check (string-prefix? "gxexec-" leaf) => #t)
                       (check (file-exists? path) => #t)
                       (child.stop)
                       (child.wait timeout: 5)
                       (check (file-exists? path) => #f))))
                 (child.close)))))))
      (else (void)))

    (test-case "stopping a group removes its children without stopping another execution"
      (call-with-temporary-directory "process-group-"
        (lambda (directory)
          (let (marker (path-expand "survived" directory))
            (using ((child (start-process! "/bin/sh"
                             ["sh" "-c" "(sleep 1; touch \"$1\") & printf ready; wait" "sh" marker]
                             gxexec: #t grace: .05)
                           : Process)
                    (other (start-process! "/bin/sh" ["sh" "-c" "exec sleep 30"]) : Process))
              (unwind-protect!
                (using (output (child.stdout) : Reader)
                  (let (ready (make-u8vector 5)) (output.read ready 0 5 5))
                  (child.stop)
                  (child.wait timeout: 5)
                  (check (process-gone? (other.pid)) => #f)
                  (thread-sleep! 1.2)
                  (check (file-exists? marker) => #f))
                (child.close)
                (other.close)))))))

    (test-case "wait timeout does not stop the execution and signal reports exit"
      (using (child (start-process! "/bin/sh" ["sh" "-c" "exec sleep 30"]) : Process)
        (unwind-protect!
          (begin
            (check-exception (child.wait timeout: .01) Timeout?)
            (child.signal SIGTERM)
            (using (result (child.wait timeout: 5) : ProcessExit)
              (check result.signal => SIGTERM)))
          (child.close))))

    (test-case "stop escalates TERM to KILL and close is repeatable"
      (using (child (start-process! "/bin/sh"
                      ["sh" "-c" "trap '' TERM; printf ready; while :; do :; done"]
                      grace: .05)
                    : Process)
        (unwind-protect!
          (using (output (child.stdout) : Reader)
            (let (ready (make-u8vector 5))
              (output.read ready 0 5 5)
              (check (utf8->string ready) => "ready"))
            (child.stop)
            (using (result (child.wait timeout: 5) : ProcessExit)
              (check result.signal => SIGKILL)))
          (child.close))
        (child.close)))

    (test-case "a process handle survives cancellation of the launcher and stopper groups"
      (for-each
       (lambda (monitored?)
         (let* ((launcher (make-detached-thread-group 'launcher))
                (stopper (make-detached-thread-group 'stopper))
                (launch (spawn-thread
                         (lambda ()
                           (start-process! "/bin/sh"
                             ["sh" "-c" "trap '' TERM; printf ready; exec sleep 10"]
                             gxexec: monitored? grace: .1))
                         'launch launcher)))
           (using (child (thread-join!/error launch) : Process)
             (unwind-protect!
               (using (output (child.stdout) : Reader)
                 (let (ready (make-u8vector 5)) (output.read ready 0 5 5))
                 (thread-group-kill! launcher)
                 (thread-join!/error (spawn-thread (lambda () (child.stop)) 'stop stopper))
                 (thread-group-kill! stopper)
                 (child.close)
                 (using (result (child.wait timeout: 2) : ProcessExit)
                   (check result.signal => SIGKILL)))
               (child.close)))))
       '(#f #t)))

    (test-case "PTY has a controlling terminal, initial size, resize and hangup EOF"
      (def (check-pty monitored?)
        (using (child (start-process! "/bin/sh"
                        ["sh" "-c" "test -t 0 && test -t 1 && test -t 2 || exit 90; stty size </dev/tty; read x </dev/tty; stty size </dev/tty"]
                        gxexec: monitored? terminal: #t rows: 24 columns: 80)
                      : Process)
          (unwind-protect!
            (using ((output (child.stdout) : Reader)
                    (input (child.stdin) : Writer))
              (check (child.terminal?) => #t)
              (check (child.stderr) => #f)
              (let (size (make-u8vector 7))
                (output.read size 0 7 7)
                (check (utf8->string size) => "24 80\r\n"))
              (child.resize 40 100)
              (input.write (string->utf8 "next\n"))
              (check (process-output output) => "next\r\n40 100\r\n")
              (using (result (child.wait timeout: 5) : ProcessExit)
                (check result.code => 0)))
            (child.close))))
      (for-each check-pty '(#f #t)))

    (test-case "concurrent executions retain their own status and IO"
      (let (workers
            (map (lambda (index)
                   (spawn-thread
                    (lambda ()
                      (using (child (start-process! "/bin/sh"
                                      ["sh" "-c" "printf '%s' \"$1\"" "sh" (number->string index)])
                                    : Process)
                        (unwind-protect!
                          (begin
                            (check (process-output (child.stdout)) => (number->string index))
                            (using (result (child.wait timeout: 5) : ProcessExit)
                              (check result.code => 0)))
                          (child.close))))))
                 '(0 1 2 3 4 5 6 7)))
        (for-each thread-join!/error workers)))

    (test-case "killing the owner or its process group preserves the cleanup monitor"
      (for-each
       (lambda (group?)
         (let ((code '(begin
                        (import :std/os/process)
                        (using (child (start-process! "/bin/sh" ["sh" "-c" "exec sleep 30"] gxexec: #t grace: .05
                                        cgroup: (getenv "GERBIL_TEST_CGROUP_ROOT" #f))
                                      : Process)
                          (displayln (child.pid))
                          (force-output)
                          (thread-sleep! 30))))
               (runtime (path-expand "~~bin/gerbil")))
           (using (owner (start-process! runtime [runtime "-e" (format "%s" code)] gxexec: #t grace: .05) : Process)
             (unwind-protect!
               (call-with-buffered-reader (owner.stdout)
                 (lambda ((output : BufferedReader))
                  (let ((pid (string->number (output.read-line-utf8)))
                       (cleaned? #f))
                   (unwind-protect!
                     (begin
                       (owner.signal SIGKILL group: group?)
                       (owner.wait timeout: 5)
                       (await-process-gone pid)
                       (set! cleaned? #t))
                     (unless cleaned? (ignore-errors (kill (- pid) SIGKILL)))))))
               (owner.close)))))
       [#f #t]))))
