;;; -*- Gerbil -*-
;;; Subprocess isolation and bounded parallel test execution
(import :std/test
        :std/io/tempfile
        :std/list/list
        :std/misc/ports
        :std/misc/process
        :std/source
        :std/text/pregexp)
(export gxtest-test)

(def tool-source (path-expand "gxtest.ss" (this-source-directory)))

(def (write-fixture (directory : :string) (name : :string) (forms : :list))
  => :string
  (let (path (path-expand name directory))
    (call-with-output-file path
      (lambda (port)
        (for-each (lambda (form) (write form port) (newline port)) forms)))
    path))

(def (run-cli (directory : :string) (args : :list)
              (collect : :procedure := read-all-as-string))
  (def status #f)
  (def output
    (invoke (path-expand "~~bin/gxi")
            ["-e" (object->string `(import ,tool-source))
             "-e" (object->string `(main ,@args))]
            directory: directory coprocess: collect
            stdout-redirection: #t stderr-redirection: #t
            check-status: (lambda (value _) (set! status value))))
  (values status output))

(def (passing-fixture (directory : :string) (name : :string))
  => :string
  (write-fixture directory name
    '((import :std/test :std/os/pid)
      (export fixture-test)
      (def fixture-test
        (test-suite "fixture"
          (test-case "fresh process"
            (check (getenv "GERBIL_GXTEST_ISOLATION_PROBE" #f) => #f)
            (setenv "GERBIL_GXTEST_ISOLATION_PROBE" "changed")
            (write-file-string (string-append (number->string (getpid)) ".pid") "ran")))))))

(def gxtest-test
  (test-suite "gxtest subprocess execution"
    (test-case "isolation gives each module a fresh process and preserves its directory"
      (call-with-temporary-directory "gxtest-isolation-"
        (lambda (directory)
          (passing-fixture directory "one-test.ss")
          (passing-fixture directory "two-test.ss")
          (let-values (((status output) (run-cli directory ["--isolate" "-v" "5"])))
            (check status => 0)
            (check (length (filter (cut string-suffix? ".pid" <>)
                                  (directory-files directory))) => 2)
            (check (and (pregexp-match "CASE-OK fresh process" output) #t) => #t)))))

    (test-case "suite filters and feature flags reach isolated children"
      (call-with-temporary-directory "gxtest-options-"
        (lambda (directory)
          (write-fixture directory "options-test.ss"
            '((import :std/test)
              (export selected-test excluded-test)
              (cond-expand
                (gxtest-isolation-feature (def enabled #t))
                (else (def enabled #f)))
              (def selected-test
                (test-suite "selected"
                  (test-case "feature forwarded" (check enabled => #t))))
              (def excluded-test
                (test-suite "excluded"
                  (test-case "must not run" (error "filter was lost"))))))
          (let-values (((status output)
                        (run-cli directory ["--parallel" "2" "-D" "gxtest-isolation-feature"
                                            "-r" "^selected-test$" "-v" "5" "."])))
            (check status => 0)
            (check (and (pregexp-match "CASE-OK feature forwarded" output) #t) => #t)
            (check (pregexp-match "CASE must not run" output) => #f)))))

    (test-case "failed and abruptly exiting children do not skip later modules"
      (call-with-temporary-directory "gxtest-failure-"
        (lambda (directory)
          (write-fixture directory "a-fail-test.ss"
            '((import :std/test)
              (export fail-test)
              (def fail-test
                (test-suite "failure" (test-case "failed check" (check 1 => 2))))))
          (write-fixture directory "b-exit-test.ss"
            '((import :std/test)
              (export exit-test)
              (def exit-test
                (test-suite "exit" (test-case "abrupt exit" (exit 17))))))
          (write-fixture directory "c-kill-test.ss"
            '((import :std/test :std/os/pid :std/os/signal)
              (export kill-test)
              (def kill-test
                (test-suite "kill" (test-case "signal termination" (kill (getpid) SIGKILL))))))
          (write-fixture directory "d-import-test.ss"
            '((error "module import failed")))
          (passing-fixture directory "z-pass-test.ss")
          (for-each
            (lambda (options)
              (let-values (((status output) (run-cli directory [options ... "-v" "0" "."])))
                (check status => (* 42 256))
                (check (and (pregexp-match "ERROR MODULE .*a-fail-test.ss" output) #t) => #t)
                (check (and (pregexp-match "ERROR MODULE .*b-exit-test.ss" output) #t) => #t)
                (check (and (pregexp-match "ERROR MODULE .*c-kill-test.ss" output) #t) => #t)
                (check (and (pregexp-match "ERROR MODULE .*d-import-test.ss" output) #t) => #t)
                (let (summary (member "FAILED MODULES (4):"
                                     (call-with-input-string output read-all-as-lines)))
                  (check (and summary (length summary)) => 5)
                  (when summary
                    (check (list-sort string<?
                             (map (lambda (line) (car (string-split line #\:))) (cdr summary)))
                           => ["  ./a-fail-test.ss" "  ./b-exit-test.ss"
                               "  ./c-kill-test.ss" "  ./d-import-test.ss"])))))
            '(("--isolate") ("--parallel" "2")))
          (check (length (filter (cut string-suffix? ".pid" <>)
                                (directory-files directory))) => 2))))

    (test-case "isolated modules clean up helpers holding their output open"
      (call-with-temporary-directory "gxtest-helper-"
        (lambda (directory)
          (write-fixture directory "helper-test.ss"
            '((import :std/test)
              (export helper-test)
              (def helper-test
                (test-suite "helper"
                  (test-case "launch background writer"
                    (open-process
                     [path: "/bin/sh"
                      arguments: ["-c" "sleep 3; echo leaked-helper-output"]
                      stdout-redirection: #f stderr-redirection: #f]))))))
          (let-values (((status output) (run-cli directory ["--isolate" "-v" "0" "."])))
            (check status => 0)
            (check (pregexp-match "leaked-helper-output" output) => #f)))))

    (test-case "an unusable cgroup fails the module before it starts"
      (call-with-temporary-directory "gxtest-cgroup-"
        (lambda (directory)
          (passing-fixture directory "never-test.ss")
          (let-values (((status output) (run-cli directory ["--cgroup" directory "."])))
            (check status => (* 42 256))
            (check (and (pregexp-match "ERROR MODULE .*never-test.ss" output) #t) => #t)
            (check (filter (cut string-suffix? ".pid" <>) (directory-files directory)) => [])))))

    (when (getenv "GERBIL_TEST_CGROUP_ROOT" #f)
      (test-case "a helper in a new session is cleaned up by the module cgroup"
        (call-with-temporary-directory "gxtest-session-"
          (lambda (directory)
            (def root (getenv "GERBIL_TEST_CGROUP_ROOT"))
            (write-fixture directory "session-test.ss"
              '((import :std/test)
                (export session-test)
                (def session-test
                  (test-suite "session"
                    (test-case "start a new session"
                      (check (process-status
                              (open-process
                               [path: "/bin/sh"
                                arguments:
                                ["-c" "exec setsid -w sh -c 'cat /proc/self/cgroup > scope || exit 1; (sleep 3; echo escaped-helper-output) &'"]
                                stdout-redirection: #f stderr-redirection: #f]))
                             => 0))))))
            (let-values (((status output) (run-cli directory ["--cgroup" root "."])))
              (check status => 0)
              (check (pregexp-match "escaped-helper-output" output) => #f)
              (let (leaf (path-strip-directory
                          (call-with-input-file (path-expand "scope" directory) read-line)))
                (check (string-prefix? "gxexec-" leaf) => #t)
                (check (file-exists? (path-expand leaf root)) => #f)))))))

    (test-case "a partial UTF-8 sequence preserves the child's exit status and output"
      (call-with-temporary-directory "gxtest-bytes-"
        (lambda (directory)
          (def (run ending)
            (write-fixture directory "bytes-test.ss"
              `((import :std/test :std/os/pid :std/os/signal)
                (export bytes-test)
                (def bytes-test
                  (test-suite "bytes"
                    (test-case "partial output"
                      (write-u8 #xc3)
                      (force-output)
                      ,ending)))))
            (run-cli directory ["--isolate" "-v" "0" "bytes-test.ss"] read-all-as-u8vector))
          (def line (u8vector-append (string->utf8 "[bytes-test.ss] ") #u8(#xc3 10)))
          (let-values (((status output) (run '(exit 0))))
            (check status => 0)
            (check output => line))
          (let-values (((status output) (run '(kill (getpid) SIGKILL))))
            (def summary
              (string-append "ERROR MODULE bytes-test.ss signal 9\n"
                             "FAILED MODULES (1):\n"
                             "  bytes-test.ss: signal 9\n"))
            (check status => (* 42 256))
            (check output => (u8vector-append line (string->utf8 summary)))))))

    (test-case "parallel output preserves prefixed stdout and stderr lines and final fragments"
      (call-with-temporary-directory "gxtest-output-"
        (lambda (directory)
          (def payload (make-string 8192 #\x))
          (for-each
            (lambda (name)
              (write-fixture directory (string-append name "-test.ss")
                `((import :std/test)
                  (export fixture-test)
                  (def fixture-test
                    (test-suite "output"
                      (test-case "fragmented writes"
                        (for-each
                          (lambda (port)
                            (for-each
                              (lambda (index)
                                (display ,name port)
                                (display index port)
                                (display ,payload port)
                                (force-output port)
                                (thread-sleep! .01)
                                (display ":end" port)
                                (newline port)
                                (force-output port))
                              '(0 1 2 3)))
                          (list (current-output-port) (current-error-port)))
                        (display ,(string-append name ":tail"))
                        (force-output)
                        (exit 0)))))))
            '("a" "b"))
          (let-values (((status output)
                        (run-cli directory ["--parallel" "2" "-v" "0" "a-test.ss" "b-test.ss"])))
            (check status => 0)
            (def expected
              (append-map
               (lambda (name)
                 (def prefix (string-append "[" name "-test.ss] " name))
                 (cons (string-append prefix ":tail")
                       (append-map
                        (lambda (index)
                          (def line (string-append prefix (number->string index) payload ":end"))
                          [line line])
                        '(0 1 2 3))))
               '("a" "b")))
            (check (list-sort string<? (call-with-input-string output read-all-as-lines))
                   => (list-sort string<? expected))))))

    (test-case "parallel execution overlaps modules and respects its process limit"
      (call-with-temporary-directory "gxtest-parallel-"
        (lambda (directory)
          (for-each
            (lambda (name)
              (write-fixture directory (string-append name "-test.ss")
                `((import :std/test)
                  (export fixture-test)
                  (def fixture-test
                    (test-suite "parallel"
                      (test-case "overlap"
                        (write-file-string ,(string-append name ".start")
                                           (number->string (time->seconds (current-time))))
                        (let loop ((remaining 1000))
                          (unless (>= (length (filter (cut string-suffix? ".start" <>)
                                                      (directory-files "."))) 2)
                            (when (zero? remaining) (error "second process never started"))
                            (thread-sleep! .01)
                            (loop (1- remaining))))
                        (thread-sleep! .2)
                        (write-file-string ,(string-append name ".end")
                                           (number->string (time->seconds (current-time))))))))))
            '("a" "b" "c" "d"))
          (let-values (((status _) (run-cli directory ["--parallel" "2" "-v" "0" "."])))
            (check status => 0))
          (let* ((events
                  (append-map
                   (lambda (name)
                     [(cons (string->number (read-file-string
                                             (path-expand (string-append name ".start") directory))) 1)
                      (cons (string->number (read-file-string
                                             (path-expand (string-append name ".end") directory))) -1)])
                   '("a" "b" "c" "d")))
                 (ordered (list-sort (lambda (a b) (< (car a) (car b))) events)))
            (let loop ((rest ordered) (active 0) (peak 0))
              (if (null? rest)
                (begin (check active => 0) (check peak => 2))
                (let (active (+ active (cdar rest)))
                  (loop (cdr rest) active (max peak active)))))))))

    (test-case "parallelism must be a positive integer"
      (call-with-temporary-directory "gxtest-invalid-"
        (lambda (directory)
          (for-each
            (lambda (value)
              (let-values (((status _) (run-cli directory ["--parallel" value])))
                (check (zero? status) => #f)))
            '("0" "-1" "1.5" "nope")))))))
