;; -*- Gerbil -*-
;;; © fare@tunes.org
;;;; Testing the runtime utilities

(export util-test)

(import
  :gerbil/runtime
  :std/text/parser/char-set
  :std/io/tempfile
  (only-in :std/test test-suite test-case check check-exception check-function)
  "../../std/cli/exit-test-support")

(def (slash? c)
  (eqv? c #\/))

(def (not-slash? c)
  (not (slash? c)))

(def (vowel? c)
  (memv c '(#\a #\e #\i #\o #\u)))

(def util-test
  (test-suite "test :gerbil/runtime/util"
    (test-case "string-index"
      (check-function string-index
        "abcde" #\c => 2
        "chronos" vowel? => 3
        "chronos" vowel? 4 => 5
        "chronos" vowel? 4 6 => 5
        "chronos" vowel? 4 5 => #f
        "chronos" vowel? 4 4 => #f
        ;; border conditions
        "chronos" vowel? 10 3 => #f
        "chronos" vowel? 0 -1 => #f
        "chronos" vowel? 4 8 =>! true
        "chronos" vowel? 8 8 =>! true
        "chronos" vowel? -1 =>! true))
    (test-case "string-rindex"
      (check-function string-rindex
        "abcde" #\c => 2
        "chronos" vowel? => 5
        "chronos" vowel? 6 => 5
        "chronos" vowel? 5 => 5
        "chronos" vowel? 4 => 3
        "chronos" vowel? 3 => 3
        "chronos" vowel? 2 => #f
        "chronos" vowel? 6 6 => #f
        "chronos" vowel? 6 5 => 5
        "chronos" vowel? 6 5 => 5
        "chronos" vowel? 4 4 => #f
        "chronos" vowel? 4 3 => 3
        "chronos" vowel? 4 2 => 3
        ;; border conditions
        "chronos" vowel? 7 =>! true
        "chronos" vowel? 7 4 =>! true
        "chronos" vowel? 0 -1 =>! true
        "chronos" vowel? 0 8 => #f
        "chronos" vowel? -1 => #f))

    ;; Escaping from with-output-to-file doesn't flush its port.
    (test-case "force-current-outputs on escape"
      (call-with-temporary-file-name
       "util-test"
       (lambda (name)
         (check (file-exists? name) => #f)
         (let/cc return
           (with-output-to-file name (lambda () (display "aa") (return))))
         (check (read-file-string name) => "")
         (let/cc return
           (with-output-to-file name (lambda () (display "aa") (force-current-outputs) (return))))
         (check (read-file-string name) => "aa"))))
    ;; force-current-outputs is in the runtime: the child gxi imports nothing.
    ;; Gambit's exit does not unwind and only flushes its console ports,
    ;; so a parameterized file port loses its output unless flushed before exit.
    (test-case "force-current-outputs before exit, without import"
      (def (flushed-before-exit param)
        (gxi-exit-output
         (lambda (file)
           [`(def port (open-output-file ,file))
            `(parameterize ((,param port))
               (display "text" (,param))
               (force-current-outputs)
               (exit 3))])))
      (check-function flushed-before-exit
        'current-output-port => (cons 3 "text")
        'current-error-port => (cons 3 "text")))
    ;; A failing flush of current-output-port is ignored, and current-error-port is
    ;; still flushed. Gambit does not fail to flush a closed port, so the failing port
    ;; writes to /dev/full (ENOSPC).
    (test-case "force-current-outputs ignores a failing flush"
      ;; TODO: a portable failing port, for systems without /dev/full.
      (when (file-exists? "/dev/full")
        (check (gxi-exit-output
                (lambda (file)
                  [`(def full (open-output-file "/dev/full"))
                   `(def port (open-output-file ,file))
                   `(parameterize ((current-output-port full)
                                   (current-error-port port))
                      (display "lost")
                      (display "text" port)
                      (force-current-outputs)
                      (exit 3))]))
               => (cons 3 "text"))))))
