;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test ./print-exit "./exit-test-support")
(export print-exit-test)

(def print-exit-test
  (test-suite "test :std/cli/print-exit"
    (test-case "silent-exit returns one void value or zero values"
      (check-function (lambda args (call/values (lambda () (apply silent-exit args)) list))
        => [(void)]
        #t => [(void)]
        #f => []))

    (test-case "print-values calls the selected printer once per value"
      (check (with-output-to-string
               (lambda ()
                 (parameterize ((value-printer (lambda (v) (display v) (newline))))
                   (print-values)
                   (print-values (void))
                   (print-values "a" #f))))
             => "a\n#f\n"))

    (test-case "print-exit flushes current-output-port before exiting"
      (def (print-exit-output . vs)
        (gxi-exit-output
         (lambda (file)
           ['(import :std/cli/print-exit)
            `(def port (open-output-file ,file))
            `(parameterize ((current-output-port port))
               (print-exit ,@vs))])))
      (check-function print-exit-output
        ;; Quote the form so the child evaluates (void) before calling print-exit.
        '(void) => (cons 0 "")
        #f 42 => (cons 0 "#f42")
        42 => (cons 0 "42")
        "x" => (cons 0 "\"x\"")
        #f => (cons 1 "#f")
        => (cons 1 "")))

    (test-case "an exception in begin-print-exit flushes the current outputs"
      (def (exit-with-error-output param)
        (gxi-exit-output
         (lambda (file)
           ['(import :std/cli/print-exit)
            `(def port (open-output-file ,file))
            `(parameterize ((,param port))
               (begin-print-exit
                 (display "partial" (current-output-port))
                 (error "boom")))])))
      ;; Output pending on current-output-port when the error happened.
      (check (exit-with-error-output 'current-output-port) => (cons 2 "partial"))
      ;; The error message on current-error-port.
      (let (result (exit-with-error-output 'current-error-port))
        (check (car result) => 2)
        (check (and (cdr result) (string-contains (cdr result) "boom") #t) => #t)))))
