;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/cli/multicall tests
(import :std/test
        :std/cli/getopt
        ./multicall
        (only-in "./multicall-test-support" main)
        "./exit-test-support")
(export multicall-test)

;;; Test entry points. They are registered globally, hence the unique prefix.
;;; Each returns its arguments and (current-program), so dispatch is observable.

(define-entry-point (multicall-test-default)
  (help: "test: default entry point"
   getopt: [])
  (list 'default (current-program)))

(define-entry-point (multicall-test-search . args)
  (help: "test: rest arguments"
   getopt: [(rest-arguments 'args)])
  (list 'search args (current-program)))

(define-entry-point (multicall-test-greet (name #f))
  (help: "test: optional argument"
   getopt: [(optional-argument 'name)])
  (list 'greet name (current-program)))

(define-entry-point (multicall-test-browse (url #f) window: (window #f))
  (help: "test: option and optional argument"
   getopt: [(option 'window "-w" "--window")
            (optional-argument 'url)])
  (list 'browse url window (current-program)))

;; Each form of getopt: other than a list: none, a count, a getopt object.
(define-entry-point (multicall-test-raw . args)
  (help: "test: no getopt:, arguments passed through")
  (list 'raw args))

(define-entry-point (multicall-test-pair a b)
  (help: "test: two positional arguments"
   getopt: 2)
  (list 'pair a b))

(register-entry-point (lambda (x) (list 'object x))
                      id: 'multicall-test-object
                      help: "test: getopt object"
                      getopt: (getopt (argument 'x)))

;; Entry points and multicall settings are global: save and restore them.
(def (call-with-saved-multicall-settings thunk)
  (let ((saved-default multicall-default) (saved-fallback? multicall-fallback?))
    (unwind-protect
      (parameterize ((current-program ["prog"]))
        (thunk))
      (set-default-entry-point! saved-default fallback: saved-fallback?))))

(defrule (with-saved-multicall-settings body ...)
  (call-with-saved-multicall-settings (lambda () body ...)))

;; Does the raised object e say "Unknown command"? Accept a raised string or an error object.
(def (unknown-command-error? e)
  (let (msg (if (string? e) e (error-message e)))
    (and (string? msg) (string-contains msg "Unknown command") #t)))

(def multicall-test
  (test-suite "test :std/cli/multicall"
    ;; Regression: define-multicall-main must expand in v0.19 (core with-id syntax).
    ;; The macro is used in ./multicall-test-support; an expansion failure breaks the import.
    ;; main is not called: it exits.
    (test-case "define-multicall-main defines main"
      (check (procedure? main) => #t))

    (test-case "default entry point with no arguments"
      (with-saved-multicall-settings
       (set-default-entry-point! 'multicall-test-default)
       ;; The default name is pushed as a string, as if the user had typed it.
       (check (dispatch-entry-point)
              => (list 'default ["multicall-test-default" "prog"]))
       (check (current-program-string (cadr (dispatch-entry-point)))
              => "prog multicall-test-default")
       ;; With no arguments, the default is called with no arguments.
       (set-default-entry-point! 'multicall-test-search fallback: #t)
       (check (dispatch-entry-point)
              => (list 'search [] ["multicall-test-search" "prog"]))))

    (test-case "known command dispatch"
      (with-saved-multicall-settings
       (check-function dispatch-entry-point
         "multicall-test-greet" "world"
          => (list 'greet "world" ["multicall-test-greet" "prog"])
         "multicall-test-greet"
          => (list 'greet #f ["multicall-test-greet" "prog"])
         "multicall-test-search" "a" "b"
          => (list 'search ["a" "b"] ["multicall-test-search" "prog"])
         "multicall-test-browse" "-w" "3" "http://x"
          => (list 'browse "http://x" "3" ["multicall-test-browse" "prog"]))))

    (test-case "a default accepting an optional argument rejects an unknown command"
      (with-saved-multicall-settings
       (set-default-entry-point! 'multicall-test-greet)
       (check (dispatch-entry-point) => (list 'greet #f ["multicall-test-greet" "prog"]))
       (check (dispatch-entry-point "typo") =>! unknown-command-error?)))

    (test-case "unknown command goes to default with all arguments with fallback: #t"
      (with-saved-multicall-settings
       (set-default-entry-point! 'multicall-test-search fallback: #t)
       (check-function dispatch-entry-point
         "foo"
          => (list 'search ["foo"] ["multicall-test-search" "prog"])
         "foo" "bar" "baz"
          => (list 'search ["foo" "bar" "baz"] ["multicall-test-search" "prog"]))))

    (test-case "option in first position goes to default with fallback: #t"
      (with-saved-multicall-settings
       (set-default-entry-point! 'multicall-test-browse fallback: #t)
       (check-function dispatch-entry-point
         "-w" "3" "http://x"
          => (list 'browse "http://x" "3" ["multicall-test-browse" "prog"])
         "--window" "4"
          => (list 'browse #f "4" ["multicall-test-browse" "prog"])
         "http://y"
          => (list 'browse "http://y" #f ["multicall-test-browse" "prog"]))
       ;; The default's getopt spec rejects options it doesn't know: getopt error, not "unknown command".
       (check (dispatch-entry-point "--no-such-option") =>! getopt-error?)))

    (test-case "empty-string first argument"
      (with-saved-multicall-settings
       (set-default-entry-point! 'multicall-test-search fallback: #t)
       ;; "" names no entry point, so it goes to the default.
       ;; NB: getopt-parse skips empty strings while parsing options,
       ;; so the "" reaches the default but is dropped by its getopt spec.
       (check-function dispatch-entry-point
         ""
          => (list 'search [] ["multicall-test-search" "prog"])
         "" "x"
          => (list 'search ["x"] ["multicall-test-search" "prog"]))))

    (test-case "known command is not hijacked by default"
      (with-saved-multicall-settings
       (set-default-entry-point! 'multicall-test-search fallback: #t)
       (check-function dispatch-entry-point
         "multicall-test-greet" "a"
          => (list 'greet "a" ["multicall-test-greet" "prog"])
         "multicall-test-greet" "multicall-test-search"
          => (list 'greet "multicall-test-search" ["multicall-test-greet" "prog"]))
       ;; Bad arguments to a known command are that command's getopt error, not a default call.
       (check-function dispatch-entry-point
         "multicall-test-greet" "a" "b" =>! getopt-error?
         "multicall-test-greet" "-w" "3" =>! getopt-error?)))

    (test-case "default help ignores unrecognized command lines"
      (with-saved-multicall-settings
       (set-default-entry-point! 'help)
       (def (output . args)
         (with-output-to-string (lambda () (apply dispatch-entry-point args))))
       (let ((err (open-output-string)) (help (output "help")))
         (parameterize ((current-error-port err))
           (check (output) => help)
           (check (get-output-string err) => "")
           (check (output "typo" "extra") => help)
           (check (get-output-string err) => "prog: \"typo\" is not a recognized subcommand.\n")
           (check (output "-w" "3") => help)))))

    (test-case "help follows a nested command path without invoking the command"
      (register-entry-point (lambda args (error "unexpected invocation"))
        name: "multicall-test-tree"
        getopt: [(command 'group (command 'leaf help: "Leaf details"))])
      (unwind-protect
        (with-saved-multicall-settings
         (def (output . topics)
           (with-output-to-string (lambda () (apply dispatch-entry-point "help" topics))))
         (let (leaf (output "multicall-test-tree" "group" "leaf"))
           (check (string-contains leaf "prog multicall-test-tree group leaf: Leaf details") ? integer?)
           (let (unknown (output "multicall-test-tree" "group" "leaf" "extra"))
             (check (string-contains unknown "prog multicall-test-tree group leaf: Unknown command extra.\nprog multicall-test-tree group leaf: Leaf details") ? integer?))))
        (hash-remove! entry-points 'multicall-test-tree)))

    (test-case "help with a known topic, unknown topic raises"
      (with-saved-multicall-settings
       (check (string-contains
               (with-output-to-string
                 (lambda () (dispatch-entry-point "help" "multicall-test-greet")))
               "multicall-test-greet")
              ? fixnum?)
       (with-output-to-string
         (lambda ()
           (check (dispatch-entry-point "help" "multicall-test-no-such-command")
                  =>! unknown-command-error?)))))

    ;; Without getopt:, the function gets the arguments as given, options included.
    (test-case "entry point without getopt: gets its arguments unparsed"
      (with-saved-multicall-settings
       (check-function dispatch-entry-point
         "multicall-test-raw" => ['raw []]
         "multicall-test-raw" "a" "-b" "--" => ['raw ["a" "-b" "--"]]
         "multicall-test-raw" "-x" => ['raw ["-x"]])))

    (test-case "getopt: N gives N positional arguments"
      (with-saved-multicall-settings
       (check-function dispatch-entry-point
         "multicall-test-pair" "x" "y" => ['pair "x" "y"]
         "multicall-test-pair" "x" =>! getopt-error?)))

    (test-case "getopt: a getopt object"
      (with-saved-multicall-settings
       (check (dispatch-entry-point "multicall-test-object" "v") => ['object "v"])))

    ;; help builds a command from every entry point's getopt:, whatever its form.
    (test-case "help covers entry points with every form of getopt:"
      (with-saved-multicall-settings
       (def (help-output . args)
         (with-output-to-string (lambda () (apply dispatch-entry-point "help" args))))
       (let (out (help-output))
         (check-function (lambda (name) (and (string-contains out name) #t))
           "multicall-test-raw" => #t
           "multicall-test-pair" => #t
           "multicall-test-object" => #t))
       (check-function (lambda (name) (and (string-contains (help-output name) name) #t))
         "multicall-test-raw" => #t
         "multicall-test-pair" => #t
         "multicall-test-object" => #t)))

    (test-case "->getopt-spec"
      (check-function (lambda (spec) (map getopt-object? (->getopt-spec spec)))
        #f => [#t]
        0 => []
        2 => [#t #t]
        [(flag 'v "-v") [(argument 'x)]] => [#t #t]
        (getopt (flag 'v "-v") (argument 'x)) => [#t #t])
      (check (->getopt-spec 'bogus) =>! true)
      (check (->getopt-spec -1) =>! true)
      ;; positional ids are symbols, like those written by hand
      (check (getopt-parse->function-arguments
              (apply getopt (->getopt-spec 2))
              (getopt-parse (apply getopt (->getopt-spec 2)) ["a" "b"]))
             => ["a" "b"]))

    (test-case "unregistered default raises"
      (with-saved-multicall-settings
       (set-default-entry-point! 'multicall-test-no-such-default)
       (check-function dispatch-entry-point
         =>! true
         "foo" =>! true)))

    (test-case "current-program in the unknown-command case"
      (with-saved-multicall-settings
       (set-default-entry-point! 'multicall-test-search fallback: #t)
       ;; The default name is pushed as a string, exactly as if the user had typed it.
       (check (caddr (dispatch-entry-point "foo"))
              => ["multicall-test-search" "prog"])
       (check (dispatch-entry-point "multicall-test-search" "foo")
              => (dispatch-entry-point "foo"))
       (parameterize ((current-program ["sub" "prog"]))
         (check (caddr (dispatch-entry-point "foo"))
                => ["multicall-test-search" "sub" "prog"])
         (check (current-program-string (caddr (dispatch-entry-point "foo")))
                => "prog sub multicall-test-search"))))

    ;; print-exit (multicall's main ends in it) and exit-with-error have no test files
    ;; of their own. Gambit's exit only flushes its console ports: each exit path must
    ;; flush a parameterized file port before exiting.
    (test-case "print-exit flushes current-output-port before exiting"
      (def (print-exit-output . vs)
        (gxi-exit-output
         (lambda (file)
           ['(import :std/cli/print-exit)
            `(def port (open-output-file ,file))
            `(parameterize ((current-output-port port))
               (print-exit ,@vs))])))
      (check-function print-exit-output
        42 => (cons 0 "42")
        "x" => (cons 0 "\"x\"")
        #f => (cons 1 "#f")
        => (cons 1 "")))

    (test-case "exit-with-error flushes the current outputs before exiting"
      (def (exit-with-error-output param)
        (gxi-exit-output
         (lambda (file)
           ['(import :std/error)
            `(def port (open-output-file ,file))
            `(parameterize ((,param port))
               (display "partial" (current-output-port))
               (exit-with-error (with-catch (lambda (e) e) (lambda () (error "boom")))))])))
      ;; Output pending on current-output-port when the error happened.
      (check (exit-with-error-output 'current-output-port) => (cons 2 "partial"))
      ;; The error message on current-error-port.
      (let (result (exit-with-error-output 'current-error-port))
        (check (car result) => 2)
        (check (and (cdr result) (string-contains (cdr result) "boom")) ? fixnum?)))))
