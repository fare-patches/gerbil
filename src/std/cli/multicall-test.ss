;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/cli/multicall tests
(import :std/test
        :std/cli/getopt
        ./multicall
        (only-in "./multicall-test-support" main)
        "./exit-test-support")
(export multicall-test)

(def (install-test-entries!)
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
                        getopt: (getopt (argument 'x))))

;; Entry points and multicall settings are global: save and restore them.
(def (call-with-saved-multicall-settings thunk)
  (let ((saved-entries (hash->list entry-points))
        (saved-default multicall-default) (saved-fallback? multicall-fallback?))
    (unwind-protect
      (parameterize ((current-program ["prog"]))
        (install-test-entries!)
        (thunk))
      (begin
        (hash-clear! entry-points)
        (for-each (lambda (binding) (hash-put! entry-points (car binding) (cdr binding)))
                  saved-entries)
        (set-default-entry-point! saved-default fallback: saved-fallback?)))))

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

    (test-case "define-multicall-main shorthand configures dispatch"
      (def (run previous definition . args)
        (gxi-exit-output
         (lambda (file)
           ['(import :std/cli/multicall)
            `(register-entry-point (lambda args (call-with-output-file ,file
                                                  (lambda (port) (write args port))))
                                   name: "keys")
            `(set-default-entry-point! ',previous fallback: #t)
            definition
            `(main ,@args)])))
      (check-function run
        'old '(define-multicall-main default: 'keys) => (cons 0 "()")
        'old '(define-multicall-main default: 'keys) "typo" => (cons 2 #f)
        'old '(define-multicall-main default: 'keys fallback: #t) "a" "-b"
        => (cons 0 "(\"a\" \"-b\")")
        'old '(define-multicall-main here default: 'keys fallback: #t) "x"
        => (cons 0 "(\"x\")")
        'keys '(define-multicall-main) "x" => (cons 0 "(\"x\")")))

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

    (test-case "dispatch and help follow a registered parser tree"
      (with-saved-multicall-settings
       (def tree (getopt (command 'group
                           (command 'leaf (option 'count "-n" parse: string->number)
                                          (argument 'x)))))
       (register-entry-point
        (lambda (path opts) (list path (hash-ref opts 'x) (hash-ref opts 'count)))
        name: "tree" getopt: tree)
       (check (dispatch-entry-point "tree" "group" "leaf" "-n3" "value")
              => '((group leaf) "value" 3))
       (check (string-contains (with-output-to-string (lambda () (help "version")))
                               "Usage: prog version") ? integer?)
       (let (direct (with-output-to-string (lambda () (help "tree" "group" "leaf"))))
         (check (string-contains direct "Usage: prog tree group leaf") ? integer?)
         (check (with-output-to-string
                  (lambda () (dispatch-entry-point "help" "tree" "group" "leaf")))
                => direct))))

    (test-case "direct help reports unknown topics from the current program"
      (with-saved-multicall-settings
       (let (err (open-output-string))
         (parameterize ((current-error-port err))
           (check (call/values (lambda () (help "missing")) list) => []))
         (check (get-output-string err) => "prog: Unknown command missing.\n"))))

    (test-case "main reports unknown help topics on stderr at every depth"
      (def (run topics stream)
        (gxi-exit-output
         (lambda (file)
           ['(import :std/cli/multicall)
            '(define-multicall-main)
            '(register-entry-point void name: "-fast" getopt: [])
            `(parameterize ((current-program '("demo"))
                            (,stream (open-output-file ,file)))
               (main "help" ,@topics))])))
      (check-function run
        '("") 'current-output-port => (cons 1 "")
        '("") 'current-error-port => (cons 1 "demo: Unknown command .\n")
        '("-fast") 'current-error-port => (cons 0 "")
        '("bad") 'current-output-port => (cons 1 "")
        '("bad") 'current-error-port => (cons 1 "demo: Unknown command bad.\n")
        '("version" "bad") 'current-output-port => (cons 1 "")
        '("version" "bad") 'current-error-port => (cons 1 "demo version: Unknown command bad.\n"))
      (let (result (run '("-fast") 'current-output-port))
        (check (car result) => 0)
        (check (and (string-contains (cdr result) "Usage: demo -fast") #t) => #t)))

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
                => "prog sub multicall-test-search"))))))
