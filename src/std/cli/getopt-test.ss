;;; :std/cli/getopt tests
(import :std/test
        (only-in :std/error contract-violation-error?)
        ./getopt)
(export getopt-test nested-getopt-test)

(def inspect-cmd
  (command 'inspect help: "inspect a server"
    (flag 'verbose "-v")
    (command 'services help: "list running services"
      (option 'count "-n" value: string->number default: 1)
      (argument 'server)
      (rest-arguments 'names))))

(def client-cmd
  (command 'client help: "client operations" (option 'profile "-p" default: "default") inspect-cmd))

(def nested-parser
  (getopt (flag 'debug "-d") client-cmd (command 'version)))

;; The nested handler is defined after its table.
(defgetopt-dispatch root-handlers
  (client
    (inspect
      (services => collect-options))
    (status => identity))
  (version => identity))

(defgetopt-dispatch flat-handlers
  (version => identity)
  (status => (lambda (_) 'ready)))

(def (collect-options opt)
  (map (cut hash-ref opt <>) '(debug profile verbose count server names)))

(def nested-getopt-test
  (test-suite "nested getopt commands"
    (test-case "parse and dispatch with options at every level"
      (let ((values path opt)
            (getopt-parse nested-parser
              '("-d" "client" "-p" "work" "inspect" "-v" "services" "-n" "2" "dev" "a" "b")))
        (check path => '(client inspect services))
        (check (getopt-dispatch root-handlers path opt)
               => '(#t "work" #t 2 "dev" ("a" "b")))))

    (test-case "return shape is a property of the grammar"
      (let ((values path opt) (getopt-parse nested-parser '("version")))
        (check path => '(version))
        (check (eq? opt (getopt-dispatch root-handlers path opt)) => #t)
        (check (hash-key? opt 'profile) => #f))
      (let ((values cmd opt) (getopt-parse (getopt (command 'version)) '("version")))
        (check cmd => 'version)
        (check (eq? opt (getopt-dispatch flat-handlers cmd opt)) => #t)
        (check (getopt-dispatch flat-handlers 'status opt) => 'ready)
        (check (eq? opt (getopt-dispatch root-handlers '(client status) opt)) => #t))
      (check (hash-ref (getopt-parse (getopt (argument 'name)) '("dev")) 'name) => "dev"))

    (test-case "dispatch errors identify the path and retain the selected command's help"
      (def (render-error thunk)
        (try
         (thunk)
         (catch (getopt-error? e)
           (call-with-output-string "" (cut getopt-display-help e "demo" <>)))))
      (for-each
       (lambda (path)
         (check-exception (getopt-dispatch root-handlers path (hash-eq)) getopt-error?))
       '(() (client) (version extra) (client missing)))
      (check (string-contains
              (render-error (lambda () (getopt-dispatch root-handlers 'missing (hash-eq))))
              "No handler for command")
             ? integer?)
      (let (usage
            (render-error
             (lambda ()
               (call-with-getopt-dispatch flat-handlers '("client" "inspect" "services" "dev")
                 program: "demo" exit-on-error: #f client-cmd))))
        (check (string-contains usage "No handler for command") ? integer?)
        (check (string-contains usage "Usage: demo client inspect services") ? integer?)))

    (test-case "leaf handler exceptions reach the caller"
      (defgetopt-dispatch handlers (run => (lambda (_) (raise 'handler-error))))
      (check-exception
       (call-with-getopt-dispatch handlers '("run") program: "demo" exit-on-error: #t (command 'run))
       (cut eq? <> 'handler-error)))

    (test-case "defaults and end of options at the leaf"
      (let ((values _ opt)
            (getopt-parse nested-parser '("client" "inspect" "services" "--" "-dev")))
        (check (hash-ref opt 'profile) => "default")
        (check (hash-ref opt 'count) => 1)
        (check (hash-ref opt 'server) => "-dev")
        (check (hash-ref opt 'names) => '())))

    (test-case "reject positional arguments on branches in either declaration order"
      (for-each (lambda (arg)
                  (check-exception (command 'bad arg inspect-cmd) true)
                  (check-exception (command 'bad inspect-cmd arg) true))
                [(argument 'a) (optional-argument 'a) (rest-arguments 'a)]))

    (test-case "missing and unknown commands report the selected branch"
      (for-each
       (lambda (args)
         (let (out (open-output-string))
           (check-exception
            (getopt-parse nested-parser args)
            (lambda (e)
              (and (getopt-error? e)
                   (begin (getopt-display-help e "demo" out)
                          (string-contains (get-output-string out) "Usage: demo client inspect")))))))
       '(("client" "inspect") ("client" "inspect" "missing"))))

    (test-case "high-level dispatch and help use full paths"
      (check (call-with-getopt (lambda (cmd _) cmd) '("client" "inspect" "services" "dev")
               program: "demo" client-cmd)
             => '(client inspect services))
      (check (call-with-getopt-dispatch root-handlers '("version")
               program: "demo" client-cmd (command 'version))
             ? hash-table?)
      (for-each
       (lambda (args)
         (let (out (open-output-string))
           (parameterize ((current-output-port out))
             (call-with-getopt-dispatch root-handlers args program: "demo" client-cmd))
           (check (string-contains (get-output-string out)
                                   "Usage: demo client inspect services [option ...] <server>")
                  ? integer?)))
       '(("help" "client" "inspect" "services")
         ("client" "help" "inspect" "services")
         ("client" "inspect" "help" "services")
         ("client" "inspect" "services" "-h")
         ("client" "inspect" "services" "--help"))))

    (test-case "group summary and long option descriptions"
      (let (out (open-output-string))
        (parameterize ((current-output-port out))
          (call-with-getopt-dispatch root-handlers '("client" "inspect" "help") program: "demo" client-cmd))
        (let (usage (get-output-string out))
          (check (string-contains usage "demo client inspect: inspect a server") ? integer?)
          (check (filter (lambda (line)
                           (and (string-contains line "services") (string-contains line "list running services")))
                         (string-split usage #\newline))
                 ? pair?)))
      (let (out (open-output-string))
        (getopt-display-help
         (getopt (flag 'debug "-d" help: "Enable debugging")
                 (option 'name #f "--a-long-option-that-will-not-fit-in-one-column"
                         help: "Choose the name" default: "dev"))
         "demo" out)
        (let (usage (get-output-string out))
          (check (string-contains usage "  -d\n    Enable debugging\n") ? integer?)
          (check (string-contains usage
                   "  --a-long-option-that-will-not-fit-in-one-column <name>\n    Choose the name [default: dev]\n")
                 ? integer?))))

    (test-case "help is recognized only in command or option position"
      (def (help-output args)
        (call-with-output-string ""
          (lambda (out)
            (parameterize ((current-output-port out))
              (call-with-getopt-dispatch root-handlers args program: "demo" client-cmd)))))
      (let (usage (help-output '("client" "-h")))
        (check (string-contains usage "Usage: demo client [option ...]") ? integer?)
        (check (help-output '("client" "help")) => usage)
        (check (help-output '("client" "-h" "inspect")) => usage)
        (check (help-output '("client" "help" "inspect"))
               => (help-output '("client" "inspect" "--help"))))
      (let (out (open-output-string))
        (parameterize ((current-output-port out))
          (call-with-getopt (lambda (_) (error "help dispatched")) '("-h")
            program: "demo" (argument 'required)))
        (check (string-contains (get-output-string out) "<required>") ? integer?))
      (check (call-with-getopt (lambda (_ opt) (hash-ref opt 'server))
               '("client" "inspect" "services" "--" "-h") program: "demo" client-cmd)
             => "-h")
      (check (call-with-getopt (lambda (_ opt) (hash-ref opt 'profile))
               '("client" "-p" "--help" "inspect" "services" "dev") program: "demo" client-cmd)
             => "--help")
      (check-exception
       (call-with-getopt-dispatch root-handlers '("client" "unknown")
         program: "demo" exit-on-error: #f client-cmd)
       getopt-error?))))

;;; Helpers

;; (parser gopt key ...) is a procedure that parses its arguments as command-line words
;; with gopt, and returns the list of the values of the given keys in the parse hash table.
(def (parser gopt . keys)
  (lambda args
    (let (h (getopt-parse gopt args))
      (map (cut hash-get h <>) keys))))

;; Like parser, for a getopt with commands: returns (cons command-key values).
(def (command-parser gopt . keys)
  (lambda args
    (let ((values cmd h) (getopt-parse gopt args))
      (cons cmd (map (cut hash-get h <>) keys)))))

;; Help text of a getopt, as a string.
(def (help-string gopt)
  (with-output-to-string (lambda () (getopt-display-help gopt "prog"))))

;; Does the string contain the substring? (#t or #f)
(def (contains? str sub)
  (and (string-contains str sub) #t))

;;; Specs. They are built inside test cases, so that a spec that the current getopt
;;; rejects (e.g. optional-value:) only fails the test cases that use it.

;; Pre-existing features only.
(def (classic-getopt)
  (getopt (flag 'verbose "-v" "--verbose")
          (option 'counter "-c" "--counter")
          (option 'digits "-d" "--digits" default: "6")
          (option 'window #f "--window")
          (option 'number "-n" "--number" value: string->number default: 0)
          (rest-arguments 'args)))
(def classic-keys '(verbose counter digits window number args))

(def getopt-test
  (test-suite "test :std/cli/getopt"

    (test-case "flags and options with separate values"
      (check-function (apply parser (classic-getopt) classic-keys)
        => [#f #f "6" #f 0 []]
        "-v" => [#t #f "6" #f 0 []]
        "--verbose" => [#t #f "6" #f 0 []]
        "-c" "5" => [#f "5" "6" #f 0 []]
        "--counter" "5" => [#f "5" "6" #f 0 []]
        "--window" "3" => [#f #f "6" "3" 0 []]
        "-d" "8" "-v" => [#t #f "8" #f 0 []]
        "-n" "42" => [#f #f "6" #f 42 []]
        "--number" "7" "a" "b" => [#f #f "6" #f 7 ["a" "b"]]
        ;; the last occurrence wins
        "-c" "1" "--counter" "2" => [#f "2" "6" #f 0 []]
        "-v" "--verbose" "-v" => [#t #f "6" #f 0 []]))

    (test-case "defaults"
      (let (h (getopt-parse (classic-getopt) []))
        (check-function hash-key?
          ;; an option without a default or init has no entry
          h 'counter => #f
          h 'digits => #t
          ;; an absent flag is not in the table
          h 'verbose => #f)
        (check-function hash-get
          h 'counter => #f
          h 'digits => "6"
          h 'number => 0))
      ;; an explicit default: #f creates an entry
      (let (h (getopt-parse (getopt (option 'o "-o" default: #f)) []))
        (check (hash-key? h 'o) => #t)
        (check (hash-get h 'o) => #f)))

    (test-case "end of options, empty words, positional words"
      (check-function (apply parser (classic-getopt) classic-keys)
        "--" "-v" "x" => [#f #f "6" #f 0 ["-v" "x"]]
        "-v" "--" "--counter" => [#t #f "6" #f 0 ["--counter"]]
        ;; "" is skipped while parsing options
        "" "-v" "" "a" => [#t #f "6" #f 0 ["a"]]
        ;; ... but it is a value when an option expects one
        "-c" "" => [#f "" "6" #f 0 []]
        ;; the first positional word ends option parsing
        "a" "-c" "1" => [#f #f "6" #f 0 ["a" "-c" "1"]]))

    (test-case "values that look like options"
      (check-function (apply parser (classic-getopt) classic-keys)
        "-c" "-1" => [#f "-1" "6" #f 0 []]
        "--counter" "--verbose" => [#f "--verbose" "6" #f 0 []]
        "-c" "--" "x" => [#f "--" "6" #f 0 ["x"]]))

    (test-case "unknown option and missing value are errors"
      (check-function (apply parser (classic-getopt) classic-keys)
        "-x" =>! getopt-error?
        "--no-such-option" =>! getopt-error?
        "-v" "-x" "a" =>! getopt-error?
        "-c" =>! getopt-error?
        "-v" "--counter" =>! getopt-error?
        "--window" =>! getopt-error?))

    (test-case "required, optional and rest arguments"
      (def gopt (getopt (flag 'verbose "-v")
                        (argument 'a)
                        (optional-argument 'b default: "B")
                        (rest-arguments 'r value: string->symbol)))
      (check-function (parser gopt 'verbose 'a 'b 'r)
        "x" => [#f "x" "B" []]
        "-v" "x" "y" => [#t "x" "y" []]
        "x" "y" "z" "w" => [#f "x" "y" '(z w)]
        =>! getopt-error?
        "-v" =>! getopt-error?)
      (def gopt2 (getopt (argument 'a value: string->number)))
      (check-function (parser gopt2 'a)
        "12" => [12]
        "1" "2" =>! getopt-error?))

    (test-case "commands"
      (def gopt (getopt (flag 'verbose "-v")
                        (command 'run (option 'n "-n" "--count") (argument 'what))
                        (command 'stop)))
      (check-function (command-parser gopt 'verbose 'n 'what)
        "run" "x" => ['run #f #f "x"]
        "-v" "run" "-n" "3" "x" => ['run #t "3" "x"]
        "stop" => ['stop #f #f #f]
        =>! getopt-error?
        "nope" =>! getopt-error?
        "stop" "x" =>! getopt-error?
        "run" "-q" "x" =>! getopt-error?))

    (test-case "parse: default is identity; flags store #t"
      (def gopt (getopt (flag 'f "-f") (option 'o "-o") (argument 'a)))
      (check-function (parser gopt 'f 'o 'a)
        "-f" "-o" "v" "x" => [#t "v" "x"]))

    (test-case "value: remains an alias of parse:"
      (def gopt (getopt (option 'counter "-c" value: string->number)
                        (argument 'a value: string->symbol)
                        (optional-argument 'b value: string->number)
                        (rest-arguments 'r value: string->number)))
      (check-function (parser gopt 'counter 'a 'b 'r)
        "-c" "1" "x" "2" "3" => [1 'x 2 [3]]
        "--" "y" => [#f 'y #f []]))

    (test-case "parse: and value: together are an error"
      (check (option 'o "-o" parse: identity value: identity) =>! true)
      (check (argument 'a parse: identity value: identity) =>! true)
      (check (optional-argument 'a parse: identity value: identity) =>! true)
      (check (rest-arguments 'a parse: identity value: identity) =>! true))

    (test-case "flag default:"
      (def gopt (getopt (flag 'quiet "-q" default: 'no)
                        (flag 'loud "-l")))
      (let (h (getopt-parse gopt []))
        (check-function hash-key?
          ;; with default: an absent flag gets its default
          h 'quiet => #t
          ;; without default: an absent flag is not stored
          h 'loud => #f)
        (check (hash-get h 'quiet) => 'no))
      (check-function (parser gopt 'quiet 'loud)
        ;; last occurrence wins, the default is replaced
        "-q" => [#t #f]
        "-q" "-q" "-l" "-l" => [#t #t]))



))
