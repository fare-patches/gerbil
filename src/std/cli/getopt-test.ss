;;; :std/cli/getopt tests
(import :std/test
        :std/source
        (only-in :std/error contract-violation-error?)
        ./getopt
        "./exit-test-support")
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
          (check (string-contains usage " -d  Enable debugging\n") ? integer?)
          (check (string-contains usage
                   "  --a-long-option-that-will-not-fit-in-one-column <name>  Choose the name [default: \"dev\"]\n")
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

;; oathtool-like: options with attached values and optional values.
(def (oath-getopt)
  (getopt (flag 'verbose "-v" "--verbose")
          (option 'counter "-c" "--counter" value: string->number)
          (option 'window #f "--window")
          (option 'digits "-d" "--digits" default: "6")
          (option 'totp #f "--totp" optional-value: "SHA1")
          (option 'mode "-m" "--mode" optional-value: "x")
          (rest-arguments 'args)))
(def oath-keys '(verbose counter window digits totp mode args))

(def getopt-test
  (test-suite "test :std/cli/getopt"

    ;;; 4. Backward compatibility: these pass with the pre-extension getopt.

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
          ;; an option without a default has no entry
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

    (test-case "omitted options preserve the function keyword default"
      (def g (getopt (option 'color "--color" parse: (lambda (_) #f))))
      (def (color color: (value 'auto)) value)
      (check (call-with-getopt-parse g (getopt-parse g []) color) => 'auto)
      (check (call-with-getopt-parse g (getopt-parse g ["--color=off"]) color) => #f))

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

    (test-case "a lone - is a positional argument"
      ;; POSIX/GNU convention (e.g. "-" for stdin). Fails with the pre-extension getopt,
      ;; which raises "Unknown option" for "-".
      (check-function (apply parser (classic-getopt) classic-keys)
        "-" => [#f #f "6" #f 0 ["-"]]
        "-c" "5" "-" => [#f "5" "6" #f 0 ["-"]]
        "-v" "-" "x" => [#t #f "6" #f 0 ["-" "x"]]
        "-" "x" => [#f #f "6" #f 0 ["-" "x"]]
        ;; it ends option parsing like any positional word
        "-" "-v" => [#f #f "6" #f 0 ["-" "-v"]]
        "-" "--" "-c" => [#f #f "6" #f 0 ["-" "--" "-c"]]
        ;; still a positional after --, and still a value for an option expecting one
        "--" "-" => [#f #f "6" #f 0 ["-"]]
        "-c" "-" => [#f "-" "6" #f 0 []])
      (def gopt (getopt (flag 'verbose "-v")
                        (argument 'in)
                        (optional-argument 'out default: "OUT")))
      (check-function (parser gopt 'verbose 'in 'out)
        "-" => [#f "-" "OUT"]
        "-v" "-" => [#t "-" "OUT"]
        "x" "-" => [#f "x" "-"]
        "-" "-" => [#f "-" "-"]
        "-v" "-" "-" => [#t "-" "-"]
        "-" "-" "-" =>! getopt-error?))

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

    (test-case "an exact registered name takes precedence"
      ;; Pre-existing getopt allows any word as a "short" name, e.g. "-cv".
      ;; It must keep matching exactly, not as "-c" with attached value "v".
      (def gopt (getopt (option 'c "-c") (flag 'cv "-cv") (option 'xy "-xy=1")))
      (check-function (parser gopt 'c 'cv 'xy)
        "-cv" => [#f #t #f]
        "-c" "v" => ["v" #f #f]
        "-xy=1" "z" => [#f #f "z"]))

    ;;; 1. --long=value

    (test-case "--long=value for options"
      (check-function (apply parser (oath-getopt) oath-keys)
        "--counter=5" => [#f 5 #f "6" #f #f []]
        "--window=3" => [#f #f "3" "6" #f #f []]
        "--digits=8" "-v" "k" => [#t #f #f "8" #f #f ["k"]]
        ;; the value is everything after the first =
        "--window=a=b" => [#f #f "a=b" "6" #f #f []]
        "--window==" => [#f #f "=" "6" #f #f []]
        "--window=" => [#f #f "" "6" #f #f []]
        ;; the next word is not consumed
        "--window=3" "4" => [#f #f "3" "6" #f #f ["4"]]
        "--window=3" "--digits" "7" => [#f #f "3" "7" #f #f []]
        ;; a value that looks like an option
        "--window=-v" => [#f #f "-v" "6" #f #f []]
        "--window=--" "x" => [#f #f "--" "6" #f #f ["x"]]
        ;; both forms mix; the last occurrence wins
        "--digits" "7" "--digits=9" => [#f #f #f "9" #f #f []]))

    (test-case "--long=value errors"
      (check-function (apply parser (oath-getopt) oath-keys)
        "--verbose=x" =>! getopt-error?
        "--verbose=" =>! getopt-error?
        "--unknown=x" =>! getopt-error?
        "--=x" =>! getopt-error?
        ;; the converter applies to the =value: string->number of "" is #f, not an error
        "--counter=" => [#f #f #f "6" #f #f []]))

    (test-case "--long=value with a classic spec (no optional-value: used)"
      (check-function (apply parser (classic-getopt) classic-keys)
        "--counter=5" => [#f "5" "6" #f 0 []]
        "--number=7" => [#f #f "6" #f 7 []]
        "--window=w" "a" => [#f #f "6" "w" 0 ["a"]]
        "--verbose=yes" =>! getopt-error?))

    ;;; 2. Attached short values

    (test-case "attached short values"
      (check-function (apply parser (oath-getopt) oath-keys)
        "-c5" => [#f 5 #f "6" #f #f []]
        "-c" "5" => [#f 5 #f "6" #f #f []]
        "-d8" "x" => [#f #f #f "8" #f #f ["x"]]
        "-dabc" => [#f #f #f "abc" #f #f []]
        ;; everything after the short name is the value, including - and =
        "-d-1" => [#f #f #f "-1" #f #f []]
        "-d=8" => [#f #f #f "=8" #f #f []]
        ;; the next word is not consumed
        "-d8" "9" => [#f #f #f "8" #f #f ["9"]]
        "-v" "-c12" "-d" "7" => [#t 12 #f "7" #f #f []]))

    (test-case "attached short values errors"
      (check-function (apply parser (oath-getopt) oath-keys)
        ;; no short-flag clustering
        "-vc" =>! getopt-error?
        "-vv" =>! getopt-error?
        "-v5" =>! getopt-error?
        ;; unknown short option with something attached
        "-x5" =>! getopt-error?
        ;; missing value still an error
        "-c" =>! getopt-error?))

    (test-case "attached short values with a classic spec"
      (check-function (apply parser (classic-getopt) classic-keys)
        "-c5" => [#f "5" "6" #f 0 []]
        "-n42" "a" => [#f #f "6" #f 42 ["a"]]
        "-vc" =>! getopt-error?))

    ;;; 3. Optional-value options

    (test-case "optional-value long option"
      (check-function (apply parser (oath-getopt) oath-keys)
        "--totp" => [#f #f #f "6" "SHA1" #f []]
        "--totp=SHA256" => [#f #f #f "6" "SHA256" #f []]
        "--totp=" => [#f #f #f "6" "" #f []]
        "--totp=a=b" => [#f #f #f "6" "a=b" #f []]
        ;; the next word is never consumed
        "--totp" "KEY" => [#f #f #f "6" "SHA1" #f ["KEY"]]
        "--totp" "SHA256" => [#f #f #f "6" "SHA1" #f ["SHA256"]]
        "--totp" "-v" => [#t #f #f "6" "SHA1" #f []]
        "--totp" "--" "-v" => [#f #f #f "6" "SHA1" #f ["-v"]]
        "-v" "--totp=SHA512" "-c" "3" "KEY" => [#t 3 #f "6" "SHA512" #f ["KEY"]]))

    (test-case "optional-value option with a short name"
      (check-function (apply parser (oath-getopt) oath-keys)
        "-m" => [#f #f #f "6" #f "x" []]
        "-mfoo" => [#f #f #f "6" #f "foo" []]
        "--mode" => [#f #f #f "6" #f "x" []]
        "--mode=bar" => [#f #f #f "6" #f "bar" []]
        ;; the next word is never consumed
        "-m" "foo" => [#f #f #f "6" #f "x" ["foo"]]
        "--mode" "foo" => [#f #f #f "6" #f "x" ["foo"]]
        "-m" "-c" "1" => [#f 1 #f "6" #f "x" []]))

    (test-case "optional-value absent option gets its default"
      (let (h (getopt-parse (oath-getopt) []))
        (check (hash-key? h 'totp) => #f)
        (check-function hash-get
          h 'totp => #f
          h 'mode => #f))
      (def gopt (getopt (option 'totp #f "--totp" optional-value: "SHA1" default: "none")))
      (check-function (parser gopt 'totp)
        => ["none"]
        "--totp" => ["SHA1"]
        "--totp=SHA256" => ["SHA256"]))

    (test-case "optional-value with a converter"
      ;; optional-value: is post-parse, like default: the converter applies only to
      ;; explicit values (--opt=X, -oX); the optional value is stored as given.
      (def gopt (getopt (option 'totp #f "--totp" optional-value: 'sha1
                                parse: string->symbol default: 'none)
                        (option 'level "-l" "--level" optional-value: 1
                                value: string->number)
                        (option 'raw "-r" optional-value: "1"
                                value: string->number)
                        (rest-arguments 'args)))
      (check-function (parser gopt 'totp 'level 'raw 'args)
        ;; the default is not converted, as for other options
        => ['none #f #f []]
        "--totp" => ['sha1 #f #f []]
        "--totp=SHA256" => ['SHA256 #f #f []]
        "-l" => ['none 1 #f []]
        "-l3" => ['none 3 #f []]
        "--level=5" "7" => ['none 5 #f ["7"]]
        "--level" "7" => ['none 1 #f ["7"]]
        ;; a string optional value is not converted either
        "-r" => ['none #f "1" []]
        "-r2" => ['none #f 2 []]))

    (test-case "optional-value may be any Scheme value"
      (def gopt (getopt (option 'sym "-s" optional-value: 'x)
                        (option 'num "-n" optional-value: 42)
                        (option 'lst "-l" optional-value: '(a . b))
                        (rest-arguments 'args)))
      (check-function (parser gopt 'sym 'num 'lst 'args)
        => [#f #f #f []]
        "-s" "-n" "-l" "w" => ['x 42 '(a . b) ["w"]]
        "-sy" "-n7" "-lz" => ["y" "7" "z" []]))

    (test-case "optional-value may be the empty string"
      (def gopt (getopt (option 'tag "-t" "--tag" optional-value: "")
                        (rest-arguments 'args)))
      (check-function (parser gopt 'tag 'args)
        => [#f []]
        "--tag" => ["" []]
        "-t" => ["" []]
        "-t" "x" => ["" ["x"]]
        "-tx" => ["x" []]
        "--tag=y" => ["y" []]))

    (test-case "optional-value inside a command"
      (def gopt (getopt (command 'gen
                          (option 'totp #f "--totp" optional-value: "SHA1")
                          (option 'counter "-c" "--counter")
                          (argument 'key))))
      (check-function (command-parser gopt 'totp 'counter 'key)
        "gen" "K" => ['gen #f #f "K"]
        "gen" "--totp" "K" => ['gen "SHA1" #f "K"]
        "gen" "--totp=SHA256" "--counter=4" "K" => ['gen "SHA256" "4" "K"]
        "gen" "-c7" "K" => ['gen #f "7" "K"]
        "gen" "--totp" =>! getopt-error?))

    (test-case "without optional-value: a value is required"
      ;; Not passing optional-value: at all is distinct from passing optional-value: #f.
      (def gopt (getopt (option 'w "-w" "--width")
                        (option 'e "-e" optional-value: "")
                        (rest-arguments 'args)))
      (check-function (parser gopt 'w 'e 'args)
        => [#f #f []]
        ;; a value is required, and a separate word is consumed as usual
        "-w" "3" "x" => ["3" #f ["x"]]
        "--width" "3" => ["3" #f []]
        "--width=4" => ["4" #f []]
        "-w5" => ["5" #f []]
        "-w" =>! getopt-error?
        "--width" =>! getopt-error?
        ;; "": an optional value; a separate word is not consumed
        "-e" "3" => [#f "" ["3"]]
        "-e" => [#f "" []]))

    (test-case "optional-value: #f is a legitimate optional value"
      (def gopt (getopt (option 'x "-x" "--x" optional-value: #f parse: string->symbol
                                default: 'absent)
                        (option 'y "-y" optional-value: #f)
                        (rest-arguments 'args)))
      (check-function (parser gopt 'x 'y 'args)
        => ['absent #f []]
        ;; bare: #f is stored, not parsed; the next word is not consumed
        "--x" => [#f #f []]
        "-x" "v" => [#f #f ["v"]]
        ;; explicit values are parsed
        "--x=v" => ['v #f []]
        "-xw" => ['w #f []]
        "-y" "z" => ['absent #f ["z"]]
        "-yz" => ['absent "z" []])
      ;; the key is present after a bare occurrence, even though the value is #f
      (check (hash-key? (getopt-parse gopt ["-y"]) 'y) => #t)
      (check (hash-get (getopt-parse gopt ["-y"]) 'y) => #f)
      (check (hash-get (getopt-parse gopt ["--x"]) 'x) => #f))

    ;;; 6. parse: keyword

    (test-case "parse: on every kind of spec"
      (def gopt (getopt (flag 'verbose "-v" parse: (lambda (x) (list 'seen x)))
                        (option 'counter "-c" "--counter" parse: string->number)
                        (option 'level #f "--level" optional-value: 'one parse: string->number)
                        (argument 'a parse: string->symbol)
                        (optional-argument 'b parse: string->number default: 0)
                        (rest-arguments 'r parse: string->number)))
      (check-function (parser gopt 'verbose 'counter 'level 'a 'b 'r)
        "x" => [#f #f #f 'x 0 []]
        ;; a flag's parse: receives #t
        "-v" "x" => [['seen #t] #f #f 'x 0 []]
        "-c" "5" "x" "2" => [#f 5 #f 'x 2 []]
        "--counter=6" "x" => [#f 6 #f 'x 0 []]
        "-c7" "x" => [#f 7 #f 'x 0 []]
        ;; the optional value is not parsed
        "--level" "x" => [#f #f 'one 'x 0 []]
        "--level=9" "x" => [#f #f 9 'x 0 []]
        "x" "2" "3" "4" => [#f #f #f 'x 2 [3 4]])
      ;; the default is not parsed
      (check (hash-get (getopt-parse (getopt (option 'n "-n" parse: string->number default: "d")) [])
                       'n)
             => "d")
      ;; an absent flag without default: is not stored, even with parse:
      (check (hash-key? (getopt-parse gopt ["x"]) 'verbose) => #f))

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

    (test-case "closed spec keywords accept interleaved positionals and reject typos"
      (let (gopt (getopt (option 'n "-n" parse: string->number "--number" default: #f)))
        (check-function (parser gopt 'n)
          => [#f]
          "--number=3" => [3]))
      (check (apply flag ['v "-v" typo: #f]) =>! true))

    (test-case "parse: and value: together are an error"
      (check (option 'o "-o" parse: identity value: identity) =>! true)
      (check (argument 'a parse: identity value: identity) =>! true)
      (check (optional-argument 'a parse: identity value: identity) =>! true)
      (check (rest-arguments 'a parse: identity value: identity) =>! true))

    (test-case "multioption collects parsed values in argument order"
      (def g (getopt (multioption 'n "-n" "--number" parse: string->number)))
      (check-function (parser g 'n)
        => [[]]
        "-n" "2" => [[2]]
        "--number=3" "-n2" "-n" "3" => [[3 2 3]])
      (check (getopt (multioption 'n "-n") (flag 'n "--none"))
             =>! contract-violation-error?))

    (test-case "a child killed by a signal cannot report success"
      (check (gxi-exit-code '(import :std/os/pid :std/os/signal)
                            '(kill (getpid) SIGKILL))
             => -9))

    (test-case "fresh interpreter loads the getopt source with omitted keywords"
      (def source (path-expand "getopt.ss" (path-directory (this-source-file))))
      (check (gxi-exit-code `(import ,source)
                            '(def opts (getopt-parse (getopt (flag 'f "-f" default: #f)) '()))
                            '(exit (if (eq? (hash-ref opts 'f) #f) 0 1)))
             => 0))

    (test-case "reject non-procedure converters at construction"
      (check (flag 'v "-v" parse: #f) =>! contract-violation-error?)
      (check (argument 'a value: 42) =>! contract-violation-error?))

    (test-case "multioption collects across the selected command path"
      (def inc (multioption 'inc "-I"))
      (let-values (((cmd opts) (getopt-parse (getopt inc (command 'go inc))
                                            '("-Ia" "go" "-Ib"))))
        (check cmd => 'go)
        (check (hash-ref opts 'inc) => '("a" "b"))))

    (test-case "short optional value help matches its attached syntax"
      (def g (getopt (option 'n "-n" optional-value: #f parse: string->number)))
      (check (contains? (help-string g) "-n[<n>]") => #t)
      (check-function (parser g 'n) "-n3" => [3]))

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

    (test-case "duplicate option names within a command"
      (check (getopt (flag 'verbose "-v") (option 'value "-v")) =>! contract-violation-error?)
      (check (getopt (flag 'v "-v" "--verbose") (flag 'v "--verbose")) =>! contract-violation-error?))

    (test-case "topic callback receives the matched parser, program and remaining path"
      (def x (argument 'x))
      (def b (command 'b x))
      (def g (getopt (command 'a b)))
      (def (inspect node program remaining)
        (list (getopt->specifiers node) program remaining))
      (check-function call-with-getopt-topic
        g '(a b) "p" inspect => (list [x] "p a b" [])
        g '(a x y) "p" inspect => (list [b] "p a" '(x y))))

    (test-case "unknown help topic writes diagnostic and usage to the requested port"
      (let ((out (open-output-string)) (err (open-output-string)))
        (parameterize ((current-error-port err))
          (getopt-display-help-topic (getopt (command 'client)) '(client typo) "demo" out))
        (check (contains? (get-output-string out) "demo client: Unknown command typo.\nUsage: demo client") => #t)
        (check (get-output-string err) => "")))

    (test-case "shared scalar ids allow only one explicit default"
      (check (getopt (flag 'x "-a" default: #f) (flag 'x "-b" default: #t))
             =>! contract-violation-error?))

    (test-case "shared ids: oathtool-style mode and encoding"
      (def gopt (getopt (flag 'mode "--hotp" parse: (lambda (_) 'hotp))
                        (option 'mode #f "--totp" optional-value: '(totp . sha1)
                                parse: (lambda (s) (cons 'totp (string->symbol s))))
                        (flag 'encoding "-b" "--base32" parse: (lambda (_) 'base32))
                        (flag 'encoding #f "--hex" parse: (lambda (_) 'hex))
                        (rest-arguments 'args)))
      (check-function (parser gopt 'mode 'encoding 'args)
        => [#f #f []]
        "--hotp" => ['hotp #f []]
        "--totp" => [(cons 'totp 'sha1) #f []]
        "--totp" "--hotp" => ['hotp #f []]
        "--hotp" "--totp=SHA256" => [(cons 'totp 'SHA256) #f []]
        "--hotp" "--totp" "KEY" => [(cons 'totp 'sha1) #f ["KEY"]]
        "-b" => [#f 'base32 []]
        "-b" "--hex" => [#f 'hex []]
        "--hex" "-b" => [#f 'base32 []]
        "--hex" "--base32" "--totp=SHA512" "K" => [(cons 'totp 'SHA512) 'base32 ["K"]])
      ;; only flags without default: share 'encoding, so it is not stored when absent
      (check (hash-key? (getopt-parse gopt []) 'encoding) => #f)
      ;; each spec is listed in the help
      (let (out (help-string gopt))
        (check-function contains?
          out "--hotp" => #t
          out "--totp" => #t
          out "--base32" => #t
          out "--hex" => #t)))

    (test-case "optional value syntax follows each spelling"
      (def g (getopt (option 'color "--color" "-c" optional-value: #f)))
      (check (contains? (help-string g) "--color[=<color>] -c[<color>]") => #t)
      (check-function (parser g 'color)
        "--color" => [#f]
        "--color=red" => ["red"]
        "-cblue" => ["blue"]))

    (test-case "help shows exact-only aliases bare"
      (def g (getopt (option 'colour "-color" "--color" optional-value: 'auto)
                     (option 'c "-c" optional-value: 'auto)))
      (def out (help-string g))
      (check-function contains?
        out "-color --color[=<colour>]" => #t
        out "-c[<c>]" => #t)
      (check-function (parser g 'colour 'c)
        "-color" => ['auto #f]
        "-colorred" => [#f "olorred"]
        "--color=red" => ["red" #f]))

    (test-case "long option names cannot contain an equals sign"
      (check (getopt (option 'debug "--debug=yes"))
             =>! contract-violation-error?))

    (test-case "help shows optional values"
      (let (out (help-string (oath-getopt)))
        (check-function contains?
          out "--totp" => #t
          out "--mode" => #t
          out "[=" => #t))
      (let (out (help-string (getopt (option 'totp #f "--totp" optional-value: "SHA1"))))
        (check-function contains?
          out "--totp" => #t
          out "[=" => #t))
      ;; a normal option is not shown with an optional value
      (let (out (help-string (getopt (option 'counter "-c" "--counter")
                                     (option 'window #f "--window"))))
        (check-function contains?
          out "--counter" => #t
          out "--window" => #t
          out "[=" => #f)))

    ;; Each section aligns its help texts 2 columns after its own widest label.
    (test-case "help aligns commands to the widest command name"
      (let (out (help-string (getopt (command 'run help: "Run it")
                                     (command 'restart help: "Restart it")
                                     (command 'qr help: "Show a QR code"))))
        (check-function contains?
          out "\n run      Run it\n" => #t
          out "\n restart  Restart it\n" => #t
          out "\n qr       Show a QR code\n" => #t)))

    (test-case "help aligns options and commands independently"
      (let (out (help-string (getopt (flag 'verbose "-v" "--verbose" help: "Verbose")
                                     (option 'count "-n" "--count" help: "Count" default: 1)
                                     (command 'go help: "Go"))))
        (check-function contains?
          out "\n -v --verbose        Verbose\n" => #t
          out "\n -n --count <count>  Count [default: 1]\n" => #t
          out "\n go  Go\n" => #t)))

    ;; A label longer than the 30-column cap gets a 2-space gap, and does not
    ;; widen the column of the others.
    (test-case "help gives overlong labels a 2-space gap"
      (let (out (help-string (getopt (flag 'quiet "-q" help: "Quiet")
                                     (flag 'long #f "--a-very-long-option-name-indeed"
                                           help: "Long"))))
        (check-function contains?
          out "\n -q  Quiet\n" => #t
          out "\n  --a-very-long-option-name-indeed  Long\n" => #t)))

    (test-case "help aligns arguments to the widest argument name"
      (let (out (help-string (getopt (argument 'in help: "Input")
                                     (optional-argument 'out help: "Output" default: "OUT")
                                     (rest-arguments 'more help: "More"))))
        (check-function contains?
          out "\n in    Input\n" => #t
          out "\n out   Output [default: \"OUT\"]\n" => #t
          out "\n more  More\n" => #t)))

    (test-case "help with string ids"
      (let (out (help-string (getopt (argument "in" help: "Input")
                                     (rest-arguments "rest" help: "More"))))
        (check-function contains?
          out "\n in    Input\n" => #t
          out "\n rest  More\n" => #t)))

    (test-case "getopt->specifiers"
      (def specs [(flag 'v "-v") (argument 'x)])
      (check (getopt->specifiers (apply getopt specs)) => specs)
      (let (go (command 'go))
        (check (getopt->specifiers (getopt go)) => [go])))

    (test-case "help usage lines separate their words"
      (check-function contains?
        (help-string (getopt (flag 'v "-v") (argument 'in)))
        "Usage: prog [option ...] <in>\n" => #t
        (help-string (getopt (flag 'v "-v") (command 'go)))
        "Usage: prog [option ...] <command> command-arg ...\n" => #t))

    ;;; 6. Exit on error

    ;; The help goes to current-error-port, then the process exits with status 2.
    ;; Gambit's exit only flushes its console ports: a file port must be flushed first.
    (test-case "exit-on-error flushes the help before exiting"
      (let (result (gxi-exit-output
                    (lambda (file)
                      ['(import :std/cli/getopt)
                       `(def port (open-output-file ,file))
                       `(parameterize ((current-error-port port))
                          (call-with-getopt void '("--no-such-option")
                                            program: "prog"
                                            (flag 'verbose "-v")))])))
        (check (car result) => 2)
        (check (and (cdr result) (contains? (cdr result) "Unknown option")) => #t)))))
