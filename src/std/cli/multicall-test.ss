;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/cli/multicall tests
(import :std/test
        :std/cli/getopt
        ./multicall)
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
(defrule (with-saved-multicall-settings body ...)
  (parameterize ((current-program ["prog"])) body ...))

(def (invoke command . args)
  (call-entry-point/internal command args))

(def (unknown-command-error? e)
  (let (msg (if (string? e) e (error-message e)))
    (and (string? msg) (string-contains msg "Unknown command") #t)))

(def multicall-test
  (test-suite "test :std/cli/multicall"
    (test-case "entry point without getopt: gets its arguments unparsed"
      (with-saved-multicall-settings
       (check-function invoke
         "multicall-test-raw" => ['raw []]
         "multicall-test-raw" "a" "-b" "--" => ['raw ["a" "-b" "--"]]
         "multicall-test-raw" "-x" => ['raw ["-x"]])))

    (test-case "getopt: N gives N positional arguments"
      (with-saved-multicall-settings
       (check-function invoke
         "multicall-test-pair" "x" "y" => ['pair "x" "y"]
         "multicall-test-pair" "x" =>! getopt-error?)))

    (test-case "getopt: a getopt object"
      (with-saved-multicall-settings
       (check (invoke "multicall-test-object" "v") => ['object "v"])))

    ;; help builds a command from every entry point's getopt:, whatever its form.
    (test-case "help covers entry points with every form of getopt:"
      (with-saved-multicall-settings
       (def (help-output . args)
         (with-output-to-string (lambda () (apply invoke "help" args))))
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

))
