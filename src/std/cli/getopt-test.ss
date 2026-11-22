;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/cli/getopt
        :std/test)
(export getopt-test)

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

(def getopt-test
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
