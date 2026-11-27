;;; -*- Gerbil -*-
;;; © vyzo
;;; tool to run tests without the need of glue code
(import :gerbil/expander
        :std/cli/getopt
        :std/error
        :std/iter
        :std/hash/misc
        :std/io
        :std/os/process
        :std/sync/wg
        :std/text/pregexp
        :std/test/base
        ./env)
(export main)

(def (features->list features)
  (map string->symbol (string-split features #\,)))

(def (main . args)
  (call-with-getopt gxtest-main args
    program: "gxtest"
    help: "run Gerbil tests"
    global-env-flag
    (option 'verbosity "-v" "--verbosity"
            value: string->number
            default: 3
            help: "set the test verobisyt mode")
    (option 'run "-r" "--run"
            help: "only run test suites whose name matches a given regex")
    (flag 'isolate "--isolate"
          help: "run each test module in a fresh subprocess")
    (option 'cgroup "--cgroup"
            help: "run isolated modules in a delegated Linux cgroup v2 directory")
    (option 'parallel "--parallel"
            value: parse-parallelism
            help: "run up to N test module subprocesses concurrently (implies --isolate)")
    ;; TODO this should be a multi-option for multiple feature when getopt supports it
    (option 'features "-D"
            value: features->list
            default: []
            help: "define one or more conditional expansion feature (comma separated) for enabling tests that require external services")
    (rest-arguments 'args
                    help: "test files or directories to execute tests in; appending /... to a directory will recursively execute or tests in it. If no arguments are passed, all tests in the current directory are executed.")))

(def (gxtest-main opt)
  (setup-local-env! opt)
  (let-hash opt
    (let (args (if (null? .args) ["."] .args))
      (exit
       (if (or .?isolate .?parallel .?cgroup)
         (run-isolated-tests args .run .features .verbosity .?global-env
                             (or .?parallel 1) .?cgroup)
         (run-tests args .run .features .verbosity))))))

(def (parse-parallelism (value : :string))
  => :fixnum
  (let (cores (string->number value))
    (if (and (fixnum? cores) (fxpositive? cores))
      cores
      (raise-bad-argument gxtest "positive integer for --parallel" value))))

(def (run-isolated-tests (args : :list) (filter :? :string)
                        (features : :list) (verbosity : :fixnum)
                        (global? : :boolean) (cores : :fixnum) (cgroup :? :string))
  => :fixnum
  (def files (collect-files args))
  (def program (path-expand "~~bin/gxtest"))
  (def options
    [program "-v" (number->string verbosity)
     (if global? ["-g"] []) ...
     (if filter ["-r" filter] []) ...
     (if (pair? features)
       ["-D" (string-join (map symbol->string features) ",")]
       [])
     ...])
  (def failures [])
  (def output-lock (make-mutex 'gxtest-output))
  (def (relay-output (child : Process) (file : :string))
    (def prefix (string-append "[" file "] "))
    (def (emit! (bytes : :u8vector))
      (with-lock output-lock
        (lambda ()
          (display prefix)
          (write-u8vector bytes (current-output-port))
          (write-u8 10)
          (force-output))))
    (with-buffered-reader (reader (child.stdout))
      ;; get-output-u8vector drains the bytes accumulated since the last line.
      (let (line (open-output-u8vector))
        (let loop ()
          (let (byte (reader.read-u8))
            (cond
             ((eof-object? byte)
              (let (tail (get-output-u8vector line))
                (unless (fxzero? (u8vector-length tail)) (emit! tail))))
             ((eqv? byte 10)
              (emit! (get-output-u8vector line))
              (loop))
             (else
              (write-u8 byte line)
              (loop))))))))
  (def (failed! (file : :string) (detail : :string))
    (with-lock output-lock
      (lambda ()
        (set! failures (cons (cons file detail) failures))
        (displayln "ERROR MODULE " file " " detail)
        (force-output))))
  (def wg (and (fx> cores 1) (pair? files) (make-wg (min cores (length files)))))
  (for (file files)
    (wg-add! wg
      (lambda ()
        (try
         (using (child (start-process! program [options ... "--" file]
                         gxexec: #t cgroup: cgroup
                         stdin-redirection: #f stderr-to-stdout: #t) : Process)
           (unwind-protect!
             (begin
               (relay-output child file)
               (using (result (child.wait) : ProcessExit)
                 (cond
                  (result.signal (failed! file (string-append "signal " (number->string result.signal))))
                  ((not (eqv? result.code 0))
                   (failed! file (string-append "exit status " (number->string result.code)))))))
             (child.close)))
         (catch (e)
           (failed! file (exception->string e)))))))
  (wg-wait! wg)
  (if (null? failures)
    0
    (begin
      (displayln "FAILED MODULES (" (length failures) "):")
      (for-each
        (lambda (failure)
          (displayln "  " (car failure) ": " (cdr failure)))
        (reverse! failures))
      (force-output)
      42)))

(def (run-tests args filter features verbosity)
  (def import-errors [])

  (def (display-test-result result)
    (if (test-result-ok? result)
     (begin
       (displayln 'OK)
       (force-output))
     (notice-error `(HARNESS ,args) result)))

  (when features
    (let (root (core-context-root))
      (for (feature features)
        (core-bind-feature! feature #f 0 root))))

  (let* ((files   (collect-files args))
         (allow   (if filter
                    (let (rx (pregexp filter))
                      (lambda (sym) (pregexp-match rx (if (symbol? sym) (symbol->string sym) sym))))
                    (lambda (sym) #t)))
         (harness (prepare-harness files allow verbosity))
         (result  (test-run! harness)))
    (display-test-result result)
    (if (test-result-ok? result) 0 42)))

(def (collect-files args)
  (reverse!
   (for/fold (result []) (arg args)
     (cond
      ((string-suffix? "/..." arg)
       (collect-files-r (substring arg 0 (- (string-length arg) 4)) result))
      ((eq? (file-type arg) 'directory)
       (for/fold (result result) (file (get-directory-files arg))
         (if (string-suffix? "-test.ss" file)
           (cons (string-append arg "/" file) result)
           result)))
      (else
       (cons arg result))))))

(def (collect-files-r dir result)
  (for/fold (result result) (arg (get-directory-files dir))
    (cond
     ((member arg '("." ".."))
      result)
     ((eq? (file-type (string-append dir "/" arg)) 'directory)
      (collect-files-r (string-append dir "/" arg) result))
     ((string-suffix? "-test.ss" arg)
      (cons (string-append dir "/" arg) result))
     (else result))))

(def (get-directory-files dir)
  (list-sort string<? (directory-files dir)))

(def (prepare-harness (files : :list) (allow? : :procedure) (verbosity : :fixnum))
  => TestHarness
  (let* ((modules
          (for/fold (r []) (file files : :string)
            (cons (prepare-module file allow?) r)))
         (desc
          (object->string files))
         (config
          (TestConfig verbosity: verbosity capture-output?: #f)))
    (TestHarness desc config modules)))

(def (prepare-module (file : :string) (accept? : :procedure))
  => TestModule
  (try
   (let* ((ctx     (import-module file #f #t))
          (exports (module-context-export ctx)))
     (let loop ((rest exports) (init #f) (finish #f) (suites []))
       (match rest
         ([export . rest]
          (if (runtime-export? export)
            (let (name (module-export-name export))
              (cond
               ((eq? name 'test-setup!)
                (loop rest
                      (: (eval-export export) :procedure)
                      finish
                      suites))
               ((eq? name 'test-cleanup!)
                (loop rest
                      init
                      (: (eval-export export) :procedure)
                      suites))
               (else
                (let (name-str (symbol->string name))
                  (if (and (string-suffix? "-test" name-str)
                           (accept? name-str))
                    (loop rest init finish
                          (cons (: (eval-export export) TestSuite) suites))
                    (loop rest init finish suites))))))
            (loop rest init finish suites)))
         (else
          (TestModule file
                      (reverse! suites)
                      []
                      (or init void)
                      (or finish void))))))
   (catch (e)
      ;; import failed
      (TestModule file
                  []
                  []
                  (lambda () (raise e))
                  void))))

(def (runtime-export? exported)
  (fx= (module-export-phi exported) 0))

(def (eval-export exported)
  (let (bind (core-resolve-module-export exported))
    (eval (binding-id bind))))
