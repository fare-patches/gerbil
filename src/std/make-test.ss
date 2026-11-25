;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Incremental make freshness and nested dependency ordering

(import :std/io/tempfile
        :std/test
        (only-in :std/error Error-message)
        (only-in :gerbil/runtime/syntax syntax-error?)
        (only-in :gerbil/compiler/base
          add-compile-job! execute-pending-compile-jobs!)
        (only-in :gerbil/compiler/driver
          ModuleDependencies-id ModuleDependencies-imports
          module-build-dependencies module-dependencies->datum datum->module-dependencies
          dependency-graph-modules)
        ./make)
(export make-test)

;; A constituent need not be imported by its parent to contribute build edges.
;; Phase imports also matter even when no phase-zero value uses their exports.
(def (test-dependency-graph (compiler? #f))
  (call-with-temporary-directory
    "gerbil-make-graph-"
    (lambda (directory)
      (def prefix (path-strip-directory directory))
      (def (write-source name forms)
        (call-with-output-file (path-expand name directory)
          (lambda (port)
            (for-each (lambda (form) (write form port) (newline port))
              forms))))
      (write-source "gerbil.pkg"
        `((package: ,(make-symbol prefix) prelude: :gerbil/base)))
      (write-source "left.ss" '((export value) (def value 1)))
      (write-source "right.ss" '((export value) (def value 2)))
      (write-source "owner.ss"
        `((export hidden)
          (module hidden
            (import ,(path-expand "left.ss" directory))
            (export answer)
            (def answer value))
          (import (phi: +1 ,(path-expand "right.ss" directory)))))
      (let* ((info (module-build-dependencies (path-expand "owner.ss" directory)))
             (imports (ModuleDependencies-imports info)))
        (check (and (memq (make-symbol prefix "/left") imports) #t) => #t)
        (check (and (memq (make-symbol prefix "/right") imports) #t) => #t)
        (check (memq (ModuleDependencies-id info) imports) => #f)
        (check (module-dependencies->datum
                 (datum->module-dependencies (module-dependencies->datum info)))
               => (module-dependencies->datum info))
        (when compiler?
          (let* ((owner (path-expand "owner.ss" directory))
                 (left (path-expand "left.ss" directory))
                 (output (path-expand "graph" directory))
                 (unused (path-expand "unused-output" directory))
                 (compiler (getenv "GERBIL_GXC" (path-expand "~~bin/gxc"))))
            (def (run arguments)
              (let (process (open-input-process [path: compiler arguments: arguments
                                                stderr-redirection: #f]))
                (try
                 (let (datum (read process))
                   (check (eof-object? (read process)) => #t)
                   (check (process-status process) => 0)
                   datum)
                 (finally (close-port process)))))
            (let (graph (run ["-deps" "-d" unused owner left]))
              (check (map ModuleDependencies-id (dependency-graph-modules graph))
                => [(ModuleDependencies-id info) (make-symbol prefix "/left")])
              (check (module-dependencies->datum (car (dependency-graph-modules graph)))
                => (module-dependencies->datum info))
              (check (eof-object? (run ["-deps" "-o" output owner left])) => #t)
              (check (call-with-input-file output read) => graph))
            (check (file-exists? unused) => #f)
            (check (file-exists? (path-expand "owner.ssi" directory)) => #f))))
      (check-exception
        (datum->module-dependencies '(module-dependencies 1 owner (bad 17)))
        error?)
      directory)))

(def (test-incremental-make (cores : :fixnum) (dependency-processes #f))
  => :void
  (call-with-temporary-directory
   "gerbil-make-test-"
   (lambda (directory)
     (def srcdir (path-expand "src" directory))
     (def libdir (path-expand "lib" directory))
     (def prefix (path-strip-directory directory))
     (def saved-load-path (load-path))
     ;; Reverse dependency order ensures scheduling, not the buildspec, orders builds.
     (def modules '("leaf" "middle" "upstream" "unrelated"))
     (def upstream '(prelude: :gerbil/core
                     (import :gerbil/core)
                     (export value (import: :gerbil/core))
                     (def value 1)))
     (def (write-source name forms)
       (call-with-output-file (path-expand name srcdir)
         (lambda (port)
           (for-each (lambda (form) (write form port) (newline port)) forms))))
     (def (build)
       (with-output-to-string
         (lambda ()
           (make modules srcdir: srcdir libdir: libdir
                 bindir: (path-expand "bin" directory)
                 parallelize: cores optimize: #f
                 dependency-processes: dependency-processes))))
     (def (timestamps)
       (map (lambda (name)
              (map (lambda (path)
                     (time->seconds
                      (file-info-last-modification-time (file-info path))))
                   (list (path-expand (string-append prefix "/" name ".ssi") libdir)
                         (path-expand (string-append "static/" prefix "__" name ".scm")
                                      libdir))))
            modules))
     (try
      (create-directory srcdir)
      (write-source "gerbil.pkg" `((package: ,(string->symbol prefix))))
      (write-source "upstream.ss" upstream)
      ;; The prelude is an implicit dependency, absent from explicit imports.
      (write-source "middle.ss"
                    `(prelude: ,(string->symbol (string-append ":" prefix "/upstream"))
                      (export nested)
                      (module nested (export result) (def result value))
                      (import nested)))
      (write-source "leaf.ss"
                    `((import (in: ,(string->symbol (string-append ":" prefix "/middle")) nested))
                      (export answer) (def answer result)))
      ;; Both dependency discovery and source compilation need the base prelude.
      (write-source "unrelated.ss"
                    '((export other lookup) (def other 2)
                      (def (lookup (table : HashTable) key) (table.ref key #f))))
      (build)
      (for-each
       (lambda (name prelude)
         (call-with-input-file
             (path-expand (string-append prefix "/" name ".ssi") libdir)
           (lambda (port)
             (check (read port) => prelude:)
             (check (read port) => prelude))))
       '("unrelated" "upstream") '(:gerbil/base :gerbil/core))
      ;; Warm dependency timestamp lookups before changing anything, in this process.
      (check (build) => "")
      (let (before (timestamps))
        ;; Rewrite identical source only to advance its mtime. Changing exports would
        ;; also exercise the expander's source cache, which is not under test here.
        (thread-sleep! 1.1)
        (write-source "upstream.ss" upstream)
        ;; Parallel builds also report the deferred native compilation jobs.
        (check (filter (cut string-prefix? "... compile " <>)
                       (string-split (build) #\newline))
               => '("... compile upstream" "... compile middle" "... compile leaf"))
        (let (after (timestamps))
          (for-each
           (lambda (old new)
             (for-each (lambda (a b) (check (> b a) => #t)) old new))
           (take before 3) (take after 3))
          (check (list-ref after 3) => (list-ref before 3))
          (check (build) => "")
          (check (timestamps) => after)))
      (let (before (timestamps))
        (thread-sleep! 1.1)
        (delete-file (path-expand (string-append prefix "/leaf.ssi") libdir))
        (check (filter (cut string-prefix? "... compile " <>)
                       (string-split (build) #\newline))
               => '("... compile leaf"))
        (let (after (timestamps))
          (for-each (lambda (a b) (check (> b a) => #t)) (car before) (car after))
          (check (cdr after) => (cdr before))
          (check (build) => "")))
      (finally
       (set-load-path! saved-load-path)))
     directory))
  (void))

(def (test-process-phased-diamond (dependency-processes #f))
  => :void
  (call-with-temporary-directory
   "gerbil-make-phases-"
   (lambda (directory)
     (def srcdir (path-expand "src" directory))
     (def libdir (path-expand "lib" directory))
     (def prefix (path-strip-directory directory))
     (def saved-load-path (load-path))
     (def (macro-source value)
       `((export number base-node make-cell)
         (defrule (number) ,value)
         ;; The inherited slot type remains private to this module.
         (defstruct hidden-cell ((value :- :fixnum)))
         (defstruct base-node ((cell :- hidden-cell)))
         (def (make-cell) (make-hidden-cell (number)))))
     (def (write-source name forms)
       (call-with-output-file (path-expand name srcdir)
         (lambda (port)
           (for-each (lambda (form) (write form port) (newline port)) forms))))
     (def (build)
       (with-output-to-string
         (lambda ()
           (make '("join" "left" "right" "macros")
                 srcdir: srcdir libdir: libdir
                 bindir: (path-expand "bin" directory) parallelize: 4
                 dependency-processes: dependency-processes))))
     (def (answer)
       (let* ((module (string->symbol (string-append ":" prefix "/join")))
              (process
               (open-process
                [path: (path-expand "~~bin/gxi")
                 arguments: ["-e" (object->string `(add-load-path! ,libdir))
                             "-e" (object->string `(import ,module))
                             "-e" "(write answer)"]
                 stderr-redirection: #f])))
         (try
          (let (result (read process))
            (check (process-status process) => 0)
            result)
          (finally (close-port process)))))
     (try
      (create-directory srcdir)
      (write-source "gerbil.pkg" `((package: ,(string->symbol prefix))))
      (write-source "macros.ss" (macro-source 7))
      (write-source "left.ss"
                    '((import ./macros)
                      (export left-node make-left-node make-cell)
                      (defstruct (left-node base-node) ())))
      (write-source "right.ss" '((import ./macros) (export right) (def right (number))))
      (write-source "join.ss"
                    '((import ./left ./right) (export answer)
                      (def (cell-value (node : left-node)) node.cell.value)
                      (def answer (+ (cell-value (make-left-node (make-cell))) right))))
      (build)
      (check (answer) => 14)
      (thread-sleep! 1.1)
      ;; Both dependent workers must see the rebuilt provider in a fresh process.
      (write-source "macros.ss" (macro-source 42))
      (build)
      (check (answer) => 84)
      (check (build) => "")
      (finally (set-load-path! saved-load-path)))
     directory))
  (void))

;; A discovery failure must not start compilation or cache a broken expansion in
;; the coordinator. A repaired source is visible to the next graph worker.
(def (test-discovery-failure-retry)
  (call-with-temporary-directory
    "gerbil-make-discovery-"
    (lambda (directory)
      (def srcdir (path-expand "src" directory))
      (def libdir (path-expand "lib" directory))
      (def prefix (path-strip-directory directory))
      (def saved-load-path (load-path))
      (def (write-source name forms)
        (call-with-output-file (path-expand name srcdir)
          (lambda (port)
            (for-each (lambda (form) (write form port) (newline port))
              forms))))
      (def (build)
        (parameterize ((current-error-port (open-output-string)))
          (with-output-to-string
            (lambda ()
              (make '("leaf" "upstream")
                srcdir: srcdir libdir: libdir
                bindir: (path-expand "bin" directory)
                parallelize: 2 dependency-processes: #t)))))
      (try
       (create-directory srcdir)
       (write-source "gerbil.pkg" `((package: ,(make-symbol prefix))))
       (write-source "upstream.ss" '((export value) (def)))
       (write-source "leaf.ss" '((import ./upstream) (export answer) (def answer value)))
       (check-exception (build)
         (lambda (exn)
           (and (error? exn)
                (equal? (Error-message exn) "source compiler process failed"))))
       (check (file-exists? (path-expand (string-append prefix "/leaf.ssi") libdir)) => #f)
       (write-source "upstream.ss" '((export value) (def value 7)))
       (build)
       (check (file-exists? (path-expand (string-append prefix "/leaf.ssi") libdir)) => #t)
       (check (build) => "")
       (finally (set-load-path! saved-load-path)))
      directory)))

(def (test-process-failure-retry)
  => :void
  (call-with-temporary-directory
   "gerbil-make-retry-"
   (lambda (directory)
     (def srcdir (path-expand "src" directory))
     (def libdir (path-expand "lib" directory))
     (def prefix (path-strip-directory directory))
     (def saved-load-path (load-path))
     (def saved-gsc (getenv "GERBIL_GSC" #f))
     (def diagnostics (open-output-string))
     (def marker (path-expand (string-append ".make/pending/" prefix "/upstream.pending") libdir))
     (def (write-source name forms)
       (call-with-output-file (path-expand name srcdir)
         (lambda (port)
           (for-each (lambda (form) (write form port) (newline port)) forms))))
     (def (build)
       (parameterize ((current-error-port diagnostics))
         (with-output-to-string
           (lambda ()
             (make '("leaf" "upstream" "independent")
                   srcdir: srcdir libdir: libdir
                   bindir: (path-expand "bin" directory)
                   parallelize: 2)))))
     (try
      (create-directory srcdir)
      (write-source "gerbil.pkg" `((package: ,(string->symbol prefix))))
      ;; Expansion succeeds, but the compiler rejects the return contract.
      (write-source "upstream.ss"
                    '((export value) (def (value) => :fixnum "bad-return")))
      (write-source "leaf.ss"
                    '((import ./upstream) (export answer) (def (answer) (value))))
      (write-source "independent.ss" '((export other) (def other 2)))
      (check-exception (build)
                       (lambda (exn)
                         (and (error? exn)
                              (equal? (Error-message exn) "source compiler process failed"))))
      (check (file-exists? marker) => #t)
      (let (output (get-output-string diagnostics))
        (check (string-contains output "upstream.ss") ? number?)
        (check (string-contains output "return type") ? number?))
      ;; A fresh child sees the repair even though discovery cached the module.
      (write-source "upstream.ss" '((export value) (def (value) => :fixnum 7)))
      ;; Failing native compilation leaves the provider pending. Its dependent
      ;; must not publish any output until the repaired provider is usable.
      (setenv "GERBIL_GSC" "/bin/false")
      (check-exception (build)
                       (lambda (exn)
                         (syntax-error? (if (uncaught-exception? exn)
                                          (uncaught-exception-reason exn)
                                          exn))))
      (check (file-exists? marker) => #t)
      (check (file-exists? (path-expand (string-append prefix "/leaf.ssi") libdir)) => #f)
      (if saved-gsc (setenv "GERBIL_GSC" saved-gsc) (setenv "GERBIL_GSC"))
      (build)
      (check (file-exists? marker) => #f)
      (check (file-exists? (path-expand (string-append prefix "/leaf.ssi") libdir)) => #t)
      (check (build) => "")
      (finally
       (if saved-gsc (setenv "GERBIL_GSC" saved-gsc) (setenv "GERBIL_GSC"))
       (close-port diagnostics)
       (set-load-path! saved-load-path)))
     directory))
  (void))

(def (test-process-cancellation (dependency-processes #f))
  => :void
  (call-with-temporary-directory
   "gerbil-make-cancel-"
   (lambda (directory)
     (def srcdir (path-expand "src" directory))
     (def wrapper (path-expand "worker" directory))
     (def pidfile (path-expand "blocked.pid" directory))
     (def diagnostics (open-output-string))
     (def saved-load-path (load-path))
     (def saved-gxc (getenv "GERBIL_GXC" #f))
     (def saved-state (getenv "GERBIL_MAKE_TEST_STATE" #f))
     (try
      (create-directory srcdir)
      (for-each
       (lambda (entry)
         (call-with-output-file (path-expand (car entry) srcdir)
           (cut display (cdr entry) <>)))
       [["gerbil.pkg" . "(package: make-cancel-test)\n"]
        ["failure.ss" . "(export value) (def value 1)\n"]
        ["blocked.ss" . "(export other) (def other 2)\n"]
        ["dependent.ss" . "(import ./failure) (def result value)\n"]])
      ;; Both children are running before failure. The blocked child ignores TERM
      ;; so cancellation must also exercise its bounded KILL/reap fallback.
      (with-output-to-file [path: wrapper permissions: #o755]
        (lambda ()
          (display "#!/bin/sh\ncase \"$*\" in\n*failure.ss*)\n  while [ ! -f \"$GERBIL_MAKE_TEST_STATE/blocked.pid\" ]; do sleep 0.01; done\n  awk 'BEGIN { for (i=0; i<32768; i++) print \"worker output exceeds pipe capacity\" }'\n  echo 'final worker diagnostic' >&2\n  exit 17;;\n*)\n  trap '' TERM\n  echo $$ > \"$GERBIL_MAKE_TEST_STATE/blocked.pid\"\n  exec sleep 60;;\nesac\n")))
      (setenv "GERBIL_GXC" wrapper)
      (setenv "GERBIL_MAKE_TEST_STATE" directory)
      (parameterize ((current-error-port diagnostics))
        (check-exception
         (with-output-to-string
           (lambda ()
             (make '("dependent" "failure" "blocked")
                   srcdir: srcdir libdir: (path-expand "lib" directory)
                   bindir: (path-expand "bin" directory) parallelize: 2
                   dependency-processes: dependency-processes)))
         (lambda (exn)
           (and (error? exn)
                (equal? (Error-message exn) "source compiler process failed")))))
      (let (output (get-output-string diagnostics))
        (check (> (string-length output) 1048576) => #t)
        (check (string-contains output "final worker diagnostic") ? number?))
      (check (file-exists? pidfile) => #t)
      (let (process (open-process
                     [path: "/bin/sh"
                      arguments: ["-c" "kill -0 \"$1\" 2>/dev/null" "worker-probe"
                                  (call-with-input-file pidfile read-line)]]))
        (try
         (check (zero? (process-status process)) => #f)
         (finally (close-port process))))
      (finally
       (if saved-gxc (setenv "GERBIL_GXC" saved-gxc) (setenv "GERBIL_GXC"))
       (if saved-state (setenv "GERBIL_MAKE_TEST_STATE" saved-state) (setenv "GERBIL_MAKE_TEST_STATE"))
       (set-load-path! saved-load-path)
       (close-port diagnostics)))
     directory))
  (void))

(def (test-process-build-options)
  => :void
  (call-with-temporary-directory
   "gerbil-make-options-"
   (lambda (directory)
     (def srcdir (path-expand "src" directory))
     (def libdir (path-expand "lib" directory))
     (def prefix (path-strip-directory directory))
     (def saved-load-path (load-path))
     (def saved-gxc (getenv "GERBIL_GXC" #f))
     (def (write-text name text)
       (call-with-output-file (path-expand name srcdir) (cut display text <>)))
     (try
      (create-directory srcdir)
      (write-text "gerbil.pkg" (string-append "(package: " prefix ")\n"))
      (write-text "payload.txt" "copied input\n")
      (write-text "module.ss"
                  "(export value)\n(begin-foreign (c-declare \"#ifndef MAKE_TEST_OPTION\\n#error missing native option\\n#endif\\n\"))\n(def value 7)\n")
      ;; foreground: must bypass the child executable, and the trailing native
      ;; options must survive normalization of the preceding copy specification.
      (setenv "GERBIL_GXC" "/bin/false")
      (with-output-to-string
        (lambda ()
          (make '((copy: "payload.txt")
                  (gxc: "module" (foreground: #t) "-cc-options" "-DMAKE_TEST_OPTION"))
                srcdir: srcdir libdir: libdir
                bindir: (path-expand "bin" directory) parallelize: 2)))
      (check (call-with-input-file
              (path-expand (string-append prefix "/payload.txt") libdir) read-line)
             => "copied input")
      (check (file-exists? (path-expand (string-append prefix "/module.ssi") libdir)) => #t)
      (check (file-exists? (path-expand (string-append prefix "/module~0.o1") libdir)) => #t)
      (finally
       (if saved-gxc (setenv "GERBIL_GXC" saved-gxc) (setenv "GERBIL_GXC"))
       (set-load-path! saved-load-path)))
     directory))
  (void))

(def make-test
  (test-suite "test :std/make"
    (test-case "native compilation honors an explicit concurrency limit"
      (def (peak-jobs cores)
        (let ((active 0) (peak 0))
          (for-each
           (lambda (i)
             (add-compile-job!
              (lambda ()
                (set! active (1+ active))
                (set! peak (max peak active))
                (thread-sleep! 0.05)
                (set! active (1- active)))
              i))
           (iota 8))
          (execute-pending-compile-jobs! cores)
          (check active => 0)
          peak))
      (check (peak-jobs 8) => 8)
      (check (peak-jobs 1) => 1))
    (test-case "native failure waits for every started job"
      (let (finished? #f)
        (add-compile-job! (lambda () (error "expected native job failure")) 'expected-failure)
        (add-compile-job! (lambda () (thread-sleep! 0.1) (set! finished? #t)) 'slow-job)
        (check-exception (execute-pending-compile-jobs!)
                         (lambda (exn)
                           (and (error? exn)
                                (equal? (Error-message exn) "expected native job failure"))))
        (check finished? => #t)))
    (test-case "incremental chain with in-process compilation"
      (test-incremental-make 0))
    (test-case "dependency graph includes unimported constituents and phases"
      (test-dependency-graph))
    (test-case "compiler dependency CLI supports batches and output files without compilation"
      (test-dependency-graph #t))
    (test-case "incremental chain with one worker"
      (test-incremental-make 1))
    (test-case "incremental chain with parallel workers"
      (test-incremental-make 4))
    (test-case "incremental chain with isolated dependency discovery"
      (test-incremental-make 4 #t))
    (test-case "incremental chain with per-module discovery workers"
      (test-incremental-make 4 'module))
    (test-case "incremental chain with package discovery batches"
      (test-incremental-make 4 'package))
    (test-case "phased diamond preserves private types and uses fresh source"
      (test-process-phased-diamond))
    (test-case "isolated discovery preserves phased dependency ordering"
      (test-process-phased-diamond #t))
    (test-case "discovery failure admits a repaired source on retry"
      (test-discovery-failure-retry))
    (test-case "source process failure releases dependents and permits retry"
      (test-process-failure-retry))
    (test-case "large worker diagnostics and cooperative cancellation"
      (test-process-cancellation))
    (test-case "dependency worker failure cancels and reaps discovery processes"
      (test-process-cancellation 'module))
    (test-case "copied inputs preserve foreground and native compiler options"
      (test-process-build-options))))
