;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Incremental make freshness and nested dependency ordering

(import :std/io/tempfile
        :std/misc/process
        :std/test
        ./make)
(export make-test make-output-integrity-test)

(def (test-incremental-make (cores : :fixnum))
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
     (def upstream '((export value) (def value 1)))
     (def (write-source name forms)
       (call-with-output-file (path-expand name srcdir)
         (lambda (port)
           (for-each (lambda (form) (write form port) (newline port)) forms))))
     (def (build)
       (with-output-to-string
         (lambda ()
           (make modules srcdir: srcdir libdir: libdir
                 bindir: (path-expand "bin" directory)
                 parallelize: cores optimize: #f))))
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
      (write-source "middle.ss"
                    '((import ./upstream)
                      (export nested)
                      (module nested (export result) (def result value))
                      (import nested)))
      (write-source "leaf.ss"
                    `((import (in: ,(string->symbol (string-append ":" prefix "/middle")) nested))
                      (export answer) (def answer result)))
      (write-source "unrelated.ss" '((export other) (def other 2)))
      (build)
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
      (finally
       (set-load-path! saved-load-path)))
     directory))
  (void))

(def make-test
  (test-suite "test :std/make"
    (test-case "incremental chain with one worker"
      (test-incremental-make 1))
    (test-case "incremental chain with parallel workers"
      (test-incremental-make 4))))

;;; Build output integrity across failed and resumed builds.
;;; Every make below runs in a fresh gxi, as a real rebuild would: in-process, the
;;; native compile jobs that a failed parallel make leaves queued in
;;; :gerbil/compiler/base would run at the end of the next make and mask staleness.
;;; The subprocess uses the installed :std/make, not ./make.

(def (run-gxi forms)
  ;; => #t on success, else the process output for the failure report
  (def status #f)
  (def output
    (run-process [(path-expand "gxi" (path-expand "~~bin"))
                  (foldr (lambda (form args) (cons* "-e" (object->string form) args))
                         [] forms) ...]
                 stdin-redirection: #f stderr-redirection: #t
                 check-status: (lambda (s _) (set! status s))))
  (or (zero? status) output))

(def (make/subprocess modules directory cores)
  (run-gxi ['(import :std/make)
            `(make ',modules
                   srcdir: ,(path-expand "src" directory)
                   libdir: ,(path-expand "lib" directory)
                   bindir: ,(path-expand "bin" directory)
                   parallelize: ,cores optimize: #t)]))

(def (write-forms path forms)
  (call-with-output-file path
    (lambda (port) (for-each (lambda (form) (write form port) (newline port)) forms))))

(def (file-mtime path)
  (time->seconds (file-info-last-modification-time (file-info path))))

(def (file-checksum path)
  ;; FNV-1a style; keeps check failure reports short.
  (let* ((n (file-info-size (file-info path)))
         (bytes (make-u8vector n)))
    (call-with-input-file path (lambda (port) (read-subu8vector bytes 0 n port)))
    (let lp ((i 0) (h 2166136261))
      (if (fx< i n)
        (lp (fx1+ i) (fxand (fx* (fxxor h (u8vector-ref bytes i)) 16777619) #xffffffff))
        h))))

(def (library-snapshot libdir)
  ;; => [[relative-path mtime checksum] ...] for every file under libdir, sorted
  (def (walk dir rel acc)
    (foldl (lambda (name acc)
             (let ((path (path-expand name dir))
                   (rel (if rel (string-append rel "/" name) name)))
               (if (eq? (file-info-type (file-info path)) 'directory)
                 (walk path rel acc)
                 (cons [rel (file-mtime path) (file-checksum path)] acc))))
           acc (directory-files dir)))
  (list-sort (lambda (x y) (string<? (car x) (car y))) (walk libdir #f [])))

(def (object-file-entry? entry)
  (string-prefix? ".o" (path-extension (car entry))))

(def (latest-object-file scm)
  ;; gsc writes base.o1 beside base.scm, then base.o2, ... on rebuilds.
  (let (base (path-strip-extension scm))
    (let lp ((n 1) (last #f))
      (let (next (string-append base ".o" (number->string n)))
        (if (file-exists? next) (lp (fx1+ n) next) last)))))

(def (stale-object-files libdir prefix)
  ;; => module .scm files under libdir/prefix lacking a newer object file
  (let (dir (path-expand prefix libdir))
    (filter (lambda (name)
              (let* ((scm (path-expand name dir))
                     (obj (latest-object-file scm)))
                ;; >=: file-info times may have one-second resolution.
                (not (and obj (>= (file-mtime obj) (file-mtime scm))))))
            (list-sort string<?
                       (filter (lambda (name) (equal? (path-extension name) ".scm"))
                               (directory-files dir))))))

(def (call-with-package proc)
  (call-with-temporary-directory
   "gerbil-make-test-"
   (lambda (directory)
     (def prefix (path-strip-directory directory))
     (def srcdir (path-expand "src" directory))
     (create-directory srcdir)
     (write-forms (path-expand "gerbil.pkg" srcdir) [`(package: ,(string->symbol prefix))])
     (proc directory prefix
           (lambda (name . forms) (write-forms (path-expand name srcdir) forms))
           (path-expand "lib" directory)))))

;; A parallel make runs gxc for a module at once but defers gsc until every module is
;; compiled; when another module fails first, the next make must not take the
;; modules lacking object files for up to date.
(def (test-resume-aborted-parallel-build)
  (call-with-package
   (lambda (directory prefix source libdir)
     (def modules '("a" "b" "c"))
     (def (c-source value) (source "c.ss" '(import ./a) '(export c-value) `(def (c-value) ,value)))
     (source "a.ss" '(export a-value) '(def (a-value) 42))
     (source "b.ss" '(import ./a) '(export b-value) '(def (b-value) (+ 1 (a-value))))
     ;; The arity error surfaces in gxc after expansion (a plain syntax error aborts
     ;; make before any build); c imports a, so gxc always runs on a before c fails.
     ;; a's .ssi is published last, after its deferred gsc jobs: none of them ran,
     ;; so a must be left unpublished, with no object files.
     (c-source '(car (a-value) 2))
     (check (string? (make/subprocess modules directory 2)) => #t)
     (check (map (lambda (ext) (file-exists? (path-expand (string-append prefix "/a" ext) libdir)))
                 '(".scm" ".ssi" ".o1" "~0.o1"))
            => '(#t #f #f #f))
     (c-source '(car [(a-value) 2]))
     (check (make/subprocess modules directory 2) => #t)
     (check (stale-object-files libdir prefix) => [])
     (check (run-gxi [`(add-load-path! ,libdir)
                      `(import ,(string->symbol (string-append ":" prefix "/b")))
                      '(exit (if (= (b-value) 43) 0 1))])
            => #t))))

;; A gxc failure must leave the previous outputs of the module untouched.
(def (test-gxc-failure-keeps-outputs cores bad-body)
  (call-with-package
   (lambda (directory prefix source libdir)
     (def modules '("a" "b"))
     (source "a.ss" '(export a-value) '(def (a-value) 42))
     (source "b.ss" '(import ./a) '(export b-value) '(def (b-value) (+ 1 (a-value))))
     (check (make/subprocess modules directory cores) => #t)
     (let (before (library-snapshot libdir))
       (thread-sleep! 1.1)
       (source "a.ss" '(export a-value) `(def (a-value) ,bad-body))
       (check (string? (make/subprocess modules directory cores)) => #t)
       (check (library-snapshot libdir) => before)))))

;; A gsc failure must leave no new or partial object files, and the next make must
;; retry gsc even though the module source did not change: the C error comes from a
;; header outside make's view, standing in for any transient gsc failure.
(def (test-gsc-failure-keeps-objects cores)
  (call-with-package
   (lambda (directory prefix source libdir)
     (def modules '("d"))
     (def header (path-expand "d.h" directory))
     (def (header-source text) (call-with-output-file header (cut display text <>)))
     (def (d-source)
       (source "d.ss" '(export d-value)
               `(begin-foreign (c-declare ,(string-append "#include \"" header "\"")))
               '(def (d-value) 4)))
     (header-source "static int d_ok = 1;\n")
     (d-source)
     (check (make/subprocess modules directory cores) => #t)
     (let (before (library-snapshot libdir))
       (thread-sleep! 1.1)
       (header-source "this is not C\n")
       (d-source)
       (check (string? (make/subprocess modules directory cores)) => #t)
       (let (after (library-snapshot libdir))
         (check (map car after) => (map car before))
         (check (filter object-file-entry? after) => (filter object-file-entry? before))))
     (header-source "static int d_ok = 2;\n")
     (check (make/subprocess modules directory cores) => #t)
     (check (stale-object-files libdir prefix) => []))))

;; Break publication after a's final native compile succeeds. Its dependent b
;; must roll back rather than publish or wait forever for a's result.
(def (test-parallel-publication-failure (block-rollback? : :boolean)) => :void
  (call-with-package
   (lambda (directory prefix source libdir)
     (def a (path-expand "a" (path-expand prefix libdir)))
     (def b (path-expand "b" (path-expand prefix libdir)))
     (def ssi (string-append a ".ssi"))
     (def update (string-append ssi ".new"))
     (def saved-update (string-append ssi ".moved"))
     (def wrapper (path-expand "gsc-wrapper" directory))
     (source "a.ss" '(export a-value) '(def (a-value) 42))
     (source "b.ss" '(import ./a) '(export b-value) '(def (b-value) (+ 1 (a-value))))
     (call-with-output-file [path: wrapper permissions: #o700]
       (lambda (port)
         (display "#!/bin/sh\nset -e\nfor arg do last=$arg; done\n" port)
         (display "\"$MAKE_TEST_GSC\" \"$@\"\n" port)
         (display "if [ \"$last\" = \"$MAKE_TEST_A_SCM\" ]; then\n" port)
         (display "  mv \"$MAKE_TEST_A_SSI.new\" \"$MAKE_TEST_A_SSI.moved\"\n" port)
         (when block-rollback?
           (display "  mkdir \"$MAKE_TEST_A_SSI\"\n" port))
         (display "fi\n" port)))
     (check
      (run-gxi
       ['(import :std/error :std/make)
        '(spawn-thread
          (lambda ()
            (thread-sleep! 15)
            (displayln "timed out waiting for parallel make to report publication failure")
            (exit 124)))
        `(begin
           (setenv "MAKE_TEST_GSC" (getenv "GERBIL_GSC" (path-expand "~~bin/gsc")))
           (setenv "MAKE_TEST_A_SCM" ,(string-append a ".scm"))
           (setenv "MAKE_TEST_A_SSI" ,ssi)
           (setenv "GERBIL_GSC" ,wrapper))
        `(with-catch
          (lambda (e)
            (def details
              (parameterize ((dump-stack-trace? #f))
                (let describe ((e e))
                  (apply string-append (exception->string e)
                         (map describe (filter Exception? (or (error-irritants e) [])))))))
            (unless
                ,(if block-rollback?
                   `(and (string-contains details ,(string-append "(rename-file " (object->string update)))
                         (string-contains details ,(string-append "(delete-file " (object->string ssi))))
                   `(and (no-such-file-or-directory-exception? e)
                         (eq? (no-such-file-or-directory-exception-procedure e) rename-file)
                         (equal? (no-such-file-or-directory-exception-arguments e)
                                 (list ,update ,ssi #t))))
              (display details)
              (exit 1)))
          (lambda ()
            (make '("b" "a")
                  srcdir: ,(path-expand "src" directory)
                  libdir: ,libdir
                  bindir: ,(path-expand "bin" directory)
                  parallelize: 2 optimize: #f)
            (displayln "make unexpectedly returned successfully")
            (exit 1)))])
      => #t)
     (check (file-exists? saved-update) => #t)
     (check (file-exists? (string-append b ".ssi")) => #f)
     (check (file-exists? (string-append b ".ssi.new")) => #f)))
  (void))

(def make-output-integrity-test
  (test-suite "test :std/make output integrity"
    (test-case "resumed parallel build recompiles modules whose gsc jobs never ran"
      (test-resume-aborted-parallel-build))
    (test-case "expansion failure keeps previous outputs, one worker"
      (test-gxc-failure-keeps-outputs 1 '(let)))
    (test-case "expansion failure keeps previous outputs, parallel workers"
      (test-gxc-failure-keeps-outputs 2 '(let)))
    (test-case "gxc compile failure keeps previous outputs, one worker"
      (test-gxc-failure-keeps-outputs 1 '(car 1 2)))
    (test-case "gxc compile failure keeps previous outputs, parallel workers"
      (test-gxc-failure-keeps-outputs 2 '(car 1 2)))
    (test-case "gsc failure keeps previous objects and is retried, one worker"
      (test-gsc-failure-keeps-objects 1))
    (test-case "gsc failure keeps previous objects and is retried, parallel workers"
      (test-gsc-failure-keeps-objects 2))
    (test-case "parallel publication failure reaches caller and rolls back dependent"
      (test-parallel-publication-failure #f))
    (test-case "parallel publication and rollback failures both reach caller"
      (test-parallel-publication-failure #t))))
