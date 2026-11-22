;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Incremental make freshness and nested dependency ordering

(import (prefix-in :gerbil/compiler/base compiler.)
        :std/source
        :std/io/tempfile
        :std/misc/process
        :std/test
        ./make)
(extern namespace: std/make run-compile-jobs!)
(export make-test make-output-integrity-test make-publication-test)

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

(def (run-gxi forms (env []))
  ;; => #t on success, else the process output for the failure report
  (def status #f)
  (def output
    (run-process ["env" env ... (path-expand "gxi" (path-expand "~~bin"))
                  (foldr (lambda (form args) (cons* "-e" (object->string form) args))
                         [] forms) ...]
                 stdin-redirection: #f stderr-redirection: #t
                 check-status: (lambda (s _) (set! status s))))
  (or (zero? status) output))

(def (make/subprocess modules directory cores (setup []))
  (run-gxi ['(import :std/make) setup ...
            `(make ',modules
                   srcdir: ,(path-expand "src" directory)
                   libdir: ,(path-expand "lib" directory)
                   bindir: ,(path-expand "bin" directory)
                   parallelize: ,cores optimize: #t)]
           ;; The native queue reads its limit before make is invoked; the
           ;; sibling barrier requires two actual gsc processes simultaneously.
           [(string-append "GERBIL_BUILD_CORES=" (number->string cores))]))

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

(def (library-snapshot libdir (include? true))
  ;; => [[relative-path mtime checksum] ...] for every file under libdir, sorted
  (def (walk dir rel acc)
    (foldl (lambda (name acc)
             (let ((path (path-expand name dir))
                   (rel (if rel (string-append rel "/" name) name)))
               (if (eq? (file-info-type (file-info path)) 'directory)
                 (walk path rel acc)
                 (cons [rel (file-mtime path) (file-checksum path)] acc))))
           acc (filter include? (directory-files dir))))
  (list-sort (lambda (x y) (string<? (car x) (car y))) (walk libdir #f [])))

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
            => (cond-expand ((defined compiler.current-compile-defer) '(#f #f #f #f))
                            (else '(#t #f #f #f))))
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
       (cond-expand
        ((defined compiler.current-compile-defer) (check (library-snapshot libdir) => before))
        (else
         (def (object? entry) (string-prefix? ".o" (path-extension (car entry))))
         (let (after (library-snapshot libdir))
           (check (map car after) => (map car before))
           (check (filter object? after) => (filter object? before))))))
     (header-source "static int d_ok = 2;\n")
     (check (make/subprocess modules directory cores) => #t)
     (check (stale-object-files libdir prefix) => []))))

;; Break publication after a's final native compile succeeds. Its dependent b
;; must roll back rather than publish or wait forever for a's result.
(def (test-legacy-publication-failure (block-rollback? : :boolean)) => :void
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

(def test-wrapper (path-expand "make-test-gsc.sh" (this-source-directory)))

(def (wrap-gsc (directory : :string) (mode : :string)) => :list
  ['(spawn-thread (lambda () (thread-sleep! 90) (displayln "gsc fixture timeout") (exit 124)))
   `(setenv "MAKE_TEST_CONTROL" ,directory)
   `(setenv "MAKE_TEST_MODE" ,mode)
   '(setenv "MAKE_TEST_GSC" (getenv "GERBIL_GSC" (path-expand "~~bin/gsc")))
   `(setenv "GERBIL_GSC" ,test-wrapper)])

(def (write-nested (source : :procedure) (value : :fixnum)) => :void
  (source "a.ss" '(export inner outer)
          `(module inner (export answer) (def (answer) ,value))
          '(def (outer) 10))
  (void))

(def (load-nested (prefix : :string) (libdir : :string) (expected : :fixnum))
  (run-gxi [`(add-load-path! ,libdir)
            `(import (in: ,(string->symbol (string-append ":" prefix "/a")) inner))
            `(exit (if (= (answer) ,expected) 0 1))]))

(def (wait-for-barrier (path : :string) (job :~ thread?) (allow-early-exit? #f))
  (let lp ((n 600))
    (cond
     ((file-exists? path) (void))
     ((thread-join! job 0 #f) => (lambda (result)
                                  (unless allow-early-exit?
                                    (error "build exited before barrier" path result))))
     ((zero? n) (error "timed out at gsc barrier" path))
     (else (thread-sleep! 0.1) (lp (fx1- n))))))

;; Read all previously published files, including the interface, and detect any
;; new public object. Private files and unfinished-build markers may coexist.
(def (public-snapshot (libdir : :string)) => :list
  (library-snapshot libdir
    (lambda (name)
      (not (or (string-prefix? "gxtmp" name)
               (string-suffix? ".ssi.old" name)
               (string-suffix? ".ssi.new" name))))))

;; make's freshness comparison has one-second resolution. Backdate a public
;; output to force one rebuild without racing the clock or changing the input.
(def (backdate-static! (prefix : :string) (libdir : :string)) => :void
  (run-process ["touch" "-t" "200001010000"
                (path-expand (string-append "static/" prefix "__a.scm") libdir)])
  (void))

(def (test-precommit-failure (parallel? : :boolean)) => :void
  (call-with-package
   (lambda (directory prefix source libdir)
     (def mode (if parallel? "siblings" "link-failure"))
     (def release (path-expand "release" directory))
     (write-nested source 1)
     (check (make/subprocess '("a") directory 1) => #t)
     (backdate-static! prefix libdir)
     (let (before (library-snapshot libdir))
       (write-nested source 2)
        (let* ((job (spawn-thread
                     (lambda ()
                       (make/subprocess '("a") directory (if parallel? 4 1)
                         (wrap-gsc directory mode)))))
               (during
                (unwind-protect
                  (begin
                    (wait-for-barrier (path-expand (if parallel? "failed" "ready") directory) job)
                    [(public-snapshot libdir) (load-nested prefix libdir 1)])
                  (begin (call-with-output-file release void) (thread-join! job))))
               (result (thread-join! job)))
          (check (string? result) => #t)
          (check (string-contains result "gsc fixture timeout") => #f)
          (if parallel?
            (check (file-exists? (path-expand "late-success" directory)) => #t)
            (check (and (string-contains result "missing_gerbil_make_test_library") #t) => #t))
          (check during => [before #t]))
       (check (library-snapshot libdir) => before)
       (check (load-nested prefix libdir 1) => #t))))
  (void))

(def (test-replacement (custom? : :boolean)) => :void
  (call-with-package
   (lambda (directory prefix source libdir)
     (def stem (path-expand "a" (path-expand prefix libdir)))
     (def host-prefix "gxtmpbuilder.1234.")
     (def setup
       (append (wrap-gsc directory "trace")
               (if custom?
                 ['(import :gerbil/compiler/base)
                  `(current-compile-temporary-prefix (lambda () ,host-prefix))]
                 [])))
     (def (compile!)
       (run-gxi ['(import :gerbil/compiler) setup ...
                 `(compile-module ,(path-expand "src/a.ss" directory)
                    [output-dir: ,libdir optimize: #t generate-ssxi: #t
                     invoke-gsc: #t keep-scm: #t])]))
     (write-nested source 1)
     (check (compile!) => #t)
     (check (load-nested prefix libdir 1) => #t)
     (let (input (call-with-input-file (path-expand "input" directory) read-line))
       (check (path-directory input) => (path-directory stem))
       (check (string-prefix? (if custom? host-prefix "gxtmp") (path-strip-directory input)) => #t)
       (write-nested source 2)
       ;; Leave the exact pathname previously passed to gsc occupied. A new
       ;; attempt may choose another name, or explicitly fail on collision.
       (when custom? (call-with-output-file input (cut display "other writer" <>)))
       (let (result (compile!))
         (when custom?
           (check (call-with-input-file input read-line) => "other writer")
           (delete-file input))
         (if (and custom? (string? result))
           (begin (check (load-nested prefix libdir 1) => #t) (check (compile!) => #t))
           (check result => #t))))
     (check (load-nested prefix libdir 2) => #t)
     (for-each
      (lambda (suffix) (check (file-exists? (string-append stem suffix)) => #t))
      '(".ssi" ".ssxi.ss" ".scm" ".o1" ".o2" "~0.scm" "~0.o2" "~inner~0.o2"))
     (check (file-exists? (path-expand (string-append "static/" prefix "__a.scm") libdir)) => #t)
     (check (library-snapshot libdir) => (public-snapshot libdir))
     (unless custom?
       ;; Gambit fills the first hole without replacing later versions.
       (let* ((first (string-append stem "~0.o1"))
              (next (string-append stem "~0.o2"))
              (later-checksum (file-checksum next)))
         (delete-file first)
         (check (compile!) => #t)
         (check (file-exists? first) => #t)
         (check (file-checksum next) => later-checksum)
         (check (file-exists? (string-append stem "~0.o3")) => #f)))))
  (void))

(def (test-legacy-markers) => :void
  (call-with-package
   (lambda (directory prefix source libdir)
     (def stem (path-expand "a" (path-expand prefix libdir)))
     (def ssi (string-append stem ".ssi"))
     (source "a.ss" '(export answer) '(def (answer) 7))
     (check (make/subprocess '("a") directory 2) => #t)
     (for-each
      (lambda (suffix n)
        (let (marker (string-append ssi suffix))
          (copy-file ssi marker)
          (check (make/subprocess '("a") directory 2) => #t)
          (check (file-exists? marker) => #f)
          (check (file-exists? (string-append stem "~0.o" n)) => #t)))
      '(".new" ".old") '("2" "3"))))
  (void))

;; Two independent gxi processes compile immutable, different sources to the
;; same module id. At the loader barrier each has already compiled its runtime
;; section and selected its loader object. Only the driver decides who wins.
(def (test-live-object-collision (custom? : :boolean)) => :void
  (call-with-package
   (lambda (directory prefix source libdir)
     (def id (string->symbol (string-append ":" prefix "/a")))
     (def (fixture name version)
       (let (dir (path-expand name directory))
         (create-directory dir)
         (write-forms (path-expand "gerbil.pkg" dir) [`(package: ,(string->symbol prefix))])
         (write-forms (path-expand "a.ss" dir)
           ['(export interface-value runtime-value)
            `(defrule (interface-value) ,version)
            `(def (runtime-value) ,version)])
         dir))
     (def seed (fixture "seed" 1))
     (def left (fixture "left" 2))
     (def right (fixture "right" 3))
     (def (load-version n)
       (run-gxi [`(add-load-path! ,libdir) `(import ,id)
                 `(exit (if (and (= (interface-value) ,n) (= (runtime-value) ,n)) 0 1))]))
     (def (compile! dir race?)
       (run-gxi ['(import :gerbil/compiler :gerbil/compiler/base)
                 (if custom?
                   ['(current-compile-temporary-prefix (lambda () "gxtmpcontest.123."))]
                   []) ...
                 (if race? (wrap-gsc dir "race") []) ...
                 `(compile-module ,(path-expand "a.ss" dir)
                    [output-dir: ,libdir invoke-gsc: #t keep-scm: #t])]))
     (def (release! dir) (call-with-output-file (path-expand "release" dir) void))
     (def (selected dir) (map (lambda (file) (call-with-input-file (path-expand file dir) read-line))
                              '("section" "loader")))
     (check (compile! seed #f) => #t)
     (check (load-version 1) => #t)
     (let* ((before (library-snapshot libdir))
            (first (spawn-thread (cut compile! left #t)))
            (second #f))
       (unwind-protect
         (begin
           (wait-for-barrier (path-expand "ready" left) first)
           (set! second (spawn-thread (cut compile! right #t)))
           (wait-for-barrier (path-expand "ready" right) second #t)
           (let ((during (public-snapshot libdir))
                 (loaded (load-version 1)))
             (release! left)
             (let* ((r1 (thread-join! first))
                    (middle (public-snapshot libdir))
                    (middle-loaded (load-version (if (eq? r1 #t) 2 1))))
               (release! right)
               (let* ((r2 (thread-join! second))
                      (after (library-snapshot libdir)))
                 (check during => before)
                 (when (file-exists? (path-expand "ready" right))
                   (check (equal? (call-with-input-file (path-expand "loader-input" left) read-line)
                                  (call-with-input-file (path-expand "loader-input" right) read-line))
                          => #f))
                 (check loaded => #t)
                 (check middle-loaded => #t)
                 (check (or (eq? r1 #t) (eq? r2 #t)) => #t)
                 (check (load-version (if (eq? r2 #t) 3 2)) => #t)
                 (check after => (public-snapshot libdir))
                 (for-each
                  (lambda (name)
                    (check (file-exists? (path-expand name (path-expand prefix libdir))) => #t))
                  '("a~0.o2" "a.o2"))
                 ;; Existing object versions remain byte-for-byte unchanged,
                 ;; even when both processes can reserve different versions.
                 (for-each
                  (lambda (entry)
                    (when (string-prefix? ".o" (path-extension (car entry)))
                      (check (assoc (car entry) after) => entry)))
                  middle)
                 (cond
                  ((and (eq? r1 #t) (eq? r2 #t))
                   (check (selected left) => '("a~0.o2" "a.o2"))
                   (check (selected right) => '("a~0.o3" "a.o3")))
                  (else
                   (let* ((left-lost? (not (eq? r1 #t)))
                          (failure (if left-lost? r1 r2)))
                     (check (string? failure) => #t)
                     (check (string-contains failure "timeout") => #f)
                     (if left-lost? (check middle => before) (check after => middle))
                     ;; The same source, prefix, wrapper and arguments succeed
                     ;; when rerun alone (its release barrier is already open).
                     (check (compile! (if left-lost? left right) #t) => #t)
                     (check (load-version (if left-lost? 2 3)) => #t))))))))
         (begin
           (release! left)
           (release! right)
           (thread-join! first)
           (when second (thread-join! second)))))))
  (void))

;; Obstruct an ordinary destination after gsc succeeds. Versioned objects
;; are renamed first; the primary's generation is untouched by the fixture.
(def (test-parallel-publication-failure) => :void
  (call-with-package
   (lambda (directory prefix source libdir)
     (def a (path-expand "a" (path-expand prefix libdir)))
     (def b (path-expand "b" (path-expand prefix libdir)))
     (def ssi (string-append a ".ssi"))
     (def section (string-append a "~0.scm"))
     (def static (path-expand (string-append "static/" prefix "__a.scm") libdir))
     (def marker (string-append ssi ".new"))
     (source "a.ss" '(export a-value) '(def (a-value) 42))
     (source "b.ss" '(import ./a) '(export b-value) '(def (b-value) (+ 1 (a-value))))
     (check (make/subprocess '("a") directory 1) => #t)
     (def old-interface (file-checksum ssi))
     (backdate-static! prefix libdir)
     (let (result (make/subprocess '("b" "a") directory 2
                    [(wrap-gsc directory "obstruct") ...
                     `(setenv "MAKE_TEST_SECTION" ,section)]))
       (check (string? result) => #t)
       (check (string-contains result "gsc fixture timeout") => #f))
     (check (file-exists? (path-expand "obstructed" directory)) => #t)
     (check (file-exists? (string-append a "~0.o2")) => #t)
     (check (file-exists? marker) => #t)
     (check (file-checksum ssi) => old-interface)
     (check (file-exists? (string-append b ".ssi")) => #f)
     (delete-file-or-directory section #t)
     (rename-file (path-expand "prior.scm" directory) section)
     ;; The ordinary rename order is unspecified. Remove the stale timestamp
     ;; used to force the failed build so only the dirty marker forces a retry.
     (run-process ["touch" section static])
     (let (src-time (file-mtime (path-expand "src/a.ss" directory)))
       (check (>= (file-mtime ssi) src-time) => #t)
       (check (>= (file-mtime static) src-time) => #t))
     (check (make/subprocess '("a") directory 2) => #t)
     (check (file-exists? (string-append a "~0.o3")) => #t)
     (check (file-exists? marker) => #f)))
  (void))

(def (test-deferred-optimizer-input)
  (call-with-package
   (lambda (directory prefix source libdir)
     (def (build)
       (run-gxi ['(import :std/make :gerbil/compiler/optimize-base)
                 '(def caller-info (make-optimizer-info))
                 `(parameterize ((current-compile-optimizer-info caller-info))
                    (make '("b" "a") srcdir: ,(path-expand "src" directory)
                          libdir: ,libdir parallelize: 2 optimize: #t))
                 '(exit (if (zero? (hash-length (optimizer-info-ssxi caller-info))) 0 1))]
                ["GERBIL_BUILD_CORES=2"]))
     (source "a.ss" '(export value) '(def (value) => :fixnum 42))
     (source "b.ss" '(import ./a) '(export result) '(def (result) (fx1+ (value))))
     (check (build) => #t)
     ;; The published signature still accepts zero arguments during generation.
     (source "a.ss" '(export value) '(def (value (s : :string)) => :string s))
     (source "b.ss" '(import ./a) '(export result) '(def (result) (string-length (value "second"))))
     (backdate-static! prefix libdir)
     (check (build) => #t)
     (check (run-gxi [`(add-load-path! ,libdir)
                      `(import ,(string->symbol (string-append ":" prefix "/b")))
                      '(exit (if (= (result) 6) 0 1))])
            => #t))))

(def (test-duplicate-native-output)
  (call-with-package
   (lambda (directory prefix source libdir)
     (def output (path-expand "duplicate.o1" directory))
     (write-nested source 1)
     (let (result
           (run-gxi ['(import :gerbil/compiler)
                     `(compile-module ,(path-expand "src/a.ss" directory)
                        [output-dir: ,libdir invoke-gsc: #t parallel: #t
                         gsc-options: ["-o" ,output]])]))
       (check (and (string? result) (string-contains result "Multiple compiler outputs for path") #t)
              => #t)
       (check (file-exists? output) => #f)
       (check (library-snapshot libdir) => [])))))

(def (test-executable-private-dependencies)
  (call-with-package
   (lambda (directory prefix source libdir)
     (def dep (path-expand (string-append "static/" prefix "__a") libdir))
     (source "a.ss" '(export value) '(def (value) 42))
     (source "prog.ss" '(import ./a) '(export main) '(def (main) (exit (if (= (value) 42) 0 1))))
     (check (make/subprocess '("a" (exe: "prog")) directory 2) => #t)
     (check (file-exists? (string-append dep ".scm")) => #t)
     (check (file-exists? (string-append dep ".c")) => #f)
     (check (file-exists? (string-append dep ".o")) => #f)
     (check (run-process [(path-expand "bin/prog" directory)]) => ""))))

(def (test-partial-job-start)
  (def ran? #f)
  (def spent (spawn-thread void))
  (thread-join! spent)
  (let (first (compiler.make-compile-job (lambda () (thread-yield!) (set! ran? #t)) 'first))
    (check-exception (run-compile-jobs! [first spent]) started-thread-exception?)
    (check ran? => #t)))

(def make-output-integrity-test
  (test-suite "test :std/make output integrity"
    (test-case "deferred optimizer sees the rebuilt provider signature"
      (test-deferred-optimizer-input))
    (test-case "a failed thread start joins earlier jobs"
      (test-partial-job-start))
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
      (test-gsc-failure-keeps-objects 2))))

;; Each compiler has its own publication protocol and failure injection points.
(cond-expand
 ((defined compiler.current-compile-defer)
  (def make-publication-test
    (test-suite "compiler-staged publication"
      (test-case "two sections cannot produce the same explicit output"
        (test-duplicate-native-output))
      (test-case "linking an executable leaves its dependency cache alone"
        (test-executable-private-dependencies))
      (test-case "staged replacement preserves nested identity"
        (test-replacement #f))
      (test-case "host-qualified staging tolerates another writer's file"
        (test-replacement #t))
      (test-case "concurrent processes cannot overwrite same object version"
        (test-live-object-collision #f))
      (test-case "concurrent processes sharing a fixed prefix cannot clobber each other"
        (test-live-object-collision #t))
      (test-case "old module remains public through a blocked, failing link"
        (test-precommit-failure #f))
      (test-case "deferred sibling finishing after failure cannot publish"
        (test-precommit-failure #t))
      (test-case "partial publication rejects dependent and forces recovery"
        (test-parallel-publication-failure))
      (test-case "fresh-looking outputs with legacy interface markers are rebuilt"
        (test-legacy-markers)))))
 (else
  (def make-publication-test
    (test-suite "interface marker publication"
      (test-case "parallel publication failure reaches caller and rolls back dependent"
        (test-legacy-publication-failure #f))
      (test-case "parallel publication and rollback failures both reach caller"
        (test-legacy-publication-failure #t))))))
