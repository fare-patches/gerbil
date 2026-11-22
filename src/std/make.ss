;;; -*- Gerbil -*-
;;; (C) vyzo at hackzen.org
;;; support for library build scripts
;;; build-spec: see documentation in doc/reference/make.md

(import :gerbil/compiler
        (prefix-in :gerbil/compiler/base compiler.)
        (only-in :gerbil/compiler/optimize-base current-compile-optimizer-info make-optimizer-info)
        :gerbil/expander
        (only-in :std/error Error)
        :std/sync/completion
        :std/sync/channel
        :std/sync/barrier
        :std/list/list
        :std/list/list-builder
        :std/list/plist
        :std/string/path
        :std/iter)
(cond-expand
 ((defined compiler.current-compile-defer)
  (import (only-in :gerbil/compiler/base
                   current-compile-defer
                   compile-attempt-jobs
                   compile-attempt-commit!
                   compile-attempt-abort!)))
 (else
  (import (only-in :gerbil/compiler/base pending-compile-jobs))))
(export make
        make-clean
        shell-config
        env-cppflags
        env-ldflags
        include-gambit-sharp
        pkg-config
        pkg-config-libs
        pkg-config-cflags
        ldflags
        cppflags
        append-options
        enable-shared?)

(def default-gambit-gsc (path-expand "~~bin/gsc"))
(def default-gerbil-gxc (path-expand "~~bin/gxc"))

#|
TODO:

  * Allow static-include: and gsc: without a ssi:, just a gxc:
    and don't nest, just add a dependency.

  * Allow for extra-dependency: to a list of other targets (as identified by spec-file ?)
    in the plist of gxc:, etc.

  * Provide a DSL to extend the spec language, each rule being defining one
    or multiple actions, each with inputs and outputs, its backgroundability,
    is perform method.

  * Learn from the successes and failures of ASDF, Bazel, Dune, Cmake, etc.
;; |#

;;; Functions that should be better moved some library...
(def (force-outputs)
  (force-output (current-error-port))
  (force-output))

(def __output-mx (make-mutex))

(def (message . lst)
  (do-with-lock __output-mx
    (apply displayln lst)
    (force-outputs)))

(def (prefix/ prefix path)
  (if prefix
    (string-append prefix "/" path)
    path))

;;; Settings: see details in doc/reference/make.md
(defstruct settings
  (srcdir libdir bindir prefix force optimize debug verbose build-deps
   libdir-prefix parallelize
   full-program-optimization
   build-release
   build-optimized
   target)
  transparent: #t constructor: :init!)

(defmethod {:init! settings}
  (lambda (self
      srcdir: (srcdir_ #f) libdir: (libdir_ #f) bindir: (bindir_ #f)
      prefix: (prefix_ #f) force: (force? #f)
      optimize: (optimize #t) debug: (debug_ #f)
      static: (_ignore-static #t)
      target: (target 'C)
      verbose: (verbose_ #f) build-deps: (build-deps_ #f)
      parallelize: (parallelize_ #t)
      full-program-optimization: (full-program-optimization #f)
      build-release: (build-release #f)
      build-optimized: (build-optimized #f))

    (def gerbil-path_ (delay (gerbil-path)))
    (def srcdir (or srcdir_ (error "srcdir must be specified")))
    (def libdir (or libdir_ (path-expand "lib" (force gerbil-path_))))
    (def bindir (or bindir_ (path-expand "bin" (force gerbil-path_))))
    (def prefix (or prefix_ (read-package-prefix srcdir)))
    (def libdir-prefix (if prefix (path-expand prefix libdir) libdir))
    (def build-deps (path-expand (or build-deps_ "build-deps") srcdir))
    (def parallelize (gerbil-build-cores parallelize_))
    (def verbose
      (cond
       (verbose_)
       ((getenv "GERBIL_BUILD_VERBOSE" #f) => string->number)
       (else #f)))
    (def debug
      (cond
       (debug_)
       ((getenv "GERBIL_BUILD_DEBUG" #f) #t)
       (else #f)))
    (struct-instance-init!
      self
      srcdir libdir bindir prefix force? optimize debug verbose build-deps
      libdir-prefix parallelize
      full-program-optimization
      build-release
      build-optimized
      target)))

(def (gerbil-build-cores (cpu-count-spec #t))
  ;; TODO: for the default (catch) case, use something like
  ;; (min (##cpu-count) (/ (available-memory) (memory-per-compilation-cpu)))
  ;; Except we need to compute (available-memory) and calibrate (memory-per-compilation-cpu)...
  ;; Until then, we disable the parallel build as it confuses a lot of beginners.
  (cond
   ((integer? cpu-count-spec) cpu-count-spec)
   ((eq? cpu-count-spec #t)
    (: (string->number (getenv "GERBIL_BUILD_CORES" "0")) :integer))
   (else 0)))

(def (settings-verbose>=? settings level)
  (def verbose (settings-verbose settings))
  (and (real? level) (real? verbose) (>= verbose level)))

(def (read-package-prefix srcdir)
  (let (plist (with-catch false (lambda () (call-with-input-file (path-expand "gerbil.pkg" srcdir) read))))
    (alet (pkg (pgetq package: plist)) (and (symbol? pkg) (symbol->string pkg)))))


;;; Build item spec
(def (spec-type spec)
  (match spec
    ((? string? _) gxc:)
    ([(? keyword? type) . _] type)
    (else (error "Bad buildspec" spec))))

(def (spec-file spec settings)
  (match spec
    ((? string? modf)
     (source-path modf ".ss" settings))
    ([gxc: modf . opts]
     (source-path modf ".ss" settings))
    ([gsc: modf . opts]
     (source-path modf ".scm" settings))
    ([ssi: modf . deps]
     (source-path modf ".ssi" settings))
    ([(or exe: static-exe: optimized-exe: optimized-static-exe:)  modf . opts]
     (source-path modf ".ss" settings))
    ([static-include: file]
     (static-file-path file settings))
    ([copy: file]
     file)
    (else
     (error "Bad buildspec" spec))))

(def (spec-inputs spec settings)
  [(spec-file spec settings)
   (spec-extra-inputs spec settings) ...
   (append-map (cut spec-inputs <> settings) (spec-submodules spec)) ...])

(def (spec-extra-inputs spec settings)
  (match spec
    ([gxc: . _] (pgetq extra-inputs: (spec-plist spec) []))
    ([gsc: . _] (pgetq extra-inputs: (spec-plist spec) []))
    (_ [])))

(def (spec-submodules spec)
  (match spec
    ([gxc: . _] (pgetq submodules: (spec-plist spec) []))
    ([ssi: _ . submodules] submodules)
    (_ [])))

(def (spec-plist spec)
  (match spec
    ([(? (cut member <> '(gxc: gsc:))) _ [plist ...] . _] plist)
    (_ [])))

(def (spec-outputs spec settings)
  (match spec
    ((? string? modf) (gxc-outputs modf #f settings))
    ([gxc: modf . opts] (gxc-outputs modf opts settings))
    ([gsc: modf . opts] [(gsc-c-path modf settings)])
    ([ssi: modf . submodules] [(library-path modf ".ssi" settings)
                               (append-map (cut spec-outputs <> settings) submodules) ...])
    ([(or exe: static-exe: optimized-exe: optimized-static-exe:) modf . opts]
     [(binary-path modf opts settings)
      (static-path modf settings)])
    ([static-include: file] [(static-file-path file settings)])
    ([copy: file] [(library-path file #f settings)])
    (else (error "unknwon buildspec" spec))))

(def (make buildspec . rest)
  (def settings (apply make-settings rest))
  ;; A parallel gxc defers its gsc jobs; publishing their modules waits for them.
  (def pending (and (> (settings-parallelize settings) 1)
                    (make-pending-modules (make-mutex 'pending-modules) (make-hash-table) [])))
  (parameterize ((current-directory (settings-srcdir settings))
                 (current-expander-compiling? #t)
                 ;; Workers share declarations for this build, including deferred producers.
                 (current-compile-optimizer-info (and (settings-optimize settings) (make-optimizer-info)))
                 (current-pending-modules pending))
    (add-load-path! (settings-srcdir settings))
    (try
     (make-build buildspec settings)
     (catch (e)
       (when pending (abandon-pending-modules! pending))
       (raise e)))
    (when pending
      (execute-pending-modules! pending))))

(def (make-build buildspec-in settings)
  (parameterize ((current-compilation-target (settings-target settings)))
    (def buildspec (normalize-buildspec buildspec-in))
    ;; detect and report duplicate files in the buildspec up front
    (let (file-counts (make-hash-table))
      (for (spec buildspec)
        (let (f (spec-file spec settings))
          (hash-put! file-counts f (+ 1 (hash-ref file-counts f 0)))))
      (let (dups (filter-map (lambda (kv) (and (> (cdr kv) 1) (car kv)))
                             (hash->list file-counts)))
        (unless (null? dups)
          (error "Duplicate files in buildspec" dups))))
    ;; mutex for imports
    (def import-mx (make-mutex 'import))
    ;; mute for dependency timestamps (mauling of load-path)
    (def dependency-mx (make-mutex 'dependency))
    ;; table of module id -> completion, indicating completion of a build
    (def completions (make-hash-table-eq))
    ;; the build coordinator barrier
    (def build-barrier
      (make-barrier (length buildspec)))
    ;; channel of compilation work ready to be performed
    (def workch (make-channel))
    ;; the build workers
    (def build-worker-count
      (max 1 (settings-parallelize settings)))
    ;; import with mutex
    (def (import/mx mod)
      (with-lock import-mx (cut import-module mod #f #f)))
    ;; spec module id
    (def (module-id spec)
      (let* ((file (spec-file spec settings))
             (ext (path-extension file)))
        (case ext
          ((".ss" ".ssi")
           (expander-context-id (import/mx file)))
          (else
           (string->symbol file)))))

    ;; does the spec need building?
    (def (build? spec)
      (let ((inputs (spec-inputs spec settings))
            (outputs (spec-outputs spec settings)))
        (or (ormap (lambda (f) (not (file-exists? f)))
                   outputs)
            ;; an interrupted build left its outputs unpublished
            (ormap file-exists? (spec-transient-outputs spec settings))
            (ormap
             (lambda (input)
               (ormap (cut file-newer? input <>)
                      outputs))
             inputs))))
    ;; does the spec needs building because of newer dependencies?
    (def (build-dependent? spec mod)
      (def outputs (spec-outputs spec settings))
      (def (newer? in)
        (cond
         ((or (module-context? in) (prelude-context? in))
          (let (id (expander-context-id in))
            (and id
                 ;; Imports from this file are not external build dependencies.
                 (not (eq? (module-strip-nesting id) (expander-context-id mod)))
                 ;; A dependency rebuilt by this make may not have published its
                 ;; .ssi yet; the lookup would miss it or find an older library.
                 (or (built-in-this-make? id)
                     (let (ts (with-catch false (lambda () (dependency-timestamp id))))
                       (if ts
                         (ormap (lambda (output) (> ts (file-timestamp output))) outputs)
                         #t))))))
         ((module-import? in)   (newer? (module-import-source in)))
         ((module-export? in)   (newer? (module-export-context in)))
         ((import-set? in)      (newer? (import-set-source in)))
         (error "unexpected import" in)))
      (ormap newer? (module-context-import mod)))

    (def (dependency-timestamp id)
      (with-lock dependency-mx
                 (lambda ()
                   ;; drop the srcdir from the load path and then get the library timestamp
                   (let (current-load-path (load-path))
                     (dynamic-wind
                         (lambda ()
                           (set-load-path!
                            (cons (settings-libdir settings)
                                  (filter (lambda (p) (not (equal? p (settings-srcdir settings))))
                                          current-load-path))))
                         (lambda () (library-timestamp id))
                         (lambda () (set-load-path! current-load-path)))))))

    ;; set once a build fails, so that the workers stop picking up work
    (def aborted? #f)

    ;; => 'built or 'fresh, once the build of the dependency is settled
    (def (built-in-this-make? id)
      (alet (completion (hash-get completions (module-strip-nesting id)))
        (eq? (completion-wait! completion) 'built)))

    ;; the build worker itself
    (def (build-worker)
      (try
       (for (work workch)
         (unless aborted?
           (let (spec (car work))
             (parameterize ((current-build-dependencies (cdr work)))
               (build spec settings))
             (completion-post! (hash-ref completions (module-id spec)) 'built))))
       (catch (e)
         (set! aborted? #t)
         (barrier-error! build-barrier e)
         (raise e))))

    ;; the build coordinator
    (def (build-coordinator spec)
      (let* ((file (spec-file spec settings))
             (mod (import/mx file))
             ;; ids of the buildspec modules this one waits for
             (deps (make-hash-table-eq)))
        (def (consider in self)
          (cond
           ((module-context? in)  (wait-for in self))
           ((prelude-context? in) (wait-for in self))
           ((module-import? in)   (consider (module-import-source in) self))
           ((module-export? in)   (consider (module-export-context in) self))
           ((import-set? in)      (consider (import-set-source in) self))
           (else
            (error "unexpected import" in))))
        (def (wait-for ctx self)
          (alet* ((id (expander-context-id ctx)) ; :<root> prelude has no id
                  ;; Nested modules are built with their enclosing file.
                  (id (module-strip-nesting id)))
            ;; A module may import its own nested modules; never wait on itself.
            (unless (eq? id self)
              (alet (completion (hash-get completions id))
                (completion-wait! completion)
                (hash-put! deps id #t)))))
        (for (in (module-context-import mod))
          (consider in (expander-context-id mod)))
        (if (or (build? spec)
                (build-dependent? spec mod))
          ;; it needs to be built, put it to the work channel, along with the
          ;; library paths of the dependencies built by this make
          (channel-put workch
                       (cons spec
                             (filter-map (lambda (id)
                                           (and (built-in-this-make? id)
                                                (path-expand (symbol->string id)
                                                             (settings-libdir settings))))
                                         (hash-keys deps))))
          ;; no need to build, unblock dependents
          (completion-post! (hash-ref completions (module-id spec)) 'fresh))
        ;; clear the barrrier
        (barrier-post! build-barrier)))

    ;; prepare the build
    (create-directory* (settings-bindir settings))
    (create-directory* (settings-libdir settings))
    (create-directory* (path-expand "static" (settings-libdir settings)))

    ;; prepare the completion table
    (for (spec buildspec)
      (let (id (module-id spec))
        (hash-put! completions id (make-completion `(build ,id)))))

    ;; spawn a thread for each spec that waits for the dependency completions
    ;; and pushes to the work channel if necessary.
    (for (spec buildspec)
      (spawn/name `(build ,(spec-file spec settings)) build-coordinator spec))

    ;; spawn the workers and wait
    (let (workers (map (lambda (i) (spawn/name `(worker ,i) build-worker))
                       (iota build-worker-count)))
      ;; On failure, let the workers finish their current module before
      ;; raising, so that the caller can abort all registered attempts.
      (def (abort! e)
        (set! aborted? #t)
        (channel-close workch)
        (for-each (lambda (worker) (with-catch void (cut thread-join! worker))) workers)
        (raise e))
      ;; wait for the coordinators to complete
      (with-catch abort! (cut barrier-wait! build-barrier))
      ;; close the channel (no more work)
      (channel-close workch)
      ;; and wait for the workers to complete
      (with-catch abort! (cut for-each thread-join! workers)))))

;; Dependencies may have been rebuilt since an earlier freshness check, including
;; in this invocation. Always observe the current file and library timestamps.
(def (file-timestamp (file : :string))
  => :flonum
  (time->seconds (file-info-last-modification-time (file-info file))))

(def (library-timestamp (id : :symbol))
  => :flonum
  (file-timestamp (core-resolve-library-module-path (library-symbol id))))

(def (module-strip-nesting id)
  (let (name (symbol->string id))
    (cond
     ((string-index name #\~)
      => (lambda (ix) (string->symbol (substring name 0 ix))))
     (else id))))

(def (library-symbol id)
  (make-symbol ":" (module-strip-nesting id)))

(def (make-clean . args)
  (defvalues (positionals keywords) (separate-keyword-arguments args #t))
  (def buildspec (match positionals ([x] x) (_ (error "invalid arguments" make positionals))))
  (def settings (apply make-settings keywords))

  (for* ((spec buildspec)
         (f    [(spec-outputs spec settings) ...
                (spec-transient-outputs spec settings) ...]))
    (when (file-exists? f)
      (displayln "... remove " f)
      (delete-file-or-directory f))))


;; Normalize-buildspec : buildspec -> buildspec
;; Groups the gsc: and static-include: and copy: specs inside the immediately following ssi:
(def (normalize-buildspec buildspec)
  (def submodules '())
  (def (get-submodules)
    (begin0 (reverse submodules) (set! submodules '())))
  (def (no-submodules spec)
    (unless (null? submodules)
      (error "incompatible sequence of build specifications" (reverse (cons spec submodules)))))
  (def (push-submodule spec)
    (set! submodules (cons spec submodules)))
  (with-list-builder (c)
    ((cut for-each <> buildspec)
     (lambda (spec)
       (case (spec-type spec)
         ((gxc:) (let (s (get-submodules))
                   (if (null? s) (c spec)
                       (c
                        (match spec
                          ([gxc: name (? pair? plist) . args]
                           [gxc: name (psetq plist submodules: (append (pgetq plist submodules:) s))])
                          ([gxc: name . args]
                           [gxc: name [submodules: s] . args])
                          ((? string? spec)
                           [gxc: spec [submodules: s]]))))))
         ((exe: static-exe: optimized-exe: optimized-static-exe:) (no-submodules spec) (c spec))
         ((gsc: static-include: copy:) (push-submodule spec))
         ((ssi:) (c (append spec (get-submodules))))
         (else (error "Unrecognized spec type" spec)))))
    (no-submodules #!eof)))

(def (shell-config cmd . args)
  (let* ((proc (open-input-process [path: cmd arguments: args]))
         (status (process-status proc)))
    (unless (zero? status)
      (error "Error executing config script" cmd args status))
    (read-line proc)))

(def (env-ldflags)
  (cond
   ((getenv "LDFLAGS" #f)
    => (lambda (flags)
         (lambda (lib)
           (string-append flags " " lib))))
   (else
    identity)))

(def (env-cppflags)
  (cond
   ((getenv "CPPFLAGS" #f)
    => (lambda (flags)
         (lambda (more)
           (if (string-empty? more)
             flags
             (string-append flags " " more)))))
   (else
    identity)))

(def (include-gambit-sharp)
  (let* ((gambit-sharp
          (path-expand "lib/_gambit#.scm"
                       (getenv "GERBIL_BUILD_PREFIX" (gerbil-home))))
         (include-gambit-sharp
          (string-append "(include \"" gambit-sharp "\")")))
    (cond
     ((gerbil-runtime-smp?)
      `("-e" "(define-cond-expand-feature|enable-smp|)"
        "-e" ,include-gambit-sharp))
     (else
      `("-e" ,include-gambit-sharp)))))

(def (build spec settings)
  (match spec
    ((? string? modf)
     (gxc-compile modf #f settings #t))
    ([gxc: modf [submodules: submodules . _] . opts]
     (for-each (cut build <> settings) submodules)
     (gxc-compile modf opts settings #t))
    ([gxc: modf . opts]
     (gxc-compile modf opts settings #t))
    ([gsc: modf . opts]
     (gsc-compile modf opts settings))
    ([ssi: modf . submodules]
     (for-each (cut build <> settings) submodules)
     (compile-ssi modf '() settings))
    ([exe:  modf . opts]
     (compile-exe/context modf opts settings))
    ([static-exe:  modf . opts]
     (compile-exe/static-linkage modf opts settings))
    ([optimized-exe: modf . opts]
     (compile-optimized-exe modf opts settings))
    ([optimized-static-exe: modf . opts]
     (compile-optimized-exe/static-linkage modf opts settings))
    ([static-include: file]
     (copy-target file settings)
     (copy-static file settings))
    ([copy: file]
     (copy-compiled file settings))
    (else
     (error "Bad buildspec" spec))))

(def (gxc-outputs mod opts settings)
  [(library-path mod ".ssi" settings)
   (static-path mod settings)])

;; Files that exist only while a build of the spec is unfinished.
(def (spec-transient-outputs spec settings)
  (match spec
    ((? string? modf) (ssi-transient-paths (library-path modf ".ssi" settings)))
    ([gxc: modf . _] (ssi-transient-paths (library-path modf ".ssi" settings)))
    ([(or exe: static-exe: optimized-exe: optimized-static-exe:) modf . opts]
     [(string-append (binary-path modf opts settings) ".new")
      (ssi-transient-paths (library-path modf ".ssi" settings)) ...])
    (_ [])))

;; The compiler marks interrupted publication with .new; .old may remain
;; from an older make. The compiler clears the markers on successful commit.
(def (ssi-transient-paths ssi)
  [(string-append ssi ".new") (string-append ssi ".old")])

;; Compatibility with compilers that write their interface before native jobs finish.
(cond-expand
 ((not (defined compiler.current-compile-defer))
  (def (ssi-update-path ssi)
    (string-append ssi ".new"))

  (def (ssi-backup-path ssi)
    (string-append ssi ".old"))

  (def (delete-file-if-exists path)
    (when (file-exists? path)
      (delete-file path)))

  ;; Sets the previous .ssi aside and marks the module unfinished.
  (def (ssi-update-begin! ssi)
    (def update (ssi-update-path ssi))
    (def backup (ssi-backup-path ssi))
    (create-directory* (path-directory ssi))
    (cond
     ;; An interrupted build may have left an unpublished .ssi in place.
     ((or (file-exists? update) (file-exists? backup))
      (delete-file-if-exists ssi))
     ((file-exists? ssi)
      (rename-file ssi backup #t)))
    (unless (file-exists? update)
      (call-with-output-file update void)))

  ;; Holds back the .ssi gxc just wrote.
  (def (ssi-update-stage! ssi)
    (when (file-exists? ssi)
      (rename-file ssi (ssi-update-path ssi) #t)))

  (def (ssi-update-publish! ssi)
    (rename-file (ssi-update-path ssi) ssi #t)
    (delete-file-if-exists (ssi-backup-path ssi)))

  (def (ssi-update-rollback! ssi)
    (def backup (ssi-backup-path ssi))
    (delete-file-if-exists ssi)
    (when (file-exists? backup)
      (rename-file backup ssi #t))
    (delete-file-if-exists (ssi-update-path ssi)))

  ;; The library path of the module that a deferred gsc job compiles a file of.
  ;; The driver names jobs (compile-file <libdir>/<id>[~<section>].scm), and nested
  ;; modules <id>~<nested>[~<section>].scm; => #f for other jobs.
  (def (compile-job-module job)
    (match (thread-name job)
      (['compile-file (? string? path)]
       (let* ((file (path-strip-extension (path-strip-directory path)))
              (base (cond
                     ((string-index file #\~) => (cut substring file 0 <>))
                     (else file))))
         (path-expand base (path-directory path))))
      (_ #f)))


  (def compile-attempt-commit! ssi-update-publish!)
  (def compile-attempt-abort! ssi-update-rollback!)))

(cond-expand
 ((defined compiler.run-compile-jobs!)
  (def run-compile-jobs! compiler.run-compile-jobs!))
 (else
  ;; Reap every started job before rollback.
  (def (run-compile-jobs! jobs)
    (let ((started []) (failure #f))
      (def (failed e) (unless failure (set! failure (list e))))
      (for-each (lambda (job)
                  (unless failure
                    (with-catch failed
                      (lambda () (thread-start! job) (set! started (cons job started))))))
                jobs)
      (for-each (lambda (job) (with-catch failed (cut compiler.join! job))) (reverse! started))
      (when failure (raise (car failure)))))))

;; records: library path without extension -> pending-module.
;; executables: thunks to run after all static inputs have been published.
(defstruct pending-modules (mx records executables))

;; deps: library paths of the dependencies built by the same make
;; result: completion posted with #t once published, #f after abort
(defstruct pending-module (ssi attempt deps result))

(def current-pending-modules
  (make-parameter #f))

;; library paths of the dependencies of the module being built, built by this make
(def current-build-dependencies
  (make-parameter []))

(def (pending-module-add! pending ssi attempt deps)
  (with-lock (pending-modules-mx pending)
    (cut hash-put! (pending-modules-records pending)
         (path-strip-extension ssi)
         (make-pending-module ssi attempt deps (make-completion `(publish ,ssi))))))

;; A loader (<id>.scm) loads the sections of its module: compile it last.
(def (compile-job-loader? job)
  (match (thread-name job)
    (['compile-file (? string? path)]
     (not (string-index (path-strip-directory path) #\~)))
    (_ #f)))

;; Runs the gsc jobs queued by the make, then publishes each module whose jobs
;; and built dependencies all succeeded, and aborts the others.
;; Reports all failures once every job finished, leaving no gsc running.
(def (execute-pending-modules! pending)
  (def records (pending-modules-records pending))
  (cond-expand
   ((defined compiler.current-compile-defer)
    (def jobs-for compile-attempt-jobs))
   (else
    (def groups (make-hash-table))
    (def others [])
    (for (job (pending-compile-jobs))
      (let (key (compile-job-module job))
        (if (and key (hash-key? records key))
          (hash-update! groups key (cut cons job <>) [])
          (set! others (cons job others)))))
    (def (jobs-for ssi) (reverse (hash-ref groups (path-strip-extension ssi) [])))))
  (def (settle! record)
    (def attempt (pending-module-attempt record))
    ;; Capture operational failures during compilation, dependency waits and
    ;; publication. Posting stays outside the catch: this worker alone owns it.
    ;; Distinguish publication, a failed dependency, and an exception.
    (def result
      (with-catch list
        (lambda ()
          (let (jobs (jobs-for attempt))
            (run-compile-jobs! (filter (? (not compile-job-loader?)) jobs))
            (run-compile-jobs! (filter compile-job-loader? jobs))
            (and (andmap (lambda (dep)
                           (let (dep-record (hash-get records dep))
                             (or (not dep-record)
                                 (completion-wait! (pending-module-result dep-record)))))
                         (pending-module-deps record))
                 (begin (compile-attempt-commit! attempt) #t))))))
    (if (eq? result #t)
      (begin
        (completion-post! (pending-module-result record) #t)
        #f)
      (let (abort-failure
            (with-catch list (lambda () (compile-attempt-abort! attempt) #f)))
        (completion-post! (pending-module-result record) #f)
        (if (and result abort-failure)
          [(Error "Module settlement and abort both failed"
                  where: 'make irritants: [(car result) (car abort-failure)])]
          (or result abort-failure)))))
  (let* ((threads (map (lambda (record)
                         (spawn/name `(publish ,(pending-module-ssi record)) settle! record))
                       (hash-values records)))
         (other-failure
          (cond-expand
           ((defined compiler.current-compile-defer) #f)
           (else (with-catch list (lambda () (run-compile-jobs! (reverse others)) #f)))))
         (failures (cons other-failure (map thread-join! threads))))
    (match (filter identity failures)
      ([] (for-each (lambda (link!) (link!)) (reverse (pending-modules-executables pending))))
      ([failure] (raise (car failure)))
      (failures
       (raise (Error "Multiple failures during parallel build settlement"
                     where: 'make irritants: (map car failures)))))))

;; Generation failed before settlement: none of these jobs has started.
(def (abandon-pending-modules! pending)
  (cond-expand ((not (defined compiler.current-compile-defer)) (pending-compile-jobs)))
  (for (record (hash-values (pending-modules-records pending)))
    (compile-attempt-abort! (pending-module-attempt record))))

(def (gsc-compile-opts opts)
  (match opts
    ([[plist ...] . rest] (listify rest))
    (_ (listify opts))))

;; TODO: split that (and more?) into many action. See :gerbil/compiler/driver
(def (gxc-compile mod opts settings (invoke-gsc? #t))
  (message "... compile " mod)
  (def gsc-opts (gsc-compile-opts opts))
  (def srcpath (source-path mod ".ss" settings))
  (let (gxc-opts
        [invoke-gsc: invoke-gsc?
         target: (settings-target settings)
         keep-scm: (not invoke-gsc?)
         output-dir: (settings-libdir settings)
         optimize: (settings-optimize settings)
         debug: (settings-debug settings)
         generate-ssxi: #t
         verbose: (settings-verbose>=? settings 9)
         parallel: (> (settings-parallelize settings) 1)
         (when/list gsc-opts [gsc-options: gsc-opts]) ...])
    (def ssi (library-path mod ".ssi" settings))
    (cond-expand
     ((defined compiler.current-compile-defer)
      (def pending (current-pending-modules))
      (def deps (current-build-dependencies))
      (parameterize ((current-compile-defer (and pending (cut pending-module-add! pending ssi <> deps))))
        (compile-module srcpath gxc-opts)))
     (else
      (def pending (and invoke-gsc? (current-pending-modules)))
      (ssi-update-begin! ssi)
      (try
       (compile-module srcpath gxc-opts)
       (catch (e)
         (ssi-update-rollback! ssi)
         (raise e)))
      (ssi-update-stage! ssi)
      (if pending
        ;; gsc jobs deferred to the end of the make
        (pending-module-add! pending ssi ssi (current-build-dependencies))
        (ssi-update-publish! ssi))))))

(def (gsc-libpath mod settings)
  (def libdir-prefix (settings-libdir-prefix settings))
  (cond
   ((string-rindex mod #\/) => (lambda (ix) (path-expand (substring mod 0 ix) libdir-prefix)))
   (else libdir-prefix)))

(def (gsc-base mod)
  (cond
   ((string-rindex mod #\/)
    => (lambda (ix) (substring mod (fx1+ ix) (string-length mod))))
   (else mod)))

(def (gsc-c-path modf settings)
  (def mod (path-strip-extension modf))
  (def libpath (gsc-libpath mod settings))
  (def base (gsc-base mod))
  (let lp ((n 1) (cpath #f))
    (let (next (path-expand (string-append base ".o" (number->string n))
                            libpath))
      (if (file-exists? next)
        (lp (fx1+ n) next)
        cpath))))

(def (gsc-compile mod opts settings)
  (def gsc-opts (gsc-compile-opts opts))
  (def srcpath (source-path mod ".scm" settings))
  (def libpath (gsc-libpath mod settings))
  (create-directory* libpath)
  (message "... compile foreign " mod)
  (let* ((proc (open-process [path: (gerbil-gsc)
                                    arguments: ["-o" libpath gsc-opts ... srcpath]
                                    stdout-redirection: #f]))
         (status (process-status proc)))
    (close-port proc)
    (unless (zero? status)
      (error "Compilation error; gsc exited with nonzero status" status)))
  ;; just copy to libdir/static/ with properly mangled module name
  (let (statpath (static-path mod settings))
    (when (file-exists? statpath)
      (delete-file statpath))
    (copy-file srcpath statpath)))

(def (gerbil-gsc)
  (getenv "GERBIL_GSC" default-gambit-gsc))
(def (gerbil-gxc)
  (getenv "GERBIL_GXC" default-gerbil-gxc))

(def (compile-ssi mod deps settings)
  (def srcpath (source-path mod ".ssi" settings))
  (def libpath (library-path mod ".ssi" settings))
  (def prefix  (settings-prefix settings))
  (message "... copy ssi " mod)
  (create-directory* (path-directory libpath))
  (when (file-exists? libpath)
    (delete-file libpath))
  (copy-file srcpath libpath))

(def (compile-exe-gsc-opts opts)
  (match opts
    ([(? keyword?) opt . rest]
     (compile-exe-gsc-opts rest))
    (else opts)))

(def (compile-exe/context mod opts settings)
  (cond
   ((or (settings-build-release settings)
        (getenv "GERBIL_BUILD_RELEASE" #f))
    (cond
     ((or (settings-build-optimized settings)
          (getenv "GERBIL_BUILD_OPTIMIZED" #f))
      (compile-optimized-exe/static-linkage mod opts settings))
      (else
       (compile-exe/static-linkage mod opts settings))))
   ((or (settings-build-optimized settings)
        (getenv "GERBIL_BUILD_OPTIMIZED" #f))
    (compile-optimized-exe mod opts settings))
   (else
    (compile-exe mod opts settings))))

(def (compile-exe mod opts settings)
  (def srcpath (source-path mod ".ss" settings))
  (def binpath (binary-path mod opts settings))
  (def gsc-opts (compile-exe-gsc-opts opts))
  (def gxc-opts
    [invoke-gsc: #t
     output-dir: (settings-libdir settings)
     output-file: binpath
     verbose: (settings-verbose>=? settings 9)
     debug: (settings-debug settings)
     full-program-optimization: (settings-full-program-optimization settings)
     parallel: #f
     (when/list gsc-opts [gsc-options: gsc-opts]) ...])
  (def (link!)
    (message "... compile exe " mod " -> " binpath)
    (cond-expand
     ((defined compiler.current-compile-defer)
      (parameterize ((current-compile-defer #f)) (gxc#compile-exe srcpath gxc-opts)))
     (else
      (gxc#compile-exe srcpath gxc-opts))))
  (gxc-compile mod gsc-opts settings #f)
  (cond
   ((current-pending-modules)
    => (lambda (pending)
         (do-with-lock (pending-modules-mx pending)
           (set! (pending-modules-executables pending)
                 (cons link! (pending-modules-executables pending))))))
   (else (link!))))

(def (compile/static-linkage mod opts settings compile-e)
  (when (member "--enable-shared" (string-split (configure-command-string) #\'))
    (error "system is configured with --enable-shared and cannot build static executables"))
  (let (static-opts (append opts '("-cc-options" "-Bstatic" "-ld-options" "-static")))
    (compile-e mod static-opts settings)))

(def (compile-exe/static-linkage mod opts settings)
  (compile/static-linkage mod opts settings compile-exe))

(def (make-settings-optimized settings)
  (def s (struct-copy settings))
  (set! (settings-full-program-optimization s) #t)
  s)

(def (compile-optimized-exe mod opts settings)
  (compile-exe mod opts (make-settings-optimized settings)))

(def (compile-optimized-exe/static-linkage mod opts settings)
  (compile/static-linkage mod opts settings compile-optimized-exe))

(def (copy-static file settings)
  (def spath (static-file-path file settings))
  (message "... copy static include " file)
  (when (file-exists? spath)
    (delete-file spath))
  (copy-file file spath))

(def (copy-target file settings)
  (let* ((libdir (settings-libdir-prefix settings))
         (srcdir (settings-srcdir settings))
         (spath (path-expand file srcdir))
         (tpath (path-expand file libdir)))
    (message "... copy static include to target directory " file)
    (create-directory* (path-directory tpath))
    (when (file-exists? tpath)
      (delete-file tpath))
    (copy-file spath tpath)))

(def (copy-compiled file settings)
  (def srcpath (source-path file #f settings))
  (def libpath (library-path file #f settings))
  (message "... copy std/" file)
  (when (file-exists? libpath)
    (delete-file libpath))
  (copy-file srcpath libpath))

(def (source-path mod ext settings)
  (path-expand (path-default-extension mod ext) (settings-srcdir settings)))

(def (library-path mod ext settings)
  (path-expand (path-force-extension mod ext) (settings-libdir-prefix settings)))

(def (binary-path mod opts settings)
  (let* ((bindir (settings-bindir settings))
         (_ (unless bindir (error "bindir must be specified")))
         (bin
          (cond
           ((pgetq bin: opts))
           ((string-rindex mod #\/)
            => (lambda (ix) (substring mod (fx1+ ix) (string-length mod))))
           (else mod)))
         (bin
          (if (string-empty? (path-extension bin))
            bin
            (path-strip-extension bin))))
    (path-expand bin bindir)))

(def (static-path mod settings)
  (let* ((libdir (settings-libdir settings))
         (staticdir (path-expand "static" libdir))
         (mod (prefix/ (settings-prefix settings) mod))
         (base (string-join (string-split mod #\/) "__"))
         (scm (path-force-extension base ".scm")))
    (path-expand scm staticdir)))

(def (static-file-path file settings)
  (let* ((libdir (settings-libdir settings))
         (staticdir (path-expand "static" libdir))
         (filename (path-strip-directory file)))
    (path-expand filename staticdir)))

;; lib: library to ask configuration for
;; args: [<arg> ...]
;;  <arg>: additionnal arguments to pass to pkg-config
(def (pkg-config lib . args)
  (apply shell-config "pkg-config" "--silence-errors" lib args))

;; calls pkg-config in order to return `ld-options`.
;;
;; libs: [<lib> ...]
;;  <lib>: library to get ld-options for
(def (pkg-config-libs . libs)
  (string-join (map (lambda (l) (pkg-config l "--libs")) libs) " "))

;; calls pkg-config in order to return `cc-options`.
;;
;; libs: [<lib> ...]
;;  <lib>: library to get cc-options for
(def (pkg-config-cflags . libs)
  (string-join (map (lambda (l) (pkg-config l "--cflags")) libs) " "))

;; tries pkg-config-libs with fallback to env-ldflags
(def (ldflags lib flags)
  (try
   (pkg-config-libs lib)
   (catch (e)
     ((env-ldflags) flags))))

;; tries pkg-confg-cflags with fallback to env-cppflags
(def (cppflags lib flags)
  (try
   (pkg-config-cflags lib)
   (catch (e)
     ((env-cppflags) flags))))

;; appends flags together; useful for -cc-options and -ld-options
(def (append-options . opts)
  (let (opts (filter (? (not string-empty?)) opts))
    (string-join opts " ")))

;; temporarily sets the load-path
(def (with-cons-load-path thunk path)
  (let (current-load-path (load-path))
    (dynamic-wind
        (cut add-load-path! path)
        thunk
        (cut set-load-path! current-load-path))))

(def (enable-shared?)
  (member "--enable-shared" (string-split (configure-command-string) #\')))
