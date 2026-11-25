;;; -*- Gerbil -*-
;;; (C) vyzo at hackzen.org
;;; support for library build scripts
;;; build-spec: see documentation in doc/reference/make.md

(import :gerbil/compiler
        (only-in :gerbil/compiler/base
          module-id->path-string pending-compile-jobs raise-compile-error)
        (only-in :gerbil/compiler/driver
          source-build-outputs source-build-native-jobs
          execute-native-compile-job! queue-native-compile-job!)
        :gerbil/expander
        :std/sync/completion
        :std/sync/channel
        :std/sync/barrier
        :std/list/list
        :std/list/list-builder
        :std/list/plist
        :std/string/path
        :std/iter)
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
  => :void
  (force-output (current-error-port))
  (force-output))

(def __output-mx (make-mutex))

(def (message . lst)
  => :void
  (do-with-lock __output-mx
    (apply displayln lst)
    (force-outputs)))

(def (prefix/ (prefix :? :string)
              (path : :string))
  => :string
  (if prefix
    (string-append prefix "/" path)
    path))

;;; Settings: see details in doc/reference/make.md
(defstruct settings
  ((srcdir                    : :string)
   (libdir                    : :string)
   (bindir                    : :string)
   (prefix                    :? :string)
   (force                     : :boolean)
   (optimize                  : :boolean)
   (debug                     :~ (? (or boolean? symbol?)))
   (verbose                   :~ (? (or boolean? real?)))
   (build-deps                : :string)
   (libdir-prefix             : :string)
   (parallelize               : :integer)
   (processes                 : :boolean)
   (dependency-processes      :~ (? (or boolean? symbol?)))
   (full-program-optimization : :boolean)
   (build-release             : :boolean)
   (build-optimized           : :boolean)
   (target                    : :symbol))
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
      processes: (processes #t)
      dependency-processes: (dependency-processes #f)
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
    ;; #t isolates the whole graph, retaining import reuse inside one child.
    ;; 'module and 'package bound each child's cache to one source or package
    ;; directory. #f discovers in the coordinator.
    (unless (memq dependency-processes '(#f #t module package))
      (error "invalid dependency discovery policy" dependency-processes))
    (set! self.srcdir srcdir)
    (set! self.libdir libdir)
    (set! self.bindir bindir)
    (set! self.prefix prefix)
    (set! self.force force?)
    (set! self.optimize optimize)
    (set! self.debug debug)
    (set! self.verbose verbose)
    (set! self.build-deps build-deps)
    (set! self.libdir-prefix libdir-prefix)
    (set! self.parallelize parallelize)
    (set! self.processes processes)
    (set! self.dependency-processes dependency-processes)
    (set! self.full-program-optimization full-program-optimization)
    (set! self.build-release build-release)
    (set! self.build-optimized build-optimized)
    (set! self.target target)))

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

(def (settings-verbose>=? (config : settings)
                          level)
  => :boolean
  (def verbose (settings-verbose config))
  (and (real? level) (real? verbose) (>= verbose level)))

(def (read-package-prefix (srcdir : :string))
  => (Maybe :string)
  (let (plist (with-catch false (lambda () (call-with-input-file (path-expand "gerbil.pkg" srcdir) read))))
    (alet (pkg (pgetq package: plist)) (and (symbol? pkg) (symbol->string pkg)))))


;;; Build item spec
(def (spec-type spec)
  (match spec
    ((? string? _) gxc:)
    ([(? keyword? type) . _] type)
    (else (error "Bad buildspec" spec))))

(def (spec-file spec
                (config : settings))
  => :string
  (match spec
    ((? string? modf)
     (source-path modf ".ss" config))
    ([gxc: modf . opts]
     (source-path modf ".ss" config))
    ([gsc: modf . opts]
     (source-path modf ".scm" config))
    ([ssi: modf . deps]
     (source-path modf ".ssi" config))
    ([(or exe: static-exe: optimized-exe: optimized-static-exe:)  modf . opts]
     (source-path modf ".ss" config))
    ([static-include: file]
     (static-file-path file config))
    ([copy: file]
     file)
    (else
     (error "Bad buildspec" spec))))

(def (spec-inputs spec
                  (config : settings))
  => :list
  [(spec-file spec config)
   (spec-extra-inputs spec config) ...
   (append-map (cut spec-inputs <> config) (spec-submodules spec)) ...])

(def (spec-extra-inputs spec
                        (config : settings))
  => :list
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

(def (spec-outputs spec
                   (config : settings))
  => :list
  (match spec
    ((? string? modf) (gxc-outputs modf #f config))
    ([gxc: modf . opts] (gxc-outputs modf opts config))
    ([gsc: modf . opts] [(gsc-c-path modf config)])
    ([ssi: modf . submodules] [(library-path modf ".ssi" config)
                               (append-map (cut spec-outputs <> config) submodules) ...])
    ([(or exe: static-exe: optimized-exe: optimized-static-exe:) modf . opts]
     [(binary-path modf opts config)
      (static-path modf config)])
    ([static-include: file] [(static-file-path file config)])
    ([copy: file] [(library-path file #f config)])
    (else (error "unknwon buildspec" spec))))

;; Workers own compiler/expander state. With dependency-processes enabled the
;; parent retains only dependency names and scheduling state.
(defstruct ProcessBuild
  ((directory :- :string) (mx :- :mutex) (active :- HashTable)
   (jobs :- :list) (pending :- :list) (failed? :- :boolean))
  final: #t)

(def current-process-build (make-parameter #f))
(def current-build-module-id (make-parameter #f))
(def current-build-provider? (make-parameter #f))

(defstruct DependencyJob
  ((index : :fixnum) (paths : :list))
  final: #t)

(def (build-marker (id : :symbol)
                   (config : settings))
  => :string
  (path-expand (string-append (module-id->path-string id) ".pending")
               (path-expand ".make/pending" (settings-libdir config))))

(def (start-process-build (config : settings))
  => ProcessBuild
  (let loop ()
    (let (directory (path-expand (string-append ".make/run-" (number->string (random-integer 4294967296)))
                                 (settings-libdir config)))
      (if (file-exists? directory)
        (loop)
        (begin
          (create-directory* directory)
          (ProcessBuild directory (make-mutex 'make-processes) (make-hash-table-eq) [] [] #f))))))

(def (signal-build-processes (processes : :list)
                             (signal : :string))
  => :void
  (let (pids (filter-map
              (lambda (process)
                (with-catch false
                  (lambda () (and (not (process-status process 0 #f))
                                  (number->string (process-pid process))))))
              processes))
    (unless (null? pids)
      ;; No Scheme thread is interrupted while it may hold a lock.
      (let (process (open-process
                      [path: "/bin/sh"
                       arguments: ["-c" "make_signal=$1; shift; kill -\"$make_signal\" \"$@\" 2>/dev/null || :"
                                   "gerbil-make-cancel" signal pids ...]
                       stdout-redirection: #f stderr-redirection: #f]))
        (process-status process)
        (close-port process)))))

(def (stop-process-build! (state : ProcessBuild))
  => :void
  (let (processes (with-lock state.mx
                   (lambda ()
                     (set! state.failed? #t)
                     (hash-keys state.active))))
    (signal-build-processes processes "TERM")
    (let (deadline (seconds->time (+ (time->seconds (current-time)) 2)))
      (for-each (lambda (process) (with-catch false (cut process-status process deadline #f))) processes))
    (signal-build-processes processes "KILL")))

(def (show-process-output (source : :string)
                          (log : :string)
                          (status : :fixnum))
  => :void
  (when (or (not (zero? status))
            (and (file-exists? log) (> (file-info-size (file-info log)) 0)))
    (with-lock __output-mx
      (lambda ()
        (let (output (current-error-port))
          (parameterize ((current-output-port output))
            (displayln "... compiler output: " source " (process status " status ")"))
          (when (file-exists? log)
            (call-with-input-file log
              (lambda (input)
                (let ((buffer (make-string 4096)))
                  (let loop ()
                    (let (count (read-substring buffer 0 4096 input))
                      (unless (zero? count)
                        (write-substring buffer 0 count output)
                        (loop))))))))
          (force-output output))))))

(def (compiler-process-command (paths : :list)
                               (arguments : :list))
  => :list
  ["env" (string-append "GERBIL_LOADPATH=" (string-join paths ":"))
   (gerbil-gxc) arguments ...])

;; Both compiler modes share ownership, cancellation, logs and result files.
;; Commands are argv lists, never interpolated shell programs.
(def (run-worker-process (srcpath : :string)
                         (stem : :string)
                         (command : :list)
                         (state : ProcessBuild)
                         (native? #f))
  (def log (string-append stem ".log"))
  (def result-file (string-append stem ".result"))
  (create-directory* (path-directory stem))
  (let (process
         (with-lock state.mx
           (lambda ()
             (when state.failed? (error "build cancelled" srcpath))
             (let (process (open-process
                            [path: "/bin/sh"
                             arguments: ["-c" "make_log=$1; shift; exec \"$@\" < /dev/null >\"$make_log\" 2>&1"
                                         "gerbil-make-worker" log
                                         command ...]
                             stdin-redirection: #f stdout-redirection: #f stderr-redirection: #f]))
               (hash-put! state.active process [srcpath log])
               process))))
    (try
     (let (status (process-status process))
       (show-process-output srcpath log status)
       (unless (zero? status)
         (if native?
           (raise-compile-error "native compiler process failed" srcpath status log)
           (error "source compiler process failed" srcpath status log)))
       (unless native? (call-with-input-file result-file read)))
     (finally
      (with-lock state.mx (lambda () (hash-remove! state.active process)))
      (close-port process)))))

(def (compile-in-process (srcpath : :string)
                         (opts : :list)
                         (config : settings)
                         (state : ProcessBuild))
  (def id (current-build-module-id))
  (def stem (path-expand (module-id->path-string id) state.directory))
  (def libdir (path-expand (settings-libdir config)))
  (def srcdir (path-expand (settings-srcdir config)))
  (def paths
    (cons libdir
      (filter (lambda (path) (not (member (path-expand path) [srcdir libdir])))
        (load-path))))
  (def arguments
    ["-compile-source" "-o" (string-append stem ".result")
     "-d" libdir "-target" (symbol->string (settings-target config))
     (if (pgetq optimize: opts) ["-O"] []) ...
     (if (pgetq debug: opts) ["-g"] []) ...
     (if (pgetq verbose: opts) ["-V"] []) ...
     (foldr (lambda (option rest) ["-gsc-flag" option rest ...])
       [] (or (pgetq gsc-options: opts) [])) ...
     srcpath])
  (def result
    (run-worker-process srcpath stem
      (compiler-process-command paths arguments) state))
  (def outputs (source-build-outputs result))
  (def jobs (source-build-native-jobs result))
  (unless (andmap file-exists? outputs)
    (error "source compiler did not finish its outputs" srcpath outputs))
  (call-with-output-file (build-marker id config) (cut write result <>))
  ;; A dependent macro may execute this module, including native-only FFI
  ;; and Gambit macros supplied by its gsc options. Publish it only when ready.
  (if (current-build-provider?)
    (for-each
      (lambda (job)
        (execute-native-compile-job! job
          (lambda (program args)
            (run-worker-process srcpath (string-append stem "-native")
              (cons program args) state #t))))
      jobs)
    (with-lock state.mx
      (lambda () (set! state.jobs (append jobs state.jobs))))))

;; A retry resolves phase imports from the providers completed in the preceding wave.
(def (discover-graph-in-process (paths : :list)
                                (index : :fixnum)
                                (config : settings)
                                (state : ProcessBuild)
                                (retry? #f) (defer? #t))
  => :list
  (def stem (path-expand (string-append "dependency-" (number->string index)) state.directory))
  (def packet
    (run-worker-process (car paths) stem
      (compiler-process-command
        (if retry? (cons (path-expand (settings-libdir config)) (load-path)) (load-path))
        [(if defer? "-deps-for-build" "-deps") "-target" (symbol->string (settings-target config))
         "-o" (string-append stem ".result") paths ...])
      state))
  (let (modules (dependency-graph-modules packet))
    (unless (= (length paths) (length modules))
      (error "incomplete dependency graph from worker" packet))
    modules))

;; Source directories are the package batching boundary. This requires no
;; expansion in the coordinator; explicit package/namespace names do not affect
;; dependency correctness. Preserve specification order within and across batches.
(def (dependency-batches (paths : :list)
                         policy)
  => :list
  (cond
   ((null? paths) [])
   ((eq? policy 'module) (map list paths))
   ((eq? policy 'package)
    (let ((groups (make-hash-table)) (order []))
      (for-each
        (lambda (path)
          (let* ((key (path-directory path)) (group (hash-get groups key)))
            (unless group
              (set! order (cons key order)))
            (hash-put! groups key (cons path (or group [])))))
        paths)
      (map (lambda (key) (reverse! (hash-ref groups key)))
        (reverse! order))))
   (else [paths])))

;; Forward literal setting keywords through the ordinary variadic entry.
;; make-build checks the build specification after make-settings consumes them.
(def (make buildspec . rest)
  (def settings (apply make-settings rest))
  (parameterize ((current-directory (settings-srcdir settings))
                 (current-expander-module-prelude
                  (make-prelude-context (import-module ':gerbil/base)))
                 (current-expander-compiling? #t))
    (add-load-path! (settings-srcdir settings))
    (using (state (start-process-build settings) :- ProcessBuild)
      (parameterize ((current-process-build state))
        (try
         (make-build (normalize-buildspec buildspec) settings)
         ;; Complete independent leaf jobs after the source workers have exited.
         (for-each (if (> (settings-parallelize settings) 1)
                     queue-native-compile-job!
                     execute-native-compile-job!)
                   (reverse state.jobs))
         (execute-pending-compile-jobs! (max 1 (settings-parallelize settings)))
         (for-each (lambda (marker)
                     (when (file-exists? marker) (delete-file marker)))
                   state.pending)
         (delete-file-or-directory state.directory #t)
         (catch (e)
           (stop-process-build! state)
           ;; In-process targets may have queued native work before source failed.
           ;; These threads have not started; do not carry them into the next build.
           (pending-compile-jobs)
           (parameterize ((current-output-port (current-error-port)))
             (displayln "Build diagnostics retained in " state.directory))
           (raise e)))))))

(def (make-build (buildspec : :list)
                 (config : settings)
                 (retry? #f))
  => :void
  (parameterize ((current-compilation-target (settings-target config)))
    (def remaining [])
    ;; detect and report duplicate files in the buildspec up front
    (let (file-counts (make-hash-table))
      (for (spec buildspec)
        (let (f (spec-file spec config))
          (hash-put! file-counts f (+ 1 (hash-ref file-counts f 0)))))
      (let (dups (filter-map (lambda (kv) (and (> (cdr kv) 1) (car kv)))
                             (hash->list file-counts)))
        (unless (null? dups)
          (error "Duplicate files in buildspec" dups))))
    ;; Plain discovery results, indexed by source path; never module contexts.
    (def modules (make-hash-table))
    ;; mute for dependency timestamps (mauling of load-path)
    (def dependency-mx (make-mutex 'dependency))
    ;; table of module id -> completion, indicating completion of a build
    (def completions (make-hash-table-eq))
    (def imported (make-hash-table-eq))
    ;; the build coordinator barrier
    (def build-barrier
      (make-barrier (length buildspec)))
    ;; channel of compilation work ready to be performed
    (def workch (make-channel))
    (def failure-mx (make-mutex 'make-failure))
    (def failure #f)
    (def (failed?) (with-lock failure-mx (lambda () failure)))
    (def (complete! id)
      (with-lock failure-mx
        (lambda ()
          (unless failure (completion-post! (hash-ref completions id) 'done)))))
    (def (fail-build! exn)
      (when (with-lock failure-mx
              (lambda ()
                (and (not failure)
                     (begin
                       (set! failure exn)
                       (channel-close workch)
                       ;; Wake dependency waiters normally; they observe failure
                       ;; before dispatching any further work.
                       (for-each (lambda (completion)
                                   (unless (completion-ready? completion)
                                     (completion-post! completion 'cancelled)))
                                 (hash-values completions))
                       (barrier-error! build-barrier exn)
                       #t))))
        (stop-process-build! (current-process-build))))
    ;; the build workers
    (def build-worker-count
      (max 1 (settings-parallelize config)))
    (def (module-info spec)
      (hash-ref modules (spec-file spec config)))
    ;; spec module id
    (def (module-id spec)
      (ModuleDependencies-id (module-info spec)))

    ;; Bound discovery concurrency just like compilation concurrency. No source
    ;; jobs start until every module name and dependency edge has been collected.
    (def (discover-modules!)
      (def policy (settings-dependency-processes config))
      (def paths
        (reverse!
          (foldl
            (lambda (spec paths)
              (let (file (spec-file spec config))
                (if (member (path-extension file) '(".ss" ".ssi"))
                  (cons file paths)
                  (begin
                    (hash-put! modules file (module-build-dependencies file))
                    paths))))
            [] buildspec)))
      (let* ((batches (dependency-batches paths policy))
             (pending batches) (index 0) (mx (make-mutex 'make-discovery)))
        (def (next!)
          (with-lock mx
            (lambda ()
              (and (pair? pending)
                   (let (paths (car pending))
                     (set! pending (cdr pending))
                     (set! index (+ index 1))
                     (DependencyJob index paths))))))
        (def (worker)
          (try
           (let loop ()
             (unless (failed?)
               (alet (item (next!))
                 (let* ((paths (DependencyJob-paths item))
                        (infos
                         (if (or policy retry?)
                           (discover-graph-in-process paths (DependencyJob-index item)
                             config (current-process-build) retry?)
                           (let (seen (make-hash-table))
                             (map (cut module-build-dependencies <> #t seen) paths)))))
                   (with-lock mx
                     (lambda ()
                       (for-each (lambda (path info) (hash-put! modules path info))
                         paths infos))))
                 (loop))))
           (catch (e) (fail-build! e))))
        (if (memq policy '(module package))
          (let (workers
                 (map (lambda (i) (spawn/name `(discover ,i) worker))
                   (iota (min build-worker-count (length batches)))))
            (for-each thread-join! workers))
          (worker))
        (when failure
          (raise failure))))

    ;; does the spec need building?
    (def (build? spec)
      (let ((inputs (spec-inputs spec config))
            (outputs (spec-outputs spec config)))
        (or (settings-force config)
            (file-exists? (build-marker (module-id spec) config))
            (ormap (lambda (f) (not (file-exists? f)))
                   outputs)
            (ormap
             (lambda (input)
               (ormap (cut file-newer? input <>)
                      outputs))
             inputs))))
    ;; does the spec needs building because of newer dependencies?
    (def (build-dependent? spec)
      (def outputs (spec-outputs spec config))
      (ormap
        (lambda (id)
          (let (ts (with-catch false (cut dependency-timestamp id)))
            (if ts
              (ormap (lambda (output) (> ts (file-timestamp output)))
                outputs)
              #t)))
        (ModuleDependencies-imports (module-info spec))))

    (def (dependency-timestamp id)
      (with-lock dependency-mx
                 (lambda ()
                   ;; drop the srcdir from the load path and then get the library timestamp
                   (let (current-load-path (load-path))
                     (dynamic-wind
                         (lambda ()
                           (set-load-path!
                            (cons (settings-libdir config)
                                  (filter (lambda (p) (not (equal? p (settings-srcdir config))))
                                          current-load-path))))
                         (lambda () (library-timestamp id))
                         (lambda () (set-load-path! current-load-path)))))))

    ;; the build worker itself
    (def (build-worker)
      (try
       (for (spec workch)
         (unless (failed?)
           (let* ((id (module-id spec))
                  (marker (build-marker id config)))
             ;; Keep the marker until native compilation succeeds as well.
             ;; This also repairs interrupted builds when processes: is disabled.
             (create-directory* (path-directory marker))
             (call-with-output-file marker (cut write ['build-incomplete id] <>))
             (using (state (current-process-build) :- ProcessBuild)
               (with-lock state.mx
                 (lambda () (set! state.pending (cons marker state.pending)))))
             (parameterize ((current-build-module-id id)
                            (current-build-provider? (or (pair? remaining) (hash-get imported id))))
               (build spec config))
             (complete! id))))
       (catch (e)
         (fail-build! e))))

    ;; the build coordinator
    (def (build-coordinator spec)
      (try
       (let (info (module-info spec))
        (for-each
          (lambda (id)
            (alet (completion (hash-get completions id))
              (completion-wait! completion)))
          (ModuleDependencies-imports info))
        (unless (failed?)
          (if (or (build? spec)
                  (build-dependent? spec))
            ;; it needs to be built, put it to the work channel
            (channel-put workch spec)
            ;; no need to build, unblock dependents
            (complete! (module-id spec))))
        ;; clear the barrrier
        (barrier-post! build-barrier))
       (catch (e) (fail-build! e))))

    ;; prepare the build
    (create-directory* (settings-bindir config))
    (create-directory* (settings-libdir config))
    (create-directory* (path-expand "static" (settings-libdir config)))

    (let (start (time->seconds (current-time)))
      (discover-modules!)
      (when (settings-verbose>=? config 1)
        (message "... dependency discovery: " (length buildspec) " modules, "
                 (- (time->seconds (current-time)) start) "s, processes: "
                 (settings-dependency-processes config))))

    ;; If phase evaluation needs native code, build its known prerequisites
    ;; first. Rediscover the consumer from the installed interfaces so imports
    ;; appearing later in its body still participate in scheduling.
    (let (pending (filter (lambda (spec) (pending-module-dependencies? (module-info spec))) buildspec))
      (unless (null? pending)
        (let ((by-id (make-hash-table-eq)) (ready (make-hash-table-eq)))
          (for-each (lambda (spec) (hash-put! by-id (module-id spec) spec)) buildspec)
          (def (include-provider! id visiting)
            (cond
             ((hash-get ready id))
             ((memq id visiting) (error "cyclic build dependency" id visiting))
             ((hash-get by-id id)
              => (lambda (spec)
                   (let (info (module-info spec))
                     (and (not (pending-module-dependencies? info))
                          (andmap (cut include-provider! <> (cons id visiting))
                            (ModuleDependencies-imports info))
                          (begin (hash-put! ready id #t) #t)))))
             (else #t)))
          (for-each
            (lambda (spec)
              (for-each (cut include-provider! <> [])
                (ModuleDependencies-imports (module-info spec))))
            pending)
          (if (zero? (hash-length ready))
            ;; External providers may already be installed. Report the original
            ;; expansion error if their interfaces still cannot satisfy the import.
            (let (paths (map (cut spec-file <> config) pending))
              (for-each (cut hash-put! modules <> <>) paths
                (discover-graph-in-process paths 0 config (current-process-build) #t #f)))
            (begin
              (set! remaining (filter (lambda (spec) (not (hash-get ready (module-id spec)))) buildspec))
              (set! buildspec (filter (lambda (spec) (hash-get ready (module-id spec))) buildspec))
              (set! build-barrier (make-barrier (length buildspec))))))))

    ;; prepare the completion table
    (for (spec buildspec)
      (for-each (cut hash-put! imported <> #t)
        (ModuleDependencies-imports (module-info spec)))
      (let (id (module-id spec))
        (hash-put! completions id (make-completion `(build ,id)))))

    ;; spawn a thread for each spec that waits for the dependency completions
    ;; and pushes to the work channel if necessary.
    (let* ((coordinators
            (map (lambda (spec)
                   (spawn/name `(build ,(spec-file spec config)) build-coordinator spec))
                 buildspec))
           (workers (map (lambda (i) (spawn/name `(worker ,i) build-worker))
                         (iota build-worker-count))))
      ;; wait for the coordinators to complete
      (with-catch fail-build! (cut barrier-wait! build-barrier))
      ;; close the channel (no more work)
      (channel-close workch)
      ;; No thread termination: every waiter is released and every worker reaped.
      (for-each thread-join! coordinators)
      (for-each thread-join! workers)
      (when failure
        (raise failure)))
    (unless (null? remaining)
      (with-cons-load-path (cut make-build remaining config #t)
        (path-expand (settings-libdir config))))))

;; Dependencies may have been rebuilt since an earlier freshness check, including
;; in this invocation. Always observe the current file and library timestamps.
(def (file-timestamp (file : :string))
  => :flonum
  (time->seconds (file-info-last-modification-time (file-info file))))

(def (library-timestamp (id : :symbol))
  => :flonum
  (file-timestamp (core-resolve-library-module-path (library-symbol id))))

(def (library-symbol (id : :symbol))
  => :symbol
  (make-symbol ":" (module-file-id id)))

(def (make-clean . args)
  (defvalues (positionals keywords) (separate-keyword-arguments args #t))
  (def buildspec (match positionals ([x] x) (_ (error "invalid arguments" make positionals))))
  (def settings (apply make-settings keywords))

  (for* ((spec buildspec)
         (f    (spec-outputs spec settings)))
    (when (file-exists? f)
      (displayln "... remove " f)
      (delete-file-or-directory f))))


;; Normalize-buildspec : buildspec -> buildspec
;; Groups the gsc: and static-include: and copy: specs inside the immediately following ssi:
(def (normalize-buildspec (buildspec : :list))
  => :list
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
                           [gxc: name (psetq plist submodules: (append (pgetq submodules: plist []) s)) . args])
                          ([gxc: name . args]
                           [gxc: name [submodules: s] . args])
                          ((? string? spec)
                           [gxc: spec [submodules: s]]))))))
         ((exe: static-exe: optimized-exe: optimized-static-exe:) (no-submodules spec) (c spec))
         ((gsc: static-include: copy:) (push-submodule spec))
         ((ssi:) (c (append spec (get-submodules))))
         (else (error "Unrecognized spec type" spec)))))
    (no-submodules #!eof)))

(def (shell-config (cmd : :string) . args)
  (let* ((proc (open-input-process [path: cmd arguments: args]))
         (status (process-status proc)))
    (unless (zero? status)
      (error "Error executing config script" cmd args status))
    (read-line proc)))

(def (env-ldflags)
  => :procedure
  (cond
   ((getenv "LDFLAGS" #f)
    => (lambda (flags)
         (lambda (lib)
           (string-append flags " " lib))))
   (else
    identity)))

(def (env-cppflags)
  => :procedure
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
  => :list
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

(def (build spec
            (config : settings))
  (match spec
    ((? string? modf)
     (gxc-compile modf #f config #t))
    ([gxc: modf . opts]
     (for-each (cut build <> config) (spec-submodules spec))
     (gxc-compile modf opts config #t))
    ([gsc: modf . opts]
     (gsc-compile modf opts config))
    ([ssi: modf . submodules]
     (for-each (cut build <> config) submodules)
     (compile-ssi modf '() config))
    ([exe:  modf . opts]
     (compile-exe/context modf opts config))
    ([static-exe:  modf . opts]
     (compile-exe/static-linkage modf opts config))
    ([optimized-exe: modf . opts]
     (compile-optimized-exe modf opts config))
    ([optimized-static-exe: modf . opts]
     (compile-optimized-exe/static-linkage modf opts config))
    ([static-include: file]
     (copy-target file config)
     (copy-static file config))
    ([copy: file]
     (copy-compiled file config))
    (else
     (error "Bad buildspec" spec))))

(def (gxc-outputs (mod : :string)
                  (opts :? :list)
                  (config : settings))
  => :list
  [(library-path mod ".ssi" config)
   (static-path mod config)])

(def (gsc-compile-opts (opts :? :list))
  => :list
  (match opts
    ([[plist ...] . rest] (listify rest))
    (_ (listify opts))))

;; TODO: split that (and more?) into many action. See :gerbil/compiler/driver
(def (gxc-compile (mod : :string)
                  (opts :? :list)
                  (config : settings)
                  (invoke-gsc? : :boolean := #t))
  (message "... compile " mod)
  (def gsc-opts (gsc-compile-opts opts))
  (def srcpath (source-path mod ".ss" config))
  (let (gxc-opts
        [invoke-gsc: invoke-gsc?
         target: (settings-target config)
         keep-scm: (not invoke-gsc?)
         output-dir: (settings-libdir config)
         generate-ssxi: #t
         optimize: (settings-optimize config)
         debug: (settings-debug config)
         verbose: (settings-verbose>=? config 9)
         parallel: (and (not (current-build-provider?)) (> (settings-parallelize config) 1))
         (when/list gsc-opts [gsc-options: gsc-opts]) ...])
    (if (and (settings-processes config)
             (> (settings-parallelize config) 0)
             (not (match opts
                    ([[plist ...] . _] (pgetq foreground: plist))
                    (else #f)))
             invoke-gsc? (current-process-build))
      (compile-in-process srcpath gxc-opts config (current-process-build))
      (compile-module srcpath gxc-opts))))

(def (gsc-libpath (mod : :string)
                  (config : settings))
  => :string
  (def libdir-prefix (settings-libdir-prefix config))
  (cond
   ((string-rindex mod #\/) => (lambda (ix) (path-expand (substring mod 0 ix) libdir-prefix)))
   (else libdir-prefix)))

(def (gsc-base (mod : :string))
  => :string
  (cond
   ((string-rindex mod #\/)
    => (lambda (ix) (substring mod (fx1+ ix) (string-length mod))))
   (else mod)))

(def (gsc-c-path (modf : :string)
                 (config : settings))
  => (Maybe :string)
  (def mod (path-strip-extension modf))
  (def libpath (gsc-libpath mod config))
  (def base (gsc-base mod))
  (let lp ((n 1) (cpath #f))
    (let (next (path-expand (string-append base ".o" (number->string n))
                            libpath))
      (if (file-exists? next)
        (lp (fx1+ n) next)
        cpath))))

(def (gsc-compile (mod : :string)
                  (opts : :list)
                  (config : settings))
  (def gsc-opts (gsc-compile-opts opts))
  (def srcpath (source-path mod ".scm" config))
  (def libpath (gsc-libpath mod config))
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
  (let (statpath (static-path mod config))
    (when (file-exists? statpath)
      (delete-file statpath))
    (copy-file srcpath statpath)))

(def (gerbil-gsc)
  (getenv "GERBIL_GSC" default-gambit-gsc))
(def (gerbil-gxc)
  (getenv "GERBIL_GXC" default-gerbil-gxc))

(def (compile-ssi (mod : :string)
                  (deps : :list)
                  (config : settings))
  (def srcpath (source-path mod ".ssi" config))
  (def libpath (library-path mod ".ssi" config))
  (message "... copy ssi " mod)
  (create-directory* (path-directory libpath))
  (when (file-exists? libpath)
    (delete-file libpath))
  (copy-file srcpath libpath))

(def (compile-exe-gsc-opts (opts : :list))
  => :list
  (match opts
    ([(? keyword?) opt . rest]
     (compile-exe-gsc-opts rest))
    (else opts)))

(def (compile-exe/context (mod : :string)
                          (opts : :list)
                          (config : settings))
  (cond
   ((or (settings-build-release config)
        (getenv "GERBIL_BUILD_RELEASE" #f))
    (cond
     ((or (settings-build-optimized config)
          (getenv "GERBIL_BUILD_OPTIMIZED" #f))
      (compile-optimized-exe/static-linkage mod opts config))
      (else
       (compile-exe/static-linkage mod opts config))))
   ((or (settings-build-optimized config)
        (getenv "GERBIL_BUILD_OPTIMIZED" #f))
    (compile-optimized-exe mod opts config))
   (else
    (compile-exe mod opts config))))

(def (compile-exe (mod : :string)
                  (opts : :list)
                  (config : settings))
  (def srcpath (source-path mod ".ss" config))
  (def binpath (binary-path mod opts config))
  (def gsc-opts (compile-exe-gsc-opts opts))
  (def gxc-opts
    [invoke-gsc: #t
     output-file: binpath
     verbose: (settings-verbose>=? config 9)
     debug: (settings-debug config)
     full-program-optimization: (settings-full-program-optimization config)
     parallel: (> (settings-parallelize config) 1)
     (when/list gsc-opts [gsc-options: gsc-opts]) ...])
  (gxc-compile mod gsc-opts config #f)
  (message "... compile exe " mod " -> " binpath)
  (gxc#compile-exe srcpath gxc-opts))

(def (compile/static-linkage (mod : :string)
                             (opts : :list)
                             (config : settings)
                             (compile-e : :procedure))
  (when (member "--enable-shared" (string-split (configure-command-string) #\'))
    (error "system is configured with --enable-shared and cannot build static executables"))
  (let (static-opts (append opts '("-cc-options" "-Bstatic" "-ld-options" "-static")))
    (compile-e mod static-opts config)))

(def (compile-exe/static-linkage (mod : :string)
                                 (opts : :list)
                                 (config : settings))
  (compile/static-linkage mod opts config compile-exe))

(def (make-settings-optimized (config : settings))
  => settings
  (def s (struct-copy config))
  (set! (settings-full-program-optimization s) #t)
  s)

(def (compile-optimized-exe (mod : :string)
                            (opts : :list)
                            (config : settings))
  (compile-exe mod opts (make-settings-optimized config)))

(def (compile-optimized-exe/static-linkage (mod : :string)
                                           (opts : :list)
                                           (config : settings))
  (compile/static-linkage mod opts config compile-optimized-exe))

(def (copy-static (file : :string)
                  (config : settings))
  (def spath (static-file-path file config))
  (message "... copy static include " file)
  (when (file-exists? spath)
    (delete-file spath))
  (copy-file file spath))

(def (copy-target (file : :string)
                  (config : settings))
  (let* ((libdir (settings-libdir-prefix config))
         (srcdir (settings-srcdir config))
         (spath (path-expand file srcdir))
         (tpath (path-expand file libdir)))
    (message "... copy static include to target directory " file)
    (create-directory* (path-directory tpath))
    (when (file-exists? tpath)
      (delete-file tpath))
    (copy-file spath tpath)))

(def (copy-compiled (file : :string)
                    (config : settings))
  (def srcpath (source-path file #f config))
  (def libpath (library-path file #f config))
  (message "... copy std/" file)
  (create-directory* (path-directory libpath))
  (when (file-exists? libpath)
    (delete-file libpath))
  (copy-file srcpath libpath))

(def (source-path (mod : :string)
                  (ext :? :string)
                  (config : settings))
  => :string
  (path-expand (path-default-extension mod ext) (settings-srcdir config)))

(def (library-path (mod : :string)
                   (ext :? :string)
                   (config : settings))
  => :string
  (path-expand (path-force-extension mod ext) (settings-libdir-prefix config)))

(def (binary-path (mod : :string)
                  (opts : :list)
                  (config : settings))
  => :string
  (let* ((bindir (settings-bindir config))
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

(def (static-path (mod : :string)
                  (config : settings))
  => :string
  (let* ((libdir (settings-libdir config))
         (staticdir (path-expand "static" libdir))
         (mod (prefix/ (settings-prefix config) mod))
         (base (string-join (string-split mod #\/) "__"))
         (scm (path-force-extension base ".scm")))
    (path-expand scm staticdir)))

(def (static-file-path (file : :string)
                       (config : settings))
  => :string
  (let* ((libdir (settings-libdir config))
         (staticdir (path-expand "static" libdir))
         (filename (path-strip-directory file)))
    (path-expand filename staticdir)))

;; lib: library to ask configuration for
;; args: [<arg> ...]
;;  <arg>: additionnal arguments to pass to pkg-config
(def (pkg-config (lib : :string) . args)
  (apply shell-config "pkg-config" "--silence-errors" lib args))

;; calls pkg-config in order to return `ld-options`.
;;
;; libs: [<lib> ...]
;;  <lib>: library to get ld-options for
(def (pkg-config-libs . libs)
  => :string
  (string-join (map (lambda (l) (pkg-config l "--libs")) libs) " "))

;; calls pkg-config in order to return `cc-options`.
;;
;; libs: [<lib> ...]
;;  <lib>: library to get cc-options for
(def (pkg-config-cflags . libs)
  => :string
  (string-join (map (lambda (l) (pkg-config l "--cflags")) libs) " "))

;; tries pkg-config-libs with fallback to env-ldflags
(def (ldflags (lib : :string)
              (flags : :string))
  => :string
  (try
   (pkg-config-libs lib)
   (catch (e)
     ((env-ldflags) flags))))

;; tries pkg-confg-cflags with fallback to env-cppflags
(def (cppflags (lib : :string)
               (flags : :string))
  => :string
  (try
   (pkg-config-cflags lib)
   (catch (e)
     ((env-cppflags) flags))))

;; appends flags together; useful for -cc-options and -ld-options
(def (append-options . opts)
  => :string
  (let (opts (filter (? (not string-empty?)) opts))
    (string-join opts " ")))

;; temporarily sets the load-path
(def (with-cons-load-path (thunk : :procedure)
                          (path : :string))
  (let (current-load-path (load-path))
    (dynamic-wind
        (cut add-load-path! path)
        thunk
        (cut set-load-path! current-load-path))))

(def (enable-shared?)
  => (Maybe :pair)
  (member "--enable-shared" (string-split (configure-command-string) #\')))
