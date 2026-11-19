;;; -*- Gerbil -*-
;;; (C) vyzo at hackzen.org
;;; gerbil compiler basic env
prelude: "../core"
package: gerbil/compiler
namespace: gxc

(import "../core/expander"
        "../expander")
(export #t)

(def __DEBUG-COMPILE
  (and (string? __DEBUG)
       (string-contains __DEBUG "compilation")))

(defsyntax (ast-case stx)
  (macro-expand-syntax-case stx 'stx-eq? 'stx-e 'quote))

(defsyntax (ast-rules stx)
  (syntax-case stx ()
    ((_ ids clause ...)
     (identifier-list? #'ids)
     (with-syntax (((clause ...)
                    (stx-map (lambda (clause)
                               (syntax-case clause ()
                                 ((hd body)
                                  #'(hd (syntax body)))
                                 ((hd fender body)
                                  #'(hd fender (syntax body)))))
                             #'(clause ...))))
       #'(lambda ($stx)
           (ast-case $stx ids clause ...))))))

(def current-compile-symbol-table
  (make-parameter #f))
(def current-compile-runtime-sections
  (make-parameter #f))
(def current-compile-runtime-names
  (make-parameter #f))
(def current-compile-output-dir
  (make-parameter #f))
(def current-compile-invoke-gsc
  (make-parameter #f))
(def current-compile-gsc-options
  (make-parameter #f))
(def current-compile-keep-scm
  (make-parameter #f))
(def current-compile-verbose
  (make-parameter
   (alet (verbosity (getenv "GERBIL_BUILD_VERBOSE" #f))
     (or (string->number verbosity)
         verbosity))))
(def current-compile-optimize
  (make-parameter #f))
(def current-compile-debug
  (make-parameter #f))
(def current-compile-generate-ssxi
  (make-parameter #f))
(def current-compile-static
  (make-parameter #f))
(def current-compile-timestamp
  (make-parameter #f))
(def current-compile-decls
  (make-parameter #f))
(def current-compile-context
  (make-parameter #f))
(def current-compile-parallel
  (make-parameter #f))

;; quote-syntax lifts
(def current-compile-lift
  (make-parameter #f))
(def current-compile-marks
  (make-parameter #f))
(def current-compile-identifiers
  (make-parameter #f))
(def current-compile-boolean-context
  (make-parameter #f))

(def (make-bound-identifier-table)
  (def (hash-e id)
    (symbol-hash (stx-e id)))
  (make-hash-table test: bound-identifier=? hash: hash-e))

;; locally scoped identifiers
(def current-compile-local-env
  (make-parameter []))

(defstruct symbol-table (gensyms bindings)
  id: gxc#symbol-table::t
  constructor: :init!)

(defmethod {:init! symbol-table}
  (lambda (self)
    (struct-instance-init! self (make-hash-table-eq) (make-hash-table-eq))))

(def (raise-compile-error message stx . details)
  (let (ctx (or (current-compile-context) '(compile)))
    (apply raise-syntax-error ctx message stx details)))

(def (verbose . args)
  (when (current-compile-verbose)
    (with-verbose-mutex (apply displayln args))))

(def __verbose-mutex (make-mutex 'compiler/driver))
(defrules with-verbose-mutex ()
  ((_ expr)
   (with-lock __verbose-mutex (lambda () expr))))

;; these characters are restricted to avoid confusing shells and other tools
(def module-path-reserved-chars
  ":#<>&!?*;()[]{}|'`\"\\")

(def (module-id->path-string id)
  (let* ((str (if (symbol? id) (symbol->string id) id))
         (len (string-length str))
         (res (make-string len)))
    (let lp ((i 0))
      (if (fx< i len)
        (let* ((char (string-ref str i))
               (xchar (if (string-index module-path-reserved-chars char)
                        #\_ char)))
          (string-set! res i xchar)
          (lp (fx1+ i)))
        res))))

(def (map* proc maybe-improper-list)
  (let recur ((rest maybe-improper-list))
    (match rest
      ([hd . rest]
       (cons (proc hd)
             (recur rest)))
      ([] [])
      (tail (proc tail)))))

(def (symbol-in-local-scope? sym)
  (or ;; either not a gensym refernce (in which case it is global)
    (not (gensym-reference? sym))
    ;; or it should be in the local env
    (memq sym (current-compile-local-env))))

(def (gensym-reference? sym)
  (let (str (symbol->string sym))
    (and (string-prefix? "_%" str)
         (string-suffix? "%_" str))))

(def (generate-runtime-binding-id id)
  (cond
   ((and (syntax-quote? id) (resolve-identifier id))
    => (lambda (bind)
         (let ((eid (binding-id bind))
               (ht (symbol-table-bindings (current-compile-symbol-table))))
           (cond
            ((interned-symbol? eid) eid)
            ((hash-get ht eid))
            ((local-binding? bind)
             (let (gid (generate-runtime-gensym-reference eid))
               (hash-put! ht eid gid)
               gid))
            ((module-binding? bind)
             (let (gid
                   (cond
                    ((module-context-ns (module-binding-context bind))
                     => (lambda (ns) (make-symbol ns "#" eid)))
                    (else (generate-runtime-gensym-reference eid))))
               (hash-put! ht eid gid)
               gid))
            (else
             ;; module bindings have been mapped in collect-bindings.
             (raise-compile-error "Cannot compile reference to uninterned binding"
                                  id eid bind))))))
   ((interned-symbol? (stx-e id))
    ;; implicit extern or optimizer introduced symbol
    (stx-e id))
   (else
    ;; gensymed reference, where did you get this one?
    (raise-compile-error "Cannot compile reference to uninterned identifier"
                         id))))

(def (generate-runtime-binding-id* id)
  (if (identifier? id)
    (generate-runtime-binding-id id)
    (generate-runtime-temporary)))

(def (generate-runtime-temporary (top #f))
  (if top
    (let ((ns (module-context-ns (core-context-top (current-expander-context))))
          (phi (current-expander-phi)))
      (if ns
        (if (fxpositive? phi)
          (make-symbol ns "[" (number->string phi) "]#_" (gensym) "_")
          (make-symbol ns "#_" (gensym) "_"))
        (if (fxpositive? phi)
          (make-symbol "[" (number->string phi) "]#_" (gensym) "_")
          (make-symbol "_" (gensym) "_"))))
    (make-symbol "_" (gensym) "_")))

(def (generate-runtime-gensym-reference sym (quote? #f))
  (let (ht (symbol-table-gensyms (current-compile-symbol-table)))
    (cond
     ((hash-get ht sym))
     (else
      (let (g (if quote?
                (make-symbol "__" sym "__" (current-compile-timestamp))
                (make-symbol "_%" sym "%_")))
        (hash-put! ht sym g)
        g)))))

(def (generate-runtime-identifier id)
  (generate-runtime-identifier-key (core-identifier-key id)))

(def (generate-runtime-identifier-key key)
  (cond
   ((interned-symbol? key) key)
   ((uninterned-symbol? key)
    (generate-runtime-gensym-reference key))
   (else
    (match key
      ([eid . mark]
       (cond
        ((expander-mark-subst mark)
         => (lambda (ht)
              (cond
               ((hash-get ht eid)
                => (lambda (id)
                     (if (interned-symbol? id) id
                         (generate-runtime-gensym-reference id))))
               (else
                (generate-runtime-identifier-key eid)))))
        (else
         (generate-runtime-identifier-key eid))))))))

(def (runtime-identifier=? id1 id2)
  (def (symbol-e id)
    (if (symbol? id) id
        (generate-runtime-binding-id id)))
  (eq? (symbol-e id1) (symbol-e id2)))

(def (identifier-symbol stx)
  (if (syntax-quote? stx)
    (generate-runtime-binding-id stx)
    (stx-e stx)))

(def (runtime-identifier-properties id)
  (let* ((bind (resolve-identifier id))
         (runtime-props
          (cond
           ((runtime-binding? bind)
            (let* ((props
                    (cond
                     ((runtime-binding-macro bind)
                      => (lambda (macro-id)
                           [macro: (generate-runtime-identifier macro-id)]))

                     (else [])))
                   (props
                    (cond
                     ((runtime-binding-type bind)
                      => (lambda (type)
                           (cond
                            ((method-ref type ':repr)
                             => (lambda (method)
                                  (let (repr (method type))
                                    [type: repr :: props])))
                            (else
                             (raise-compile-error "unrepresentable type" id type)))))
                     (else props))))
              props))
           (else []))))
         (cond
          ((binding-properties bind)
           => (lambda (props)
                (foldl (lambda (prop props)
                         (with ([key . value] prop)
                           (cond
                            ((method-ref value ':repr)
                             => (lambda (method)
                                  (let (repr (method value))
                                    [key repr :: props])))
                            (else
                             [key ['quote value] :: props]))))
                       runtime-props
                       props)))
          (else runtime-props))))

;; Compilation owns its private siblings until synchronous completion or handoff
;; to make. Jobs inherit the owner's parameters, but never publish individually.
(def current-compile-attempt (make-parameter #f))
(def current-compile-defer (make-parameter #f))
(def current-compile-temporary-prefix
  (make-parameter (lambda () (string-append "gxtmp" (number->string (##os-getpid)) "."))))

(defstruct compile-attempt (primary generation prefix paths dirs jobs mx state))
(defstruct compile-output (logical private kind))

;; flock is attached to the open directory, not to a replaceable output inode.
;; Never block the Scheme scheduler in flock, or leak the lock across exec.
(extern namespace: #f gxc-try-lock-directory gxc-close-directory-lock)
(begin-foreign
  (c-declare "
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
static int gxc_try_lock_directory(const char *path) {
  int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return -(errno + 2);
  if (flock(fd, LOCK_EX | LOCK_NB) == 0) return fd;
  int e = errno;
  close(fd);
  return (e == EWOULDBLOCK || e == EINTR) ? -1 : -(e + 2);
}")
  (define gxc-try-lock-directory (c-lambda (nonnull-UTF-8-string) int "gxc_try_lock_directory"))
  (define gxc-close-directory-lock (c-lambda (int) void "(void)close(___arg1);")))

(def (call-with-publication-lock dir thunk)
  (let retry ()
    (let (fd (gxc-try-lock-directory dir))
      (cond
       ((>= fd 0) (unwind-protect (thunk) (gxc-close-directory-lock fd)))
       ((= fd -1) (thread-sleep! .01) (retry))
       (else (error "Cannot lock compiler output directory" dir (- -2 fd)))))))

(def (compile-path-info path)
  (with-catch
   (lambda (e) (if (no-such-file-or-directory-exception? e) #f (raise e)))
   (cut file-info path #f)))

(def (compile-generation primary)
  (def (stamp path)
    (alet (fi (compile-path-info path))
      [(file-info-device fi) (file-info-inode fi) (file-info-size fi)
       (time->seconds (file-info-last-change-time fi))
       (time->seconds (file-info-last-modification-time fi))]))
  [(stamp primary) (stamp (string-append primary ".new"))])

(def (compile-next-object logical-scm)
  (let (root (string-append (path-strip-extension logical-scm) ".o"))
    (let loop ((n 1))
      (let (path (string-append root (number->string n)))
        (if (file-exists? path) (loop (1+ n)) path)))))

(def (compile-create-parent! dir)
  (let retry ()
    (with-catch
     (lambda (e) (if (file-exists-exception? e) (retry) (raise e)))
     (cut create-directory* dir))))

(def (new-compile-attempt primary)
  (let* ((base ((current-compile-temporary-prefix)))
         (primary (path-expand primary))
         (dir (path-directory primary)))
    (unless (and (string? base) (positive? (string-length base))
                 (not (string-index base #\/)) (not (string-index base #\\))
                 (not (string-index base (integer->char 0))))
      (error "Invalid compiler temporary prefix" base))
    (compile-create-parent! dir)
    (let* ((generation (compile-generation primary))
           ;; mkdir is the exclusive reservation. A time/serial component avoids
           ;; recycling a released name on retry; mkdir handles live collisions.
           (seed (string-append base (number->string (##os-getpid)) "."
                   (number->string (inexact->exact (floor (* 1000000 (time->seconds (current-time))))))
                   "." (symbol->string (gensym 'a))))
           (reservation (create-temporary-directory [path: (path-expand seed dir) permissions: #o700]))
           (dirs (make-hash-table)))
      (hash-put! dirs dir reservation)
      (make-compile-attempt primary generation
        (string-append (path-strip-directory reservation) ".")
        (make-hash-table) dirs [] (make-mutex) 'open))))

(def (compile-stage-path logical (kind 'ordinary))
  (let* ((a (current-compile-attempt))
         (logical (path-expand logical)))
    (unless (and a (memq kind '(ordinary version temporary)))
      (error "Invalid compiler staging request" logical kind))
    (with-lock (compile-attempt-mx a)
      (lambda ()
        (unless (eq? 'open (compile-attempt-state a))
          (error "Compiler attempt already settled" logical))
        (cond
         ((hash-get (compile-attempt-paths a) logical) => compile-output-private)
         (else
          (let* ((dir (path-directory logical))
                 (prefix (compile-attempt-prefix a))
                 (private (path-expand (string-append prefix (path-strip-directory logical)) dir)))
            ;; Two primaries can stage into the same static directory. Reserve
            ;; the prefix there too before allowing either producer to write.
            (unless (hash-get (compile-attempt-dirs a) dir)
              (compile-create-parent! dir)
              (let (reservation (path-expand (substring prefix 0 (1- (string-length prefix))) dir))
                (create-directory [path: reservation permissions: #o700])
                (hash-put! (compile-attempt-dirs a) dir reservation)))
            (when (compile-path-info private)
              (error "Compiler staging path is occupied" private))
            (hash-put! (compile-attempt-paths a) logical (make-compile-output logical private kind))
            private)))))))

(def (compile-attempt-add-job! thunk name)
  (let (a (current-compile-attempt))
    (set! (compile-attempt-jobs a)
      (cons (make-compile-job thunk name) (compile-attempt-jobs a)))))

;; Join even after a failed sibling (or a failed thread-start!). No cleanup
;; may race a writer. A raised #f must still count as failure.
(def (compile-attempt-run-jobs! a)
  (let ((started []) (failure #f))
    (def (failed e) (unless failure (set! failure (list e))))
    (for-each (lambda (job)
                (unless failure
                  (with-catch failed
                    (lambda () (thread-start! job) (set! started (cons job started))))))
              (reverse (compile-attempt-jobs a)))
    (for-each (lambda (job) (with-catch failed (cut join! job))) (reverse! started))
    (when failure (raise (car failure)))))

(def (compile-cleanup! a)
  (hash-for-each (lambda (_ entry)
                   (let (path (compile-output-private entry))
                     (when (compile-path-info path) (delete-file path))))
                 (compile-attempt-paths a))
  (hash-for-each (lambda (_ dir) (delete-directory dir)) (compile-attempt-dirs a)))

(def (compile-attempt-abort! a)
  (with-lock (compile-attempt-mx a)
    (lambda ()
      (when (eq? 'open (compile-attempt-state a))
        (set! (compile-attempt-state a) 'aborted)
        (compile-cleanup! a)))))

(def (compile-attempt-publish! a)
  (def primary (compile-attempt-primary a))
  (def dir (path-directory primary))
  (def marker (string-append primary ".new"))
  (def paths (compile-attempt-paths a))
  (def (publish entry)
    (rename-file (compile-output-private entry) (compile-output-logical entry)
                 (not (eq? 'version (compile-output-kind entry)))))
  (let (last (hash-get paths primary))
    (unless (and last (memq (compile-output-kind last) '(ordinary version)))
      (error "Missing staged primary" primary))
    (call-with-publication-lock dir
      (lambda ()
        (unless (equal? (compile-attempt-generation a) (compile-generation primary))
          (error "Concurrent publication changed compiler output" primary))
        (hash-for-each
         (lambda (logical entry)
           (unless (eq? 'temporary (compile-output-kind entry))
             (unless (eq? 'regular (file-info-type (file-info (compile-output-private entry) #f)))
               (error "Expected a staged regular file" logical))
             (when (and (eq? 'version (compile-output-kind entry)) (compile-path-info logical))
               (error "Compiler object version is occupied" logical))))
         paths)
        ;; Replace even an inherited marker with a new generation. Once this
        ;; rename succeeds, only a *successful* publication removes the marker.
        (let (staged-marker (path-expand "incomplete" (hash-ref (compile-attempt-dirs a) dir)))
          (unwind-protect
            (begin
              (call-with-output-file staged-marker void)
              (rename-file staged-marker marker #t))
            (when (compile-path-info staged-marker) (delete-file staged-marker))))
        (for-each
         (lambda (kind)
           (hash-for-each
            (lambda (_ entry)
              (when (and (eq? kind (compile-output-kind entry)) (not (eq? entry last)))
                (publish entry)))
            paths))
         '(version ordinary))
        (publish last)
        (when (string-suffix? ".ssi" primary)
          (let (legacy (string-append primary ".old"))
            (when (compile-path-info legacy) (delete-file legacy))))
        (delete-file marker)))))

(def (compile-attempt-commit! a)
  (with-lock (compile-attempt-mx a)
    (lambda ()
      (unless (eq? 'open (compile-attempt-state a))
        (error "Compiler attempt already settled" (compile-attempt-primary a)))
      (unwind-protect
        (begin (compile-attempt-publish! a) (set! (compile-attempt-state a) 'committed))
        (when (eq? 'open (compile-attempt-state a)) (set! (compile-attempt-state a) 'aborted))
        (compile-cleanup! a)))))

(def (call-with-compile-attempt primary thunk)
  (let ((a (new-compile-attempt primary)) (transferred? #f))
    (unwind-protect
      (parameterize ((current-compile-attempt a))
        (begin0 (thunk)
          (cond
           ((current-compile-defer) => (lambda (defer) (defer a) (set! transferred? #t)))
           (else (compile-attempt-run-jobs! a) (compile-attempt-commit! a)))))
      (unless transferred? (compile-attempt-abort! a)))))

;; parallel build support
(def __compile-jobs [])
(def __available-cores
  (string->number
   (getenv "GERBIL_BUILD_CORES" "1")))
(def __jobs-mx (make-mutex))
(def __jobs-cv (make-condition-variable))

(def (add-compile-job! thunk (name (current-compile-context)))
  (mutex-lock! __jobs-mx)
  (let (job (make-compile-job thunk name))
    (set! __compile-jobs (cons job __compile-jobs)))
  (mutex-unlock! __jobs-mx))

(def (pending-compile-jobs)
  (mutex-lock! __jobs-mx)
  (let (result (reverse! __compile-jobs))
    (set! __compile-jobs [])
    (mutex-unlock! __jobs-mx)
    result))

(def (execute-pending-compile-jobs!)
  (let loop ()
    (let (pending (pending-compile-jobs))
      (unless (null? pending)
        (for-each thread-start! pending)
        (for-each join! pending)))))

(def (make-compile-job thunk name)
  (make-thread
   (lambda ()
     (let loop ()
       (mutex-lock! __jobs-mx)
       (if (> __available-cores 0)
         (begin
           (set! __available-cores (1- __available-cores))
           (mutex-unlock! __jobs-mx)
           (with-verbose-mutex
            (displayln "... execute compile job " name))
           (unwind-protect
             (thunk)
             (mutex-lock! __jobs-mx)
             (set! __available-cores (fx1+ __available-cores))
             (condition-variable-signal! __jobs-cv)
             (mutex-unlock! __jobs-mx)))
         (begin
           (mutex-unlock! __jobs-mx __jobs-cv)
           (loop)))))
   name))

(defrules go! ()
  ((_ expr)
   (spawn (lambda () expr))))

(def (join! thread)
  (with-catch
   (lambda (exn)
     (if (uncaught-exception? exn)
       (raise (uncaught-exception-reason exn))
       (raise exn)))
   (cut thread-join! thread)))
