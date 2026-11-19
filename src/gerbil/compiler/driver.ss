;;; -*- Gerbil -*-
;;; (C) vyzo at hackzen.org
;;; gerbil compiler compilation methods
prelude: "../core"
package: gerbil/compiler
namespace: gxc

(import "../expander"
        "../runtime/error"
        "base"
        "compile"
        "optimize")
(export compile-module compile-exe)

(extern namespace: #f gerbil-path) ;; needed until bootstrap re-generated

(def default-gerbil-gsc
  (path-expand "gsc" (path-expand "bin" (path-expand "~~"))))
(def default-gerbil-gcc "gcc")
(def default-gerbil-ar "ar")

(def +driver-mutex+ (make-mutex 'compiler/driver))
(defrules with-driver-mutex ()
  ((_ expr)
   (with-lock +driver-mutex+ (lambda () expr))))

(def (compile-timestamp)
  (inexact->exact (floor (time->seconds (current-time)))))

(def (compile-timestamp-nanos)
  (time->seconds (current-time)))

(def scheme-file-settings '(permissions: #o644 char-encoding: UTF-8 eol-encoding: lf))

(def (with-output-to-scheme-file path fun)
  (with-output-to-file [path: path . scheme-file-settings] fun))

(def +gerbil-gsc+ #f)
(def (gerbil-gsc)
  (unless +gerbil-gsc+
    (set! +gerbil-gsc+ (getenv "GERBIL_GSC" default-gerbil-gsc)))
  +gerbil-gsc+)

(def +gerbil-gcc+ #f)
(def (gerbil-gcc)
  (unless +gerbil-gcc+
    (set! +gerbil-gcc+ (getenv "GERBIL_GCC" default-gerbil-gcc)))
  +gerbil-gcc+)

(def +gerbil-ar+ #f)
(def (gerbil-ar)
  (unless +gerbil-ar+
    (set! +gerbil-ar+ (getenv "GERBIL_AR" default-gerbil-ar)))
  +gerbil-ar+)

(def (gerbil-rpath gerbil-libdir)
  (string-append
   (cond-expand (darwin "-Wl,-rpath,") (else "-Wl,-rpath="))
   gerbil-libdir))

(def compiler-obj-suffix
  (cond-expand
    (visualc ".obj")
    (else ".o")))

; generates an `include` form for use in a source code, gsc's -e option etc.
; It takes care of windows paths where we need to escape the path.
; e.g. (displayln (include-source "d:\\gerbil\\mycode.scm")) should print
; (include "d:\\gerbil\\mycode.scm")
; instead of:
; (include "d:\gerbil\mycode.scm")
; which results in an error:
; *** ERROR -- Invalid escaped character: #\g
(def (include-source path)
  (string-append "(include " (object->string path) ")"))

(def gerbil-runtime-modules
  '("gerbil/runtime/gambit"
    "gerbil/runtime/util"
    "gerbil/runtime/table"
    "gerbil/runtime/control"
    "gerbil/runtime/system"
    "gerbil/runtime/c3"
    "gerbil/runtime/mop"
    "gerbil/runtime/mop-system-classes"
    "gerbil/runtime/error"
    "gerbil/runtime/interface"
    "gerbil/runtime/hash"
    "gerbil/runtime/thread"
    "gerbil/runtime/syntax"
    "gerbil/runtime/eval"
    "gerbil/runtime/repl"
    "gerbil/runtime/loader"
    "gerbil/runtime/init"
    "gerbil/runtime"))

(def (delete-directory* dir)
  (delete-file-or-directory dir #t))

(def (compile-module srcpath (opts []))
  (unless (string? srcpath)
    (raise-compile-error "Invalid module source path" srcpath))

  (let* ((outdir      (pgetq output-dir: opts))
         (invoke-gsc? (pgetq invoke-gsc: opts))
         (target      (or (pgetq target: opts) 'C))
         (gsc-options (append
		       ["-target" (symbol->string target)]
		       (or (pgetq gsc-options: opts) [])))
         (keep-scm?   (pgetq keep-scm: opts))
         (verbosity   (pgetq verbose: opts))
         (optimize    (pgetq optimize: opts))
         (debug       (pgetq debug: opts))
         (gen-ssxi    (pgetq generate-ssxi: opts))
         (parallel?   (pgetq parallel: opts)))

    (when outdir
      (with-driver-mutex (create-directory* outdir)))
    (when optimize
      (with-driver-mutex (optimizer-info-init!)))
    (parameterize ((current-compile-output-dir outdir)
                   (current-compile-invoke-gsc invoke-gsc?)
                   (current-compile-gsc-options gsc-options)
                   (current-compile-keep-scm keep-scm?)
                   (current-compile-verbose verbosity)
                   (current-compile-optimize optimize)
                   (current-compile-debug debug)
                   (current-compile-generate-ssxi gen-ssxi)
                   (current-compile-timestamp (compile-timestamp))
                   (current-compile-context `((compile-module ,srcpath)))
                   (current-compile-identifiers (make-bound-identifier-table))
                   (current-compile-parallel parallel?)
                   (current-compilation-target target)
                   (current-expander-compiling? #t))
      (verbose "compile " srcpath)
      (let (ctx (with-driver-mutex (import-module srcpath)))
        (call-with-compile-attempt (compile-output-file ctx #f ".ssi")
          (cut compile-top-module ctx))))))

(def (compile-exe srcpath (opts []))
  (unless (string? srcpath)
    (raise-compile-error "Invalid module source path" srcpath))

  (let* ((outdir      (pgetq output-dir: opts))
         (invoke-gsc? (pgetq invoke-gsc: opts))
         (target      (or (pgetq target: opts) 'C))
         (gsc-options (append
		       ["-target" (symbol->string target)]
		       (or (pgetq gsc-options: opts) [])))
         (keep-scm?   (pgetq keep-scm: opts))
         (verbosity   (pgetq verbose: opts))
         (debug       (pgetq debug: opts))
         (parallel?   (pgetq parallel: opts)))
    (when outdir
      (with-driver-mutex (create-directory* outdir)))
    (parameterize ((current-compile-output-dir outdir)
                   (current-compile-invoke-gsc invoke-gsc?)
                   (current-compilation-target target)
                   (current-compile-gsc-options gsc-options)
                   (current-compile-keep-scm keep-scm?)
                   (current-compile-verbose verbosity)
                   (current-compile-debug debug)
                   (current-compile-timestamp (compile-timestamp))
                   (current-compile-context `((compile-exe ,srcpath)))
                   (current-compile-identifiers (make-bound-identifier-table))
                   (current-compile-parallel parallel?)
                   (current-expander-compiling? #t))
      (verbose "compile exe " srcpath)
      (let* ((ctx (with-driver-mutex (import-module srcpath)))
             (bin (path-expand (compile-exe-output-file ctx opts)))
             (primary (if invoke-gsc? bin (string-append bin "__exe.scm"))))
        (with-driver-mutex (create-directory* (path-directory bin)))
        (call-with-compile-attempt primary
          (cut compile-executable-module ctx opts))))))

(def (compile-executable-module ctx opts)
  (if (pgetq full-program-optimization: opts)
    (compile-executable-module/full-program-optimization ctx opts)
    (compile-executable-module/separate ctx opts)))

(def (compile-executable-module/separate ctx opts)
  (def (generate-stub builtin-modules)
    (let (mod-main (find-runtime-symbol ctx 'main))
      (write `(define builtin-modules (quote ,builtin-modules)))
      (write `(define (gerbil-main)
                (with-unwind-protect
                 (lambda ()
                   (gerbil-runtime-init! builtin-modules)
                   (apply ,mod-main (cdr (command-line))))
                 (lambda ()
                   (with-catch void (lambda () (force-output (current-output-port))))
                   (with-catch void (lambda () (force-output (current-error-port))))))))
      (write '(gerbil-main))
      (newline)))

  (def (get-libgerbil-ld-opts gerbil-libdir)
    (call-with-input-file (path-expand "libgerbil.ldd" gerbil-libdir) read))

  (def (replace-extension-with-c path)
    (replace-extension path ".c"))

  (def (replace-extension-with-object path)
    (replace-extension path compiler-obj-suffix))

  (def (userlib-module? ctx)
    (and (not (exclude-module? ctx))
         (not (libgerbil-module? ctx))))

  (def (libgerbil-module? ctx)
    (let (id-str (symbol->string (expander-context-id ctx)))
      (and (not (exclude-module? id-str))
           (or (string-prefix? "gerbil/" id-str)
               (string-prefix? "std/" id-str)))))

  (def (exclude-module? ctx-or-str)
    (let (str (if (string? ctx-or-str)
                ctx-or-str
                (symbol->string (expander-context-id ctx-or-str))))
      (string-prefix? "gerbil/core" str)))

  (def (not-file-empty? path)
    (not (file-empty? path)))

  (def (fold-libgerbil-runtime-scm gerbil-staticdir libgerbil-scm)
    (let (gerbil-runtime-scm
          (map (lambda (rtm)
                 (path-expand
                  (string-append
                   (string-join (string-split rtm #\/) "__")
                   ".scm")
                  gerbil-staticdir))
               gerbil-runtime-modules))
      (remove-duplicates (append gerbil-runtime-scm libgerbil-scm))))

  (def (remove-duplicates strlst)
    (let loop ((rest strlst) (result []))
      (match rest
        ([path . rest]
         (if (member path result)
           (loop rest result)
           (loop rest (cons path result))))
        (else (reverse! result)))))

  (def (compile-stub output-scm output-bin)
    (let* ((gerbil-home      (getenv "GERBIL_BUILD_PREFIX" (gerbil-home)))
           (gerbil-libdir    (path-expand "lib" gerbil-home))
           (gerbil-staticdir (path-expand "static" gerbil-libdir))
           (deps             (find-runtime-module-deps ctx))
           (libgerbil-deps   (filter libgerbil-module? deps))
           (libgerbil-scm    (map find-static-module-file libgerbil-deps))
           (libgerbil-scm    (fold-libgerbil-runtime-scm gerbil-staticdir libgerbil-scm))
           (libgerbil-c      (map replace-extension-with-c libgerbil-scm))
           (libgerbil-o      (map replace-extension-with-object libgerbil-scm))
           (src-deps         (filter userlib-module? deps))
           (src-deps-scm     (map find-static-module-file src-deps))
           (src-deps-scm     (filter not-file-empty? src-deps-scm))
           (src-deps-scm     (map path-expand src-deps-scm))
           (src-bin-scm      (find-static-module-file ctx))
           (src-bin-scm      (path-expand src-bin-scm))
           (output-bin       (path-expand output-bin))
           (output-scm       (path-expand output-scm))
           (gsc-link-opts    (gsc-link-options))
           (gsc-static-opts  (gsc-static-include-options gerbil-staticdir))
           (output-ld-opts   (gcc-ld-options))
           (libgerbil-ld-opts (get-libgerbil-ld-opts gerbil-libdir))
           (rpath (gerbil-rpath gerbil-libdir))
           (builtin-modules
            (remove-duplicates
             (append gerbil-runtime-modules
                     (map (lambda (mod) (symbol->string (expander-context-id mod)))
                          (cons ctx deps))))))

      ;; A cache hit supplies committed inputs. On a miss produce a private
      ;; matched C/object pair; no writer needs to wait on a public .lock file.
      (def (dependency-pair scm)
        (let ((c (replace-extension-with-c scm))
              (o (replace-extension-with-object scm)))
          (if (and (file-exists? c) (file-exists? o)
                   (not (file-newer? scm c)) (not (file-newer? scm o)))
            (cons c o)
            (let (c* (exe-compile-c scm scm c 'ordinary gsc-link-opts))
              (cons c* (exe-compile-object c c* o 'ordinary gsc-static-opts #f))))))

      (with-output-to-scheme-file (compile-stage-path output-scm)
        (cut generate-stub builtin-modules))
      (when (current-compile-invoke-gsc)
        (let (deps (map dependency-pair [src-deps-scm ... src-bin-scm]))
          (exe-link-stub output-scm output-bin 'temporary
                         [libgerbil-c ... (map car deps) ...]
                         (map cdr deps) libgerbil-o
                         gsc-link-opts gsc-static-opts
                         [output-ld-opts ...
                          (if (gerbil-enable-shared?) [rpath] []) ...
                          "-L" gerbil-libdir "-lgambit" libgerbil-ld-opts ...])))))

  (let* ((output-bin (compile-exe-output-file ctx opts))
         (output-scm (string-append output-bin "__exe.scm")))
    (compile-stub output-scm output-bin)))

(def (compile-executable-module/full-program-optimization ctx opts)
  (def (reset-declare)
    '(declare
       (gambit-scheme)
       (block)
       (core)
       (inline)
       (inline-primitives)
       (inlining-limit 350)
       (constant-fold)
       (lambda-lift)
       (standard-bindings)
       (extended-bindings)
       (run-time-bindings)
       (safe)
       (interrupts-enabled)
       (proper-tail-calls)
       (not generative-lambda)
       (optimize-dead-local-variables)
       (optimize-dead-definitions)
       (generic)
       (mostly-fixnum-flonum)))

  (def (generate-stub deps)
    (let ((mod-main (find-runtime-symbol ctx 'main))
          (reset-decl (reset-declare))
          (user-decl (user-declare)))
      (for-each
        (lambda (dep)
          (write '(##namespace ("")))
          (newline)
          (write reset-decl)
          (newline)
          (when user-decl
            (write user-decl)
            (newline))
          (write `(include ,dep))
          (newline))
        deps)
      (write `(define (gerbil-main)
                ;; we don't know what the tree shaker will throw out
                ;; so we cannot assume that compiled in modules are fully present
                ;; thus we initialize the runtime with an empty builtin module list
                ;; so that the user can actually load things if he needs to
                (gerbil-runtime-init! '())
                (apply ,mod-main (cdr (command-line)))))
      (write '(gerbil-main))
      (newline)))

  (def (user-declare)
    (let* ((gsc-opts (pgetq gsc-options: opts))
           (gsc-prelude (and gsc-opts (member "-prelude" gsc-opts)))
           (gsc-prelude
            (and gsc-prelude
                 (read (open-input-string (cadr gsc-prelude))))))
      (let lp ((rest [gsc-prelude]) (user-decls []))
        (match rest
          ([expr . rest]
           (match expr
             (['declare . decls]
              (lp rest (foldl cons user-decls decls)))
             (['begin . exprs]
              (lp (append exprs rest) user-decls))
             (else
              (lp rest user-decls))))
          (else
           (if (null? user-decls)
             #f
             (cons 'declare (reverse user-decls))))))))

  (def (compile-stub output-scm output-bin)
    (let* ((gerbil-home (getenv "GERBIL_BUILD_PREFIX" (gerbil-home)))
           (gerbil-libdir (path-expand "lib" gerbil-home))
           (runtime (map find-static-module-file gerbil-runtime-modules))
           (gambit-sharp (path-expand "lib/_gambit#.scm" gerbil-home))
           (include-gambit-sharp (include-source gambit-sharp))
           (bin-scm (find-static-module-file ctx))
           (deps (find-runtime-module-deps ctx))
           (deps (map find-static-module-file deps))
           (deps (filter (? (not file-empty?)) deps))
           (deps (filter (lambda (f) (not (member f runtime))) deps))
            (gsc-link-opts (gsc-link-options))
           (gsc-static-opts (gsc-static-include-options (path-expand "static" gerbil-libdir)))
           (output-ld-opts (gcc-ld-options))
           (gsc-gx-macros
            (if (gerbil-runtime-smp?)
              ["-e" "(define-cond-expand-feature|enable-smp|)"
               "-e" include-gambit-sharp]
              ["-e" include-gambit-sharp]))
           (gsc-link-opts
            (append gsc-link-opts gsc-gx-macros))
           (rpath
            (gerbil-rpath gerbil-libdir))
           (default-ld-options
             (cond-expand
               ((or freebsd netbsd) ["-lutil" "-lm"])
               (else ["-ldl" "-lm"]))))
      (with-output-to-scheme-file (compile-stage-path output-scm)
        (cut generate-stub [runtime ... deps ... bin-scm]))
      (when (current-compile-invoke-gsc)
        (exe-link-stub output-scm output-bin 'ordinary [] [] []
                       gsc-link-opts gsc-static-opts
                       [output-ld-opts ...
                        (if (gerbil-enable-shared?) [rpath] []) ...
                        "-L" gerbil-libdir "-lgambit" default-ld-options ...]))))

  (let* ((output-bin (path-expand (compile-exe-output-file ctx opts)))
         (output-scm (string-append output-bin "__exe.scm")))
    (compile-stub output-scm output-bin)))

(def (find-export-binding ctx id)
  (cond
   ((find (match <>
            ((module-export _ _ 0 (eq? id)) #t)
            (else #f))
          (module-context-export ctx))
    => core-resolve-module-export)
   (else #f)))

(def (find-runtime-symbol ctx id)
  (cond
   ((find-export-binding ctx id)
    => (lambda (bind)
         (unless (runtime-binding? bind)
           (raise-compile-error "export is not a runtime binding" id))
         (binding-id bind)))
   (else
    (raise-compile-error "module does not export symbol"
                         (expander-context-id ctx) id))))

(def (find-runtime-module-deps ctx)
  (def ht (make-hash-table-eq))

  (def (import-set-template in phi)
    (let ((iphi (fx+ phi (import-set-phi in)))
          (imports (module-context-import (import-set-source in))))
      (let lp ((rest imports) (r []))
        (match rest
          ([in . rest]
           (cond
            ((module-context? in)
             (if (fxzero? iphi)
               (lp rest (cons in r))
               (lp rest r)))
            ((module-import? in)
             (let (iphi (fx+ phi (module-import-phi in)))
               (if (fxzero? iphi)
                 (lp rest (cons (module-export-context (module-import-source in)) r))
                 (lp rest r))))
            ((import-set? in)
             (let (xphi (fx+ iphi (import-set-phi in)))
               (cond
                ((fxzero? xphi)
                 (lp rest (cons (import-set-source in) r)))
                ((fxpositive? xphi)
                 (lp rest (foldl cons r (import-set-template in iphi))))
                (else
                 (lp rest r)))))
            (else
             (lp rest r))))
          (else r)))))

  (def (find-deps rest deps)
    (match rest
      ([hd . rest]
       (cond
        ((module-context? hd)
         (let ((id (expander-context-id hd))
               (imports (module-context-import hd)))
           (cond
            ((hash-get ht id)
             (find-deps rest deps))
            ((core-context-prelude hd)
             => (lambda (pre)
                  (let (xdeps (find-deps (cons pre imports) deps))
                    (hash-put! ht id hd)
                    (find-deps rest (cons hd xdeps)))))
            (else
             (let (xdeps (find-deps imports deps))
               (hash-put! ht id hd)
               (find-deps rest (cons hd xdeps)))))))
        ((prelude-context? hd)
         (let (id (expander-context-id hd))
           (cond
            ((hash-get ht id)
             (find-deps rest deps))
            (else
             (let (xdeps (find-deps (prelude-context-import hd) deps))
               (if (hash-get ht id)     ; imports picked up the module
                 (find-deps rest xdeps)
                 (begin
                   (hash-put! ht id hd)
                   (find-deps rest (cons hd xdeps)))))))))
        ((module-import? hd)
         (if (fxzero? (module-import-phi hd))
           (find-deps (cons (module-import-source hd) rest) deps)
           (find-deps rest deps)))
        ((module-export? hd)
         (find-deps (cons (module-export-context hd) rest) deps))
        ((import-set? hd)
         (cond
          ((fxzero? (import-set-phi hd))
           (find-deps (cons (import-set-source hd) rest) deps))
          ((fxpositive? (import-set-phi hd))
           (let (xdeps (import-set-template hd 0))
             (find-deps (foldl cons rest xdeps) deps)))
          (else
           (find-deps rest deps))))
        (else
         (error "Unexpected module import" hd))))
      (else deps)))

  (reverse
   (filter
    expander-context-id
    (find-deps
     (cond
      ((core-context-prelude ctx)
       => (lambda (pre) (cons pre (module-context-import ctx))))
      (else (module-context-import ctx)))
     []))))

(def (find-static-module-file ctx)
  (let* ((context-id
          (if (module-context? ctx)
            (expander-context-id ctx)
            (string->symbol ctx)))
         (scm (string-append (static-module-name context-id) ".scm"))
         (dirs (load-path))
         (dirs
          (let (user-libpath (getenv "GERBIL_PATH" #f))
            ;; this might have changed if we programmatically set it
            ;; can happen in tests
            (if user-libpath
              (let (user-libpath (path-expand "lib" user-libpath))
                (if (member user-libpath dirs)
                  dirs
                  (cons user-libpath dirs)))
              dirs)))
         (dirs
          (cond
           ((current-compile-output-dir)
            => (cut cons <> dirs))
           (else dirs)))
         (dirs (map (cut path-expand "static" <>) dirs)))
    (let lp ((rest dirs))
      (match rest
        ([dir . rest]
         (let (path (path-expand scm dir))
           (if (file-exists? path)
             path
             (lp rest))))
        (else
         (raise-compile-error "cannot find static module" (expander-context-id ctx) scm))))))

(def (file-empty? path)
  (zero? (file-info-size (file-info path #t))))

(def (compile-top-module ctx)
  (parameterize ((current-expander-context ctx)
                 (current-expander-phi 0)
                 (current-expander-marks [])
                 (current-compile-symbol-table
                  (make-symbol-table))
                 (current-compile-runtime-sections
                  (make-hash-table-eq))
                 (current-compile-runtime-names
                  (make-hash-table)))
    (verbose "compile " (expander-context-id ctx))
    (when (current-compile-optimize)
      (with-driver-mutex (optimize! ctx)))
    (collect-bindings ctx)

    (compile-runtime-code ctx)
    (compile-meta-code ctx)

    (when (and (current-compile-optimize)
               (current-compile-generate-ssxi))
      (compile-ssxi-code ctx))))

(def (collect-bindings ctx)
  (apply-collect-bindings
   (module-context-code ctx)))

(def (compile-runtime-code ctx)
  (def (compile1 ctx)
    (let* ((code (module-context-code ctx))
           (rtm  (let (idstr (module-id->path-string (expander-context-id ctx)))
                   (string-append idstr "~0")))
           (rtc? (apply-find-runtime-code code)))
      (when rtc?
        (hash-put! (current-compile-runtime-sections) ctx rtm))
      (generate-runtime-code ctx code (and rtc? rtm))))

  (def (context-timestamp ctx)
    (string->symbol
     (string-append (symbol->string (expander-context-id ctx))
                    "::timestamp")))

  (def (generate-runtime-code ctx code rtm)
    (let* ((runtime-code? (and rtm #t))
           (lifts (box []))
           (runtime-code
            (and runtime-code?
                 (parameterize ((current-expander-context ctx)
                                (current-expander-phi 0)
                                (current-compile-lift lifts)
                                (current-compile-marks (make-hash-table-eq)))
                   (apply-generate-runtime code))))
           (runtime-code
            (and runtime-code?
                 (if (null? (unbox lifts))
                   runtime-code
                   ['begin (reverse (unbox lifts)) ... runtime-code])))
           (runtime-code
            (and runtime-code?
                 ['begin `(define ,(context-timestamp ctx) ,(current-compile-timestamp))
                         runtime-code]))
           (loader-code
            (parameterize ((current-expander-context ctx))
              (apply-generate-loader code)))
           (loader-code
            ['begin loader-code (if runtime-code? ['load-module rtm] '(begin))])
           (scm0 (compile-output-file ctx 0 ".scm"))
           (scmrt (compile-output-file ctx #f ".scm"))
            (scms (compile-stage-path (compile-static-output-file ctx))))
      (when runtime-code?
        (compile-scm-file scm0 runtime-code))
      (parameterize ((current-compile-gsc-options #f))
        (compile-scm-file scmrt loader-code))
      (if runtime-code?
        (copy-file (compile-stage-path scm0) scms)
        (call-with-output-file scms void))))

  (let (all-modules (cons ctx (lift-nested-modules ctx)))
    (for-each
      (lambda (ctx)
        ;; declarations are module scoped and are not inherited by nested modules
        (parameterize ((current-compile-decls []))
          (compile1 ctx)))
      all-modules)))

(def (compile-meta-code ctx)
  (def (compile-ssi code)
    (let* ((path (compile-output-file ctx #f ".ssi"))
           (prelude
            (let (super (phi-context-super ctx))
              (cond
               ((expander-context-id super) => (cut make-symbol ":" <>))
               (else ':<root>))))
           (ns (module-context-ns ctx))
           (idstr (symbol->string (expander-context-id ctx)))
           (pkg
            (cond
             ((string-rindex idstr #\/)
              => (lambda (x) (string->symbol (substring idstr 0 x))))
             (else #f)))
           (rt (hash-get (current-compile-runtime-sections) ctx)))
      (verbose "compile " path)
      (with-output-to-scheme-file (compile-stage-path path)
        (lambda ()
          (displayln "prelude:" " " prelude)
          (when pkg (displayln "package:" " " pkg))
          (displayln "namespace:" " " ns)
          (newline)
          (pretty-print code)
          (when rt
            (pretty-print
             ['%#call ['%#ref 'load-module] ['%#quote rt]]))))))

  (def (compile-phi part)
    (match part
      ([phi-ctx phi n code]
       (let (code
             (parameterize ((current-expander-context phi-ctx)
                            (current-expander-phi phi))
               (generate-runtime-phi code)))
         (compile-scm-file (compile-output-file ctx n ".scm") code #t)))))

  (let ((values ssi-code phi-code)
        (generate-meta-code ctx))
    (compile-ssi ssi-code)
    (for-each compile-phi phi-code)))

(def (compile-ssxi-code ctx)
  (let* ((path (compile-output-file ctx #f ".ssxi.ss"))
         (code (apply-generate-ssxi (module-context-code ctx)))
         (idstr (symbol->string (expander-context-id ctx)))
         (pkg
          (cond
           ((string-rindex idstr #\/)
            => (lambda (x) (string->symbol (substring idstr 0 x))))
           (else #f))))

    (verbose "compile " path)
    (with-output-to-scheme-file (compile-stage-path path)
      (lambda ()
        (displayln "prelude: :gerbil/compiler/ssxi")
        (when pkg (displayln "package: " pkg))
        (newline)
        (pretty-print code)))))

(def (generate-meta-code ctx)
  ;; => ssi-code [[phi-ctx phi n phi-code] ...]
  (let* ((state (make-meta-state ctx))
         (ssi-code (apply-generate-meta (module-context-code ctx) state: state)))
    (values ssi-code (meta-state-end! state))))

(def (generate-runtime-phi stx)
  (let (lifts (box []))
    (parameterize ((current-compile-lift lifts)
                   (current-compile-marks (make-hash-table-eq)))
      (let (code (apply-generate-runtime-phi stx))
        (if (null? (unbox lifts)) code
            ['begin (reverse (unbox lifts)) ... code])))))

(def (lift-nested-modules ctx)
  (let (modules (box []))
    (apply-lift-modules (module-context-code ctx) modules: modules)
    (reverse (unbox modules))))

;;; utilities
(def (compile-scm-file path code (phi? #f))
  (verbose "compile " path)
  (with-output-to-scheme-file (compile-stage-path path)
    (lambda ()
      (pretty-print
       `(declare
          (block)
          (standard-bindings)
          (extended-bindings)
          ,@(if phi? '((inlining-limit 200)) '())))
      (pretty-print code)))
  (when (current-compile-invoke-gsc)
    (let (compile-it (prepare-gsc-compile-job path phi?))
      (if (current-compile-parallel)
        (compile-attempt-add-job! compile-it `(compile-file ,path))
        (compile-it)))))

(def (gsc-link-options (phi? #f))
  (let lp ((rest (current-compile-gsc-options)) (opts []))
    (match rest
      (["-cc-options" _ . rest]
       (lp rest opts))
      (["-ld-options" _ . rest]
       (lp rest opts))
      ([opt . rest]
       (lp rest (cons opt opts)))
      (else
       (if (current-compile-debug)
         ["-debug-source" "-track-scheme" (reverse opts) ...]
         (reverse opts))))))

(def (gsc-cc-options (phi? #f) static: (static? #f))
  (if phi?
    (if (current-compile-debug)
      ["-cc-options" "-g"]
      [])
    (let lp ((rest (current-compile-gsc-options)) (opts []))
      (match rest
        (["-cc-options" (and opt "-Bstatic") . rest]
         (if static?
           (lp rest (cons* opt "-cc-options" opts))
           (lp rest opts)))
        (["-cc-options" opt . rest]
         (lp rest (cons* opt "-cc-options" opts)))
        (["-ld-options" _ . rest]
         (lp rest opts))
        ([_ . rest]
         (lp rest opts))
        (else
         (if (current-compile-debug)
           ["-cc-options" "-g" (reverse! opts) ...]
           (reverse! opts)))))))

(def (gsc-ld-options (phi? #f) static: (static? #f))
  (if phi?
    []
    (let lp ((rest (current-compile-gsc-options)) (opts []))
      (match rest
        (["-ld-options" (and opt "-static") . rest]
         (if static?
           (lp rest (cons* opt "-ld-options" opts))
           (lp rest opts)))
        (["-ld-options" opt . rest]
         (lp rest (cons* opt "-ld-options" opts)))
        (["-cc-options" _ . rest]
         (lp rest opts))
        ([_ . rest]
         (lp rest opts))
        (else
         (reverse! opts))))))

(def (gsc-static-include-options staticdir)
  (let (user-staticdir
        (path-expand
            (path-expand "lib/static" (gerbil-path))))
    ["-cc-options" (string-append "-I " staticdir " -I "  user-staticdir)]))

(def (gcc-ld-options)
    (let lp ((rest (current-compile-gsc-options)) (opts []))
      (match rest
        (["-cc-options" _ . rest]
         (lp rest opts))
        (["-ld-options" opt . rest]
         (lp rest
             (append opts (filter not-string-empty? (string-split opt #\space)))))
        ([_ . rest]
         (lp rest opts))
        (else opts))))

(def (not-string-empty? str)
  (not (string-empty? str)))

(def (replace-extension path ext)
  (string-append (path-strip-extension path) ext))

(def (gsc-option opts key)
  (alet (tail (member key opts)) (cadr tail)))

;; The driver consumes -o as a logical destination. Never pass an unmodified
;; user output path alongside the physical -o (Gambit uses the first one).
(def (gsc-staged-options opts)
  ;; -e ends Gambit's compiler-option scan. Keep caller expressions in order,
  ;; after all compiler options and before our source-location hook.
  (let lp ((rest opts) (flags []) (exprs []))
    (match rest
      (["-o" _ . rest] (lp rest flags exprs))
      (["-e" expr . rest] (lp rest flags (cons* expr "-e" exprs)))
      (["-keep-c" . rest] (lp rest (cons "-keep-temp" flags) exprs))
      ([opt . rest] (lp rest (cons opt flags) exprs))
      (else (append (reverse! flags) (reverse! exprs))))))

(def (gsc-identity-options opts output dynamic?)
  (let* ((file (path-strip-directory output))
         (mod (or (gsc-option opts "-module-ref") (path-strip-extension file))))
    [(if (gsc-option opts "-module-ref") [] ["-module-ref" mod]) ...
     (if (gsc-option opts "-linker-name") [] ["-linker-name" (if dynamic? file mod)]) ...]))

;; Gambit reads the private file but records its source container in Scheme
;; debug info, #line directives and the base path for relative includes.
(def (gsc-source-options physical logical)
  (if (equal? physical logical) []
    ["-e" (object->string
           `(let ((previous ##path->container-hook))
              (##path->container-hook-set!
               (lambda (path)
                 (if (equal? path ,physical) ,logical
                   (and previous (previous path)))))))]))

(def (gsc-register-dumps! opts path)
  (for-each (lambda (suffix)
              (when (member (string-append "-" suffix) opts)
                (compile-stage-path (replace-extension path (string-append "." suffix)))))
            '("gvm" "cfg" "dg")))

;; gambuild compiles C from the object's directory. Map both spellings that
;; can reach native debug info (the input argument and its absolute path).
(def (gsc-native-debug-options physical logical output)
  (cond-expand
    (visualc [])
    (else
     (if (current-compile-debug)
       (let (dir (path-directory output))
         (def (mapping src dest)
           (string-append "'-fdebug-prefix-map="
                          (string-join (string-split (string-append src "=" dest) #\')
                                       "'\\''")
                          "'"))
         ["-cc-options" (string-append
                         (mapping physical logical) " "
                         (mapping (path-normalize physical #t dir)
                                  (path-normalize logical #t dir)))])
       []))))

(def (gsc-target-extension opts)
  (case (string->symbol (or (gsc-option opts "-target") "C"))
    ((js) ".js") ((python) ".py") ((ruby) ".rb") ((php) ".php")
    ((java) ".java") ((go) ".go") (else ".c")))

(def (gsc-output-destination opts default)
  (let (output (gsc-option opts "-o"))
    (if output
      (let (path (path-normalize output))
        (if (equal? path (path-strip-trailing-directory-separator path))
          path
          (path-expand (path-strip-directory default) path)))
      default)))

(def (prepare-gsc-compile-job path phi?)
  (let* ((opts (gsc-link-options phi?))
         (scm (compile-stage-path path))
         (c (replace-extension path (gsc-target-extension opts)))
         (target? (member "-c" opts))
         (obj? (member "-obj" opts))
         (dynamic? (not (or target? obj?)))
         (dest (gsc-output-destination opts (cond (target? c)
                                                  (obj? (replace-extension path compiler-obj-suffix))
                                                  (else path))))
         (version? (and dynamic?
                        (let (o (gsc-option opts "-o"))
                          (or (not o)
                              (let (o (path-normalize o))
                                (not (equal? o (path-strip-trailing-directory-separator o))))))))
         (output (if version? (compile-next-object dest) dest))
         (output* (compile-stage-path output (if version? 'version 'ordinary)))
         ;; Gambit derives this file from its input, even with explicit -o.
         (c* (and (not target?)
                  (compile-stage-path c (if (or (member "-keep-c" opts) (member "-keep-temp" opts))
                                          'ordinary 'temporary)))))
    (when (or (member "-link" opts) (member "-exe" opts))
      (raise-compile-error "Use compile-exe for linked output" path))
    (gsc-register-dumps! opts (if target? output c))
    (let ((program (gerbil-gsc))
          (args ["-o" output* (gsc-identity-options opts output dynamic?) ...
                 (gsc-cc-options phi?) ... (gsc-ld-options phi?) ...
                 (if c* (gsc-native-debug-options c* c output*) []) ...
                 (gsc-staged-options opts) ... (gsc-source-options scm path) ... scm]))
      (cut invoke program args))))

(def (exe-compile-c scm scm* c kind opts)
  (let (c* (compile-stage-path c kind))
    (gsc-register-dumps! opts c)
    (invoke (gerbil-gsc)
            ["-c" "-o" c* (gsc-identity-options opts c #f) ...
             (gsc-staged-options opts) ... (gsc-source-options scm* scm) ... scm*])
    c*))

(def (exe-compile-object c c* o kind includes static?)
  (let (o* (compile-stage-path o kind))
    (invoke (gerbil-gsc)
            ["-obj" "-o" o* (gsc-cc-options static: static?) ...
             (gsc-native-debug-options c* c o*) ... includes ... c*])
    o*))

(def (exe-link-stub scm bin kind libs-c deps-o libs-o opts includes ld-opts)
  (let* ((c (replace-extension scm ".c"))
         (c* (exe-compile-c scm (compile-stage-path scm) c kind opts))
         (link (gsc-output-destination opts (replace-extension scm "_.c")))
         (link* (compile-stage-path link kind))
         (static? (eq? kind 'ordinary)))
    (invoke (gerbil-gsc)
            ["-link" "-o" link*
             (if (gsc-option opts "-linker-name") []
               ["-linker-name" (path-strip-extension (path-strip-directory link))]) ...
             (gsc-staged-options opts) ... libs-c ... c*])
    (let ((o* (exe-compile-object c c* (replace-extension c compiler-obj-suffix)
                                  kind includes static?))
          (link-o* (exe-compile-object link link* (replace-extension link compiler-obj-suffix)
                                       kind includes static?)))
      (invoke (gerbil-gcc)
              ["-w" "-o" (compile-stage-path bin)
               deps-o ... o* link-o* libs-o ... ld-opts ...]))))

(def (compile-output-file ctx n ext)
  (def (module-relative-path ctx)
    (path-strip-directory (module-id->path-string (expander-context-id ctx))))

  (def (module-source-directory ctx)
    (path-directory
     (let (mpath (module-context-path ctx))
       (if (string? mpath) mpath (last mpath)))))

  (def (section-string n)
    (cond
     ((number? n) (number->string n))
     ((symbol? n) (symbol->string n))
     ((string? n) n)
     (else
      (raise-compile-error "Unexpected section" n))))

  (def (file-name path)
    (if n
      (string-append path "~" (section-string n) ext)
      (string-append path ext)))

  (def (file-path)
    (cond
     ((current-compile-output-dir)
      => (lambda (outdir)
           (path-expand
            (file-name (module-id->path-string (expander-context-id ctx)))
            outdir)))
     (else
      (path-expand
       (file-name (module-relative-path ctx))
       (module-source-directory ctx)))))

  (let (path (file-path))
    (with-driver-mutex (create-directory* (path-directory path)))
    path))

(def (compile-static-output-file ctx)
  (def (file-name id)
    (string-append (static-module-name id) ".scm"))

  (def (file-path)
    (let (file (file-name (expander-context-id ctx)))
      (cond
       ((current-compile-output-dir)
        => (lambda (outdir)
             (path-expand file (path-expand "static" outdir))))
       (else
        (path-expand file "static")))))

  (let (path (file-path))
    (with-driver-mutex (create-directory* (path-directory path)))
    path))

(def (compile-exe-output-file ctx opts)
  (cond
   ((pgetq output-file: opts))
   (else
    (path-strip-directory (symbol->string (expander-context-id ctx))))))

(def (static-module-name idstr)
  (cond
   ((string? idstr)
    (let* ((str (module-id->path-string idstr))
           (strs (string-split str #\/)))
      (string-join strs "__")))
   ((symbol? idstr)
    (static-module-name (symbol->string idstr)))
   (else
    (error "Bad module id" idstr))))

(def (gerbil-enable-shared?)
  (member "--enable-shared" (string-split (configure-command-string) #\')))

(def (invoke program args
             stdout-redirection: (stdout-redirection #f)
             stderr-redirection: (stderr-redirection #f))
  (verbose "invoke " [program . args])
  (let* ((proc (open-process [path: program arguments: args
                                    stdout-redirection: stdout-redirection
                                    stderr-redirection: stderr-redirection]))
         (output (and (or stdout-redirection stderr-redirection)
                      (read-line proc #f))))
    (let (status (process-status proc))
      (close-port proc)
      (unless (zero? status)
        (display output)
        (raise-compile-error "Compilation error; process exit with nonzero status"
                             [program . args]
                             status)))))
