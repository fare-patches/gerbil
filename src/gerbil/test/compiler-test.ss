;;; -*- Gerbil -*-
;;; © vyzo
;;; compiler regression tests
(import :std/test
        :std/source
        :std/io/tempfile
        (only-in :std/misc/process run-process/batch)
        :gerbil/compiler
        :gerbil/expander
        :gerbil/runtime/syntax
        :gerbil/runtime/init)
(export compiler-specializer-test
        compiler-safety-test
        compiler-typed-test
        compiler-syntax-test
        compiler-builtins-test)

(def (must-compile-and-execute path (dependencies []) (inspect-source #f)
                                timeout: (timeout #f))
  (let ((output-dir (make-temporary-file-name "compiler.out"))
        (current-load-path (load-path)))
    (add-load-path! output-dir)
    (unwind-protect
      ;; Fixture exports must not leak into another test's expander context.
      (parameterize ((current-expander-context (make-top-context)))
        (for-each
          (lambda (dependency)
            (compile-module (path-expand dependency (this-source-directory))
              [output-dir: output-dir invoke-gsc: #t optimize: #t generate-ssxi: #t]))
          dependencies)
        (check (compile-module (path-expand path (this-source-directory))
                 [output-dir: output-dir invoke-gsc: (not inspect-source)
                  optimize: #t generate-ssxi: #t])
               ? true)
        (when inspect-source
          ;; Inspect the -S output, then native-compile those exact Scheme files.
          (inspect-source output-dir)
          (let (module-dir (path-expand "test" output-dir))
            (for-each
              (lambda (file)
                (when (equal? (path-extension file) ".scm")
                  (run-process/batch [(getenv "GERBIL_GSC" (path-expand "~~bin/gsc"))
                                      (path-expand file module-dir)])))
              (directory-files module-dir))))
        (let* ((modid (string->symbol
                       (string-append ":test/"
                         (path-strip-extension (path-strip-directory path)))))
               (mod (import-module modid))
               (main-binding
                (parameterize ((current-expander-context mod))
                  (resolve-identifier 'main))))
          (eval `(import ,modid))
          (when main-binding
            (call-with-timeout timeout (eval (binding-id main-binding))))))
      (set-load-path! current-load-path)
      (when (file-exists? output-dir)
        (delete-file-or-directory output-dir #t)))))

;; Run thunk; with a timeout in seconds, run it in a thread and fail the check
;; instead of hanging when it doesn't return in time (e.g. miscompiled code
;; looping forever).
(def (call-with-timeout timeout thunk)
  (if timeout
    (let* ((thread (spawn (lambda ()
                            (with-catch (lambda (e) (cons 'raised e))
                                        (lambda () (thunk) 'done)))))
           (result (thread-join! thread timeout 'timeout)))
      (cond
       ((pair? result) (raise (cdr result)))
       ((eq? result 'timeout) (thread-terminate! thread)))
      (check result => 'done))
    (thunk)))

(def (must-not-compile path)
  (let (output-dir (make-temporary-file-name "compiler.out"))
    (check-exception (compile-module (path-expand path (this-source-directory))
                                     [output-dir:
                                      output-dir
                                      invoke-gsc: #t
                                      optimize: #t
                                      generate-ssxi: #t])
                     syntax-error?)
    (delete-file-or-directory output-dir #t)))

;; Walk generated reader datums, excluding quoted contracts and locations.
(def (forms op tree)
  (cond
   ((not (pair? tree)) [])
   ((eq? (car tree) 'quote) [])
   (else
    (append (if (eq? (car tree) op) (list tree) [])
            (forms op (car tree)) (forms op (cdr tree))))))

(def (compiled-body definitions binding)
  (let (matches (filter (lambda (form) (eq? (cadr form) binding)) definitions))
    (check (length matches) => 1)
    (let (expr (caddar matches))
      (check (car expr) => 'lambda)
      expr)))

(def compiler-specializer-test
  (test-suite "compiler specializer tests"
    (test-case "specializer methods"
      (must-compile-and-execute "compiler-test-support/specializer-methods.ss"))
    (test-case "issue #1144"
      (must-compile-and-execute "compiler-test-support/issue-1144.ss"))))

(def compiler-safety-test
  (test-suite "compiler type safety tests"
    (test-case "call non procedure (1)"
      (must-not-compile "compiler-test-support/non-procedure-1.ss"))
    (test-case "call non procedure (2)"
      (must-not-compile "compiler-test-support/non-procedure-2.ss"))
    (test-case "call non procedure (3)"
      (must-not-compile "compiler-test-support/non-procedure-3.ss"))
    (test-case "call non procedure (4)"
      (must-not-compile "compiler-test-support/non-procedure-4.ss"))
    (test-case "bad return type"
      (must-not-compile "compiler-test-support/bad-return-type.ss"))
    (test-case "bad Maybe return type"
      (must-not-compile "compiler-test-support/maybe-bad-return.ss"))
    (test-case "bad typed Maybe return type"
      (must-not-compile "compiler-test-support/maybe-bad-typed-return.ss"))
    (test-case "bad Maybe void return type"
      (must-not-compile "compiler-test-support/maybe-bad-void-return.ss"))
    (test-case "nullable body cannot prove ordinary return type"
      (must-not-compile "compiler-test-support/maybe-raw-return.ss"))))

(def compiler-typed-test
  (test-suite "compiler type inference tests"
    (test-case "disjointness requires proof, including system types"
      (parameterize ((gxc#current-compile-optimizer-info (gxc#make-optimizer-info)))
        (gxc#optimizer-info-init!)
        (gxc#optimizer-load-builtin-ssxi (current-expander-context))
        (def (type name) (gxc#optimizer-resolve-class 'test name))
        (check (gxc#!type-disjoint? (type 'fixnum::t) (type 'string::t)) => #t)
        (check (gxc#!type-disjoint? (type 'fixnum::t) (type 'number::t)) => #f)
        ;; Neither is a subtype of the other, but fixnums inhabit both.
        (check (gxc#!type-disjoint? (type 'number::t) (type 'immediate::t)) => #f)
        (check (gxc#!type-disjoint? (type 'false::t) (type 'boolean::t)) => #f)
        (check (gxc#!type-disjoint? (gxc#nullable-type (type 'fixnum::t))
                                  (gxc#nullable-type (type 'string::t)))
               => #f)))
    (test-case "overlapping mixins across compiled modules"
      (must-compile-and-execute "compiler-test-support/mixin-client.ss"
        ["compiler-test-support/mixin-provider.ss"]
        (lambda (output-dir)
          (def definitions
            (forms 'define
              (call-with-input-file (path-expand "test/mixin-provider~0.scm" output-dir)
                (lambda (port) (read-all port)))))
          ;; Proven disjointness still folds; do not fix overlap by disabling all
          ;; negative folding. Runtime cases check retained side effects as well.
          (for-each
           (lambda (name)
             (def body
               (compiled-body definitions
                 (string->symbol (string-append "test/mixin-provider#__" name))))
             (check (forms 'class-instance? body) => [])
             (check (forms '##structure-instance-of? body) => [])
             (check (forms '##structure-direct-instance-of? body) => []))
           '("final-disjoint" "struct-disjoint" "struct-mixins-disjoint")))))
    (test-case "optimizer type snapshots retain nullable bases"
      (parameterize ((gxc#current-compile-optimizer-info (gxc#make-optimizer-info))
                     (gxc#current-compile-local-type (make-hash-table-eq)))
        (gxc#optimizer-info-init!)
        (gxc#optimizer-load-builtin-ssxi (current-expander-context))
        (def base-a (gxc#optimizer-resolve-class 'test 'fixnum::t))
        (def base-b (gxc#optimizer-resolve-class 'test 'string::t))
        (gxc#optimizer-declare-type! 'global (gxc#nullable-type base-a))
        (gxc#optimizer-declare-type! 'local (gxc#nullable-type base-a) #t)
        (let (before (gxc#optimizer-current-types))
          (check (assq 'global before) => '(global nullable fixnum::t))
          (check (assq 'local before) => '(local nullable fixnum::t))
          (gxc#optimizer-declare-type! 'local (gxc#nullable-type base-b) #t)
          (let (after (gxc#optimizer-current-types))
            (check (assq 'global after) => '(global nullable fixnum::t))
            (check (assq 'local after) => '(local nullable string::t))
            (check (equal? before after) => #f)))))
    (test-case "Maybe contracts across modules"
      (must-compile-and-execute "compiler-test-support/maybe-client.ss"
        ["compiler-test-support/maybe-provider.ss"]
        (lambda (output-dir)
          (def source
            (call-with-input-file (path-expand "test/maybe-client~0.scm" output-dir)
              (lambda (port) (read-all port))))
          (def definitions (forms 'define source))
          (def main (compiled-body definitions 'test/maybe-client#main))
          (for-each
            (lambda (spec)
              (let* ((name (car spec))
                     (binding (string->symbol (string-append "test/maybe-client#" name)))
                     (unchecked (string->symbol (string-append "test/maybe-client#__" name)))
                     (body (compiled-body definitions unchecked)))
                (check (or (pair? (forms binding main)) (pair? (forms unchecked main))) => #t)
                (check (length (forms unchecked (compiled-body definitions binding))) => 1)
                (check (length (forms 'class-instance? body)) => (cadr spec))
                (check (length (forms 'cast body)) => (caddr spec))
                (check (length (forms 'raise-contract-violation-error body)) => (cadddr spec))
                (check (length (forms '##structure-direct-instance-of? body))
                       => (if (equal? name "view-predicate-guard") 1 0))
                (when (member name '("class-guard" "view-guard"
                                     "class-predicate-guard" "view-predicate-guard"))
                  (check (map cadr (forms 'list body)) => '((quote #t)))
                  (check (length (forms 'if body)) => 1)
                  (check (cadddr (car (forms 'if body))) => '(quote #f)))))
            '(("class-guard" 0 0 0) ("view-guard" 0 0 0)
              ("class-predicate-guard" 1 0 0) ("view-predicate-guard" 0 0 0)
              ("class-open" 1 0 1) ("view-open" 0 1 0)))
          (let (declarations
                (forms 'declare-type
                  (call-with-input-file (path-expand "test/maybe-provider.ssxi.ss" output-dir)
                    (lambda (port) (read-all port)))))
            (for-each
              (lambda (spec)
                (let (decl (find (lambda (decl) (eq? (cadr decl) (car spec))) declarations))
                  (check decl ? pair?)
                  (let (signature (cadr (member signature: (caddr decl))))
                    (check (cadr (member return: signature)) => (cadr spec)))))
              '((test/maybe-provider#item-result (nullable test/maybe-provider#Item::t))
                (test/maybe-provider#view-result (nullable test/maybe-provider#View::t))
                (test/maybe-provider#typed-item-result (nullable test/maybe-provider#Item::t))
                (test/maybe-provider#integer-result (nullable fixnum::t))
                (test/maybe-provider#void-result (nullable void::t))
                (test/maybe-provider#any-result (nullable t::t)))))))
      (for-each
        (lambda (spec)
          (check (gxc#!signature-return
                  (gxc#!procedure-signature
                   (gxc#optimizer-resolve-type (car spec))))
                 => (cadr spec)))
        '((test/maybe-provider#item-result (nullable test/maybe-provider#Item::t))
          (test/maybe-provider#view-result (nullable test/maybe-provider#View::t))
          (test/maybe-provider#integer-result (nullable fixnum::t))
          (test/maybe-provider#void-result (nullable void::t))
          (test/maybe-provider#any-result (nullable t::t)))))
    (test-case "nullable predicate and cast folding in generated Scheme"
      (must-compile-and-execute "compiler-test-support/nullable-fold.ss" []
        (lambda (output-dir)
          ;; compile-runtime-code writes section 0 here, not the loader or SSXI.
          (def source
            (call-with-input-file
              (path-expand "test/nullable-fold~0.scm" output-dir)
              (lambda (port) (read-all port))))
          (def definitions (forms 'define source))
          (def (binding name)
            (string->symbol (string-append "test/nullable-fold#" name)))
          (def (body name)
            (compiled-body definitions (binding name)))
          (def main (body "main"))
          (for-each
            (lambda (spec)
              (let* ((name (car spec))
                     (checked (body name))
                     (unchecked (body (string-append "__" name))))
                ;; The exported entry point delegates to the body being inspected.
                (check (length (forms (binding (string-append "__" name)) checked)) => 1)
                ;; main consumes every entry point (some as first-class procedures).
                (check (> (length (forms (binding name) main)) 0) => #t)
                (check (length (forms 'class-instance? unchecked)) => (cadr spec))
                (check (length (forms '##structure-direct-instance-of? unchecked)) => (caddr spec))
                (check (length (forms 'cast unchecked)) => (cadddr spec))
                (check (length (forms 'raise-contract-violation-error unchecked))
                       => (list-ref spec 4))
                (for-each
                  (lambda (op) (check (forms (binding op) unchecked) => []))
                  '("Item?" "View?" "make-View"))
                ;; Positive evidence of folding, not just absent operations/dead code.
                (check (map cadr (forms 'list unchecked)) => (list-ref spec 5))
                (check (length (forms 'if unchecked)) => (list-ref spec 6))
                (when (and (pair? (list-ref spec 5)) (= (list-ref spec 6) 1))
                  (let (branch (car (forms 'if unchecked)))
                    (check (map cadr (forms 'list (caddr branch))) => '((quote #t)))
                    (check (cadddr branch) => '(quote #f))))))
            '(("class-known" 0 0 0 0 ((quote #t)) 0)
              ("class-truth" 0 0 0 0 ((quote #t)) 1)
              ("class-predicate" 1 0 0 0 ((quote #t)) 1)
              ("class-open-predicate" 1 0 0 0 () 0)
              ("class-open-cast" 1 0 0 1 () 1)
              ("view-known" 0 0 0 0 ((quote #t)) 0)
              ("view-truth" 0 0 0 0 ((quote #t)) 1)
              ("view-predicate" 0 1 0 0 ((quote #t)) 1)
              ("view-open-predicate" 0 1 0 0 () 0)
              ("view-open-cast" 0 0 1 0 () 0)
              ("view-convert" 0 0 1 0 () 0))))))
    (test-case "nullable interface contracts"
      (must-compile-and-execute "compiler-test-support/nullable-interface.ss"))
    (test-case "nullable intermediate dotted receivers"
      (must-compile-and-execute "compiler-test-support/nullable-dotted.ss"))
    (test-case "nullable contracts across modules"
      (must-compile-and-execute "compiler-test-support/nullable-client.ss"
        ["compiler-test-support/nullable-provider.ss"])
      (check (gxc#!signature-return
              (gxc#!procedure-signature
               (gxc#optimizer-resolve-type 'test/nullable-provider#nullable-result)))
             => '(nullable test/nullable-provider#NullableAPI::t)))
    (test-case "top level classes after use in procedure"
      (must-compile-and-execute "compiler-test-support/class-after-use.ss"))
    (test-case "mutable bindings infer the greatest common type"
      (must-compile-and-execute "compiler-test-support/mutable-binding-type.ss"))
    (test-case "mutable bindings with sticky type"
      (must-compile-and-execute "compiler-test-support/mutable-binding-type-2.ss"))
    (test-case "mutable bindings with fixpoint sticky type"
      (must-compile-and-execute "compiler-test-support/mutable-binding-type-3.ss"))
    (test-case "typed keyword + rest arguments, compiled"
      (must-compile-and-execute "compiler-test-support/typed-keyword-rest.ss"))
    (test-case "#!key keyword table, compiled"
      ;; Miscompiled keyword table construction makes the calls loop forever.
      (must-compile-and-execute "compiler-test-support/key-table-call.ss" timeout: 30))))

(def compiler-syntax-test
  (test-suite "compiler syntactic features"
    (test-case "deep dots"
      (must-compile-and-execute "compiler-test-support/deep-dots.ss"))
    (test-case "interface mixins"
      (must-compile-and-execute "compiler-test-support/interface-mixin.ss"))))

(def compiler-builtins-test
  (test-suite "compiler builtins support"
    (test-case "builtins"
      (must-compile-and-execute "compiler-test-support/builtins.ss"))
    (test-case "builtins (bad)"
      ;; TODO: add plenty of bad cases at for lots of builtins --
      ;; at least for each general shape of builtin type, an example of bad use.
      (must-not-compile "compiler-test-support/with-output-bad.ss"))))
