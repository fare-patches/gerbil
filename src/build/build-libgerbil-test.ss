;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :gerbil/expander
        :std/source
        :std/test)
(export build-libgerbil-test)

;;; Read the actual private helper without executing the build script's main.
;;; It is evaluated alone, so it may use only :gerbil/base and :gerbil/expander;
;;; a reference to another definition of build-libgerbil.ss fails when called.
(def (read-ordering-procedure) => :procedure
  (let (form
        (call-with-input-file (path-expand "build-libgerbil.ss" (this-source-directory))
          (lambda (port)
            (let loop ()
              (let (form (read port))
                (cond
                 ((eof-object? form) (error "missing order-modules definition"))
                 ((and (pair? form) (eq? (car form) 'def)
                       (pair? (cadr form)) (eq? (caadr form) 'order-modules)) form)
                 (else (loop))))))))
    (:- (parameterize ((current-expander-context (make-top-context)))
          (eval '(import :gerbil/base :gerbil/expander))
          (eval `(let () ,form order-modules)))
        :procedure)))

(def order-modules (read-ordering-procedure))

;;; Real expander contexts, with no application loading or compilation.
(def (fixture-module (name : :string)) => module-context
  (let (id (string->symbol (string-append "fixture/" name)))
    (make-module-context id #f (symbol->string id) (symbol->string id))))

(def (fixture-order (modules : :list)
                    (roots : :list)) => :list
  (let (table (make-hash-table-eq))
    (for-each (lambda (ctx)
                (hash-put! table (string->symbol (string-append ":" (symbol->string (expander-context-id ctx)))) ctx))
              modules)
    (:- (parameterize ((current-expander-module-import (lambda (name reload?) (hash-ref table name))))
          (order-modules (map (lambda (name) (string-append "fixture/" name)) roots)))
        :list)))

(def (runtime-import (ctx : module-context)
                     (phi : :fixnum)) => module-import
  (make-module-import (make-module-export ctx 'binding 0 'binding #f) 'binding phi #f))

(def build-libgerbil-test
  (test-suite "libgerbil dependency ordering"
    (test-case "chain and diamond retain dependency-first deterministic order"
      (let ((a (fixture-module "a")) (b (fixture-module "b"))
            (c (fixture-module "c")) (d (fixture-module "d")))
        (module-context-import-set! a [b])
        (module-context-import-set! b [c])
        (check (fixture-order [a b c] ["a"]) => ["fixture/c" "fixture/b" "fixture/a"])
        (module-context-import-set! a [b c])
        (module-context-import-set! b [d])
        (module-context-import-set! c [d])
        (check (fixture-order [a b c d] ["a" "c"]) => ["fixture/d" "fixture/b" "fixture/c" "fixture/a"])))
    (test-case "shared dependencies across roots retain their first position"
      (let ((a (fixture-module "a")) (b (fixture-module "b"))
            (c (fixture-module "c")) (d (fixture-module "d")) (e (fixture-module "e")))
        (module-context-import-set! a [c d])
        (module-context-import-set! b [c e])
        (check (fixture-order [a b c d e] ["a" "b"])
               => ["fixture/c" "fixture/d" "fixture/a" "fixture/e" "fixture/b"])))
    (test-case "runtime imports and positive import-set templates preserve phases"
      (let ((a (fixture-module "a")) (b (fixture-module "b"))
            (c (fixture-module "c")) (ignored (fixture-module "ignored")))
        (module-context-import-set! b [(runtime-import c 0) (runtime-import ignored 1)])
        (module-context-import-set! a [(make-import-set b 0 [])])
        (check (fixture-order [a b c ignored] ["a"]) => ["fixture/c" "fixture/b" "fixture/a"])
        (module-context-import-set! a [(make-import-set b 1 [])])
        (check (fixture-order [a b c ignored] ["a"]) => ["fixture/c" "fixture/a"])
        (module-context-import-set! a [(make-import-set b -1 [])])
        (check (fixture-order [a b c ignored] ["a"]) => ["fixture/a"])))
    (test-case "preludes retain their output position and exclusions stay omitted"
      (let* ((a (fixture-module "a")) (b (fixture-module "b"))
             (prelude (make-prelude-context #f))
             (excluded (make-module-context 'gerbil/core/fixture #f "excluded" "excluded")))
        (expander-context-id-set! prelude 'fixture/prelude)
        (prelude-context-import-set! prelude [b])
        (phi-context-super-set! a prelude)
        (module-context-import-set! a [b excluded])
        (check (fixture-order [a b excluded] ["a"]) => ["fixture/b" "fixture/prelude" "fixture/a"])))
    (test-case "a large repeated acyclic graph visits shared subgraphs only once"
      (let loop ((n 0) (modules []))
        (if (= n 160)
          ;; Revisiting shared subgraphs takes exponential time: fail, not hang.
          (let (worker (spawn (lambda () (fixture-order modules ["159"]))))
            (check (thread-join! worker 60 'timeout)
                   => (map (lambda (i) (string-append "fixture/" (number->string i))) (iota 160))))
          (let (ctx (fixture-module (number->string n)))
            (unless (null? modules) (module-context-import-set! ctx [(car modules) (car modules)]))
            (loop (1+ n) (cons ctx modules))))))))
