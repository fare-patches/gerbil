(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/eval::timestamp 1795039815)
  (begin
    (define __syntax::t
      (let ((__tmp180905 (list)) (__tmp180904 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         '__syntax::t
         '__syntax
         __tmp180905
         '(e id)
         __tmp180904
         '#f)))
    (define __syntax?
      (let () (declare (not safe)) (__make-class-predicate __syntax::t)))
    (define make-__syntax
      (lambda _%$args180709%_
        (apply make-instance __syntax::t _%$args180709%_)))
    (define __syntax-e
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor __syntax::t 'e)))
    (define __syntax-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor __syntax::t 'id)))
    (define __syntax-e-set!
      (let () (declare (not safe)) (__make-class-slot-mutator __syntax::t 'e)))
    (define __syntax-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator __syntax::t 'id)))
    (define &__syntax-e
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor __syntax::t 'e)))
    (define &__syntax-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor __syntax::t 'id)))
    (define &__syntax-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator __syntax::t 'e)))
    (define &__syntax-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator __syntax::t 'id)))
    (define __core-form::t
      (let ((__tmp180907 (list __syntax::t))
            (__tmp180906 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         '__core-form::t
         '__core-form
         __tmp180907
         '()
         __tmp180906
         '#f)))
    (define __core-form?
      (let () (declare (not safe)) (__make-class-predicate __core-form::t)))
    (define make-__core-form
      (lambda _%$args180706%_
        (apply make-instance __core-form::t _%$args180706%_)))
    (define __core-form-e
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor __core-form::t 'e)))
    (define __core-form-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor __core-form::t 'id)))
    (define __core-form-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator __core-form::t 'e)))
    (define __core-form-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator __core-form::t 'id)))
    (define &__core-form-e
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor __core-form::t 'e)))
    (define &__core-form-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor __core-form::t 'id)))
    (define &__core-form-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator __core-form::t 'e)))
    (define &__core-form-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator __core-form::t 'id)))
    (define __core-expression::t
      (let ((__tmp180909 (list __core-form::t))
            (__tmp180908 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         '__core-expression::t
         '__core-expression
         __tmp180909
         '()
         __tmp180908
         '#f)))
    (define __core-expression?
      (let ()
        (declare (not safe))
        (__make-class-predicate __core-expression::t)))
    (define make-__core-expression
      (lambda _%$args180703%_
        (apply make-instance __core-expression::t _%$args180703%_)))
    (define __core-expression-e
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor __core-expression::t 'e)))
    (define __core-expression-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor __core-expression::t 'id)))
    (define __core-expression-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator __core-expression::t 'e)))
    (define __core-expression-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator __core-expression::t 'id)))
    (define &__core-expression-e
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor __core-expression::t 'e)))
    (define &__core-expression-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor __core-expression::t 'id)))
    (define &__core-expression-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator __core-expression::t 'e)))
    (define &__core-expression-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator __core-expression::t 'id)))
    (define __core-special-form::t
      (let ((__tmp180911 (list __core-form::t))
            (__tmp180910 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         '__core-special-form::t
         '__core-special-form
         __tmp180911
         '()
         __tmp180910
         '#f)))
    (define __core-special-form?
      (let ()
        (declare (not safe))
        (__make-class-predicate __core-special-form::t)))
    (define make-__core-special-form
      (lambda _%$args180700%_
        (apply make-instance __core-special-form::t _%$args180700%_)))
    (define __core-special-form-e
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor __core-special-form::t 'e)))
    (define __core-special-form-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor __core-special-form::t 'id)))
    (define __core-special-form-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator __core-special-form::t 'e)))
    (define __core-special-form-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator __core-special-form::t 'id)))
    (define &__core-special-form-e
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor __core-special-form::t 'e)))
    (define &__core-special-form-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor __core-special-form::t 'id)))
    (define &__core-special-form-e-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator __core-special-form::t 'e)))
    (define &__core-special-form-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator __core-special-form::t 'id)))
    (define __core (let () (declare (not safe)) (make-hash-table-eq)))
    (define __current-expander (make-parameter '#f))
    (define __current-compiler (make-parameter '#f))
    (define __current-path (make-parameter '()))
    (define __core-resolve
      (lambda (_%id180677%_)
        (let* ((_%h180679%_ __core)
               (_%key180682%_
                (let () (declare (not safe)) (__AST-e _%id180677%_)))
               (_%h180686%_ _%h180679%_)
               (_%h180688%_ _%h180686%_))
          (declare (not safe))
          (__hash-get _%h180688%_ _%key180682%_))))
    (define __core-bound-id?__%
      (lambda (_%id180660%_ _%is?180661%_)
        (let ((_%$e180663%_ (__core-resolve _%id180660%_)))
          (if _%$e180663%_ (_%is?180661%_ _%$e180663%_) '#f))))
    (define __core-bound-id?__0
      (lambda (_%id180670%_)
        (let ((_%is?180672%_ true))
          (__core-bound-id?__% _%id180670%_ _%is?180672%_))))
    (define __core-bound-id?
      (lambda _g180912_
        (let ((_g180913_ (let () (declare (not safe)) (##length _g180912_))))
          (cond ((let () (declare (not safe)) (##fx= _g180913_ 1))
                 (apply __core-bound-id?__0 _g180912_))
                ((let () (declare (not safe)) (##fx= _g180913_ 2))
                 (apply __core-bound-id?__% _g180912_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __core-bound-id?
                  _g180912_))))))
    (define __core-bind-syntax!__%
      (lambda (_%id180618%_ _%e180619%_ _%make180620%_)
        (let* ((_%h180622%_ __core)
               (_%key180625%_ _%id180618%_)
               (_%value180628%_
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%e180619%_ '__syntax::t))
                    _%e180619%_
                    (_%make180620%_ _%e180619%_ _%id180618%_)))
               (_%h180632%_ _%h180622%_)
               (_%h180634%_ _%h180632%_))
          (declare (not safe))
          (__hash-put! _%h180634%_ _%key180625%_ _%value180628%_))))
    (define __core-bind-syntax!__0
      (lambda (_%id180650%_ _%e180651%_)
        (let ((_%make180653%_ make-__syntax))
          (__core-bind-syntax!__% _%id180650%_ _%e180651%_ _%make180653%_))))
    (define __core-bind-syntax!
      (lambda _g180914_
        (let ((_g180915_ (let () (declare (not safe)) (##length _g180914_))))
          (cond ((let () (declare (not safe)) (##fx= _g180915_ 2))
                 (apply __core-bind-syntax!__0 _g180914_))
                ((let () (declare (not safe)) (##fx= _g180915_ 3))
                 (apply __core-bind-syntax!__% _g180914_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __core-bind-syntax!
                  _g180914_))))))
    (define __SRC__%
      (lambda (_%e180598%_ _%src-stx180599%_)
        (if (or (pair? _%e180598%_) (symbol? _%e180598%_))
            (let ((__tmp180916
                   (if (let ()
                         (declare (not safe))
                         (##structure-instance-of?
                          _%src-stx180599%_
                          'gerbil#AST::t))
                       (__locat (let ()
                                  (declare (not safe))
                                  (__AST-source _%src-stx180599%_)))
                       '#f)))
              (declare (not safe))
              (##make-source _%e180598%_ __tmp180916))
            (if (let ()
                  (declare (not safe))
                  (##structure-instance-of? _%e180598%_ 'gerbil#AST::t))
                (let ((__tmp180918
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref _%e180598%_ '1 '#f '#f)))
                      (__tmp180917
                       (__locat (let ()
                                  (declare (not safe))
                                  (__AST-source _%e180598%_)))))
                  (declare (not safe))
                  (##make-source __tmp180918 __tmp180917))
                (let ()
                  (declare (not safe))
                  (error '"BUG! Cannot sourcify object" _%e180598%_))))))
    (define __SRC__0
      (lambda (_%e180610%_)
        (let ((_%src-stx180612%_ '#f))
          (__SRC__% _%e180610%_ _%src-stx180612%_))))
    (define __SRC
      (lambda _g180919_
        (let ((_g180920_ (let () (declare (not safe)) (##length _g180919_))))
          (cond ((let () (declare (not safe)) (##fx= _g180920_ 1))
                 (apply __SRC__0 _g180919_))
                ((let () (declare (not safe)) (##fx= _g180920_ 2))
                 (apply __SRC__% _g180919_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __SRC
                  _g180919_))))))
    (define __locat
      (lambda (_%loc180595%_)
        (if (let () (declare (not safe)) (##locat? _%loc180595%_))
            _%loc180595%_
            '#f)))
    (define __check-values
      (lambda (_%obj180590%_ _%k180591%_)
        (let ((_%count180593%_
               (if (let () (declare (not safe)) (##values? _%obj180590%_))
                   (let ()
                     (declare (not safe))
                     (##values-length _%obj180590%_))
                   '1)))
          (if (fx= _%count180593%_ _%k180591%_)
              '#!void
              (let ((__tmp180922
                     (if (fx< _%count180593%_ _%k180591%_)
                         '"Too few values for context"
                         '"Too many values for context"))
                    (__tmp180921
                     (if (let ()
                           (declare (not safe))
                           (##values? _%obj180590%_))
                         (let ()
                           (declare (not safe))
                           (##values->list _%obj180590%_))
                         _%obj180590%_)))
                (declare (not safe))
                (error __tmp180922 __tmp180921 _%k180591%_))))))
    (define __compile
      (lambda (_%stx180559%_)
        (let* ((_%$e180561%_ _%stx180559%_)
               (_%$%$E180563180569%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e180561%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e180561%_))
              (let* ((_%$%$tgt180564180572%_
                      (let () (declare (not safe)) (__AST-e _%$e180561%_)))
                     (_%$%$hd180565180575%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt180564180572%_)))
                     (_%$%$tl180566180578%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt180564180572%_)))
                     (_%form180582%_ _%$%$hd180565180575%_)
                     (_%$e180584%_ (__core-resolve _%form180582%_)))
                (if _%$e180584%_
                    ((##structure-ref _%$e180584%_ '1 __syntax::t '#f)
                     _%stx180559%_)
                    (let ()
                      (declare (not safe))
                      (__raise-syntax-error
                       '#f
                       '"Bad syntax; cannot resolve form"
                       _%stx180559%_
                       _%form180582%_))))
              (_%$%$E180563180569%_)))))
    (define __compile-error__%
      (lambda (_%stx180546%_ _%detail180547%_)
        (let ()
          (declare (not safe))
          (__raise-syntax-error
           'compile
           '"Bad syntax; cannot compile"
           _%stx180546%_
           _%detail180547%_))))
    (define __compile-error__0
      (lambda (_%stx180552%_)
        (let ((_%detail180554%_ '#f))
          (__compile-error__% _%stx180552%_ _%detail180554%_))))
    (define __compile-error
      (lambda _g180923_
        (let ((_g180924_ (let () (declare (not safe)) (##length _g180923_))))
          (cond ((let () (declare (not safe)) (##fx= _g180924_ 1))
                 (apply __compile-error__0 _g180923_))
                ((let () (declare (not safe)) (##fx= _g180924_ 2))
                 (apply __compile-error__% _g180923_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __compile-error
                  _g180923_))))))
    (define __compile-ignore%
      (lambda (_%stx180543%_) (__SRC__% ''#!void _%stx180543%_)))
    (define __compile-begin%
      (lambda (_%stx180518%_)
        (let* ((_%$e180520%_ _%stx180518%_)
               (_%$%$E180522180528%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e180520%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e180520%_))
              (let* ((_%$%$tgt180523180531%_
                      (let () (declare (not safe)) (__AST-e _%$e180520%_)))
                     (_%$%$hd180524180534%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt180523180531%_)))
                     (_%$%$tl180525180537%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt180523180531%_)))
                     (_%body180541%_ _%$%$tl180525180537%_))
                (__SRC__%
                 (cons 'begin (map __compile _%body180541%_))
                 _%stx180518%_))
              (_%$%$E180522180528%_)))))
    (define __compile-begin-foreign%
      (lambda (_%stx180493%_)
        (let* ((_%$e180495%_ _%stx180493%_)
               (_%$%$E180497180503%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e180495%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e180495%_))
              (let* ((_%$%$tgt180498180506%_
                      (let () (declare (not safe)) (__AST-e _%$e180495%_)))
                     (_%$%$hd180499180509%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt180498180506%_)))
                     (_%$%$tl180500180512%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt180498180506%_)))
                     (_%body180516%_ _%$%$tl180500180512%_))
                (__SRC__%
                 (cons 'begin
                       (let ()
                         (declare (not safe))
                         (__AST->datum _%body180516%_)))
                 _%stx180493%_))
              (_%$%$E180497180503%_)))))
    (define __compile-import%
      (lambda (_%stx180468%_)
        (let* ((_%$e180470%_ _%stx180468%_)
               (_%$%$E180472180478%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e180470%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e180470%_))
              (let* ((_%$%$tgt180473180481%_
                      (let () (declare (not safe)) (__AST-e _%$e180470%_)))
                     (_%$%$hd180474180484%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt180473180481%_)))
                     (_%$%$tl180475180487%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt180473180481%_)))
                     (_%body180491%_ _%$%$tl180475180487%_))
                (__SRC__%
                 (list '__eval-import (list 'quote _%body180491%_))
                 _%stx180468%_))
              (_%$%$E180472180478%_)))))
    (define __compile-begin-annotation%
      (lambda (_%stx180415%_)
        (let* ((_%$e180417%_ _%stx180415%_)
               (_%$%$E180419180431%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e180417%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e180417%_))
              (let* ((_%$%$tgt180420180434%_
                      (let () (declare (not safe)) (__AST-e _%$e180417%_)))
                     (_%$%$hd180421180437%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt180420180434%_)))
                     (_%$%$tl180422180440%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt180420180434%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl180422180440%_))
                    (let* ((_%$%$tgt180423180444%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl180422180440%_)))
                           (_%$%$hd180424180447%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt180423180444%_)))
                           (_%$%$tl180425180450%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt180423180444%_)))
                           (_%ann180454%_ _%$%$hd180424180447%_))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$%$tl180425180450%_))
                          (let* ((_%$%$tgt180426180456%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$%$tl180425180450%_)))
                                 (_%$%$hd180427180459%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt180426180456%_)))
                                 (_%$%$tl180428180462%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt180426180456%_)))
                                 (_%expr180466%_ _%$%$hd180427180459%_))
                            (if (equal? (let ()
                                          (declare (not safe))
                                          (__AST-e _%$%$tl180428180462%_))
                                        '())
                                (__compile _%expr180466%_)
                                (_%$%$E180419180431%_)))
                          (_%$%$E180419180431%_)))
                    (_%$%$E180419180431%_)))
              (_%$%$E180419180431%_)))))
    (define __compile-define-values%
      (lambda (_%stx180306%_)
        (let* ((_%$e180308%_ _%stx180306%_)
               (_%$%$E180310180322%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e180308%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e180308%_))
              (let* ((_%$%$tgt180311180325%_
                      (let () (declare (not safe)) (__AST-e _%$e180308%_)))
                     (_%$%$hd180312180328%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt180311180325%_)))
                     (_%$%$tl180313180331%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt180311180325%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl180313180331%_))
                    (let* ((_%$%$tgt180314180335%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl180313180331%_)))
                           (_%$%$hd180315180338%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt180314180335%_)))
                           (_%$%$tl180316180341%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt180314180335%_)))
                           (_%hd180345%_ _%$%$hd180315180338%_))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$%$tl180316180341%_))
                          (let* ((_%$%$tgt180317180347%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$%$tl180316180341%_)))
                                 (_%$%$hd180318180350%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt180317180347%_)))
                                 (_%$%$tl180319180353%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt180317180347%_)))
                                 (_%expr180357%_ _%$%$hd180318180350%_))
                            (if (equal? (let ()
                                          (declare (not safe))
                                          (__AST-e _%$%$tl180319180353%_))
                                        '())
                                (let* ((_%$e180359%_ _%hd180345%_)
                                       (_%$%$E180361180402%_
                                        (lambda ()
                                          (let ((_%$%$E180362180387%_
                                                 (lambda ()
                                                   (let* ((_%$%$E180363180374%_
                                                           (lambda ()
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (__raise-syntax-error
                        '#f
                        '"Bad syntax; malformed ast clause"
                        _%$e180359%_))))
                  (_%ids180377%_ _%hd180345%_)
                  (_%len180379%_ (length _%ids180377%_))
                  (_%tmp180381%_
                   (__SRC__0 (let () (declare (not safe)) (##gensym)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (__SRC__%
                                                      (cons 'begin
                                                            (cons (__SRC__%
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (list 'define
                                 _%tmp180381%_
                                 (__compile _%expr180357%_))
                           _%stx180306%_)
                          (cons (__SRC__%
                                 (list '__check-values
                                       _%tmp180381%_
                                       _%len180379%_)
                                 _%stx180306%_)
                                (let ((__tmp180926
                                       (lambda (_%id180384%_ _%k180385%_)
                                         (if (let ()
                                               (declare (not safe))
                                               (__AST-e _%id180384%_))
                                             (__SRC__%
                                              (list 'define
                                                    (__SRC__0 _%id180384%_)
                                                    (list '##values-ref
                                                          _%tmp180381%_
                                                          _%k180385%_))
                                              _%stx180306%_)
                                             '#f)))
                                      (__tmp180925
                                       (let ()
                                         (declare (not safe))
                                         (##iota _%len180379%_))))
                                  (declare (not safe))
                                  (filter-map__1
                                   __tmp180926
                                   _%ids180377%_
                                   __tmp180925)))))
              _%stx180306%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (if (let ()
                                                  (declare (not safe))
                                                  (__AST-pair? _%$e180359%_))
                                                (let* ((_%$%$tgt180364180390%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (__AST-e _%$e180359%_)))
                                                       (_%$%$hd180365180393%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%$tgt180364180390%_)))
                                                       (_%$%$tl180366180396%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%$tgt180364180390%_)))
                                                       (_%id180400%_
                                                        _%$%$hd180365180393%_))
                                                  (if (equal? (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (__AST-e _%$%$tl180366180396%_))
                      '())
              (__SRC__%
               (list 'define
                     (__SRC__0 _%id180400%_)
                     (__compile _%expr180357%_))
               _%stx180306%_)
              (_%$%$E180362180387%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%$E180362180387%_))))))
                                  (if (let ()
                                        (declare (not safe))
                                        (__AST-pair? _%$e180359%_))
                                      (let* ((_%$%$tgt180367180405%_
                                              (let ()
                                                (declare (not safe))
                                                (__AST-e _%$e180359%_)))
                                             (_%$%$hd180368180408%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%$tgt180367180405%_)))
                                             (_%$%$tl180369180411%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%$tgt180367180405%_))))
                                        (if (equal? (let ()
                                                      (declare (not safe))
                                                      (__AST-e _%$%$hd180368180408%_))
                                                    '#f)
                                            (if (equal? (let ()
                                                          (declare (not safe))
                                                          (__AST-e _%$%$tl180369180411%_))
                                                        '())
                                                (__compile _%expr180357%_)
                                                (_%$%$E180361180402%_))
                                            (_%$%$E180361180402%_)))
                                      (_%$%$E180361180402%_)))
                                (_%$%$E180310180322%_)))
                          (_%$%$E180310180322%_)))
                    (_%$%$E180310180322%_)))
              (_%$%$E180310180322%_)))))
    (define __compile-head-id
      (lambda (_%e180304%_)
        (__SRC__0
         (if (let () (declare (not safe)) (__AST-e _%e180304%_))
             _%e180304%_
             (let () (declare (not safe)) (##gensym))))))
    (define __compile-lambda-head
      (lambda (_%hd180261%_)
        (let _%recur180263%_ ((_%rest180265%_ _%hd180261%_))
          (let* ((_%$e180267%_ _%rest180265%_)
                 (_%$%$E180269180287%_
                  (lambda ()
                    (let ((_%$%$E180270180284%_
                           (lambda ()
                             (let* ((_%$%$E180271180279%_
                                     (lambda ()
                                       (let ()
                                         (declare (not safe))
                                         (__raise-syntax-error
                                          '#f
                                          '"Bad syntax; malformed ast clause"
                                          _%$e180267%_))))
                                    (_%tail180282%_ _%$e180267%_))
                               (__compile-head-id _%tail180282%_)))))
                      (if (equal? (let ()
                                    (declare (not safe))
                                    (__AST-e _%$e180267%_))
                                  '())
                          '()
                          (_%$%$E180270180284%_))))))
            (if (let () (declare (not safe)) (__AST-pair? _%$e180267%_))
                (let* ((_%$%$tgt180272180290%_
                        (let () (declare (not safe)) (__AST-e _%$e180267%_)))
                       (_%$%$hd180273180293%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%$tgt180272180290%_)))
                       (_%$%$tl180274180296%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%$tgt180272180290%_)))
                       (_%hd180300%_ _%$%$hd180273180293%_)
                       (_%rest180302%_ _%$%$tl180274180296%_))
                  (cons (__compile-head-id _%hd180300%_)
                        (_%recur180263%_ _%rest180302%_)))
                (_%$%$E180269180287%_))))))
    (define __compile-lambda%
      (lambda (_%stx180208%_)
        (let* ((_%$e180210%_ _%stx180208%_)
               (_%$%$E180212180224%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e180210%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e180210%_))
              (let* ((_%$%$tgt180213180227%_
                      (let () (declare (not safe)) (__AST-e _%$e180210%_)))
                     (_%$%$hd180214180230%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt180213180227%_)))
                     (_%$%$tl180215180233%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt180213180227%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl180215180233%_))
                    (let* ((_%$%$tgt180216180237%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl180215180233%_)))
                           (_%$%$hd180217180240%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt180216180237%_)))
                           (_%$%$tl180218180243%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt180216180237%_)))
                           (_%hd180247%_ _%$%$hd180217180240%_))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$%$tl180218180243%_))
                          (let* ((_%$%$tgt180219180249%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$%$tl180218180243%_)))
                                 (_%$%$hd180220180252%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt180219180249%_)))
                                 (_%$%$tl180221180255%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt180219180249%_)))
                                 (_%body180259%_ _%$%$hd180220180252%_))
                            (if (equal? (let ()
                                          (declare (not safe))
                                          (__AST-e _%$%$tl180221180255%_))
                                        '())
                                (__SRC__%
                                 (list 'lambda
                                       (__compile-lambda-head _%hd180247%_)
                                       (__compile _%body180259%_))
                                 _%stx180208%_)
                                (_%$%$E180212180224%_)))
                          (_%$%$E180212180224%_)))
                    (_%$%$E180212180224%_)))
              (_%$%$E180212180224%_)))))
    (define __compile-case-lambda%
      (lambda (_%stx179973%_)
        (letrec ((_%variadic?179975%_
                  (lambda (_%hd180173%_)
                    (let* ((_%$e180175%_ _%hd180173%_)
                           (_%$%$E180177180193%_
                            (lambda ()
                              (let ((_%$%$E180178180190%_
                                     (lambda ()
                                       (let ((_%$%$E180179180187%_
                                              (lambda ()
                                                (let ()
                                                  (declare (not safe))
                                                  (__raise-syntax-error
                                                   '#f
                                                   '"Bad syntax; malformed ast clause"
                                                   _%$e180175%_)))))
                                         '#t))))
                                (if (equal? (let ()
                                              (declare (not safe))
                                              (__AST-e _%$e180175%_))
                                            '())
                                    '#f
                                    (_%$%$E180178180190%_))))))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$e180175%_))
                          (let* ((_%$%$tgt180180180196%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$e180175%_)))
                                 (_%$%$hd180181180199%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt180180180196%_)))
                                 (_%$%$tl180182180202%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt180180180196%_)))
                                 (_%rest180206%_ _%$%$tl180182180202%_))
                            (_%variadic?179975%_ _%rest180206%_))
                          (_%$%$E180177180193%_)))))
                 (_%arity179976%_
                  (lambda (_%hd180111%_)
                    (let _%lp180113%_ ((_%rest180115%_ _%hd180111%_)
                                       (_%k180116%_ '0))
                      (let* ((_%$e180118%_ _%rest180115%_)
                             (_%$%$E180120180131%_
                              (lambda ()
                                (let ((_%$%$E180121180128%_
                                       (lambda ()
                                         (let ()
                                           (declare (not safe))
                                           (__raise-syntax-error
                                            '#f
                                            '"Bad syntax; malformed ast clause"
                                            _%$e180118%_)))))
                                  _%k180116%_))))
                        (if (let ()
                              (declare (not safe))
                              (__AST-pair? _%$e180118%_))
                            (let* ((_%$%$tgt180122180134%_
                                    (let ()
                                      (declare (not safe))
                                      (__AST-e _%$e180118%_)))
                                   (_%$%$hd180123180137%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%$tgt180122180134%_)))
                                   (_%$%$tl180124180140%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%$tgt180122180134%_)))
                                   (_%rest180144%_ _%$%$tl180124180140%_))
                              (_%lp180113%_
                               _%rest180144%_
                               (let ((_%x180146%_ _%k180116%_))
                                 (if (fixnum? _%x180146%_)
                                     (let ((_%x180151%_ _%x180146%_))
                                       (declare (not safe))
                                       (__fx1+ _%x180151%_))
                                     (begin
                                       (raise-contract-violation-error
                                        '"contract violation"
                                        'context:
                                        'gerbil/runtime/eval
                                        'contract:
                                        'fixnum?
                                        'value:
                                        _%x180146%_)
                                       '#!void)))))
                            (_%$%$E180120180131%_))))))
                 (_%generate179977%_
                  (lambda (_%rest180038%_ _%args180039%_ _%len180040%_)
                    (let* ((_%$e180042%_ _%rest180038%_)
                           (_%$%$E180044180055%_
                            (lambda ()
                              (let ((_%$%$E180045180052%_
                                     (lambda ()
                                       (let ()
                                         (declare (not safe))
                                         (__raise-syntax-error
                                          '#f
                                          '"Bad syntax; malformed ast clause"
                                          _%$e180042%_)))))
                                (__SRC__%
                                 (list 'error
                                       '"No clause matching arguments"
                                       _%args180039%_)
                                 _%stx179973%_)))))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$e180042%_))
                          (let* ((_%$%$tgt180046180058%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$e180042%_)))
                                 (_%$%$hd180047180061%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt180046180058%_)))
                                 (_%$%$tl180048180064%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt180046180058%_)))
                                 (_%clause180068%_ _%$%$hd180047180061%_)
                                 (_%rest180070%_ _%$%$tl180048180064%_)
                                 (_%$e180072%_ _%clause180068%_)
                                 (_%$%$E180074180083%_
                                  (lambda ()
                                    (let ()
                                      (declare (not safe))
                                      (__raise-syntax-error
                                       '#f
                                       '"Bad syntax; malformed ast clause"
                                       _%$e180072%_)))))
                            (if (let ()
                                  (declare (not safe))
                                  (__AST-pair? _%$e180072%_))
                                (let* ((_%$%$tgt180075180086%_
                                        (let ()
                                          (declare (not safe))
                                          (__AST-e _%$e180072%_)))
                                       (_%$%$hd180076180089%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%$tgt180075180086%_)))
                                       (_%$%$tl180077180092%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%$tgt180075180086%_)))
                                       (_%hd180096%_ _%$%$hd180076180089%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (__AST-pair? _%$%$tl180077180092%_))
                                      (let* ((_%$%$tgt180078180098%_
                                              (let ()
                                                (declare (not safe))
                                                (__AST-e _%$%$tl180077180092%_)))
                                             (_%$%$hd180079180101%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%$tgt180078180098%_)))
                                             (_%$%$tl180080180104%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%$tgt180078180098%_))))
                                        (if (equal? (let ()
                                                      (declare (not safe))
                                                      (__AST-e _%$%$tl180080180104%_))
                                                    '())
                                            (let ((_%clen180108%_
                                                   (_%arity179976%_
                                                    _%hd180096%_))
                                                  (_%cmp180109%_
                                                   (if (_%variadic?179975%_
                                                        _%hd180096%_)
                                                       'fx>=
                                                       'fx=)))
                                              (__SRC__%
                                               (list 'if
                                                     (list _%cmp180109%_
                                                           _%len180040%_
                                                           _%clen180108%_)
                                                     (__SRC__%
                                                      (list '##apply
                                                            (__compile-lambda%
                                                             (cons '%#lambda
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%clause180068%_))
                    _%args180039%_)
              _%stx179973%_)
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%generate179977%_
                                                      _%rest180070%_
                                                      _%args180039%_
                                                      _%len180040%_))
                                               _%stx179973%_))
                                            (_%$%$E180074180083%_)))
                                      (_%$%$E180074180083%_)))
                                (_%$%$E180074180083%_)))
                          (_%$%$E180044180055%_))))))
          (let* ((_%$e179979%_ _%stx179973%_)
                 (_%$%$E179981180013%_
                  (lambda ()
                    (let ((_%$%$E179982179995%_
                           (lambda ()
                             (let ()
                               (declare (not safe))
                               (__raise-syntax-error
                                '#f
                                '"Bad syntax; malformed ast clause"
                                _%$e179979%_)))))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$e179979%_))
                          (let* ((_%$%$tgt179983179998%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$e179979%_)))
                                 (_%$%$hd179984180001%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt179983179998%_)))
                                 (_%$%$tl179985180004%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt179983179998%_)))
                                 (_%clauses180008%_ _%$%$tl179985180004%_))
                            (let ((_%args180010%_
                                   (__SRC__%
                                    (let () (declare (not safe)) (##gensym))
                                    _%stx179973%_))
                                  (_%len180011%_
                                   (__SRC__%
                                    (let () (declare (not safe)) (##gensym))
                                    _%stx179973%_)))
                              (__SRC__%
                               (list 'lambda
                                     _%args180010%_
                                     (__SRC__%
                                      (list 'let
                                            (list (list _%len180011%_
                                                        (__SRC__%
                                                         (list '##length
                                                               _%args180010%_)
                                                         _%stx179973%_)))
                                            (_%generate179977%_
                                             _%clauses180008%_
                                             _%args180010%_
                                             _%len180011%_))
                                      _%stx179973%_))
                               _%stx179973%_)))
                          (_%$%$E179982179995%_))))))
            (if (let () (declare (not safe)) (__AST-pair? _%$e179979%_))
                (let* ((_%$%$tgt179986180016%_
                        (let () (declare (not safe)) (__AST-e _%$e179979%_)))
                       (_%$%$hd179987180019%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%$tgt179986180016%_)))
                       (_%$%$tl179988180022%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%$tgt179986180016%_))))
                  (if (let ()
                        (declare (not safe))
                        (__AST-pair? _%$%$tl179988180022%_))
                      (let* ((_%$%$tgt179989180026%_
                              (let ()
                                (declare (not safe))
                                (__AST-e _%$%$tl179988180022%_)))
                             (_%$%$hd179990180029%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%$tgt179989180026%_)))
                             (_%$%$tl179991180032%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%$tgt179989180026%_)))
                             (_%clause180036%_ _%$%$hd179990180029%_))
                        (if (equal? (let ()
                                      (declare (not safe))
                                      (__AST-e _%$%$tl179991180032%_))
                                    '())
                            (__compile-lambda%
                             (cons '%#lambda _%clause180036%_))
                            (_%$%$E179981180013%_)))
                      (_%$%$E179981180013%_)))
                (_%$%$E179981180013%_))))))
    (define __compile-let-form
      (lambda (_%stx179742%_ _%compile-simple179743%_ _%compile-values179744%_)
        (letrec ((_%simple-bind?179746%_
                  (lambda (_%hd179931%_)
                    (let* ((_%$%hd179932179942%_ _%hd179931%_)
                           (_%$%else179935179950%_ (lambda () '#f)))
                      (let ((_%$%K179938179963%_ (lambda (_%id179961%_) '#t))
                            (_%$%K179937179955%_ (lambda () '#t)))
                        (let ((_%$%try-match179934179958%_
                               (lambda ()
                                 (if (let ()
                                       (declare (not safe))
                                       (##eq? _%$%hd179932179942%_ '#f))
                                     (_%$%K179937179955%_)
                                     (_%$%else179935179950%_)))))
                          (if (pair? _%$%hd179932179942%_)
                              (let ((_%$%tl179940179968%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%hd179932179942%_)))
                                    (_%$%hd179939179966%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%hd179932179942%_))))
                                (if (null? _%$%tl179940179968%_)
                                    (let ((_%id179971%_ _%$%hd179939179966%_))
                                      (_%$%K179938179963%_ _%id179971%_))
                                    (_%$%try-match179934179958%_)))
                              (_%$%try-match179934179958%_)))))))
                 (_%car-e179747%_
                  (lambda (_%hd179929%_)
                    (if (pair? _%hd179929%_)
                        (let () (declare (not safe)) (##car _%hd179929%_))
                        _%hd179929%_))))
          (let* ((_%$e179749%_ _%stx179742%_)
                 (_%$%$E179751179894%_
                  (lambda ()
                    (let ((_%$%$E179752179774%_
                           (lambda ()
                             (let ()
                               (declare (not safe))
                               (__raise-syntax-error
                                '#f
                                '"Bad syntax; malformed ast clause"
                                _%$e179749%_)))))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$e179749%_))
                          (let* ((_%$%$tgt179753179777%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$e179749%_)))
                                 (_%$%$hd179754179780%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt179753179777%_)))
                                 (_%$%$tl179755179783%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt179753179777%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (__AST-pair? _%$%$tl179755179783%_))
                                (let* ((_%$%$tgt179756179787%_
                                        (let ()
                                          (declare (not safe))
                                          (__AST-e _%$%$tl179755179783%_)))
                                       (_%$%$hd179757179790%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%$tgt179756179787%_)))
                                       (_%$%$tl179758179793%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%$tgt179756179787%_)))
                                       (_%hd179797%_ _%$%$hd179757179790%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (__AST-pair? _%$%$tl179758179793%_))
                                      (let* ((_%$%$tgt179759179799%_
                                              (let ()
                                                (declare (not safe))
                                                (__AST-e _%$%$tl179758179793%_)))
                                             (_%$%$hd179760179802%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%$tgt179759179799%_)))
                                             (_%$%$tl179761179805%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%$tgt179759179799%_)))
                                             (_%body179809%_
                                              _%$%$hd179760179802%_))
                                        (if (equal? (let ()
                                                      (declare (not safe))
                                                      (__AST-e _%$%$tl179761179805%_))
                                                    '())
                                            (let* ((_%hd-ids179849%_
                                                    (map (lambda (_%bind179811%_)
                                                           (let* ((_%$e179813%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%bind179811%_)
                          (_%$%$E179815179824%_
                           (lambda ()
                             (let ()
                               (declare (not safe))
                               (__raise-syntax-error
                                '#f
                                '"Bad syntax; malformed ast clause"
                                _%$e179813%_)))))
                     (if (let ()
                           (declare (not safe))
                           (__AST-pair? _%$e179813%_))
                         (let* ((_%$%$tgt179816179827%_
                                 (let ()
                                   (declare (not safe))
                                   (__AST-e _%$e179813%_)))
                                (_%$%$hd179817179830%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%$tgt179816179827%_)))
                                (_%$%$tl179818179833%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%$tgt179816179827%_)))
                                (_%ids179837%_ _%$%$hd179817179830%_))
                           (if (let ()
                                 (declare (not safe))
                                 (__AST-pair? _%$%$tl179818179833%_))
                               (let* ((_%$%$tgt179819179839%_
                                       (let ()
                                         (declare (not safe))
                                         (__AST-e _%$%$tl179818179833%_)))
                                      (_%$%$hd179820179842%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%$tgt179819179839%_)))
                                      (_%$%$tl179821179845%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%$tgt179819179839%_))))
                                 (if (equal? (let ()
                                               (declare (not safe))
                                               (__AST-e _%$%$tl179821179845%_))
                                             '())
                                     _%ids179837%_
                                     (_%$%$E179815179824%_)))
                               (_%$%$E179815179824%_)))
                         (_%$%$E179815179824%_))))
                 _%hd179797%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%exprs179889%_
                                                    (map (lambda (_%bind179851%_)
                                                           (let* ((_%$e179853%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%bind179851%_)
                          (_%$%$E179855179864%_
                           (lambda ()
                             (let ()
                               (declare (not safe))
                               (__raise-syntax-error
                                '#f
                                '"Bad syntax; malformed ast clause"
                                _%$e179853%_)))))
                     (if (let ()
                           (declare (not safe))
                           (__AST-pair? _%$e179853%_))
                         (let* ((_%$%$tgt179856179867%_
                                 (let ()
                                   (declare (not safe))
                                   (__AST-e _%$e179853%_)))
                                (_%$%$hd179857179870%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%$tgt179856179867%_)))
                                (_%$%$tl179858179873%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%$tgt179856179867%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (__AST-pair? _%$%$tl179858179873%_))
                               (let* ((_%$%$tgt179859179877%_
                                       (let ()
                                         (declare (not safe))
                                         (__AST-e _%$%$tl179858179873%_)))
                                      (_%$%$hd179860179880%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%$tgt179859179877%_)))
                                      (_%$%$tl179861179883%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%$tgt179859179877%_)))
                                      (_%expr179887%_ _%$%$hd179860179880%_))
                                 (if (equal? (let ()
                                               (declare (not safe))
                                               (__AST-e _%$%$tl179861179883%_))
                                             '())
                                     (__compile _%expr179887%_)
                                     (_%$%$E179855179864%_)))
                               (_%$%$E179855179864%_)))
                         (_%$%$E179855179864%_))))
                 _%hd179797%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%body179891%_
                                                    (__compile
                                                     _%body179809%_)))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (andmap__0
                                                     _%simple-bind?179746%_
                                                     _%hd-ids179849%_))
                                                  (_%compile-simple179743%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##map _%car-e179747%_
                                                            _%hd-ids179849%_))
                                                   _%exprs179889%_
                                                   _%body179891%_)
                                                  (_%compile-values179744%_
                                                   _%hd-ids179849%_
                                                   _%exprs179889%_
                                                   _%body179891%_)))
                                            (_%$%$E179752179774%_)))
                                      (_%$%$E179752179774%_)))
                                (_%$%$E179752179774%_)))
                          (_%$%$E179752179774%_))))))
            (if (let () (declare (not safe)) (__AST-pair? _%$e179749%_))
                (let* ((_%$%$tgt179762179897%_
                        (let () (declare (not safe)) (__AST-e _%$e179749%_)))
                       (_%$%$hd179763179900%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%$tgt179762179897%_)))
                       (_%$%$tl179764179903%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%$tgt179762179897%_))))
                  (if (let ()
                        (declare (not safe))
                        (__AST-pair? _%$%$tl179764179903%_))
                      (let* ((_%$%$tgt179765179907%_
                              (let ()
                                (declare (not safe))
                                (__AST-e _%$%$tl179764179903%_)))
                             (_%$%$hd179766179910%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%$tgt179765179907%_)))
                             (_%$%$tl179767179913%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%$tgt179765179907%_))))
                        (if (equal? (let ()
                                      (declare (not safe))
                                      (__AST-e _%$%$hd179766179910%_))
                                    '())
                            (if (let ()
                                  (declare (not safe))
                                  (__AST-pair? _%$%$tl179767179913%_))
                                (let* ((_%$%$tgt179768179917%_
                                        (let ()
                                          (declare (not safe))
                                          (__AST-e _%$%$tl179767179913%_)))
                                       (_%$%$hd179769179920%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%$tgt179768179917%_)))
                                       (_%$%$tl179770179923%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%$tgt179768179917%_)))
                                       (_%body179927%_ _%$%$hd179769179920%_))
                                  (if (equal? (let ()
                                                (declare (not safe))
                                                (__AST-e _%$%$tl179770179923%_))
                                              '())
                                      (__compile _%body179927%_)
                                      (_%$%$E179751179894%_)))
                                (_%$%$E179751179894%_))
                            (_%$%$E179751179894%_)))
                      (_%$%$E179751179894%_)))
                (_%$%$E179751179894%_))))))
    (define __compile-let-values%
      (lambda (_%stx179554%_)
        (letrec ((_%compile-simple179556%_
                  (lambda (_%hd-ids179738%_ _%exprs179739%_ _%body179740%_)
                    (__SRC__%
                     (list 'let
                           (let ((__tmp180927
                                  (map __compile-head-id _%hd-ids179738%_)))
                             (declare (not safe))
                             (##map list __tmp180927 _%exprs179739%_))
                           _%body179740%_)
                     _%stx179554%_)))
                 (_%compile-values179557%_
                  (lambda (_%hd-ids179653%_ _%exprs179654%_ _%body179655%_)
                    (let _%lp179657%_ ((_%rest179659%_ _%hd-ids179653%_)
                                       (_%exprs179660%_ _%exprs179654%_)
                                       (_%bind179661%_ '())
                                       (_%post179662%_ '()))
                      (let* ((_%$%rest179663179677%_ _%rest179659%_)
                             (_%$%else179666179685%_
                              (lambda ()
                                (__SRC__%
                                 (list 'let
                                       (reverse _%bind179661%_)
                                       (_%compile-post179558%_
                                        _%post179662%_
                                        _%body179655%_))
                                 _%stx179554%_))))
                        (let ((_%$%K179671179721%_
                               (lambda (_%rest179718%_ _%id179719%_)
                                 (_%lp179657%_
                                  _%rest179718%_
                                  (cdr _%exprs179660%_)
                                  (cons (list (__compile-head-id _%id179719%_)
                                              (car _%exprs179660%_))
                                        _%bind179661%_)
                                  _%post179662%_)))
                              (_%$%K179668179703%_
                               (lambda (_%rest179689%_ _%hd179690%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (__AST-id? _%hd179690%_))
                                     (_%lp179657%_
                                      _%rest179689%_
                                      (cdr _%exprs179660%_)
                                      (cons (list (__compile-head-id
                                                   _%hd179690%_)
                                                  (list 'values->list
                                                        (car _%exprs179660%_)))
                                            _%bind179661%_)
                                      _%post179662%_)
                                     (if (list? _%hd179690%_)
                                         (let* ((_%len179694%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##length _%hd179690%_)))
                                                (_%tmp179696%_
                                                 (__SRC__0
                                                  (let ()
                                                    (declare (not safe))
                                                    (##gensym)))))
                                           (_%lp179657%_
                                            _%rest179689%_
                                            (cdr _%exprs179660%_)
                                            (cons (list _%tmp179696%_
                                                        (car _%exprs179660%_))
                                                  _%bind179661%_)
                                            (cons (cons _%tmp179696%_
                                                        (cons _%len179694%_
                                                              (let ((__tmp180929
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (lambda (_%id179699%_ _%k179700%_)
                               (if (let ()
                                     (declare (not safe))
                                     (__AST-e _%id179699%_))
                                   (cons (__SRC__0 _%id179699%_) _%k179700%_)
                                   '#f)))
                            (__tmp180928
                             (let ()
                               (declare (not safe))
                               (##iota _%len179694%_))))
                        (declare (not safe))
                        (filter-map__1 __tmp180929 _%hd179690%_ __tmp180928))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  _%post179662%_)))
                                         (__compile-error__%
                                          _%stx179554%_
                                          _%hd179690%_))))))
                          (if (pair? _%$%rest179663179677%_)
                              (let ((_%$%tl179673179726%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest179663179677%_)))
                                    (_%$%hd179672179724%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest179663179677%_))))
                                (if (pair? _%$%hd179672179724%_)
                                    (let ((_%$%tl179675179731%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%hd179672179724%_)))
                                          (_%$%hd179674179729%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%hd179672179724%_))))
                                      (if (null? _%$%tl179675179731%_)
                                          (let ((_%id179734%_
                                                 _%$%hd179674179729%_)
                                                (_%rest179736%_
                                                 _%$%tl179673179726%_))
                                            (_%$%K179671179721%_
                                             _%rest179736%_
                                             _%id179734%_))
                                          (let ((_%hd179711%_
                                                 _%$%hd179672179724%_)
                                                (_%rest179713%_
                                                 _%$%tl179673179726%_))
                                            (_%$%K179668179703%_
                                             _%rest179713%_
                                             _%hd179711%_))))
                                    (let ((_%hd179711%_ _%$%hd179672179724%_)
                                          (_%rest179713%_
                                           _%$%tl179673179726%_))
                                      (_%$%K179668179703%_
                                       _%rest179713%_
                                       _%hd179711%_))))
                              (_%$%else179666179685%_)))))))
                 (_%compile-post179558%_
                  (lambda (_%post179560%_ _%body179561%_)
                    (let _%lp179563%_ ((_%rest179565%_ _%post179560%_)
                                       (_%check179566%_ '())
                                       (_%bind179567%_ '()))
                      (let* ((_%$%rest179568179580%_ _%rest179565%_)
                             (_%$%else179570179588%_
                              (lambda ()
                                (__SRC__%
                                 (cons 'begin
                                       (let ((__tmp180930
                                              (list (__SRC__%
                                                     (list 'let
                                                           _%bind179567%_
                                                           _%body179561%_)
                                                     _%stx179554%_))))
                                         (declare (not safe))
                                         (##append
                                          _%check179566%_
                                          __tmp180930)))
                                 _%stx179554%_)))
                             (_%$%K179572179627%_
                              (lambda (_%rest179591%_
                                       _%init179592%_
                                       _%len179593%_
                                       _%tmp179594%_)
                                (_%lp179563%_
                                 _%rest179591%_
                                 (cons (__SRC__%
                                        (list '__check-values
                                              _%tmp179594%_
                                              _%len179593%_)
                                        _%stx179554%_)
                                       _%check179566%_)
                                 (let ((__tmp180931
                                        (lambda (_%hd179596%_ _%r179597%_)
                                          (let* ((_%$%hd179598179605%_
                                                  _%hd179596%_)
                                                 (_%$%E179600179609%_
                                                  (lambda ()
                                                    (let ()
                                                      (declare (not safe))
                                                      (error '"No clause matching"
                                                             _%$%hd179598179605%_
                                                             '([id . k])))
                                                    '#!void))
                                                 (_%$%K179601179615%_
                                                  (lambda (_%k179612%_
                                                           _%id179613%_)
                                                    (cons (list _%id179613%_
                                                                (list '##values-ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%tmp179594%_
                              _%k179612%_))
                  _%r179597%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (if (pair? _%$%hd179598179605%_)
                                                (let ((_%$%hd179602179618%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%hd179598179605%_)))
                                                      (_%$%tl179603179620%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%hd179598179605%_))))
                                                  (let* ((_%id179623%_
                                                          _%$%hd179602179618%_)
                                                         (_%k179625%_
                                                          _%$%tl179603179620%_))
                                                    (_%$%K179601179615%_
                                                     _%k179625%_
                                                     _%id179623%_)))
                                                (_%$%E179600179609%_))))))
                                   (declare (not safe))
                                   (foldr__0
                                    __tmp180931
                                    _%bind179567%_
                                    _%init179592%_))))))
                        (if (pair? _%$%rest179568179580%_)
                            (let ((_%$%hd179573179630%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest179568179580%_)))
                                  (_%$%tl179574179632%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest179568179580%_))))
                              (if (pair? _%$%hd179573179630%_)
                                  (let ((_%$%hd179575179635%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%hd179573179630%_)))
                                        (_%$%tl179576179637%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%hd179573179630%_))))
                                    (let ((_%tmp179640%_ _%$%hd179575179635%_))
                                      (if (pair? _%$%tl179576179637%_)
                                          (let ((_%$%hd179577179642%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%tl179576179637%_)))
                                                (_%$%tl179578179644%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%tl179576179637%_))))
                                            (let* ((_%len179647%_
                                                    _%$%hd179577179642%_)
                                                   (_%init179649%_
                                                    _%$%tl179578179644%_)
                                                   (_%rest179651%_
                                                    _%$%tl179574179632%_))
                                              (_%$%K179572179627%_
                                               _%rest179651%_
                                               _%init179649%_
                                               _%len179647%_
                                               _%tmp179640%_)))
                                          (_%$%else179570179588%_))))
                                  (_%$%else179570179588%_)))
                            (_%$%else179570179588%_)))))))
          (__compile-let-form
           _%stx179554%_
           _%compile-simple179556%_
           _%compile-values179557%_))))
    (define __compile-letrec-values%
      (lambda (_%stx179351%_)
        (letrec ((_%compile-simple179353%_
                  (lambda (_%hd-ids179550%_ _%exprs179551%_ _%body179552%_)
                    (__SRC__%
                     (list 'letrec
                           (let ((__tmp180932
                                  (map __compile-head-id _%hd-ids179550%_)))
                             (declare (not safe))
                             (##map list __tmp180932 _%exprs179551%_))
                           _%body179552%_)
                     _%stx179351%_)))
                 (_%compile-values179354%_
                  (lambda (_%hd-ids179461%_ _%exprs179462%_ _%body179463%_)
                    (let _%lp179465%_ ((_%rest179467%_ _%hd-ids179461%_)
                                       (_%exprs179468%_ _%exprs179462%_)
                                       (_%pre179469%_ '())
                                       (_%bind179470%_ '())
                                       (_%post179471%_ '()))
                      (let* ((_%$%rest179472179486%_ _%rest179467%_)
                             (_%$%else179475179494%_
                              (lambda ()
                                (_%compile-inner179355%_
                                 _%pre179469%_
                                 _%bind179470%_
                                 _%post179471%_
                                 _%body179463%_))))
                        (let ((_%$%K179480179533%_
                               (lambda (_%rest179530%_ _%id179531%_)
                                 (_%lp179465%_
                                  _%rest179530%_
                                  (cdr _%exprs179468%_)
                                  _%pre179469%_
                                  (cons (list (__compile-head-id _%id179531%_)
                                              (car _%exprs179468%_))
                                        _%bind179470%_)
                                  _%post179471%_)))
                              (_%$%K179477179515%_
                               (lambda (_%rest179498%_ _%hd179499%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (__AST-id? _%hd179499%_))
                                     (_%lp179465%_
                                      _%rest179498%_
                                      (cdr _%exprs179468%_)
                                      _%pre179469%_
                                      (cons (list (__compile-head-id
                                                   _%hd179499%_)
                                                  (list 'values->list
                                                        (car _%exprs179468%_)))
                                            _%bind179470%_)
                                      _%post179471%_)
                                     (if (list? _%hd179499%_)
                                         (let* ((_%len179503%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##length _%hd179499%_)))
                                                (_%tmp179505%_
                                                 (__SRC__0
                                                  (let ()
                                                    (declare (not safe))
                                                    (##gensym)))))
                                           (_%lp179465%_
                                            _%rest179498%_
                                            (cdr _%exprs179468%_)
                                            (let ((__tmp180933
                                                   (lambda (_%id179508%_
                                                            _%r179509%_)
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (__AST-e _%id179508%_))
                                                         (cons (cons (__SRC__0
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%id179508%_)
                             '('#!void))
                       _%r179509%_)
                 _%r179509%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (declare (not safe))
                                              (foldl__0
                                               __tmp180933
                                               _%pre179469%_
                                               _%hd179499%_))
                                            (cons (list _%tmp179505%_
                                                        (car _%exprs179468%_))
                                                  _%bind179470%_)
                                            (cons (cons _%tmp179505%_
                                                        (cons _%len179503%_
                                                              (let ((__tmp180935
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (lambda (_%id179511%_ _%k179512%_)
                               (if (let ()
                                     (declare (not safe))
                                     (__AST-e _%id179511%_))
                                   (cons (__SRC__0 _%id179511%_) _%k179512%_)
                                   '#f)))
                            (__tmp180934
                             (let ()
                               (declare (not safe))
                               (##iota _%len179503%_))))
                        (declare (not safe))
                        (filter-map__1 __tmp180935 _%hd179499%_ __tmp180934))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  _%post179471%_)))
                                         (__compile-error__%
                                          _%stx179351%_
                                          _%hd179499%_))))))
                          (if (pair? _%$%rest179472179486%_)
                              (let ((_%$%tl179482179538%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest179472179486%_)))
                                    (_%$%hd179481179536%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest179472179486%_))))
                                (if (pair? _%$%hd179481179536%_)
                                    (let ((_%$%tl179484179543%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%hd179481179536%_)))
                                          (_%$%hd179483179541%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%hd179481179536%_))))
                                      (if (null? _%$%tl179484179543%_)
                                          (let ((_%id179546%_
                                                 _%$%hd179483179541%_)
                                                (_%rest179548%_
                                                 _%$%tl179482179538%_))
                                            (_%$%K179480179533%_
                                             _%rest179548%_
                                             _%id179546%_))
                                          (let ((_%hd179523%_
                                                 _%$%hd179481179536%_)
                                                (_%rest179525%_
                                                 _%$%tl179482179538%_))
                                            (_%$%K179477179515%_
                                             _%rest179525%_
                                             _%hd179523%_))))
                                    (let ((_%hd179523%_ _%$%hd179481179536%_)
                                          (_%rest179525%_
                                           _%$%tl179482179538%_))
                                      (_%$%K179477179515%_
                                       _%rest179525%_
                                       _%hd179523%_))))
                              (_%$%else179475179494%_)))))))
                 (_%compile-inner179355%_
                  (lambda (_%pre179456%_
                           _%bind179457%_
                           _%post179458%_
                           _%body179459%_)
                    (if (null? _%pre179456%_)
                        (_%compile-bind179356%_
                         _%bind179457%_
                         _%post179458%_
                         _%body179459%_)
                        (__SRC__%
                         (list 'let
                               (reverse _%pre179456%_)
                               (_%compile-bind179356%_
                                _%bind179457%_
                                _%post179458%_
                                _%body179459%_))
                         _%stx179351%_))))
                 (_%compile-bind179356%_
                  (lambda (_%bind179452%_ _%post179453%_ _%body179454%_)
                    (__SRC__%
                     (list 'letrec
                           (reverse _%bind179452%_)
                           (_%compile-post179357%_
                            _%post179453%_
                            _%body179454%_))
                     _%stx179351%_)))
                 (_%compile-post179357%_
                  (lambda (_%post179359%_ _%body179360%_)
                    (let _%lp179362%_ ((_%rest179364%_ _%post179359%_)
                                       (_%check179365%_ '())
                                       (_%bind179366%_ '()))
                      (let* ((_%$%rest179367179379%_ _%rest179364%_)
                             (_%$%else179369179387%_
                              (lambda ()
                                (__SRC__%
                                 (cons 'begin
                                       (append _%check179365%_
                                               _%bind179366%_
                                               (list _%body179360%_)))
                                 _%stx179351%_)))
                             (_%$%K179371179426%_
                              (lambda (_%rest179390%_
                                       _%init179391%_
                                       _%len179392%_
                                       _%tmp179393%_)
                                (_%lp179362%_
                                 _%rest179390%_
                                 (cons (__SRC__%
                                        (list '__check-values
                                              _%tmp179393%_
                                              _%len179392%_)
                                        _%stx179351%_)
                                       _%check179365%_)
                                 (let ((__tmp180936
                                        (lambda (_%hd179395%_ _%r179396%_)
                                          (let* ((_%$%hd179397179404%_
                                                  _%hd179395%_)
                                                 (_%$%E179399179408%_
                                                  (lambda ()
                                                    (let ()
                                                      (declare (not safe))
                                                      (error '"No clause matching"
                                                             _%$%hd179397179404%_
                                                             '([id . k])))
                                                    '#!void))
                                                 (_%$%K179400179414%_
                                                  (lambda (_%k179411%_
                                                           _%id179412%_)
                                                    (cons (list 'set!
                                                                _%id179412%_
                                                                (list '##values-ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%tmp179393%_
                              _%k179411%_))
                  _%r179396%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (if (pair? _%$%hd179397179404%_)
                                                (let ((_%$%hd179401179417%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%hd179397179404%_)))
                                                      (_%$%tl179402179419%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%hd179397179404%_))))
                                                  (let* ((_%id179422%_
                                                          _%$%hd179401179417%_)
                                                         (_%k179424%_
                                                          _%$%tl179402179419%_))
                                                    (_%$%K179400179414%_
                                                     _%k179424%_
                                                     _%id179422%_)))
                                                (_%$%E179399179408%_))))))
                                   (declare (not safe))
                                   (foldr__0
                                    __tmp180936
                                    _%bind179366%_
                                    _%init179391%_))))))
                        (if (pair? _%$%rest179367179379%_)
                            (let ((_%$%hd179372179429%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest179367179379%_)))
                                  (_%$%tl179373179431%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest179367179379%_))))
                              (if (pair? _%$%hd179372179429%_)
                                  (let ((_%$%hd179374179434%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%hd179372179429%_)))
                                        (_%$%tl179375179436%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%hd179372179429%_))))
                                    (let ((_%tmp179439%_ _%$%hd179374179434%_))
                                      (if (pair? _%$%tl179375179436%_)
                                          (let ((_%$%hd179376179441%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%tl179375179436%_)))
                                                (_%$%tl179377179443%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%tl179375179436%_))))
                                            (let* ((_%len179446%_
                                                    _%$%hd179376179441%_)
                                                   (_%init179448%_
                                                    _%$%tl179377179443%_)
                                                   (_%rest179450%_
                                                    _%$%tl179373179431%_))
                                              (_%$%K179371179426%_
                                               _%rest179450%_
                                               _%init179448%_
                                               _%len179446%_
                                               _%tmp179439%_)))
                                          (_%$%else179369179387%_))))
                                  (_%$%else179369179387%_)))
                            (_%$%else179369179387%_)))))))
          (__compile-let-form
           _%stx179351%_
           _%compile-simple179353%_
           _%compile-values179354%_))))
    (define __compile-letrec*-values%
      (lambda (_%stx179102%_)
        (letrec ((_%compile-simple179104%_
                  (lambda (_%hd-ids179347%_ _%exprs179348%_ _%body179349%_)
                    (__SRC__%
                     (list 'letrec*
                           (let ((__tmp180937
                                  (map __compile-head-id _%hd-ids179347%_)))
                             (declare (not safe))
                             (##map list __tmp180937 _%exprs179348%_))
                           _%body179349%_)
                     _%stx179102%_)))
                 (_%compile-values179105%_
                  (lambda (_%hd-ids179254%_ _%exprs179255%_ _%body179256%_)
                    (let _%lp179258%_ ((_%rest179260%_ _%hd-ids179254%_)
                                       (_%exprs179261%_ _%exprs179255%_)
                                       (_%bind179262%_ '())
                                       (_%post179263%_ '()))
                      (let* ((_%$%rest179264179278%_ _%rest179260%_)
                             (_%$%else179267179286%_
                              (lambda ()
                                (_%compile-bind179106%_
                                 _%bind179262%_
                                 _%post179263%_
                                 _%body179256%_))))
                        (let ((_%$%K179272179330%_
                               (lambda (_%rest179325%_ _%hd179326%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (__AST-id? _%hd179326%_))
                                     (let ((_%id179328%_
                                            (__SRC__0 _%hd179326%_)))
                                       (_%lp179258%_
                                        _%rest179325%_
                                        (cdr _%exprs179261%_)
                                        (cons (cons _%id179328%_ '('#!void))
                                              _%bind179262%_)
                                        (cons (list _%id179328%_
                                                    (car _%exprs179261%_))
                                              _%post179263%_)))
                                     (_%lp179258%_
                                      _%rest179325%_
                                      (cdr _%exprs179261%_)
                                      _%bind179262%_
                                      (cons (list '#f (car _%exprs179261%_))
                                            _%post179263%_)))))
                              (_%$%K179269179310%_
                               (lambda (_%rest179290%_ _%hd179291%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (__AST-id? _%hd179291%_))
                                     (let ((_%id179294%_
                                            (__SRC__0 _%hd179291%_)))
                                       (_%lp179258%_
                                        _%rest179290%_
                                        (cdr _%exprs179261%_)
                                        (cons (cons _%id179294%_ '('#!void))
                                              _%bind179262%_)
                                        (cons (list _%id179294%_
                                                    (list 'values->list
                                                          (car _%exprs179261%_)))
                                              _%post179263%_)))
                                     (if (let ()
                                           (declare (not safe))
                                           (__AST-e _%hd179291%_))
                                         (if (list? _%hd179291%_)
                                             (let* ((_%len179298%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##length
                                                        _%hd179291%_)))
                                                    (_%tmp179300%_
                                                     (__SRC__0
                                                      (let ()
                                                        (declare (not safe))
                                                        (##gensym)))))
                                               (_%lp179258%_
                                                _%rest179290%_
                                                (cdr _%exprs179261%_)
                                                (let ((__tmp180938
                                                       (lambda (_%id179303%_
                                                                _%r179304%_)
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (__AST-e _%id179303%_))
                     (cons (cons (__SRC__0 _%id179303%_) '('#!void))
                           _%r179304%_)
                     _%r179304%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (foldl__0
                                                   __tmp180938
                                                   _%bind179262%_
                                                   _%hd179291%_))
                                                (cons (cons _%tmp179300%_
                                                            (cons (car _%exprs179261%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons _%len179298%_
                                (let ((__tmp180940
                                       (lambda (_%id179306%_ _%k179307%_)
                                         (if (let ()
                                               (declare (not safe))
                                               (__AST-e _%id179306%_))
                                             (cons (__SRC__0 _%id179306%_)
                                                   _%k179307%_)
                                             '#f)))
                                      (__tmp180939
                                       (let ()
                                         (declare (not safe))
                                         (##iota _%len179298%_))))
                                  (declare (not safe))
                                  (filter-map__1
                                   __tmp180940
                                   _%hd179291%_
                                   __tmp180939)))))
              _%post179263%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             (__compile-error__%
                                              _%stx179102%_
                                              _%hd179291%_))
                                         (_%lp179258%_
                                          _%rest179290%_
                                          (cdr _%exprs179261%_)
                                          _%bind179262%_
                                          (cons (list '#f
                                                      (car _%exprs179261%_))
                                                _%post179263%_)))))))
                          (if (pair? _%$%rest179264179278%_)
                              (let ((_%$%tl179274179335%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest179264179278%_)))
                                    (_%$%hd179273179333%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest179264179278%_))))
                                (if (pair? _%$%hd179273179333%_)
                                    (let ((_%$%tl179276179340%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%hd179273179333%_)))
                                          (_%$%hd179275179338%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%hd179273179333%_))))
                                      (if (null? _%$%tl179276179340%_)
                                          (let ((_%hd179343%_
                                                 _%$%hd179275179338%_)
                                                (_%rest179345%_
                                                 _%$%tl179274179335%_))
                                            (_%$%K179272179330%_
                                             _%rest179345%_
                                             _%hd179343%_))
                                          (let ((_%hd179318%_
                                                 _%$%hd179273179333%_)
                                                (_%rest179320%_
                                                 _%$%tl179274179335%_))
                                            (_%$%K179269179310%_
                                             _%rest179320%_
                                             _%hd179318%_))))
                                    (let ((_%hd179318%_ _%$%hd179273179333%_)
                                          (_%rest179320%_
                                           _%$%tl179274179335%_))
                                      (_%$%K179269179310%_
                                       _%rest179320%_
                                       _%hd179318%_))))
                              (_%$%else179267179286%_)))))))
                 (_%compile-bind179106%_
                  (lambda (_%bind179250%_ _%post179251%_ _%body179252%_)
                    (__SRC__%
                     (list 'let
                           (reverse _%bind179250%_)
                           (_%compile-post179107%_
                            _%post179251%_
                            _%body179252%_))
                     _%stx179102%_)))
                 (_%compile-post179107%_
                  (lambda (_%post179109%_ _%body179110%_)
                    (__SRC__%
                     (cons 'begin
                           (let ((__tmp180942
                                  (lambda (_%hd179112%_ _%r179113%_)
                                    (let* ((_%$%hd179114179137%_ _%hd179112%_)
                                           (_%$%E179118179141%_
                                            (lambda ()
                                              (let ()
                                                (declare (not safe))
                                                (error '"No clause matching"
                                                       _%$%hd179114179137%_
                                                       '([#f expr])
                                                       '([id expr])
                                                       '([tmp
                                                          expr
                                                          len
                                                          .
                                                          init])))
                                              '#!void)))
                                      (let ((_%$%K179131179235%_
                                             (lambda (_%expr179233%_)
                                               (cons _%expr179233%_
                                                     _%r179113%_)))
                                            (_%$%K179126179213%_
                                             (lambda (_%expr179210%_
                                                      _%id179211%_)
                                               (cons (__SRC__%
                                                      (list 'set!
                                                            _%id179211%_
                                                            _%expr179210%_)
                                                      _%stx179102%_)
                                                     _%r179113%_)))
                                            (_%$%K179119179180%_
                                             (lambda (_%init179145%_
                                                      _%len179146%_
                                                      _%expr179147%_
                                                      _%tmp179148%_)
                                               (cons (__SRC__%
                                                      (cons 'let
                                                            (cons (list (list _%tmp179148%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                      _%expr179147%_))
                          (cons (__SRC__%
                                 (list '__check-values
                                       _%tmp179148%_
                                       _%len179146%_)
                                 _%stx179102%_)
                                (map (lambda (_%hd179150%_)
                                       (let* ((_%$%hd179151179158%_
                                               _%hd179150%_)
                                              (_%$%E179153179162%_
                                               (lambda ()
                                                 (let ()
                                                   (declare (not safe))
                                                   (error '"No clause matching"
                                                          _%$%hd179151179158%_
                                                          '([id . k])))
                                                 '#!void))
                                              (_%$%K179154179168%_
                                               (lambda (_%k179165%_
                                                        _%id179166%_)
                                                 (__SRC__%
                                                  (list 'set!
                                                        _%id179166%_
                                                        (list '##values-ref
                                                              _%tmp179148%_
                                                              _%k179165%_))
                                                  _%stx179102%_))))
                                         (if (pair? _%$%hd179151179158%_)
                                             (let ((_%$%hd179155179171%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%hd179151179158%_)))
                                                   (_%$%tl179156179173%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%hd179151179158%_))))
                                               (let* ((_%id179176%_
                                                       _%$%hd179155179171%_)
                                                      (_%k179178%_
                                                       _%$%tl179156179173%_))
                                                 (_%$%K179154179168%_
                                                  _%k179178%_
                                                  _%id179176%_)))
                                             (_%$%E179153179162%_))))
                                     _%init179145%_))))
              _%stx179102%_)
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%r179113%_))))
                                        (let* ((_%__match180802180803%_
                                                (lambda (_%$%hd179120179183%_
                                                         _%$%tl179121179185%_
                                                         _%$%hd179122179190%_
                                                         _%$%tl179123179192%_)
                                                  (let ((_%tmp179188%_
                                                         _%$%hd179120179183%_)
                                                        (_%expr179195%_
                                                         _%$%hd179122179190%_))
                                                    (_%$%E179118179141%_))))
                                               (_%__match180796180797%_
                                                (lambda (_%$%hd179120179183%_
                                                         _%$%tl179121179185%_)
                                                  (let ((_%tmp179188%_
                                                         _%$%hd179120179183%_))
                                                    (_%$%E179118179141%_)))))
                                          (if (pair? _%$%hd179114179137%_)
                                              (let ((_%$%tl179133179240%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%hd179114179137%_)))
                                                    (_%$%hd179132179238%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%hd179114179137%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (##eq? _%$%hd179132179238%_
                                                             '#f))
                                                    (if (pair? _%$%tl179133179240%_)
                                                        (let ((_%$%tl179135179245%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%tl179133179240%_)))
                      (_%$%hd179134179243%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%tl179133179240%_))))
                  (if (null? _%$%tl179135179245%_)
                      (let ((_%expr179248%_ _%$%hd179134179243%_))
                        (_%$%K179131179235%_ _%expr179248%_))
                      (if (pair? _%$%tl179135179245%_)
                          (let ((_%$%tl179125179199%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%tl179135179245%_)))
                                (_%$%hd179124179197%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%tl179135179245%_))))
                            (let ((_%tmp179188%_ _%$%hd179132179238%_)
                                  (_%expr179195%_ _%$%hd179134179243%_)
                                  (_%len179202%_ _%$%hd179124179197%_)
                                  (_%init179204%_ _%$%tl179125179199%_))
                              (_%$%K179119179180%_
                               _%init179204%_
                               _%len179202%_
                               _%expr179195%_
                               _%tmp179188%_)))
                          (_%__match180802180803%_
                           _%$%hd179132179238%_
                           _%$%tl179133179240%_
                           _%$%hd179134179243%_
                           _%$%tl179135179245%_))))
                (_%__match180796180797%_
                 _%$%hd179132179238%_
                 _%$%tl179133179240%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (pair? _%$%tl179133179240%_)
                                                        (let ((_%$%tl179130179225%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%tl179133179240%_)))
                      (_%$%hd179129179223%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%tl179133179240%_))))
                  (if (null? _%$%tl179130179225%_)
                      (let ((_%id179221%_ _%$%hd179132179238%_)
                            (_%expr179228%_ _%$%hd179129179223%_))
                        (_%$%K179126179213%_ _%expr179228%_ _%id179221%_))
                      (if (pair? _%$%tl179130179225%_)
                          (let ((_%$%tl179125179199%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%tl179130179225%_)))
                                (_%$%hd179124179197%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%tl179130179225%_))))
                            (let ((_%tmp179188%_ _%$%hd179132179238%_)
                                  (_%expr179195%_ _%$%hd179129179223%_)
                                  (_%len179202%_ _%$%hd179124179197%_)
                                  (_%init179204%_ _%$%tl179125179199%_))
                              (_%$%K179119179180%_
                               _%init179204%_
                               _%len179202%_
                               _%expr179195%_
                               _%tmp179188%_)))
                          (_%__match180802180803%_
                           _%$%hd179132179238%_
                           _%$%tl179133179240%_
                           _%$%hd179129179223%_
                           _%$%tl179130179225%_))))
                (_%__match180796180797%_
                 _%$%hd179132179238%_
                 _%$%tl179133179240%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%E179118179141%_)))))))
                                 (__tmp180941 (list _%body179110%_)))
                             (declare (not safe))
                             (foldl__0
                              __tmp180942
                              __tmp180941
                              _%post179109%_)))
                     _%stx179102%_))))
          (__compile-let-form
           _%stx179102%_
           _%compile-simple179104%_
           _%compile-values179105%_))))
    (define __compile-call%
      (lambda (_%stx179062%_)
        (let* ((_%$e179064%_ _%stx179062%_)
               (_%$%$E179066179075%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e179064%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e179064%_))
              (let* ((_%$%$tgt179067179078%_
                      (let () (declare (not safe)) (__AST-e _%$e179064%_)))
                     (_%$%$hd179068179081%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt179067179078%_)))
                     (_%$%$tl179069179084%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt179067179078%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl179069179084%_))
                    (let* ((_%$%$tgt179070179088%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl179069179084%_)))
                           (_%$%$hd179071179091%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt179070179088%_)))
                           (_%$%$tl179072179094%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt179070179088%_)))
                           (_%rator179098%_ _%$%$hd179071179091%_)
                           (_%rands179100%_ _%$%$tl179072179094%_))
                      (__SRC__%
                       (cons (__compile _%rator179098%_)
                             (map __compile _%rands179100%_))
                       _%stx179062%_))
                    (_%$%$E179066179075%_)))
              (_%$%$E179066179075%_)))))
    (define __compile-ref%
      (lambda (_%stx179024%_)
        (let* ((_%$e179026%_ _%stx179024%_)
               (_%$%$E179028179037%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e179026%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e179026%_))
              (let* ((_%$%$tgt179029179040%_
                      (let () (declare (not safe)) (__AST-e _%$e179026%_)))
                     (_%$%$hd179030179043%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt179029179040%_)))
                     (_%$%$tl179031179046%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt179029179040%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl179031179046%_))
                    (let* ((_%$%$tgt179032179050%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl179031179046%_)))
                           (_%$%$hd179033179053%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt179032179050%_)))
                           (_%$%$tl179034179056%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt179032179050%_)))
                           (_%id179060%_ _%$%$hd179033179053%_))
                      (if (equal? (let ()
                                    (declare (not safe))
                                    (__AST-e _%$%$tl179034179056%_))
                                  '())
                          (__SRC__% _%id179060%_ _%stx179024%_)
                          (_%$%$E179028179037%_)))
                    (_%$%$E179028179037%_)))
              (_%$%$E179028179037%_)))))
    (define __compile-setq%
      (lambda (_%stx178971%_)
        (let* ((_%$e178973%_ _%stx178971%_)
               (_%$%$E178975178987%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e178973%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e178973%_))
              (let* ((_%$%$tgt178976178990%_
                      (let () (declare (not safe)) (__AST-e _%$e178973%_)))
                     (_%$%$hd178977178993%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt178976178990%_)))
                     (_%$%$tl178978178996%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt178976178990%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl178978178996%_))
                    (let* ((_%$%$tgt178979179000%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl178978178996%_)))
                           (_%$%$hd178980179003%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt178979179000%_)))
                           (_%$%$tl178981179006%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt178979179000%_)))
                           (_%id179010%_ _%$%$hd178980179003%_))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$%$tl178981179006%_))
                          (let* ((_%$%$tgt178982179012%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$%$tl178981179006%_)))
                                 (_%$%$hd178983179015%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt178982179012%_)))
                                 (_%$%$tl178984179018%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt178982179012%_)))
                                 (_%expr179022%_ _%$%$hd178983179015%_))
                            (if (equal? (let ()
                                          (declare (not safe))
                                          (__AST-e _%$%$tl178984179018%_))
                                        '())
                                (__SRC__%
                                 (list 'set!
                                       (__SRC__% _%id179010%_ _%stx178971%_)
                                       (__compile _%expr179022%_))
                                 _%stx178971%_)
                                (_%$%$E178975178987%_)))
                          (_%$%$E178975178987%_)))
                    (_%$%$E178975178987%_)))
              (_%$%$E178975178987%_)))))
    (define __compile-if%
      (lambda (_%stx178903%_)
        (let* ((_%$e178905%_ _%stx178903%_)
               (_%$%$E178907178922%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e178905%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e178905%_))
              (let* ((_%$%$tgt178908178925%_
                      (let () (declare (not safe)) (__AST-e _%$e178905%_)))
                     (_%$%$hd178909178928%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt178908178925%_)))
                     (_%$%$tl178910178931%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt178908178925%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl178910178931%_))
                    (let* ((_%$%$tgt178911178935%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl178910178931%_)))
                           (_%$%$hd178912178938%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt178911178935%_)))
                           (_%$%$tl178913178941%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt178911178935%_)))
                           (_%p178945%_ _%$%$hd178912178938%_))
                      (if (let ()
                            (declare (not safe))
                            (__AST-pair? _%$%$tl178913178941%_))
                          (let* ((_%$%$tgt178914178947%_
                                  (let ()
                                    (declare (not safe))
                                    (__AST-e _%$%$tl178913178941%_)))
                                 (_%$%$hd178915178950%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$tgt178914178947%_)))
                                 (_%$%$tl178916178953%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$tgt178914178947%_)))
                                 (_%t178957%_ _%$%$hd178915178950%_))
                            (if (let ()
                                  (declare (not safe))
                                  (__AST-pair? _%$%$tl178916178953%_))
                                (let* ((_%$%$tgt178917178959%_
                                        (let ()
                                          (declare (not safe))
                                          (__AST-e _%$%$tl178916178953%_)))
                                       (_%$%$hd178918178962%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%$tgt178917178959%_)))
                                       (_%$%$tl178919178965%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%$tgt178917178959%_)))
                                       (_%f178969%_ _%$%$hd178918178962%_))
                                  (if (equal? (let ()
                                                (declare (not safe))
                                                (__AST-e _%$%$tl178919178965%_))
                                              '())
                                      (__SRC__%
                                       (list 'if
                                             (__compile _%p178945%_)
                                             (__compile _%t178957%_)
                                             (__compile _%f178969%_))
                                       _%stx178903%_)
                                      (_%$%$E178907178922%_)))
                                (_%$%$E178907178922%_)))
                          (_%$%$E178907178922%_)))
                    (_%$%$E178907178922%_)))
              (_%$%$E178907178922%_)))))
    (define __compile-quote%
      (lambda (_%stx178865%_)
        (let* ((_%$e178867%_ _%stx178865%_)
               (_%$%$E178869178878%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e178867%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e178867%_))
              (let* ((_%$%$tgt178870178881%_
                      (let () (declare (not safe)) (__AST-e _%$e178867%_)))
                     (_%$%$hd178871178884%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt178870178881%_)))
                     (_%$%$tl178872178887%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt178870178881%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl178872178887%_))
                    (let* ((_%$%$tgt178873178891%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl178872178887%_)))
                           (_%$%$hd178874178894%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt178873178891%_)))
                           (_%$%$tl178875178897%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt178873178891%_)))
                           (_%e178901%_ _%$%$hd178874178894%_))
                      (if (equal? (let ()
                                    (declare (not safe))
                                    (__AST-e _%$%$tl178875178897%_))
                                  '())
                          (__SRC__%
                           (list 'quote
                                 (let ()
                                   (declare (not safe))
                                   (__AST->datum _%e178901%_)))
                           _%stx178865%_)
                          (_%$%$E178869178878%_)))
                    (_%$%$E178869178878%_)))
              (_%$%$E178869178878%_)))))
    (define __compile-quote-syntax%
      (lambda (_%stx178827%_)
        (let* ((_%$e178829%_ _%stx178827%_)
               (_%$%$E178831178840%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (__raise-syntax-error
                     '#f
                     '"Bad syntax; malformed ast clause"
                     _%$e178829%_)))))
          (if (let () (declare (not safe)) (__AST-pair? _%$e178829%_))
              (let* ((_%$%$tgt178832178843%_
                      (let () (declare (not safe)) (__AST-e _%$e178829%_)))
                     (_%$%$hd178833178846%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%$tgt178832178843%_)))
                     (_%$%$tl178834178849%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%$tgt178832178843%_))))
                (if (let ()
                      (declare (not safe))
                      (__AST-pair? _%$%$tl178834178849%_))
                    (let* ((_%$%$tgt178835178853%_
                            (let ()
                              (declare (not safe))
                              (__AST-e _%$%$tl178834178849%_)))
                           (_%$%$hd178836178856%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%$tgt178835178853%_)))
                           (_%$%$tl178837178859%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%$tgt178835178853%_)))
                           (_%e178863%_ _%$%$hd178836178856%_))
                      (if (equal? (let ()
                                    (declare (not safe))
                                    (__AST-e _%$%$tl178837178859%_))
                                  '())
                          (__SRC__% (list 'quote _%e178863%_) _%stx178827%_)
                          (_%$%$E178831178840%_)))
                    (_%$%$E178831178840%_)))
              (_%$%$E178831178840%_)))))
    (__core-bind-syntax!__% '%#begin __compile-begin% make-__core-special-form)
    (__core-bind-syntax!__%
     '%#begin-syntax
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#begin-foreign
     __compile-begin-foreign%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#module
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#import
     __compile-import%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#export
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#provide
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#define-values
     __compile-define-values%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#define-syntax
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#define-alias
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#define-runtime
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#extern
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#declare
     __compile-ignore%
     make-__core-special-form)
    (__core-bind-syntax!__%
     '%#begin-annotation
     __compile-begin-annotation%
     make-__core-expression)
    (__core-bind-syntax!__% '%#quote __compile-quote% make-__core-expression)
    (__core-bind-syntax!__%
     '%#quote-syntax
     __compile-quote-syntax%
     make-__core-expression)
    (__core-bind-syntax!__% '%#lambda __compile-lambda% make-__core-expression)
    (__core-bind-syntax!__%
     '%#case-lambda
     __compile-case-lambda%
     make-__core-expression)
    (__core-bind-syntax!__%
     '%#let-values
     __compile-let-values%
     make-__core-expression)
    (__core-bind-syntax!__%
     '%#letrec-values
     __compile-letrec-values%
     make-__core-expression)
    (__core-bind-syntax!__%
     '%#letrec*-values
     __compile-letrec*-values%
     make-__core-expression)
    (__core-bind-syntax!__% '%#call __compile-call% make-__core-expression)
    (__core-bind-syntax!__% '%#if __compile-if% make-__core-expression)
    (__core-bind-syntax!__% '%#ref __compile-ref% make-__core-expression)
    (__core-bind-syntax!__% '%#set! __compile-setq% make-__core-expression)
    (__core-bind-syntax!__% '%#cond-expand __compile-error make-__core-form)
    (__core-bind-syntax!__% '%#include __compile-error make-__core-form)
    (__core-bind-syntax!__% '%#let-syntax __compile-error make-__core-form)
    (__core-bind-syntax!__%
     '%#letrec-syntax
     __compile-error
     make-__core-form)))
