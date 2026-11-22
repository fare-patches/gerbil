(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/compile::timestamp 1795039817)
  (begin
    (define gxc#gambit-annotations
      '(not gambit-scheme
            ieee-scheme
            r4rs-scheme
            r5rs-scheme
            block
            separate
            core
            inline
            inline-primitives
            inlining-limit
            constant-fold
            lambda-lift
            standard-bindings
            extended-bindings
            run-time-bindings
            safe
            interrupts-enabled
            poll-on-return
            proper-tail-calls
            generative-lambda
            optimize-dead-local-variables
            optimize-dead-definitions
            generic
            fixnum
            flonum
            mostly-fixnum
            mostly-flonum
            mostly-fixnum-flonum
            debug
            debug-location
            debug-source
            debug-environments))
    (define gxc#checked-primitives
      '(##direct-structure-ref
        ##direct-structure-set!
        ##structure-ref
        ##structure-set!))
    (define gxc#::collect-bindings::t
      (let ((__tmp218187 (list gxc#::void::t))
            (__tmp218186 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::collect-bindings::t
         '::collect-bindings
         __tmp218187
         '()
         __tmp218186
         '#f)))
    (define gxc#::collect-bindings?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::collect-bindings::t)))
    (define gxc#make-::collect-bindings
      (lambda _%$args216801%_
        (apply make-instance gxc#::collect-bindings::t _%$args216801%_)))
    (define gxc#::collect-bindings-bind-methods!
      (let ((__tmp218188
             (lambda ()
               (force gxc#::void-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-bindings::t
                  '%#begin
                  gxc#apply-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-bindings::t
                  '%#begin-syntax
                  gxc#apply-begin-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-bindings::t
                  '%#module
                  gxc#apply-module%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-bindings::t
                  '%#define-values
                  gxc#collect-bindings-define-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-bindings::t
                  '%#define-syntax
                  gxc#collect-bindings-define-syntax%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::collect-bindings::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218188)))
    (define gxc#apply-collect-bindings
      (lambda (_%stx216793%_)
        (force gxc#::collect-bindings-bind-methods!)
        (let* ((_%self216796%_
                (let ((__obj218162
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::collect-bindings::t))))
                  __obj218162))
               (__tmp218189
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self216796%_ _%stx216793%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp218189
           gxc#current-compile-method
           _%self216796%_))))
    (define gxc#::lift-modules::t
      (let ((__tmp218191 (list gxc#::void::t))
            (__tmp218190 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::lift-modules::t
         '::lift-modules
         __tmp218191
         '(modules)
         __tmp218190
         '#f)))
    (define gxc#::lift-modules?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::lift-modules::t)))
    (define gxc#make-::lift-modules
      (lambda _%$args216790%_
        (apply make-instance gxc#::lift-modules::t _%$args216790%_)))
    (define gxc#::lift-modules-modules
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::lift-modules::t 'modules)))
    (define gxc#::lift-modules-modules-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::lift-modules::t 'modules)))
    (define gxc#&::lift-modules-modules
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#::lift-modules::t 'modules)))
    (define gxc#&::lift-modules-modules-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#::lift-modules::t 'modules)))
    (define gxc#::lift-modules-bind-methods!
      (let ((__tmp218192
             (lambda ()
               (force gxc#::void-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::lift-modules::t
                  '%#begin
                  gxc#apply-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::lift-modules::t
                  '%#module
                  gxc#lift-modules-module%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::lift-modules::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218192)))
    (define gxc#apply-lift-modules__%
      (lambda (_%@@keywords216765%_ _%$%modules216762216766%_ _%stx216767%_)
        (let ((_%modules216770%_
               (if (eq? _%$%modules216762216766%_ absent-value)
                   (let ()
                     (declare (not safe))
                     (error '"Missing required keyword argument" 'modules:))
                   _%$%modules216762216766%_)))
          (force gxc#::lift-modules-bind-methods!)
          (let* ((_%self216772%_
                  (let ((__obj218164
                         (let ()
                           (declare (not safe))
                           (##structure gxc#::lift-modules::t '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj218164
                       _%modules216770%_
                       '1
                       '#f
                       '#f))
                    __obj218164))
                 (__tmp218193
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self216772%_ _%stx216767%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp218193
             gxc#current-compile-method
             _%self216772%_)))))
    (define gxc#apply-lift-modules__@
      (lambda (_%@@keywords216779%_ . _%args216780%_)
        (apply gxc#apply-lift-modules__%
               _%@@keywords216779%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords216779%_
                  'modules:
                  absent-value))
               _%args216780%_)))
    (define gxc#apply-lift-modules
      (lambda _%$%args216763216786%_
        (apply keyword-dispatch
               '#(modules:)
               gxc#apply-lift-modules__@
               _%$%args216763216786%_)))
    (define gxc#::find-runtime-code::t
      (let ((__tmp218195 (list)) (__tmp218194 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::find-runtime-code::t
         '::find-runtime-code
         __tmp218195
         '()
         __tmp218194
         '#f)))
    (define gxc#::find-runtime-code?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::find-runtime-code::t)))
    (define gxc#make-::find-runtime-code
      (lambda _%$args216758%_
        (apply make-instance gxc#::find-runtime-code::t _%$args216758%_)))
    (define gxc#::find-runtime-code-bind-methods!
      (let ((__tmp218196
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#begin
                  gxc#find-runtime-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#begin-syntax
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#begin-foreign
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#begin-annotation
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#module
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#import
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#export
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#provide
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#extern
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#define-values
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#define-syntax
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#define-alias
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#declare
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#lambda
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#case-lambda
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#let-values
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#letrec-values
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#letrec*-values
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#quote
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#call
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#call-unchecked
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#if
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#ref
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#set!
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#struct-instance?
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#struct-direct-instance?
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#struct-ref
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#struct-set!
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#struct-direct-ref
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#struct-direct-set!
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#struct-unchecked-ref
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-runtime-code::t
                  '%#struct-unchecked-set!
                  gxc#true-method))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::find-runtime-code::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218196)))
    (define gxc#apply-find-runtime-code
      (lambda (_%stx216750%_)
        (force gxc#::find-runtime-code-bind-methods!)
        (let* ((_%self216753%_
                (let ((__obj218166
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::find-runtime-code::t))))
                  __obj218166))
               (__tmp218197
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self216753%_ _%stx216750%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp218197
           gxc#current-compile-method
           _%self216753%_))))
    (define gxc#::find-lambda-expression::t
      (let ((__tmp218199 (list gxc#::false::t))
            (__tmp218198 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::find-lambda-expression::t
         '::find-lambda-expression
         __tmp218199
         '()
         __tmp218198
         '#f)))
    (define gxc#::find-lambda-expression?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::find-lambda-expression::t)))
    (define gxc#make-::find-lambda-expression
      (lambda _%$args216747%_
        (apply make-instance gxc#::find-lambda-expression::t _%$args216747%_)))
    (define gxc#::find-lambda-expression-bind-methods!
      (let ((__tmp218200
             (lambda ()
               (force gxc#::false-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-lambda-expression::t
                  '%#begin
                  gxc#apply-last-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-lambda-expression::t
                  '%#begin-annotation
                  gxc#apply-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-lambda-expression::t
                  '%#lambda
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-lambda-expression::t
                  '%#case-lambda
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-lambda-expression::t
                  '%#let-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-lambda-expression::t
                  '%#letrec-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-lambda-expression::t
                  '%#letrec*-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::find-lambda-expression::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218200)))
    (define gxc#apply-find-lambda-expression
      (lambda (_%stx216739%_)
        (force gxc#::find-lambda-expression-bind-methods!)
        (let* ((_%self216742%_
                (let ((__obj218168
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::find-lambda-expression::t))))
                  __obj218168))
               (__tmp218201
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self216742%_ _%stx216739%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp218201
           gxc#current-compile-method
           _%self216742%_))))
    (define gxc#::count-values::t
      (let ((__tmp218203 (list gxc#::false-expression::t))
            (__tmp218202 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::count-values::t
         '::count-values
         __tmp218203
         '()
         __tmp218202
         '#f)))
    (define gxc#::count-values?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::count-values::t)))
    (define gxc#make-::count-values
      (lambda _%$args216736%_
        (apply make-instance gxc#::count-values::t _%$args216736%_)))
    (define gxc#::count-values-bind-methods!
      (let ((__tmp218204
             (lambda ()
               (force gxc#::false-expression-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#begin
                  gxc#apply-last-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#begin-annotation
                  gxc#apply-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#lambda
                  gxc#count-values-single%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#case-lambda
                  gxc#count-values-single%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#let-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#letrec-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#letrec*-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#quote
                  gxc#count-values-single%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#call
                  gxc#count-values-call%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#call-unchecked
                  gxc#count-values-call%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::count-values::t
                  '%#if
                  gxc#count-values-if%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::count-values::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218204)))
    (define gxc#apply-count-values
      (lambda (_%stx216728%_)
        (force gxc#::count-values-bind-methods!)
        (let* ((_%self216731%_
                (let ((__obj218170
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::count-values::t))))
                  __obj218170))
               (__tmp218205
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self216731%_ _%stx216728%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp218205
           gxc#current-compile-method
           _%self216731%_))))
    (define gxc#::generate-runtime-empty::t
      (let ((__tmp218206 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::generate-runtime-empty::t
         '::generate-runtime-empty
         __tmp218206
         '()
         '()
         '#f)))
    (define gxc#::generate-runtime-empty?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::generate-runtime-empty::t)))
    (define gxc#make-::generate-runtime-empty
      (lambda _%$args216725%_
        (apply make-instance gxc#::generate-runtime-empty::t _%$args216725%_)))
    (define gxc#::generate-runtime-empty-bind-methods!
      (let ((__tmp218207
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#begin
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#begin-syntax
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#begin-foreign
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#begin-annotation
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#module
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#import
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#export
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#provide
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#extern
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#define-values
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#define-syntax
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#define-alias
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#define-runtime
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#declare
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#lambda
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#case-lambda
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#let-values
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#letrec-values
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#letrec*-values
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#quote
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#call
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#call-unchecked
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#if
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#ref
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#set!
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#struct-instance?
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#struct-direct-instance?
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#struct-ref
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#struct-set!
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#struct-direct-ref
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#struct-direct-set!
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#struct-unchecked-ref
                  gxc#generate-runtime-empty))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-empty::t
                  '%#struct-unchecked-set!
                  gxc#generate-runtime-empty)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218207)))
    (define gxc#::generate-loader::t
      (let ((__tmp218209 (list gxc#::generate-runtime-empty::t))
            (__tmp218208 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::generate-loader::t
         '::generate-loader
         __tmp218209
         '()
         __tmp218208
         '#f)))
    (define gxc#::generate-loader?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::generate-loader::t)))
    (define gxc#make-::generate-loader
      (lambda _%$args216721%_
        (apply make-instance gxc#::generate-loader::t _%$args216721%_)))
    (define gxc#::generate-loader-bind-methods!
      (let ((__tmp218210
             (lambda ()
               (force gxc#::generate-runtime-empty-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-loader::t
                  '%#begin
                  gxc#generate-runtime-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-loader::t
                  '%#import
                  gxc#generate-runtime-loader-import%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::generate-loader::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218210)))
    (define gxc#apply-generate-loader
      (lambda (_%stx216713%_)
        (force gxc#::generate-loader-bind-methods!)
        (let* ((_%self216716%_
                (let ((__obj218173
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::generate-loader::t))))
                  __obj218173))
               (__tmp218211
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self216716%_ _%stx216713%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp218211
           gxc#current-compile-method
           _%self216716%_))))
    (define gxc#::generate-runtime::t
      (let ((__tmp218212 (list gxc#::generate-runtime-empty::t)))
        (declare (not safe))
        (make-class-type
         'gxc#::generate-runtime::t
         '::generate-runtime
         __tmp218212
         '()
         '()
         '#f)))
    (define gxc#::generate-runtime?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::generate-runtime::t)))
    (define gxc#make-::generate-runtime
      (lambda _%$args216710%_
        (apply make-instance gxc#::generate-runtime::t _%$args216710%_)))
    (define gxc#::generate-runtime-bind-methods!
      (let ((__tmp218213
             (lambda ()
               (force gxc#::generate-runtime-empty-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#begin
                  gxc#generate-runtime-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#begin-foreign
                  gxc#generate-runtime-begin-foreign%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#begin-annotation
                  gxc#generate-runtime-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#define-values
                  gxc#generate-runtime-define-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#declare
                  gxc#generate-runtime-declare%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#lambda
                  gxc#generate-runtime-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#case-lambda
                  gxc#generate-runtime-case-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#let-values
                  gxc#generate-runtime-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#letrec-values
                  gxc#generate-runtime-letrec-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#letrec*-values
                  gxc#generate-runtime-letrec*-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#quote
                  gxc#generate-runtime-quote%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#quote-syntax
                  gxc#generate-runtime-quote-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#call
                  gxc#generate-runtime-call%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#call-unchecked
                  gxc#generate-runtime-call-unchecked%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#if
                  gxc#generate-runtime-if%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#ref
                  gxc#generate-runtime-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#set!
                  gxc#generate-runtime-setq%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#struct-instance?
                  gxc#generate-runtime-struct-instancep%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#struct-direct-instance?
                  gxc#generate-runtime-struct-direct-instancep%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#struct-ref
                  gxc#generate-runtime-struct-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#struct-set!
                  gxc#generate-runtime-struct-setq%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#struct-direct-ref
                  gxc#generate-runtime-struct-direct-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#struct-direct-set!
                  gxc#generate-runtime-struct-direct-setq%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#struct-unchecked-ref
                  gxc#generate-runtime-struct-unchecked-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime::t
                  '%#struct-unchecked-set!
                  gxc#generate-runtime-struct-unchecked-setq%)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218213)))
    (define gxc#apply-generate-runtime
      (lambda (_%stx216702%_)
        (force gxc#::generate-runtime-bind-methods!)
        (let* ((_%self216705%_
                (let ((__obj218175
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::generate-runtime::t))))
                  __obj218175))
               (__tmp218214
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self216705%_ _%stx216702%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp218214
           gxc#current-compile-method
           _%self216705%_))))
    (define gxc#::generate-runtime-phi::t
      (let ((__tmp218216 (list gxc#::generate-runtime::t))
            (__tmp218215 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::generate-runtime-phi::t
         '::generate-runtime-phi
         __tmp218216
         '()
         __tmp218215
         '#f)))
    (define gxc#::generate-runtime-phi?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::generate-runtime-phi::t)))
    (define gxc#make-::generate-runtime-phi
      (lambda _%$args216699%_
        (apply make-instance gxc#::generate-runtime-phi::t _%$args216699%_)))
    (define gxc#::generate-runtime-phi-bind-methods!
      (let ((__tmp218217
             (lambda ()
               (force gxc#::generate-runtime-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-runtime-phi::t
                  '%#define-runtime
                  gxc#generate-runtime-phi-define-runtime%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::generate-runtime-phi::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218217)))
    (define gxc#apply-generate-runtime-phi
      (lambda (_%stx216691%_)
        (force gxc#::generate-runtime-phi-bind-methods!)
        (let* ((_%self216694%_
                (let ((__obj218177
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::generate-runtime-phi::t))))
                  __obj218177))
               (__tmp218218
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self216694%_ _%stx216691%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp218218
           gxc#current-compile-method
           _%self216694%_))))
    (define gxc#::collect-expression-refs::t
      (let ((__tmp218219 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::collect-expression-refs::t
         '::collect-expression-refs
         __tmp218219
         '(table)
         '()
         '#f)))
    (define gxc#::collect-expression-refs?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::collect-expression-refs::t)))
    (define gxc#make-::collect-expression-refs
      (lambda _%$args216688%_
        (apply make-instance
               gxc#::collect-expression-refs::t
               _%$args216688%_)))
    (define gxc#::collect-expression-refs-table
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::collect-expression-refs::t 'table)))
    (define gxc#::collect-expression-refs-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::collect-expression-refs::t 'table)))
    (define gxc#&::collect-expression-refs-table
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::collect-expression-refs::t
         'table)))
    (define gxc#&::collect-expression-refs-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::collect-expression-refs::t
         'table)))
    (define gxc#::collect-expression-refs-bind-methods!
      (let ((__tmp218220
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#begin
                  gxc#apply-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#begin-annotation
                  gxc#apply-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#lambda
                  gxc#apply-body-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#case-lambda
                  gxc#apply-body-case-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#let-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#letrec-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#letrec*-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#quote
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#quote-syntax
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#call
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#call-unchecked
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#if
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#ref
                  gxc#collect-refs-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#set!
                  gxc#collect-refs-setq%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#struct-instance?
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#struct-direct-instance?
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#struct-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#struct-set!
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#struct-direct-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#struct-direct-set!
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#struct-unchecked-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-expression-refs::t
                  '%#struct-unchecked-set!
                  gxc#apply-operands)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218220)))
    (define gxc#apply-collect-expression-refs__%
      (lambda (_%@@keywords216663%_ _%$%table216660216664%_ _%stx216665%_)
        (let ((_%table216668%_
               (if (eq? _%$%table216660216664%_ absent-value)
                   (let ()
                     (declare (not safe))
                     (error '"Missing required keyword argument" 'table:))
                   _%$%table216660216664%_)))
          (force gxc#::collect-expression-refs-bind-methods!)
          (let* ((_%self216670%_
                  (let ((__obj218179
                         (let ()
                           (declare (not safe))
                           (##structure
                            gxc#::collect-expression-refs::t
                            '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj218179
                       _%table216668%_
                       '1
                       '#f
                       '#f))
                    __obj218179))
                 (__tmp218221
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self216670%_ _%stx216665%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp218221
             gxc#current-compile-method
             _%self216670%_)))))
    (define gxc#apply-collect-expression-refs__@
      (lambda (_%@@keywords216677%_ . _%args216678%_)
        (apply gxc#apply-collect-expression-refs__%
               _%@@keywords216677%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords216677%_
                  'table:
                  absent-value))
               _%args216678%_)))
    (define gxc#apply-collect-expression-refs
      (lambda _%$%args216661216684%_
        (apply keyword-dispatch
               '#(table:)
               gxc#apply-collect-expression-refs__@
               _%$%args216661216684%_)))
    (define gxc#::generate-meta::t
      (let ((__tmp218223 (list gxc#::void-expression::t))
            (__tmp218222 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::generate-meta::t
         '::generate-meta
         __tmp218223
         '(state)
         __tmp218222
         '#f)))
    (define gxc#::generate-meta?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::generate-meta::t)))
    (define gxc#make-::generate-meta
      (lambda _%$args216656%_
        (apply make-instance gxc#::generate-meta::t _%$args216656%_)))
    (define gxc#::generate-meta-state
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::generate-meta::t 'state)))
    (define gxc#::generate-meta-state-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::generate-meta::t 'state)))
    (define gxc#&::generate-meta-state
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#::generate-meta::t 'state)))
    (define gxc#&::generate-meta-state-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#::generate-meta::t 'state)))
    (define gxc#::generate-meta-bind-methods!
      (let ((__tmp218224
             (lambda ()
               (force gxc#::void-expression-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#begin
                  gxc#generate-meta-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#begin-syntax
                  gxc#generate-meta-begin-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#module
                  gxc#generate-meta-module%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#import
                  gxc#generate-meta-import%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#export
                  gxc#generate-meta-export%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#provide
                  gxc#generate-meta-provide%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#extern
                  gxc#generate-meta-extern%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#define-values
                  gxc#generate-meta-define-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#define-syntax
                  gxc#generate-meta-define-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#define-alias
                  gxc#generate-meta-define-alias%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#define-runtime
                  gxc#generate-meta-define-runtime%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#begin-foreign
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta::t
                  '%#declare
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::generate-meta::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218224)))
    (define gxc#apply-generate-meta__%
      (lambda (_%@@keywords216631%_ _%$%state216628216632%_ _%stx216633%_)
        (let ((_%state216636%_
               (if (eq? _%$%state216628216632%_ absent-value)
                   (let ()
                     (declare (not safe))
                     (error '"Missing required keyword argument" 'state:))
                   _%$%state216628216632%_)))
          (force gxc#::generate-meta-bind-methods!)
          (let* ((_%self216638%_
                  (let ((__obj218181
                         (let ()
                           (declare (not safe))
                           (##structure gxc#::generate-meta::t '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj218181
                       _%state216636%_
                       '1
                       '#f
                       '#f))
                    __obj218181))
                 (__tmp218225
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self216638%_ _%stx216633%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp218225
             gxc#current-compile-method
             _%self216638%_)))))
    (define gxc#apply-generate-meta__@
      (lambda (_%@@keywords216645%_ . _%args216646%_)
        (apply gxc#apply-generate-meta__%
               _%@@keywords216645%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords216645%_
                  'state:
                  absent-value))
               _%args216646%_)))
    (define gxc#apply-generate-meta
      (lambda _%$%args216629216652%_
        (apply keyword-dispatch
               '#(state:)
               gxc#apply-generate-meta__@
               _%$%args216629216652%_)))
    (define gxc#::generate-meta-phi::t
      (let ((__tmp218227 (list)) (__tmp218226 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::generate-meta-phi::t
         '::generate-meta-phi
         __tmp218227
         '(state)
         __tmp218226
         '#f)))
    (define gxc#::generate-meta-phi?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::generate-meta-phi::t)))
    (define gxc#make-::generate-meta-phi
      (lambda _%$args216624%_
        (apply make-instance gxc#::generate-meta-phi::t _%$args216624%_)))
    (define gxc#::generate-meta-phi-state
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::generate-meta-phi::t 'state)))
    (define gxc#::generate-meta-phi-state-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::generate-meta-phi::t 'state)))
    (define gxc#&::generate-meta-phi-state
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::generate-meta-phi::t
         'state)))
    (define gxc#&::generate-meta-phi-state-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::generate-meta-phi::t
         'state)))
    (define gxc#::generate-meta-phi-bind-methods!
      (let ((__tmp218228
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#begin
                  gxc#generate-meta-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#begin-syntax
                  gxc#generate-meta-begin-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#define-syntax
                  gxc#generate-meta-define-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#define-alias
                  gxc#generate-meta-define-alias%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#define-values
                  gxc#generate-meta-phi-define-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#begin-annotation
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#lambda
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#case-lambda
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#let-values
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#letrec-values
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#letrec*-values
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#quote
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#quote-syntax
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#call
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#call-unchecked
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#if
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#ref
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#set!
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#struct-instance?
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#struct-direct-instance?
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#struct-ref
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#struct-set!
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#struct-direct-ref
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#struct-direct-set!
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#struct-unchecked-ref
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#struct-unchecked-set!
                  gxc#generate-meta-phi-expr))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-meta-phi::t
                  '%#declare
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::generate-meta-phi::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp218228)))
    (define gxc#apply-generate-meta-phi__%
      (lambda (_%@@keywords216599%_ _%$%state216596216600%_ _%stx216601%_)
        (let ((_%state216604%_
               (if (eq? _%$%state216596216600%_ absent-value)
                   (let ()
                     (declare (not safe))
                     (error '"Missing required keyword argument" 'state:))
                   _%$%state216596216600%_)))
          (force gxc#::generate-meta-phi-bind-methods!)
          (let* ((_%self216606%_
                  (let ((__obj218183
                         (let ()
                           (declare (not safe))
                           (##structure gxc#::generate-meta-phi::t '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj218183
                       _%state216604%_
                       '1
                       '#f
                       '#f))
                    __obj218183))
                 (__tmp218229
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self216606%_ _%stx216601%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp218229
             gxc#current-compile-method
             _%self216606%_)))))
    (define gxc#apply-generate-meta-phi__@
      (lambda (_%@@keywords216613%_ . _%args216614%_)
        (apply gxc#apply-generate-meta-phi__%
               _%@@keywords216613%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords216613%_
                  'state:
                  absent-value))
               _%args216614%_)))
    (define gxc#apply-generate-meta-phi
      (lambda _%$%args216597216620%_
        (apply keyword-dispatch
               '#(state:)
               gxc#apply-generate-meta-phi__@
               _%$%args216597216620%_)))
    (define gxc#collect-bindings-define-values%
      (lambda (_%self216525%_ _%stx216526%_)
        (let* ((_%$%g216528216545%_
                (lambda (_%$%g216529216542%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g216529216542%_))))
               (_%$%g216527216592%_
                (lambda (_%$%g216529216548%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g216529216548%_))
                      (let ((_%$%e216532216550%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g216529216548%_))))
                        (let ((_%$%hd216533216553%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e216532216550%_)))
                              (_%$%tl216534216555%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e216532216550%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl216534216555%_))
                              (let ((_%$%e216535216558%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl216534216555%_))))
                                (let ((_%$%hd216536216561%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e216535216558%_)))
                                      (_%$%tl216537216563%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e216535216558%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl216537216563%_))
                                      (let ((_%$%e216538216566%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl216537216563%_))))
                                        (let ((_%$%hd216539216569%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e216538216566%_)))
                                              (_%$%tl216540216571%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e216538216566%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl216540216571%_))
                                              (let ((__tmp218230
                                                     (lambda (_%bind216590%_)
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#identifier?
                                                              _%bind216590%_))
                                                           (gxc#add-module-binding!
                                                            _%bind216590%_
                                                            '#f)
                                                           '#!void))))
                                                (declare (not safe))
                                                (gx#stx-for-each1
                                                 __tmp218230
                                                 _%$%hd216536216561%_))
                                              (_%$%g216528216545%_
                                               _%$%g216529216548%_))))
                                      (_%$%g216528216545%_
                                       _%$%g216529216548%_))))
                              (_%$%g216528216545%_ _%$%g216529216548%_))))
                      (_%$%g216528216545%_ _%$%g216529216548%_)))))
          (_%$%g216527216592%_ _%stx216526%_))))
    (define gxc#collect-bindings-define-syntax%
      (lambda (_%self216457%_ _%stx216458%_)
        (let* ((_%$%g216460216477%_
                (lambda (_%$%g216461216474%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g216461216474%_))))
               (_%$%g216459216522%_
                (lambda (_%$%g216461216480%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g216461216480%_))
                      (let ((_%$%e216464216482%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g216461216480%_))))
                        (let ((_%$%hd216465216485%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e216464216482%_)))
                              (_%$%tl216466216487%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e216464216482%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl216466216487%_))
                              (let ((_%$%e216467216490%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl216466216487%_))))
                                (let ((_%$%hd216468216493%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e216467216490%_)))
                                      (_%$%tl216469216495%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e216467216490%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl216469216495%_))
                                      (let ((_%$%e216470216498%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl216469216495%_))))
                                        (let ((_%$%hd216471216501%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e216470216498%_)))
                                              (_%$%tl216472216503%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e216470216498%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl216472216503%_))
                                              (gxc#add-module-binding!
                                               _%$%hd216468216493%_
                                               '#t)
                                              (_%$%g216460216477%_
                                               _%$%g216461216480%_))))
                                      (_%$%g216460216477%_
                                       _%$%g216461216480%_))))
                              (_%$%g216460216477%_ _%$%g216461216480%_))))
                      (_%$%g216460216477%_ _%$%g216461216480%_)))))
          (_%$%g216459216522%_ _%stx216458%_))))
    (define gxc#lift-modules-module%
      (lambda (_%self216399%_ _%stx216400%_)
        (let* ((_%$%g216402216416%_
                (lambda (_%$%g216403216413%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g216403216413%_))))
               (_%$%g216401216454%_
                (lambda (_%$%g216403216419%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g216403216419%_))
                      (let ((_%$%e216406216421%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g216403216419%_))))
                        (let ((_%$%hd216407216424%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e216406216421%_)))
                              (_%$%tl216408216426%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e216406216421%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl216408216426%_))
                              (let ((_%$%e216409216429%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl216408216426%_))))
                                (let ((_%$%hd216410216432%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e216409216429%_)))
                                      (_%$%tl216411216434%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e216409216429%_))))
                                  (let ((_%ctx216451%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#syntax-local-e__0
                                            _%$%hd216410216432%_))))
                                    (set-box!
                                     (let ()
                                       (declare (not safe))
                                       (slot-ref__0 _%self216399%_ 'modules))
                                     (cons _%ctx216451%_
                                           (unbox (let ()
                                                    (declare (not safe))
                                                    (slot-ref__0
                                                     _%self216399%_
                                                     'modules)))))
                                    (let ((__tmp218231
                                           (lambda ()
                                             (let ((__tmp218232
                                                    (##structure-ref
                                                     _%ctx216451%_
                                                     '11
                                                     gx#module-context::t
                                                     '#f)))
                                               (declare (not safe))
                                               (gxc#compile-e__1
                                                _%self216399%_
                                                __tmp218232)))))
                                      (declare (not safe))
                                      (call-with-parameters__1
                                       __tmp218231
                                       gx#current-expander-context
                                       _%ctx216451%_)))))
                              (_%$%g216402216416%_ _%$%g216403216419%_))))
                      (_%$%g216402216416%_ _%$%g216403216419%_)))))
          (_%$%g216401216454%_ _%stx216400%_))))
    (define gxc#current-compile-decls-unsafe?
      (lambda ()
        (let ((_%$%decls216353216355%_
               (let () (declare (not safe)) (gxc#current-compile-decls))))
          (if _%$%decls216353216355%_
              (let ((_%decls216357%_ _%$%decls216353216355%_))
                (let _%lp216359%_ ((_%rest216361%_ _%decls216357%_))
                  (let* ((_%$%rest216362216370%_ _%rest216361%_)
                         (_%$%else216364216378%_ (lambda () '#f))
                         (_%$%K216366216387%_
                          (lambda (_%decls216381%_ _%decl216382%_)
                            (if (equal? _%decl216382%_ '(not safe))
                                '#t
                                (if (equal? _%decl216382%_ '(safe))
                                    '#f
                                    (_%lp216359%_ _%decls216381%_))))))
                    (if (pair? _%$%rest216362216370%_)
                        (let ((_%$%hd216367216390%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%rest216362216370%_)))
                              (_%$%tl216368216392%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%rest216362216370%_))))
                          (let* ((_%decl216395%_ _%$%hd216367216390%_)
                                 (_%decls216397%_ _%$%tl216368216392%_))
                            (_%$%K216366216387%_
                             _%decls216397%_
                             _%decl216395%_)))
                        (_%$%else216364216378%_)))))
              '#f))))
    (define gxc#add-module-binding!
      (lambda (_%id216347%_ _%syntax?216348%_)
        (let ((_%eid216350%_
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gx#resolve-identifier__0 _%id216347%_))
                '1
                gx#binding::t
                '#f))
              (_%ht216351%_
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gxc#current-compile-symbol-table))
                '2
                gxc#symbol-table::t
                '#f)))
          (if (let () (declare (not safe)) (interned-symbol? _%eid216350%_))
              '#!void
              (let ((__tmp218233
                     (let ((__tmp218234
                            (let ()
                              (declare (not safe))
                              (gxc#generate-runtime-gensym-reference__0
                               _%eid216350%_))))
                       (declare (not safe))
                       (gx#make-binding-id__1 __tmp218234 _%syntax?216348%_))))
                (declare (not safe))
                (hash-put! _%ht216351%_ _%eid216350%_ __tmp218233))))))
    (define gxc#generate-runtime-empty
      (lambda (_%self216344%_ _%stx216345%_) '(begin)))
    (define gxc#generate-runtime-begin%
      (lambda (_%self216191%_ _%stx216192%_)
        (letrec ((_%simplify216194%_
                  (lambda (_%body216242%_)
                    (let _%lp216244%_ ((_%rest216246%_ _%body216242%_)
                                       (_%r216247%_ '()))
                      (let* ((_%$%rest216248216256%_ _%rest216246%_)
                             (_%$%else216250216264%_
                              (lambda () (reverse _%r216247%_)))
                             (_%$%K216252216332%_
                              (lambda (_%rest216267%_ _%hd216268%_)
                                (let* ((_%$%hd216269216285%_ _%hd216268%_)
                                       (_%$%else216273216293%_
                                        (lambda ()
                                          (_%lp216244%_
                                           _%rest216267%_
                                           (cons _%hd216268%_ _%r216247%_)))))
                                  (let ((_%$%K216281216322%_
                                         (lambda (_%exprs216320%_)
                                           (_%lp216244%_
                                            (append _%exprs216320%_
                                                    _%rest216267%_)
                                            _%r216247%_)))
                                        (_%$%K216276216306%_
                                         (lambda ()
                                           (if (null? _%rest216267%_)
                                               (_%lp216244%_
                                                _%rest216267%_
                                                (cons _%hd216268%_
                                                      _%r216247%_))
                                               (_%lp216244%_
                                                _%rest216267%_
                                                _%r216247%_))))
                                        (_%$%K216275216298%_
                                         (lambda ()
                                           (if (null? _%rest216267%_)
                                               (_%lp216244%_
                                                _%rest216267%_
                                                (cons _%hd216268%_
                                                      _%r216247%_))
                                               (_%lp216244%_
                                                _%rest216267%_
                                                _%r216247%_)))))
                                    (let ((_%$%try-match216272216301%_
                                           (lambda ()
                                             (if (symbol? _%$%hd216269216285%_)
                                                 (_%$%K216275216298%_)
                                                 (_%$%else216273216293%_)))))
                                      (if (pair? _%$%hd216269216285%_)
                                          (let ((_%$%tl216283216327%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%hd216269216285%_)))
                                                (_%$%hd216282216325%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%hd216269216285%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##eq? _%$%hd216282216325%_
                                                         'begin))
                                                (let ((_%exprs216330%_
                                                       _%$%tl216283216327%_))
                                                  (_%$%K216281216322%_
                                                   _%exprs216330%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (##eq? _%$%hd216282216325%_
                                                             'quote))
                                                    (if (pair? _%$%tl216283216327%_)
                                                        (let ((_%$%tl216280216314%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##cdr _%$%tl216283216327%_))))
                  (if (null? _%$%tl216280216314%_)
                      (_%$%K216276216306%_)
                      (_%$%try-match216272216301%_)))
                (_%$%try-match216272216301%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%try-match216272216301%_))))
                                          (_%$%try-match216272216301%_))))))))
                        (if (pair? _%$%rest216248216256%_)
                            (let ((_%$%hd216253216335%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest216248216256%_)))
                                  (_%$%tl216254216337%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest216248216256%_))))
                              (let* ((_%hd216340%_ _%$%hd216253216335%_)
                                     (_%rest216342%_ _%$%tl216254216337%_))
                                (_%$%K216252216332%_
                                 _%rest216342%_
                                 _%hd216340%_)))
                            (_%$%else216250216264%_)))))))
          (let* ((_%$%g216196216206%_
                  (lambda (_%$%g216197216203%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g216197216203%_))))
                 (_%$%g216195216239%_
                  (lambda (_%$%g216197216209%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g216197216209%_))
                        (let ((_%$%e216199216211%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g216197216209%_))))
                          (let ((_%$%hd216200216214%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e216199216211%_)))
                                (_%$%tl216201216216%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e216199216211%_))))
                            (let* ((_%body216234%_
                                    (map (lambda (_%$%g216229216231%_)
                                           (let ()
                                             (declare (not safe))
                                             (gxc#compile-e__1
                                              _%self216191%_
                                              _%$%g216229216231%_)))
                                         _%$%tl216201216216%_))
                                   (_%body216236%_
                                    (_%simplify216194%_ _%body216234%_)))
                              (if (let ((__tmp218235 (length _%body216236%_)))
                                    (declare (not safe))
                                    (##fx= __tmp218235 '1))
                                  (car _%body216236%_)
                                  (cons 'begin _%body216236%_)))))
                        (_%$%g216196216206%_ _%$%g216197216209%_)))))
            (_%$%g216195216239%_ _%stx216192%_)))))
    (define gxc#generate-runtime-begin-foreign%
      (lambda (_%self216152%_ _%stx216153%_)
        (let* ((_%$%g216155216165%_
                (lambda (_%$%g216156216162%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g216156216162%_))))
               (_%$%g216154216188%_
                (lambda (_%$%g216156216168%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g216156216168%_))
                      (let ((_%$%e216158216170%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g216156216168%_))))
                        (let ((_%$%hd216159216173%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e216158216170%_)))
                              (_%$%tl216160216175%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e216158216170%_))))
                          (cons 'begin
                                (let ()
                                  (declare (not safe))
                                  (gx#syntax->datum _%$%tl216160216175%_)))))
                      (_%$%g216155216165%_ _%$%g216156216168%_)))))
          (_%$%g216154216188%_ _%stx216153%_))))
    (define gxc#generate-runtime-begin-annotation%
      (lambda (_%self215918%_ _%stx215919%_)
        (let* ((_%__stx216825216826%_ _%stx215919%_)
               (_%$%g215923215975%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx216825216826%_)))))
          (let ((_%__kont216827216828%_
                 (lambda (_%$%g215925216134%_ _%$%g215926216135%_)
                   (let ()
                     (declare (not safe))
                     (gxc#compile-e__1 _%self215918%_ _%$%g215925216134%_))))
                (_%__kont216829216830%_
                 (lambda (_%$%g215936216082%_
                          _%$%g215937216083%_
                          _%$%g215938216084%_)
                   (if (let ((__tmp218236
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%g215938216084%_))))
                         (declare (not safe))
                         (##memq __tmp218236 '(@inline)))
                       '(begin)
                       (let ()
                         (declare (not safe))
                         (gxc#compile-e__1
                          _%self215918%_
                          _%$%g215936216082%_)))))
                (_%__kont216833216834%_
                 (lambda (_%$%g215960216004%_ _%$%g215961216005%_)
                   (let ((_%decls216020%_
                          (map gx#syntax->datum _%$%g215961216005%_)))
                     (let ((__tmp218238
                            (lambda ()
                              (cons 'begin
                                    (cons (cons 'declare _%decls216020%_)
                                          (cons (let ()
                                                  (declare (not safe))
                                                  (gxc#compile-e__1
                                                   _%self215918%_
                                                   _%$%g215960216004%_))
                                                '())))))
                           (__tmp218237
                            (append _%decls216020%_
                                    (let ()
                                      (declare (not safe))
                                      (gxc#current-compile-decls)))))
                       (declare (not safe))
                       (call-with-parameters__1
                        __tmp218238
                        gxc#current-compile-decls
                        __tmp218237))))))
            (let* ((_%__match216880216881%_
                    (lambda (_%$%e215939216028%_
                             _%$%hd215940216031%_
                             _%$%tl215941216033%_
                             _%$%e215942216036%_
                             _%$%hd215943216039%_
                             _%$%tl215944216041%_
                             _%$%e215945216044%_
                             _%$%hd215946216047%_
                             _%$%tl215947216049%_
                             _%__splice216831216832%_
                             _%$%target215948216052%_
                             _%$%tl215950216054%_)
                      (letrec ((_%$%loop215951216057%_
                                (lambda (_%$%hd215949216060%_
                                         _%$%param215955216062%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd215949216060%_))
                                      (let ((_%$%e215952216064%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd215949216060%_))))
                                        (let ((_%$%lp-tl215954216069%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e215952216064%_)))
                                              (_%$%lp-hd215953216067%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e215952216064%_))))
                                          (_%$%loop215951216057%_
                                           _%$%lp-tl215954216069%_
                                           (cons _%$%lp-hd215953216067%_
                                                 _%$%param215955216062%_))))
                                      (let ((_%$%param215956216072%_
                                             (reverse _%$%param215955216062%_)))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl215944216041%_))
                                            (let ((_%$%e215957216074%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl215944216041%_))))
                                              (let ((_%$%tl215959216079%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e215957216074%_)))
                                                    (_%$%hd215958216077%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e215957216074%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl215959216079%_))
                                                    (let ((_%$%g215936216082%_
                                                           _%$%hd215958216077%_)
                                                          (_%$%g215937216083%_
                                                           _%$%param215956216072%_)
                                                          (_%$%g215938216084%_
                                                           _%$%hd215946216047%_))
                                                      (if (and (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#identifier? _%$%g215938216084%_))
                       (not (let ((__tmp218239
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%g215938216084%_))))
                              (declare (not safe))
                              (##memq __tmp218239 gxc#gambit-annotations))))
                  (_%__kont216829216830%_
                   _%$%g215936216082%_
                   _%$%g215937216083%_
                   _%$%g215938216084%_)
                  (_%__kont216833216834%_
                   _%$%hd215958216077%_
                   _%$%hd215943216039%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g215923215975%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g215923215975%_))))))))
                        (_%$%loop215951216057%_
                         _%$%target215948216052%_
                         '()))))
                   (_%__match216854216855%_
                    (lambda (_%$%e215927216110%_
                             _%$%hd215928216113%_
                             _%$%tl215929216115%_
                             _%$%e215930216118%_
                             _%$%hd215931216121%_
                             _%$%tl215932216123%_
                             _%$%e215933216126%_
                             _%$%hd215934216129%_
                             _%$%tl215935216131%_)
                      (let ((_%$%g215925216134%_ _%$%hd215934216129%_)
                            (_%$%g215926216135%_ _%$%hd215931216121%_))
                        (if (let ()
                              (declare (not safe))
                              (gx#identifier? _%$%g215926216135%_))
                            (_%__kont216827216828%_
                             _%$%g215925216134%_
                             _%$%g215926216135%_)
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%hd215931216121%_))
                                (let ((_%$%e215945216044%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%hd215931216121%_))))
                                  (let ((_%$%tl215947216049%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e215945216044%_)))
                                        (_%$%hd215946216047%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e215945216044%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair/null?
                                           _%$%tl215947216049%_))
                                        (let ((_%__splice216831216832%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-split-splice->vector
                                                  _%$%tl215947216049%_
                                                  '0))))
                                          (let ((_%$%tl215950216054%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice216831216832%_
                                                    '1)))
                                                (_%$%target215948216052%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice216831216832%_
                                                    '0))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl215950216054%_))
                                                (_%__match216880216881%_
                                                 _%$%e215927216110%_
                                                 _%$%hd215928216113%_
                                                 _%$%tl215929216115%_
                                                 _%$%e215930216118%_
                                                 _%$%hd215931216121%_
                                                 _%$%tl215932216123%_
                                                 _%$%e215945216044%_
                                                 _%$%hd215946216047%_
                                                 _%$%tl215947216049%_
                                                 _%__splice216831216832%_
                                                 _%$%target215948216052%_
                                                 _%$%tl215950216054%_)
                                                (_%__kont216833216834%_
                                                 _%$%hd215934216129%_
                                                 _%$%hd215931216121%_))))
                                        (_%__kont216833216834%_
                                         _%$%hd215934216129%_
                                         _%$%hd215931216121%_))))
                                (_%__kont216833216834%_
                                 _%$%hd215934216129%_
                                 _%$%hd215931216121%_)))))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx216825216826%_))
                  (let ((_%$%e215927216110%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx216825216826%_))))
                    (let ((_%$%tl215929216115%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e215927216110%_)))
                          (_%$%hd215928216113%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e215927216110%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl215929216115%_))
                          (let ((_%$%e215930216118%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl215929216115%_))))
                            (let ((_%$%tl215932216123%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e215930216118%_)))
                                  (_%$%hd215931216121%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e215930216118%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl215932216123%_))
                                  (let ((_%$%e215933216126%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%tl215932216123%_))))
                                    (let ((_%$%tl215935216131%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e215933216126%_)))
                                          (_%$%hd215934216129%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e215933216126%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl215935216131%_))
                                          (_%__match216854216855%_
                                           _%$%e215927216110%_
                                           _%$%hd215928216113%_
                                           _%$%tl215929216115%_
                                           _%$%e215930216118%_
                                           _%$%hd215931216121%_
                                           _%$%tl215932216123%_
                                           _%$%e215933216126%_
                                           _%$%hd215934216129%_
                                           _%$%tl215935216131%_)
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%hd215931216121%_))
                                              (let ((_%$%e215945216044%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%hd215931216121%_))))
                                                (let ((_%$%tl215947216049%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e215945216044%_)))
                                                      (_%$%hd215946216047%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e215945216044%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair/null?
                                                         _%$%tl215947216049%_))
                                                      (let ((_%__splice216831216832%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-split-splice->vector
                        _%$%tl215947216049%_
                        '0))))
                (let ((_%$%tl215950216054%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice216831216832%_ '1)))
                      (_%$%target215948216052%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice216831216832%_ '0))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl215950216054%_))
                      (_%__match216880216881%_
                       _%$%e215927216110%_
                       _%$%hd215928216113%_
                       _%$%tl215929216115%_
                       _%$%e215930216118%_
                       _%$%hd215931216121%_
                       _%$%tl215932216123%_
                       _%$%e215945216044%_
                       _%$%hd215946216047%_
                       _%$%tl215947216049%_
                       _%__splice216831216832%_
                       _%$%target215948216052%_
                       _%$%tl215950216054%_)
                      (let () (declare (not safe)) (_%$%g215923215975%_)))))
              (let () (declare (not safe)) (_%$%g215923215975%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g215923215975%_))))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd215931216121%_))
                                      (let ((_%$%e215945216044%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd215931216121%_))))
                                        (let ((_%$%tl215947216049%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e215945216044%_)))
                                              (_%$%hd215946216047%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e215945216044%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair/null?
                                                 _%$%tl215947216049%_))
                                              (let ((_%__splice216831216832%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#syntax-split-splice->vector
                                                        _%$%tl215947216049%_
                                                        '0))))
                                                (let ((_%$%tl215950216054%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice216831216832%_
                                                          '1)))
                                                      (_%$%target215948216052%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##vector-ref
                                                          _%__splice216831216832%_
                                                          '0))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl215950216054%_))
                                                      (_%__match216880216881%_
                                                       _%$%e215927216110%_
                                                       _%$%hd215928216113%_
                                                       _%$%tl215929216115%_
                                                       _%$%e215930216118%_
                                                       _%$%hd215931216121%_
                                                       _%$%tl215932216123%_
                                                       _%$%e215945216044%_
                                                       _%$%hd215946216047%_
                                                       _%$%tl215947216049%_
                                                       _%__splice216831216832%_
                                                       _%$%target215948216052%_
                                                       _%$%tl215950216054%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (_%$%g215923215975%_)))))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g215923215975%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g215923215975%_))))))
                          (let ()
                            (declare (not safe))
                            (_%$%g215923215975%_)))))
                  (let () (declare (not safe)) (_%$%g215923215975%_))))))))
    (define gxc#generate-runtime-declare%
      (lambda (_%self215877%_ _%stx215878%_)
        (let* ((_%$%g215880215890%_
                (lambda (_%$%g215881215887%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g215881215887%_))))
               (_%$%g215879215915%_
                (lambda (_%$%g215881215893%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g215881215893%_))
                      (let ((_%$%e215883215895%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g215881215893%_))))
                        (let ((_%$%hd215884215898%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e215883215895%_)))
                              (_%$%tl215885215900%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e215883215895%_))))
                          (let ((_%decls215913%_
                                 (map gx#syntax->datum _%$%tl215885215900%_)))
                            (let ((__tmp218240
                                   (append _%decls215913%_
                                           (let ()
                                             (declare (not safe))
                                             (gxc#current-compile-decls)))))
                              (declare (not safe))
                              (gxc#current-compile-decls __tmp218240))
                            (cons 'declare _%decls215913%_))))
                      (_%$%g215880215890%_ _%$%g215881215893%_)))))
          (_%$%g215879215915%_ _%stx215878%_))))
    (define gxc#generate-runtime-define-values%
      (lambda (_%self215624%_ _%stx215625%_)
        (let* ((_%$%g215627215644%_
                (lambda (_%$%g215628215641%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g215628215641%_))))
               (_%$%g215626215874%_
                (lambda (_%$%g215628215647%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g215628215647%_))
                      (let ((_%$%e215631215649%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g215628215647%_))))
                        (let ((_%$%hd215632215652%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e215631215649%_)))
                              (_%$%tl215633215654%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e215631215649%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl215633215654%_))
                              (let ((_%$%e215634215657%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl215633215654%_))))
                                (let ((_%$%hd215635215660%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e215634215657%_)))
                                      (_%$%tl215636215662%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e215634215657%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl215636215662%_))
                                      (let ((_%$%e215637215665%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl215636215662%_))))
                                        (let ((_%$%hd215638215668%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e215637215665%_)))
                                              (_%$%tl215639215670%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e215637215665%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl215639215670%_))
                                              (let* ((_%__stx216933216934%_
                                                      _%$%hd215635215660%_)
                                                     (_%$%g215691215705%_
                                                      (lambda ()
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#raise-syntax-error
                                                           '#f
                                                           '"Bad syntax; invalid match target"
                                                           _%__stx216933216934%_)))))
                                                (let ((_%__kont216935216936%_
                                                       (lambda ()
                                                         (let ()
                                                           (declare (not safe))
                                                           (gxc#compile-e__1
                                                            _%self215624%_
                                                            _%$%hd215638215668%_))))
                                                      (_%__kont216937216938%_
                                                       (lambda (_%$%g215697215837%_)
                                                         (let ((_%eid215846%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gxc#generate-runtime-binding-id
                           _%$%g215697215837%_))))
                   (let ((_%$%lambda-expr215847215849%_
                          (gxc#apply-find-lambda-expression
                           _%$%hd215638215668%_)))
                     (if _%$%lambda-expr215847215849%_
                         (let* ((_%lambda-expr215851%_
                                 _%$%lambda-expr215847215849%_)
                                (__tmp218241
                                 (let ()
                                   (declare (not safe))
                                   (gxc#current-compile-runtime-names))))
                           (declare (not safe))
                           (hash-put!
                            __tmp218241
                            _%lambda-expr215851%_
                            _%eid215846%_))
                         '#f))
                   (cons 'define
                         (cons _%eid215846%_
                               (cons (let ()
                                       (declare (not safe))
                                       (gxc#compile-e__1
                                        _%self215624%_
                                        _%$%hd215638215668%_))
                                     '()))))))
              (_%__kont216939216940%_
               (lambda ()
                 (let* ((_%tmp215712%_
                         (let ()
                           (declare (not safe))
                           (gxc#generate-runtime-temporary__% '#t)))
                        (_%body215821%_
                         (let _%lp215714%_ ((_%rest215716%_
                                             _%$%hd215635215660%_)
                                            (_%k215717%_ '0)
                                            (_%r215718%_ '()))
                           (let* ((_%__stx216903216904%_ _%rest215716%_)
                                  (_%$%g215723215740%_
                                   (lambda ()
                                     (let ()
                                       (declare (not safe))
                                       (gx#raise-syntax-error
                                        '#f
                                        '"Bad syntax; invalid match target"
                                        _%__stx216903216904%_)))))
                             (let ((_%__kont216905216906%_
                                    (lambda (_%$%g215725215808%_)
                                      (_%lp215714%_
                                       _%$%g215725215808%_
                                       (let ()
                                         (declare (not safe))
                                         (##fx+ _%k215717%_ '1))
                                       _%r215718%_)))
                                   (_%__kont216907216908%_
                                    (lambda (_%$%g215730215781%_
                                             _%$%g215731215782%_)
                                      (_%lp215714%_
                                       _%$%g215730215781%_
                                       (let ()
                                         (declare (not safe))
                                         (##fx+ _%k215717%_ '1))
                                       (cons (cons 'define
                                                   (cons (let ()
                                                           (declare (not safe))
                                                           (gxc#generate-runtime-binding-id
                                                            _%$%g215731215782%_))
                                                         (cons (gxc#generate-runtime-values-ref
                                                                _%tmp215712%_
                                                                _%k215717%_
                                                                _%$%g215730215781%_)
                                                               '())))
                                             _%r215718%_))))
                                   (_%__kont216909216910%_
                                    (lambda (_%$%g215735215752%_)
                                      (let ((__tmp218242
                                             (cons (cons 'define
                                                         (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gxc#generate-runtime-binding-id _%$%g215735215752%_))
                       (cons (gxc#generate-runtime-values->list
                              _%tmp215712%_
                              _%k215717%_)
                             '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   '())))
                                        (declare (not safe))
                                        (foldl__0
                                         cons
                                         __tmp218242
                                         _%r215718%_))))
                                   (_%__kont216911216912%_
                                    (lambda () (reverse _%r215718%_))))
                               (let ((_%$%g215721215768%_
                                      (lambda ()
                                        (let ((_%$%g215735215752%_
                                               _%__stx216903216904%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#identifier?
                                                 _%$%g215735215752%_))
                                              (_%__kont216909216910%_
                                               _%$%g215735215752%_)
                                              (_%__kont216911216912%_))))))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%__stx216903216904%_))
                                     (let ((_%$%e215726215797%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#stx-e
                                               _%__stx216903216904%_))))
                                       (let ((_%$%tl215728215802%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e215726215797%_)))
                                             (_%$%hd215727215800%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e215726215797%_))))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-datum?
                                                _%$%hd215727215800%_))
                                             (let ((_%$%e215729215805%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%$%hd215727215800%_))))
                                               (if (equal? _%$%e215729215805%_
                                                           '#f)
                                                   (_%__kont216905216906%_
                                                    _%$%tl215728215802%_)
                                                   (_%__kont216907216908%_
                                                    _%$%tl215728215802%_
                                                    _%$%hd215727215800%_)))
                                             (_%__kont216907216908%_
                                              _%$%tl215728215802%_
                                              _%$%hd215727215800%_))))
                                     (_%$%g215721215768%_))))))))
                   (cons 'begin
                         (cons (cons 'define
                                     (cons _%tmp215712%_
                                           (cons (let ()
                                                   (declare (not safe))
                                                   (gxc#compile-e__1
                                                    _%self215624%_
                                                    _%$%hd215638215668%_))
                                                 '())))
                               (cons (gxc#generate-runtime-check-values
                                      _%tmp215712%_
                                      _%$%hd215635215660%_
                                      _%$%hd215638215668%_)
                                     _%body215821%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%__stx216933216934%_))
                                                      (let ((_%$%e215693215858%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%__stx216933216934%_))))
                (let ((_%$%tl215695215863%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e215693215858%_)))
                      (_%$%hd215694215861%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e215693215858%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-datum? _%$%hd215694215861%_))
                      (let ((_%$%e215696215866%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%hd215694215861%_))))
                        (if (equal? _%$%e215696215866%_ '#f)
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl215695215863%_))
                                (_%__kont216935216936%_)
                                (_%__kont216939216940%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl215695215863%_))
                                (_%__kont216937216938%_ _%$%hd215694215861%_)
                                (_%__kont216939216940%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl215695215863%_))
                          (_%__kont216937216938%_ _%$%hd215694215861%_)
                          (_%__kont216939216940%_)))))
              (_%__kont216939216940%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g215627215644%_
                                               _%$%g215628215647%_))))
                                      (_%$%g215627215644%_
                                       _%$%g215628215647%_))))
                              (_%$%g215627215644%_ _%$%g215628215647%_))))
                      (_%$%g215627215644%_ _%$%g215628215647%_)))))
          (_%$%g215626215874%_ _%stx215625%_))))
    (define gxc#generate-runtime-check-values
      (lambda (_%vals215599%_ _%hd215600%_ _%expr215601%_)
        (let ((_%$e215603%_ (gxc#apply-count-values _%expr215601%_)))
          (if _%$e215603%_
              (let ((_%len215608%_
                     (let ()
                       (declare (not safe))
                       (gx#stx-length _%hd215600%_)))
                    (_%cmp215609%_
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-list? _%hd215600%_))
                         fx=
                         fx>=)))
                (if (or (let () (declare (not safe)) (##fx= _%len215608%_ '0))
                        (_%cmp215609%_ _%$e215603%_ _%len215608%_))
                    '#!void
                    (let ()
                      (declare (not safe))
                      (gxc#raise-compile-error
                       '"Value count mismatch"
                       _%expr215601%_
                       _%hd215600%_))))
              (let* ((_%len215615%_
                      (let ()
                        (declare (not safe))
                        (gx#stx-length _%hd215600%_)))
                     (_%cmp215617%_
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-list? _%hd215600%_))
                          '##fx=
                          '##fx>=))
                     (_%errmsg215619%_
                      (let ((__tmp218244
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-list? _%hd215600%_))
                                 '"Context expects "
                                 '"Context expects at least "))
                            (__tmp218243 (number->string _%len215615%_)))
                        (declare (not safe))
                        (##string-append __tmp218244 __tmp218243 '" values")))
                     (_%count215621%_
                      (let ()
                        (declare (not safe))
                        (gxc#generate-runtime-temporary__0))))
                (if (if (let ()
                          (declare (not safe))
                          (gx#stx-list? _%hd215600%_))
                        '#f
                        (let () (declare (not safe)) (##fx= _%len215615%_ '0)))
                    '#!void
                    (cons 'let
                          (cons (cons (cons _%count215621%_
                                            (cons (gxc#generate-runtime-values-count
                                                   _%vals215599%_)
                                                  '()))
                                      '())
                                (cons (cons 'if
                                            (cons (cons 'not
                                                        (cons (if (gxc#current-compile-decls-unsafe?)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons _%cmp215617%_
                                (cons _%count215621%_
                                      (cons _%len215615%_ '())))
                          (cons 'let
                                (cons '()
                                      (cons '(declare (not safe))
                                            (cons (cons _%cmp215617%_
                                                        (cons _%count215621%_
                                                              (cons _%len215615%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  '())))))
                      '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (cons (cons 'error
                                                              (cons _%errmsg215619%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons _%count215621%_ '())))
                '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      '())))))))))
    (define gxc#generate-runtime-values-count
      (lambda (_%var215594%_)
        (letrec ((_%generate-inline215596%_
                  (lambda ()
                    (cons 'if
                          (cons (cons '##values? (cons _%var215594%_ '()))
                                (cons (cons '##values-length
                                            (cons _%var215594%_ '()))
                                      (cons '1 '())))))))
          (if (gxc#current-compile-decls-unsafe?)
              (_%generate-inline215596%_)
              (cons 'let
                    (cons '()
                          (cons '(declare (not safe))
                                (cons (_%generate-inline215596%_) '()))))))))
    (define gxc#generate-runtime-values-ref
      (lambda (_%var215587%_ _%i215588%_ _%rest215589%_)
        (letrec ((_%generate-inline215591%_
                  (lambda ()
                    (if (and (let ()
                               (declare (not safe))
                               (##fx= _%i215588%_ '0))
                             (not (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%rest215589%_))))
                        (cons 'if
                              (cons (cons '##values? (cons _%var215587%_ '()))
                                    (cons (cons '##values-ref
                                                (cons _%var215587%_
                                                      (cons '0 '())))
                                          (cons _%var215587%_ '()))))
                        (cons '##values-ref
                              (cons _%var215587%_ (cons _%i215588%_ '())))))))
          (if (gxc#current-compile-decls-unsafe?)
              (_%generate-inline215591%_)
              (cons 'let
                    (cons '()
                          (cons '(declare (not safe))
                                (cons (_%generate-inline215591%_) '()))))))))
    (define gxc#generate-runtime-values->list
      (lambda (_%var215581%_ _%i215582%_)
        (if (let () (declare (not safe)) (##fx= _%i215582%_ '0))
            (if (gxc#current-compile-decls-unsafe?)
                (cons 'if
                      (cons (cons '##values? (cons _%var215581%_ '()))
                            (cons (cons '##values->list
                                        (cons _%var215581%_ '()))
                                  (cons (cons 'list (cons _%var215581%_ '()))
                                        '()))))
                (cons 'let
                      (cons '()
                            (cons '(declare (not safe))
                                  (cons (cons 'if
                                              (cons (cons '##values?
                                                          (cons _%var215581%_
                                                                '()))
                                                    (cons (cons '##values->list
                                                                (cons _%var215581%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '()))
                  (cons (cons 'list (cons _%var215581%_ '())) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        '())))))
            (if (let () (declare (not safe)) (##fx= _%i215582%_ '1))
                (if (gxc#current-compile-decls-unsafe?)
                    (cons 'if
                          (cons (cons '##values? (cons _%var215581%_ '()))
                                (cons (cons '##cdr
                                            (cons (cons '##values->list
                                                        (cons _%var215581%_
                                                              '()))
                                                  '()))
                                      (cons ''() '()))))
                    (cons 'let
                          (cons '()
                                (cons '(declare (not safe))
                                      (cons (cons 'if
                                                  (cons (cons '##values?
                                                              (cons _%var215581%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))
                (cons (cons '##cdr
                            (cons (cons '##values->list
                                        (cons _%var215581%_ '()))
                                  '()))
                      (cons ''() '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            '())))))
                (if (gxc#current-compile-decls-unsafe?)
                    (cons '##list-tail
                          (cons (cons '##values->list (cons _%var215581%_ '()))
                                (cons _%i215582%_ '())))
                    (cons 'let
                          (cons '()
                                (cons '(declare (not safe))
                                      (cons (cons '##list-tail
                                                  (cons (cons '##values->list
                                                              (cons _%var215581%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))
                (cons _%i215582%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            '())))))))))
    (define gxc#generate-runtime-lambda%
      (lambda (_%self215513%_ _%stx215514%_)
        (let* ((_%$%g215516215533%_
                (lambda (_%$%g215517215530%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g215517215530%_))))
               (_%$%g215515215578%_
                (lambda (_%$%g215517215536%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g215517215536%_))
                      (let ((_%$%e215520215538%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g215517215536%_))))
                        (let ((_%$%hd215521215541%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e215520215538%_)))
                              (_%$%tl215522215543%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e215520215538%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl215522215543%_))
                              (let ((_%$%e215523215546%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl215522215543%_))))
                                (let ((_%$%hd215524215549%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e215523215546%_)))
                                      (_%$%tl215525215551%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e215523215546%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl215525215551%_))
                                      (let ((_%$%e215526215554%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl215525215551%_))))
                                        (let ((_%$%hd215527215557%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e215526215554%_)))
                                              (_%$%tl215528215559%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e215526215554%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl215528215559%_))
                                              (gxc#generate-runtime-lambda-form
                                               _%self215513%_
                                               _%$%hd215524215549%_
                                               _%$%hd215527215557%_)
                                              (_%$%g215516215533%_
                                               _%$%g215517215536%_))))
                                      (_%$%g215516215533%_
                                       _%$%g215517215536%_))))
                              (_%$%g215516215533%_ _%$%g215517215536%_))))
                      (_%$%g215516215533%_ _%$%g215517215536%_)))))
          (_%$%g215515215578%_ _%stx215514%_))))
    (define gxc#generate-runtime-lambda-form
      (lambda (_%self215472%_ _%hd215473%_ _%body215474%_)
        (let* ((_%hd215476%_ (gxc#generate-runtime-lambda-head _%hd215473%_))
               (_%body215478%_
                (let ()
                  (declare (not safe))
                  (gxc#compile-e__1 _%self215472%_ _%body215474%_)))
               (_%body215510%_
                (let* ((_%$%body215479215487%_ _%body215478%_)
                       (_%$%else215481215495%_
                        (lambda () (cons _%body215478%_ '())))
                       (_%$%K215483215500%_
                        (lambda (_%exprs215498%_) _%exprs215498%_)))
                  (if (pair? _%$%body215479215487%_)
                      (let ((_%$%hd215484215503%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%body215479215487%_)))
                            (_%$%tl215485215505%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%body215479215487%_))))
                        (if (let ()
                              (declare (not safe))
                              (##eq? _%$%hd215484215503%_ 'begin))
                            (let ((_%exprs215508%_ _%$%tl215485215505%_))
                              (_%$%K215483215500%_ _%exprs215508%_))
                            (_%$%else215481215495%_)))
                      (_%$%else215481215495%_)))))
          (cons 'lambda (cons _%hd215476%_ _%body215510%_)))))
    (define gxc#generate-runtime-lambda-head
      (lambda (_%hd215470%_)
        (let ()
          (declare (not safe))
          (gx#stx-map1 gxc#generate-runtime-binding-id* _%hd215470%_))))
    (define gxc#generate-runtime-case-lambda%
      (lambda (_%self214027%_ _%stx214028%_)
        (letrec ((_%dispatch-case?214030%_
                  (lambda (_%hd214708%_ _%body214709%_)
                    (let* ((_%form214711%_
                            (cons _%hd214708%_ (cons _%body214709%_ '())))
                           (_%__stx216965216966%_ _%form214711%_)
                           (_%$%g214716214873%_
                            (lambda ()
                              (let ()
                                (declare (not safe))
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; invalid match target"
                                 _%__stx216965216966%_)))))
                      (let ((_%__kont216967216968%_
                             (lambda (_%$%g214718215390%_
                                      _%$%g214719215391%_
                                      _%$%g214720215392%_)
                               '#t))
                            (_%__kont216973216974%_
                             (lambda (_%$%g214763215182%_
                                      _%$%g214764215183%_
                                      _%$%g214765215184%_
                                      _%$%g214766215185%_
                                      _%$%g214767215186%_
                                      _%$%g214768215187%_)
                               '#t))
                            (_%__kont216979216980%_
                             (lambda (_%$%g214829214981%_
                                      _%$%g214830214982%_
                                      _%$%g214831214983%_
                                      _%$%g214832214984%_)
                               '#t))
                            (_%__kont216981216982%_ (lambda () '#f)))
                        (let* ((_%__match217106217107%_
                                (lambda (_%$%e214833214885%_
                                         _%$%hd214834214888%_
                                         _%$%tl214835214890%_
                                         _%$%e214836214893%_
                                         _%$%hd214837214896%_
                                         _%$%tl214838214898%_
                                         _%$%e214839214901%_
                                         _%$%hd214840214904%_
                                         _%$%tl214841214906%_
                                         _%$%e214842214909%_
                                         _%$%hd214843214912%_
                                         _%$%tl214844214914%_
                                         _%$%e214845214917%_
                                         _%$%hd214846214920%_
                                         _%$%tl214847214922%_
                                         _%$%e214848214925%_
                                         _%$%hd214849214928%_
                                         _%$%tl214850214930%_
                                         _%$%e214851214933%_
                                         _%$%hd214852214936%_
                                         _%$%tl214853214938%_
                                         _%$%e214854214941%_
                                         _%$%hd214855214944%_
                                         _%$%tl214856214946%_
                                         _%$%e214857214949%_
                                         _%$%hd214858214952%_
                                         _%$%tl214859214954%_
                                         _%$%e214860214957%_
                                         _%$%hd214861214960%_
                                         _%$%tl214862214962%_
                                         _%$%e214863214965%_
                                         _%$%hd214864214968%_
                                         _%$%tl214865214970%_
                                         _%$%e214866214973%_
                                         _%$%hd214867214976%_
                                         _%$%tl214868214978%_)
                                  (let ((_%$%g214829214981%_
                                         _%$%hd214867214976%_)
                                        (_%$%g214830214982%_
                                         _%$%hd214858214952%_)
                                        (_%$%g214831214983%_
                                         _%$%hd214849214928%_)
                                        (_%$%g214832214984%_
                                         _%$%hd214834214888%_))
                                    (if (and (let ()
                                               (declare (not safe))
                                               (gx#identifier?
                                                _%$%g214832214984%_))
                                             (let ()
                                               (declare (not safe))
                                               (gxc#runtime-identifier=?
                                                _%$%g214831214983%_
                                                'apply))
                                             (let ()
                                               (declare (not safe))
                                               (gx#free-identifier=?
                                                _%$%g214832214984%_
                                                _%$%g214829214981%_))
                                             (not (let ()
                                                    (declare (not safe))
                                                    (gx#free-identifier=?
                                                     _%$%g214830214982%_
                                                     _%$%g214832214984%_))))
                                        (_%__kont216979216980%_
                                         _%$%g214829214981%_
                                         _%$%g214830214982%_
                                         _%$%g214831214983%_
                                         _%$%g214832214984%_)
                                        (_%__kont216981216982%_)))))
                               (_%__match217078217079%_
                                (lambda (_%$%e214833214885%_
                                         _%$%hd214834214888%_
                                         _%$%tl214835214890%_
                                         _%$%e214836214893%_
                                         _%$%hd214837214896%_
                                         _%$%tl214838214898%_
                                         _%$%e214839214901%_
                                         _%$%hd214840214904%_
                                         _%$%tl214841214906%_
                                         _%$%e214842214909%_
                                         _%$%hd214843214912%_
                                         _%$%tl214844214914%_
                                         _%$%e214845214917%_
                                         _%$%hd214846214920%_
                                         _%$%tl214847214922%_
                                         _%$%e214848214925%_
                                         _%$%hd214849214928%_
                                         _%$%tl214850214930%_
                                         _%$%e214851214933%_
                                         _%$%hd214852214936%_
                                         _%$%tl214853214938%_
                                         _%$%e214854214941%_
                                         _%$%hd214855214944%_
                                         _%$%tl214856214946%_
                                         _%$%e214857214949%_
                                         _%$%hd214858214952%_
                                         _%$%tl214859214954%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl214853214938%_))
                                      (let ((_%$%e214860214957%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl214853214938%_))))
                                        (let ((_%$%tl214862214962%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e214860214957%_)))
                                              (_%$%hd214861214960%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e214860214957%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%hd214861214960%_))
                                              (let ((_%$%e214863214965%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%hd214861214960%_))))
                                                (let ((_%$%tl214865214970%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e214863214965%_)))
                                                      (_%$%hd214864214968%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e214863214965%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#identifier?
                                                         _%$%hd214864214968%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-eq?
                                                             '%#ref
                                                             _%$%hd214864214968%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%tl214865214970%_))
                      (let ((_%$%e214866214973%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl214865214970%_))))
                        (let ((_%$%tl214868214978%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e214866214973%_)))
                              (_%$%hd214867214976%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e214866214973%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl214868214978%_))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl214862214962%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl214838214898%_))
                                      (_%__match217106217107%_
                                       _%$%e214833214885%_
                                       _%$%hd214834214888%_
                                       _%$%tl214835214890%_
                                       _%$%e214836214893%_
                                       _%$%hd214837214896%_
                                       _%$%tl214838214898%_
                                       _%$%e214839214901%_
                                       _%$%hd214840214904%_
                                       _%$%tl214841214906%_
                                       _%$%e214842214909%_
                                       _%$%hd214843214912%_
                                       _%$%tl214844214914%_
                                       _%$%e214845214917%_
                                       _%$%hd214846214920%_
                                       _%$%tl214847214922%_
                                       _%$%e214848214925%_
                                       _%$%hd214849214928%_
                                       _%$%tl214850214930%_
                                       _%$%e214851214933%_
                                       _%$%hd214852214936%_
                                       _%$%tl214853214938%_
                                       _%$%e214854214941%_
                                       _%$%hd214855214944%_
                                       _%$%tl214856214946%_
                                       _%$%e214857214949%_
                                       _%$%hd214858214952%_
                                       _%$%tl214859214954%_
                                       _%$%e214860214957%_
                                       _%$%hd214861214960%_
                                       _%$%tl214862214962%_
                                       _%$%e214863214965%_
                                       _%$%hd214864214968%_
                                       _%$%tl214865214970%_
                                       _%$%e214866214973%_
                                       _%$%hd214867214976%_
                                       _%$%tl214868214978%_)
                                      (_%__kont216981216982%_))
                                  (_%__kont216981216982%_))
                              (_%__kont216981216982%_))))
                      (_%__kont216981216982%_))
                  (_%__kont216981216982%_))
              (_%__kont216981216982%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%__kont216981216982%_))))
                                      (_%__kont216981216982%_))))
                               (_%__match217008217009%_
                                (lambda (_%$%e214769215026%_
                                         _%$%hd214770215029%_
                                         _%$%tl214771215031%_
                                         _%__splice216975216976%_
                                         _%$%target214772215034%_
                                         _%$%tl214774215036%_)
                                  (letrec ((_%$%loop214775215039%_
                                            (lambda (_%$%hd214773215042%_
                                                     _%$%arg214779215044%_)
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd214773215042%_))
                                                  (let ((_%$%e214776215046%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%hd214773215042%_))))
                                                    (let ((_%$%lp-tl214778215051%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e214776215046%_)))
                                                          (_%$%lp-hd214777215049%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e214776215046%_))))
                                                      (_%$%loop214775215039%_
                                                       _%$%lp-tl214778215051%_
                                                       (cons _%$%lp-hd214777215049%_
                                                             _%$%arg214779215044%_))))
                                                  (let ((_%$%arg214780215054%_
                                                         (reverse _%$%arg214779215044%_)))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl214771215031%_))
                                                        (let ((_%$%e214781215056%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl214771215031%_))))
                  (let ((_%$%tl214783215061%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e214781215056%_)))
                        (_%$%hd214782215059%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e214781215056%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd214782215059%_))
                        (let ((_%$%e214784215064%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd214782215059%_))))
                          (let ((_%$%tl214786215069%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214784215064%_)))
                                (_%$%hd214785215067%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214784215064%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%hd214785215067%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-eq?
                                       '%#call
                                       _%$%hd214785215067%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl214786215069%_))
                                        (let ((_%$%e214787215072%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl214786215069%_))))
                                          (let ((_%$%tl214789215077%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e214787215072%_)))
                                                (_%$%hd214788215075%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e214787215072%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%hd214788215075%_))
                                                (let ((_%$%e214790215080%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%hd214788215075%_))))
                                                  (let ((_%$%tl214792215085%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e214790215080%_)))
                                                        (_%$%hd214791215083%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e214790215080%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#identifier?
                                                           _%$%hd214791215083%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-eq?
                                                               '%#ref
                                                               _%$%hd214791215083%_))
                                                            (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl214792215085%_))
                        (let ((_%$%e214793215088%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl214792215085%_))))
                          (let ((_%$%tl214795215093%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214793215088%_)))
                                (_%$%hd214794215091%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214793215088%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl214795215093%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%tl214789215077%_))
                                    (let ((_%$%e214796215096%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%tl214789215077%_))))
                                      (let ((_%$%tl214798215101%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e214796215096%_)))
                                            (_%$%hd214797215099%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e214796215096%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%hd214797215099%_))
                                            (let ((_%$%e214799215104%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%hd214797215099%_))))
                                              (let ((_%$%tl214801215109%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e214799215104%_)))
                                                    (_%$%hd214800215107%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e214799215104%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#identifier?
                                                       _%$%hd214800215107%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-eq?
                                                           '%#ref
                                                           _%$%hd214800215107%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%tl214801215109%_))
                                                            (let ((_%$%e214802215112%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl214801215109%_))))
                      (let ((_%$%tl214804215117%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e214802215112%_)))
                            (_%$%hd214803215115%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e214802215112%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl214804215117%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair/null? _%$%tl214798215101%_))
                                (if (let ((__tmp218245
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-length
                                              _%$%tl214798215101%_))))
                                      (declare (not safe))
                                      (##fx>= __tmp218245 '1))
                                    (let ((_%__splice216977216978%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-split-splice->vector
                                              _%$%tl214798215101%_
                                              '1))))
                                      (let ((_%$%tl214807215122%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice216977216978%_
                                                '1)))
                                            (_%$%target214805215120%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice216977216978%_
                                                '0))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl214807215122%_))
                                            (let ((_%$%e214814215125%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl214807215122%_))))
                                              (let ((_%$%tl214816215130%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e214814215125%_)))
                                                    (_%$%hd214815215128%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e214814215125%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%hd214815215128%_))
                                                    (let ((_%$%e214817215133%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%hd214815215128%_))))
                                                      (let ((_%$%tl214819215138%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e214817215133%_)))
                    (_%$%hd214818215136%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e214817215133%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#identifier? _%$%hd214818215136%_))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-eq? '%#ref _%$%hd214818215136%_))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl214819215138%_))
                            (let ((_%$%e214820215141%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl214819215138%_))))
                              (let ((_%$%tl214822215146%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e214820215141%_)))
                                    (_%$%hd214821215144%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e214820215141%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-null? _%$%tl214822215146%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl214816215130%_))
                                        (letrec ((_%$%loop214808215149%_
                                                  (lambda (_%$%hd214806215152%_
                                                           _%$%xarg214812215154%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd214806215152%_))
                                                        (let ((_%$%e214809215156%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%hd214806215152%_))))
                  (let ((_%$%lp-tl214811215161%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e214809215156%_)))
                        (_%$%lp-hd214810215159%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e214809215156%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%lp-hd214810215159%_))
                        (let ((_%$%e214823215164%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%lp-hd214810215159%_))))
                          (let ((_%$%tl214825215169%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214823215164%_)))
                                (_%$%hd214824215167%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214823215164%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%hd214824215167%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-eq? '%#ref _%$%hd214824215167%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl214825215169%_))
                                        (let ((_%$%e214826215172%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl214825215169%_))))
                                          (let ((_%$%tl214828215177%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e214826215172%_)))
                                                (_%$%hd214827215175%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e214826215172%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl214828215177%_))
                                                (_%$%loop214808215149%_
                                                 _%$%lp-tl214811215161%_
                                                 (cons _%$%hd214827215175%_
                                                       _%$%xarg214812215154%_))
                                                (_%__match217078217079%_
                                                 _%$%e214769215026%_
                                                 _%$%hd214770215029%_
                                                 _%$%tl214771215031%_
                                                 _%$%e214781215056%_
                                                 _%$%hd214782215059%_
                                                 _%$%tl214783215061%_
                                                 _%$%e214784215064%_
                                                 _%$%hd214785215067%_
                                                 _%$%tl214786215069%_
                                                 _%$%e214787215072%_
                                                 _%$%hd214788215075%_
                                                 _%$%tl214789215077%_
                                                 _%$%e214790215080%_
                                                 _%$%hd214791215083%_
                                                 _%$%tl214792215085%_
                                                 _%$%e214793215088%_
                                                 _%$%hd214794215091%_
                                                 _%$%tl214795215093%_
                                                 _%$%e214796215096%_
                                                 _%$%hd214797215099%_
                                                 _%$%tl214798215101%_
                                                 _%$%e214799215104%_
                                                 _%$%hd214800215107%_
                                                 _%$%tl214801215109%_
                                                 _%$%e214802215112%_
                                                 _%$%hd214803215115%_
                                                 _%$%tl214804215117%_))))
                                        (_%__match217078217079%_
                                         _%$%e214769215026%_
                                         _%$%hd214770215029%_
                                         _%$%tl214771215031%_
                                         _%$%e214781215056%_
                                         _%$%hd214782215059%_
                                         _%$%tl214783215061%_
                                         _%$%e214784215064%_
                                         _%$%hd214785215067%_
                                         _%$%tl214786215069%_
                                         _%$%e214787215072%_
                                         _%$%hd214788215075%_
                                         _%$%tl214789215077%_
                                         _%$%e214790215080%_
                                         _%$%hd214791215083%_
                                         _%$%tl214792215085%_
                                         _%$%e214793215088%_
                                         _%$%hd214794215091%_
                                         _%$%tl214795215093%_
                                         _%$%e214796215096%_
                                         _%$%hd214797215099%_
                                         _%$%tl214798215101%_
                                         _%$%e214799215104%_
                                         _%$%hd214800215107%_
                                         _%$%tl214801215109%_
                                         _%$%e214802215112%_
                                         _%$%hd214803215115%_
                                         _%$%tl214804215117%_))
                                    (_%__match217078217079%_
                                     _%$%e214769215026%_
                                     _%$%hd214770215029%_
                                     _%$%tl214771215031%_
                                     _%$%e214781215056%_
                                     _%$%hd214782215059%_
                                     _%$%tl214783215061%_
                                     _%$%e214784215064%_
                                     _%$%hd214785215067%_
                                     _%$%tl214786215069%_
                                     _%$%e214787215072%_
                                     _%$%hd214788215075%_
                                     _%$%tl214789215077%_
                                     _%$%e214790215080%_
                                     _%$%hd214791215083%_
                                     _%$%tl214792215085%_
                                     _%$%e214793215088%_
                                     _%$%hd214794215091%_
                                     _%$%tl214795215093%_
                                     _%$%e214796215096%_
                                     _%$%hd214797215099%_
                                     _%$%tl214798215101%_
                                     _%$%e214799215104%_
                                     _%$%hd214800215107%_
                                     _%$%tl214801215109%_
                                     _%$%e214802215112%_
                                     _%$%hd214803215115%_
                                     _%$%tl214804215117%_))
                                (_%__match217078217079%_
                                 _%$%e214769215026%_
                                 _%$%hd214770215029%_
                                 _%$%tl214771215031%_
                                 _%$%e214781215056%_
                                 _%$%hd214782215059%_
                                 _%$%tl214783215061%_
                                 _%$%e214784215064%_
                                 _%$%hd214785215067%_
                                 _%$%tl214786215069%_
                                 _%$%e214787215072%_
                                 _%$%hd214788215075%_
                                 _%$%tl214789215077%_
                                 _%$%e214790215080%_
                                 _%$%hd214791215083%_
                                 _%$%tl214792215085%_
                                 _%$%e214793215088%_
                                 _%$%hd214794215091%_
                                 _%$%tl214795215093%_
                                 _%$%e214796215096%_
                                 _%$%hd214797215099%_
                                 _%$%tl214798215101%_
                                 _%$%e214799215104%_
                                 _%$%hd214800215107%_
                                 _%$%tl214801215109%_
                                 _%$%e214802215112%_
                                 _%$%hd214803215115%_
                                 _%$%tl214804215117%_))))
                        (_%__match217078217079%_
                         _%$%e214769215026%_
                         _%$%hd214770215029%_
                         _%$%tl214771215031%_
                         _%$%e214781215056%_
                         _%$%hd214782215059%_
                         _%$%tl214783215061%_
                         _%$%e214784215064%_
                         _%$%hd214785215067%_
                         _%$%tl214786215069%_
                         _%$%e214787215072%_
                         _%$%hd214788215075%_
                         _%$%tl214789215077%_
                         _%$%e214790215080%_
                         _%$%hd214791215083%_
                         _%$%tl214792215085%_
                         _%$%e214793215088%_
                         _%$%hd214794215091%_
                         _%$%tl214795215093%_
                         _%$%e214796215096%_
                         _%$%hd214797215099%_
                         _%$%tl214798215101%_
                         _%$%e214799215104%_
                         _%$%hd214800215107%_
                         _%$%tl214801215109%_
                         _%$%e214802215112%_
                         _%$%hd214803215115%_
                         _%$%tl214804215117%_))))
                (let ((_%$%xarg214813215180%_
                       (reverse _%$%xarg214812215154%_)))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl214783215061%_))
                      (let ((_%$%g214763215182%_ _%$%hd214821215144%_)
                            (_%$%g214764215183%_ _%$%xarg214813215180%_)
                            (_%$%g214765215184%_ _%$%hd214803215115%_)
                            (_%$%g214766215185%_ _%$%hd214794215091%_)
                            (_%$%g214767215186%_ _%$%tl214774215036%_)
                            (_%$%g214768215187%_ _%$%arg214780215054%_))
                        (if (and (let ((__tmp218246
                                        (let ((__tmp218247
                                               (lambda (_%$%g215230215233%_
                                                        _%$%g215231215235%_)
                                                 (cons _%$%g215230215233%_
                                                       _%$%g215231215235%_))))
                                          (declare (not safe))
                                          (foldr__0
                                           __tmp218247
                                           '()
                                           _%$%g214768215187%_))))
                                   (declare (not safe))
                                   (gx#identifier-list? __tmp218246))
                                 (let ()
                                   (declare (not safe))
                                   (gx#identifier? _%$%g214767215186%_))
                                 (let ()
                                   (declare (not safe))
                                   (gxc#runtime-identifier=?
                                    _%$%g214766215185%_
                                    'apply))
                                 (let ((__tmp218250
                                        (length (let ((__tmp218251
                                                       (lambda (_%$%g215237215240%_
                                                                _%$%g215238215242%_)
                                                         (cons _%$%g215237215240%_
                                                               _%$%g215238215242%_))))
                                                  (declare (not safe))
                                                  (foldr__0
                                                   __tmp218251
                                                   '()
                                                   _%$%g214768215187%_))))
                                       (__tmp218248
                                        (length (let ((__tmp218249
                                                       (lambda (_%$%g215244215247%_
                                                                _%$%g215245215249%_)
                                                         (cons _%$%g215244215247%_
                                                               _%$%g215245215249%_))))
                                                  (declare (not safe))
                                                  (foldr__0
                                                   __tmp218249
                                                   '()
                                                   _%$%g214764215183%_)))))
                                   (declare (not safe))
                                   (##fx= __tmp218250 __tmp218248))
                                 (let ((__tmp218254
                                        (let ((__tmp218255
                                               (lambda (_%$%g215251215254%_
                                                        _%$%g215252215256%_)
                                                 (cons _%$%g215251215254%_
                                                       _%$%g215252215256%_))))
                                          (declare (not safe))
                                          (foldr__0
                                           __tmp218255
                                           '()
                                           _%$%g214768215187%_)))
                                       (__tmp218252
                                        (let ((__tmp218253
                                               (lambda (_%$%g215258215261%_
                                                        _%$%g215259215263%_)
                                                 (cons _%$%g215258215261%_
                                                       _%$%g215259215263%_))))
                                          (declare (not safe))
                                          (foldr__0
                                           __tmp218253
                                           '()
                                           _%$%g214764215183%_))))
                                   (declare (not safe))
                                   (andmap__1
                                    gx#free-identifier=?
                                    __tmp218254
                                    __tmp218252))
                                 (let ()
                                   (declare (not safe))
                                   (gx#free-identifier=?
                                    _%$%g214767215186%_
                                    _%$%g214763215182%_))
                                 (not (let ((__tmp218259
                                             (lambda (_%$%g215265215267%_)
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#free-identifier=?
                                                  _%$%g215265215267%_
                                                  _%$%g214765215184%_))))
                                            (__tmp218256
                                             (let ((__tmp218258
                                                    (lambda (_%$%g215269215272%_
                                                             _%$%g215270215274%_)
                                                      (cons _%$%g215269215272%_
                                                            _%$%g215270215274%_)))
                                                   (__tmp218257
                                                    (cons _%$%g214767215186%_
                                                          '())))
                                               (declare (not safe))
                                               (foldr__0
                                                __tmp218258
                                                __tmp218257
                                                _%$%g214768215187%_))))
                                        (declare (not safe))
                                        (__find __tmp218259 __tmp218256))))
                            (_%__kont216973216974%_
                             _%$%g214763215182%_
                             _%$%g214764215183%_
                             _%$%g214765215184%_
                             _%$%g214766215185%_
                             _%$%g214767215186%_
                             _%$%g214768215187%_)
                            (_%__match217078217079%_
                             _%$%e214769215026%_
                             _%$%hd214770215029%_
                             _%$%tl214771215031%_
                             _%$%e214781215056%_
                             _%$%hd214782215059%_
                             _%$%tl214783215061%_
                             _%$%e214784215064%_
                             _%$%hd214785215067%_
                             _%$%tl214786215069%_
                             _%$%e214787215072%_
                             _%$%hd214788215075%_
                             _%$%tl214789215077%_
                             _%$%e214790215080%_
                             _%$%hd214791215083%_
                             _%$%tl214792215085%_
                             _%$%e214793215088%_
                             _%$%hd214794215091%_
                             _%$%tl214795215093%_
                             _%$%e214796215096%_
                             _%$%hd214797215099%_
                             _%$%tl214798215101%_
                             _%$%e214799215104%_
                             _%$%hd214800215107%_
                             _%$%tl214801215109%_
                             _%$%e214802215112%_
                             _%$%hd214803215115%_
                             _%$%tl214804215117%_)))
                      (_%__match217078217079%_
                       _%$%e214769215026%_
                       _%$%hd214770215029%_
                       _%$%tl214771215031%_
                       _%$%e214781215056%_
                       _%$%hd214782215059%_
                       _%$%tl214783215061%_
                       _%$%e214784215064%_
                       _%$%hd214785215067%_
                       _%$%tl214786215069%_
                       _%$%e214787215072%_
                       _%$%hd214788215075%_
                       _%$%tl214789215077%_
                       _%$%e214790215080%_
                       _%$%hd214791215083%_
                       _%$%tl214792215085%_
                       _%$%e214793215088%_
                       _%$%hd214794215091%_
                       _%$%tl214795215093%_
                       _%$%e214796215096%_
                       _%$%hd214797215099%_
                       _%$%tl214798215101%_
                       _%$%e214799215104%_
                       _%$%hd214800215107%_
                       _%$%tl214801215109%_
                       _%$%e214802215112%_
                       _%$%hd214803215115%_
                       _%$%tl214804215117%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop214808215149%_
                                           _%$%target214805215120%_
                                           '()))
                                        (_%__match217078217079%_
                                         _%$%e214769215026%_
                                         _%$%hd214770215029%_
                                         _%$%tl214771215031%_
                                         _%$%e214781215056%_
                                         _%$%hd214782215059%_
                                         _%$%tl214783215061%_
                                         _%$%e214784215064%_
                                         _%$%hd214785215067%_
                                         _%$%tl214786215069%_
                                         _%$%e214787215072%_
                                         _%$%hd214788215075%_
                                         _%$%tl214789215077%_
                                         _%$%e214790215080%_
                                         _%$%hd214791215083%_
                                         _%$%tl214792215085%_
                                         _%$%e214793215088%_
                                         _%$%hd214794215091%_
                                         _%$%tl214795215093%_
                                         _%$%e214796215096%_
                                         _%$%hd214797215099%_
                                         _%$%tl214798215101%_
                                         _%$%e214799215104%_
                                         _%$%hd214800215107%_
                                         _%$%tl214801215109%_
                                         _%$%e214802215112%_
                                         _%$%hd214803215115%_
                                         _%$%tl214804215117%_))
                                    (_%__match217078217079%_
                                     _%$%e214769215026%_
                                     _%$%hd214770215029%_
                                     _%$%tl214771215031%_
                                     _%$%e214781215056%_
                                     _%$%hd214782215059%_
                                     _%$%tl214783215061%_
                                     _%$%e214784215064%_
                                     _%$%hd214785215067%_
                                     _%$%tl214786215069%_
                                     _%$%e214787215072%_
                                     _%$%hd214788215075%_
                                     _%$%tl214789215077%_
                                     _%$%e214790215080%_
                                     _%$%hd214791215083%_
                                     _%$%tl214792215085%_
                                     _%$%e214793215088%_
                                     _%$%hd214794215091%_
                                     _%$%tl214795215093%_
                                     _%$%e214796215096%_
                                     _%$%hd214797215099%_
                                     _%$%tl214798215101%_
                                     _%$%e214799215104%_
                                     _%$%hd214800215107%_
                                     _%$%tl214801215109%_
                                     _%$%e214802215112%_
                                     _%$%hd214803215115%_
                                     _%$%tl214804215117%_))))
                            (_%__match217078217079%_
                             _%$%e214769215026%_
                             _%$%hd214770215029%_
                             _%$%tl214771215031%_
                             _%$%e214781215056%_
                             _%$%hd214782215059%_
                             _%$%tl214783215061%_
                             _%$%e214784215064%_
                             _%$%hd214785215067%_
                             _%$%tl214786215069%_
                             _%$%e214787215072%_
                             _%$%hd214788215075%_
                             _%$%tl214789215077%_
                             _%$%e214790215080%_
                             _%$%hd214791215083%_
                             _%$%tl214792215085%_
                             _%$%e214793215088%_
                             _%$%hd214794215091%_
                             _%$%tl214795215093%_
                             _%$%e214796215096%_
                             _%$%hd214797215099%_
                             _%$%tl214798215101%_
                             _%$%e214799215104%_
                             _%$%hd214800215107%_
                             _%$%tl214801215109%_
                             _%$%e214802215112%_
                             _%$%hd214803215115%_
                             _%$%tl214804215117%_))
                        (_%__match217078217079%_
                         _%$%e214769215026%_
                         _%$%hd214770215029%_
                         _%$%tl214771215031%_
                         _%$%e214781215056%_
                         _%$%hd214782215059%_
                         _%$%tl214783215061%_
                         _%$%e214784215064%_
                         _%$%hd214785215067%_
                         _%$%tl214786215069%_
                         _%$%e214787215072%_
                         _%$%hd214788215075%_
                         _%$%tl214789215077%_
                         _%$%e214790215080%_
                         _%$%hd214791215083%_
                         _%$%tl214792215085%_
                         _%$%e214793215088%_
                         _%$%hd214794215091%_
                         _%$%tl214795215093%_
                         _%$%e214796215096%_
                         _%$%hd214797215099%_
                         _%$%tl214798215101%_
                         _%$%e214799215104%_
                         _%$%hd214800215107%_
                         _%$%tl214801215109%_
                         _%$%e214802215112%_
                         _%$%hd214803215115%_
                         _%$%tl214804215117%_))
                    (_%__match217078217079%_
                     _%$%e214769215026%_
                     _%$%hd214770215029%_
                     _%$%tl214771215031%_
                     _%$%e214781215056%_
                     _%$%hd214782215059%_
                     _%$%tl214783215061%_
                     _%$%e214784215064%_
                     _%$%hd214785215067%_
                     _%$%tl214786215069%_
                     _%$%e214787215072%_
                     _%$%hd214788215075%_
                     _%$%tl214789215077%_
                     _%$%e214790215080%_
                     _%$%hd214791215083%_
                     _%$%tl214792215085%_
                     _%$%e214793215088%_
                     _%$%hd214794215091%_
                     _%$%tl214795215093%_
                     _%$%e214796215096%_
                     _%$%hd214797215099%_
                     _%$%tl214798215101%_
                     _%$%e214799215104%_
                     _%$%hd214800215107%_
                     _%$%tl214801215109%_
                     _%$%e214802215112%_
                     _%$%hd214803215115%_
                     _%$%tl214804215117%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__match217078217079%_
                                                     _%$%e214769215026%_
                                                     _%$%hd214770215029%_
                                                     _%$%tl214771215031%_
                                                     _%$%e214781215056%_
                                                     _%$%hd214782215059%_
                                                     _%$%tl214783215061%_
                                                     _%$%e214784215064%_
                                                     _%$%hd214785215067%_
                                                     _%$%tl214786215069%_
                                                     _%$%e214787215072%_
                                                     _%$%hd214788215075%_
                                                     _%$%tl214789215077%_
                                                     _%$%e214790215080%_
                                                     _%$%hd214791215083%_
                                                     _%$%tl214792215085%_
                                                     _%$%e214793215088%_
                                                     _%$%hd214794215091%_
                                                     _%$%tl214795215093%_
                                                     _%$%e214796215096%_
                                                     _%$%hd214797215099%_
                                                     _%$%tl214798215101%_
                                                     _%$%e214799215104%_
                                                     _%$%hd214800215107%_
                                                     _%$%tl214801215109%_
                                                     _%$%e214802215112%_
                                                     _%$%hd214803215115%_
                                                     _%$%tl214804215117%_))))
                                            (_%__match217078217079%_
                                             _%$%e214769215026%_
                                             _%$%hd214770215029%_
                                             _%$%tl214771215031%_
                                             _%$%e214781215056%_
                                             _%$%hd214782215059%_
                                             _%$%tl214783215061%_
                                             _%$%e214784215064%_
                                             _%$%hd214785215067%_
                                             _%$%tl214786215069%_
                                             _%$%e214787215072%_
                                             _%$%hd214788215075%_
                                             _%$%tl214789215077%_
                                             _%$%e214790215080%_
                                             _%$%hd214791215083%_
                                             _%$%tl214792215085%_
                                             _%$%e214793215088%_
                                             _%$%hd214794215091%_
                                             _%$%tl214795215093%_
                                             _%$%e214796215096%_
                                             _%$%hd214797215099%_
                                             _%$%tl214798215101%_
                                             _%$%e214799215104%_
                                             _%$%hd214800215107%_
                                             _%$%tl214801215109%_
                                             _%$%e214802215112%_
                                             _%$%hd214803215115%_
                                             _%$%tl214804215117%_))))
                                    (_%__match217078217079%_
                                     _%$%e214769215026%_
                                     _%$%hd214770215029%_
                                     _%$%tl214771215031%_
                                     _%$%e214781215056%_
                                     _%$%hd214782215059%_
                                     _%$%tl214783215061%_
                                     _%$%e214784215064%_
                                     _%$%hd214785215067%_
                                     _%$%tl214786215069%_
                                     _%$%e214787215072%_
                                     _%$%hd214788215075%_
                                     _%$%tl214789215077%_
                                     _%$%e214790215080%_
                                     _%$%hd214791215083%_
                                     _%$%tl214792215085%_
                                     _%$%e214793215088%_
                                     _%$%hd214794215091%_
                                     _%$%tl214795215093%_
                                     _%$%e214796215096%_
                                     _%$%hd214797215099%_
                                     _%$%tl214798215101%_
                                     _%$%e214799215104%_
                                     _%$%hd214800215107%_
                                     _%$%tl214801215109%_
                                     _%$%e214802215112%_
                                     _%$%hd214803215115%_
                                     _%$%tl214804215117%_))
                                (_%__match217078217079%_
                                 _%$%e214769215026%_
                                 _%$%hd214770215029%_
                                 _%$%tl214771215031%_
                                 _%$%e214781215056%_
                                 _%$%hd214782215059%_
                                 _%$%tl214783215061%_
                                 _%$%e214784215064%_
                                 _%$%hd214785215067%_
                                 _%$%tl214786215069%_
                                 _%$%e214787215072%_
                                 _%$%hd214788215075%_
                                 _%$%tl214789215077%_
                                 _%$%e214790215080%_
                                 _%$%hd214791215083%_
                                 _%$%tl214792215085%_
                                 _%$%e214793215088%_
                                 _%$%hd214794215091%_
                                 _%$%tl214795215093%_
                                 _%$%e214796215096%_
                                 _%$%hd214797215099%_
                                 _%$%tl214798215101%_
                                 _%$%e214799215104%_
                                 _%$%hd214800215107%_
                                 _%$%tl214801215109%_
                                 _%$%e214802215112%_
                                 _%$%hd214803215115%_
                                 _%$%tl214804215117%_))
                            (_%__kont216981216982%_))))
                    (_%__kont216981216982%_))
                (_%__kont216981216982%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont216981216982%_))))
                                            (_%__kont216981216982%_))))
                                    (_%__kont216981216982%_))
                                (_%__kont216981216982%_))))
                        (_%__kont216981216982%_))
                    (_%__kont216981216982%_))
                (_%__kont216981216982%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%__kont216981216982%_))))
                                        (_%__kont216981216982%_))
                                    (_%__kont216981216982%_))
                                (_%__kont216981216982%_))))
                        (_%__kont216981216982%_))))
                (_%__kont216981216982%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (_%$%loop214775215039%_
                                     _%$%target214772215034%_
                                     '()))))
                               (_%__match216996216997%_
                                (lambda (_%$%e214721215282%_
                                         _%$%hd214722215285%_
                                         _%$%tl214723215287%_
                                         _%__splice216969216970%_
                                         _%$%target214724215290%_
                                         _%$%tl214726215292%_)
                                  (letrec ((_%$%loop214727215295%_
                                            (lambda (_%$%hd214725215298%_
                                                     _%$%arg214731215300%_)
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd214725215298%_))
                                                  (let ((_%$%e214728215302%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%hd214725215298%_))))
                                                    (let ((_%$%lp-tl214730215307%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e214728215302%_)))
                                                          (_%$%lp-hd214729215305%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e214728215302%_))))
                                                      (_%$%loop214727215295%_
                                                       _%$%lp-tl214730215307%_
                                                       (cons _%$%lp-hd214729215305%_
                                                             _%$%arg214731215300%_))))
                                                  (let ((_%$%arg214732215310%_
                                                         (reverse _%$%arg214731215300%_)))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl214723215287%_))
                                                        (let ((_%$%e214733215312%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl214723215287%_))))
                  (let ((_%$%tl214735215317%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e214733215312%_)))
                        (_%$%hd214734215315%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e214733215312%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd214734215315%_))
                        (let ((_%$%e214736215320%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd214734215315%_))))
                          (let ((_%$%tl214738215325%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214736215320%_)))
                                (_%$%hd214737215323%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214736215320%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%hd214737215323%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-eq?
                                       '%#call
                                       _%$%hd214737215323%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl214738215325%_))
                                        (let ((_%$%e214739215328%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl214738215325%_))))
                                          (let ((_%$%tl214741215333%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e214739215328%_)))
                                                (_%$%hd214740215331%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e214739215328%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%hd214740215331%_))
                                                (let ((_%$%e214742215336%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%hd214740215331%_))))
                                                  (let ((_%$%tl214744215341%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e214742215336%_)))
                                                        (_%$%hd214743215339%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e214742215336%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#identifier?
                                                           _%$%hd214743215339%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-eq?
                                                               '%#ref
                                                               _%$%hd214743215339%_))
                                                            (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl214744215341%_))
                        (let ((_%$%e214745215344%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl214744215341%_))))
                          (let ((_%$%tl214747215349%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214745215344%_)))
                                (_%$%hd214746215347%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214745215344%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl214747215349%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair/null? _%$%tl214741215333%_))
                                    (let ((_%__splice216971216972%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-split-splice->vector
                                              _%$%tl214741215333%_
                                              '0))))
                                      (let ((_%$%tl214750215354%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice216971216972%_
                                                '1)))
                                            (_%$%target214748215352%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice216971216972%_
                                                '0))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl214750215354%_))
                                            (letrec ((_%$%loop214751215357%_
                                                      (lambda (_%$%hd214749215360%_
                                                               _%$%xarg214755215362%_)
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%hd214749215360%_))
                                                            (let ((_%$%e214752215364%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%hd214749215360%_))))
                      (let ((_%$%lp-tl214754215369%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e214752215364%_)))
                            (_%$%lp-hd214753215367%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e214752215364%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%lp-hd214753215367%_))
                            (let ((_%$%e214757215372%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%lp-hd214753215367%_))))
                              (let ((_%$%tl214759215377%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e214757215372%_)))
                                    (_%$%hd214758215375%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e214757215372%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#identifier? _%$%hd214758215375%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-eq?
                                           '%#ref
                                           _%$%hd214758215375%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl214759215377%_))
                                            (let ((_%$%e214760215380%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl214759215377%_))))
                                              (let ((_%$%tl214762215385%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e214760215380%_)))
                                                    (_%$%hd214761215383%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e214760215380%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl214762215385%_))
                                                    (_%$%loop214751215357%_
                                                     _%$%lp-tl214754215369%_
                                                     (cons _%$%hd214761215383%_
                                                           _%$%xarg214755215362%_))
                                                    (_%__match217008217009%_
                                                     _%$%e214721215282%_
                                                     _%$%hd214722215285%_
                                                     _%$%tl214723215287%_
                                                     _%__splice216969216970%_
                                                     _%$%target214724215290%_
                                                     _%$%tl214726215292%_))))
                                            (_%__match217008217009%_
                                             _%$%e214721215282%_
                                             _%$%hd214722215285%_
                                             _%$%tl214723215287%_
                                             _%__splice216969216970%_
                                             _%$%target214724215290%_
                                             _%$%tl214726215292%_))
                                        (_%__match217008217009%_
                                         _%$%e214721215282%_
                                         _%$%hd214722215285%_
                                         _%$%tl214723215287%_
                                         _%__splice216969216970%_
                                         _%$%target214724215290%_
                                         _%$%tl214726215292%_))
                                    (_%__match217008217009%_
                                     _%$%e214721215282%_
                                     _%$%hd214722215285%_
                                     _%$%tl214723215287%_
                                     _%__splice216969216970%_
                                     _%$%target214724215290%_
                                     _%$%tl214726215292%_))))
                            (_%__match217008217009%_
                             _%$%e214721215282%_
                             _%$%hd214722215285%_
                             _%$%tl214723215287%_
                             _%__splice216969216970%_
                             _%$%target214724215290%_
                             _%$%tl214726215292%_))))
                    (let ((_%$%xarg214756215388%_
                           (reverse _%$%xarg214755215362%_)))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl214735215317%_))
                          (let ((_%$%g214718215390%_ _%$%xarg214756215388%_)
                                (_%$%g214719215391%_ _%$%hd214746215347%_)
                                (_%$%g214720215392%_ _%$%arg214732215310%_))
                            (if (and (let ((__tmp218260
                                            (let ((__tmp218261
                                                   (lambda (_%$%g215420215423%_
                                                            _%$%g215421215425%_)
                                                     (cons _%$%g215420215423%_
                                                           _%$%g215421215425%_))))
                                              (declare (not safe))
                                              (foldr__0
                                               __tmp218261
                                               '()
                                               _%$%g214720215392%_))))
                                       (declare (not safe))
                                       (gx#identifier-list? __tmp218260))
                                     (let ((__tmp218264
                                            (length (let ((__tmp218265
                                                           (lambda (_%$%g215427215430%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%g215428215432%_)
                     (cons _%$%g215427215430%_ _%$%g215428215432%_))))
              (declare (not safe))
              (foldr__0 __tmp218265 '() _%$%g214720215392%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (__tmp218262
                                            (length (let ((__tmp218263
                                                           (lambda (_%$%g215434215437%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%g215435215439%_)
                     (cons _%$%g215434215437%_ _%$%g215435215439%_))))
              (declare (not safe))
              (foldr__0 __tmp218263 '() _%$%g214718215390%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       (declare (not safe))
                                       (##fx= __tmp218264 __tmp218262))
                                     (let ((__tmp218268
                                            (let ((__tmp218269
                                                   (lambda (_%$%g215441215444%_
                                                            _%$%g215442215446%_)
                                                     (cons _%$%g215441215444%_
                                                           _%$%g215442215446%_))))
                                              (declare (not safe))
                                              (foldr__0
                                               __tmp218269
                                               '()
                                               _%$%g214720215392%_)))
                                           (__tmp218266
                                            (let ((__tmp218267
                                                   (lambda (_%$%g215448215451%_
                                                            _%$%g215449215453%_)
                                                     (cons _%$%g215448215451%_
                                                           _%$%g215449215453%_))))
                                              (declare (not safe))
                                              (foldr__0
                                               __tmp218267
                                               '()
                                               _%$%g214718215390%_))))
                                       (declare (not safe))
                                       (andmap__1
                                        gx#free-identifier=?
                                        __tmp218268
                                        __tmp218266))
                                     (not (let ((__tmp218272
                                                 (lambda (_%$%g215455215457%_)
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#free-identifier=?
                                                      _%$%g215455215457%_
                                                      _%$%g214719215391%_))))
                                                (__tmp218270
                                                 (let ((__tmp218271
                                                        (lambda (_%$%g215459215462%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%g215460215464%_)
                  (cons _%$%g215459215462%_ _%$%g215460215464%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (declare (not safe))
                                                   (foldr__0
                                                    __tmp218271
                                                    '()
                                                    _%$%g214720215392%_))))
                                            (declare (not safe))
                                            (__find __tmp218272 __tmp218270))))
                                (_%__kont216967216968%_
                                 _%$%g214718215390%_
                                 _%$%g214719215391%_
                                 _%$%g214720215392%_)
                                (_%__match217008217009%_
                                 _%$%e214721215282%_
                                 _%$%hd214722215285%_
                                 _%$%tl214723215287%_
                                 _%__splice216969216970%_
                                 _%$%target214724215290%_
                                 _%$%tl214726215292%_)))
                          (_%__match217008217009%_
                           _%$%e214721215282%_
                           _%$%hd214722215285%_
                           _%$%tl214723215287%_
                           _%__splice216969216970%_
                           _%$%target214724215290%_
                           _%$%tl214726215292%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%loop214751215357%_
                                               _%$%target214748215352%_
                                               '()))
                                            (_%__match217008217009%_
                                             _%$%e214721215282%_
                                             _%$%hd214722215285%_
                                             _%$%tl214723215287%_
                                             _%__splice216969216970%_
                                             _%$%target214724215290%_
                                             _%$%tl214726215292%_))))
                                    (_%__match217008217009%_
                                     _%$%e214721215282%_
                                     _%$%hd214722215285%_
                                     _%$%tl214723215287%_
                                     _%__splice216969216970%_
                                     _%$%target214724215290%_
                                     _%$%tl214726215292%_))
                                (_%__match217008217009%_
                                 _%$%e214721215282%_
                                 _%$%hd214722215285%_
                                 _%$%tl214723215287%_
                                 _%__splice216969216970%_
                                 _%$%target214724215290%_
                                 _%$%tl214726215292%_))))
                        (_%__match217008217009%_
                         _%$%e214721215282%_
                         _%$%hd214722215285%_
                         _%$%tl214723215287%_
                         _%__splice216969216970%_
                         _%$%target214724215290%_
                         _%$%tl214726215292%_))
                    (_%__match217008217009%_
                     _%$%e214721215282%_
                     _%$%hd214722215285%_
                     _%$%tl214723215287%_
                     _%__splice216969216970%_
                     _%$%target214724215290%_
                     _%$%tl214726215292%_))
                (_%__match217008217009%_
                 _%$%e214721215282%_
                 _%$%hd214722215285%_
                 _%$%tl214723215287%_
                 _%__splice216969216970%_
                 _%$%target214724215290%_
                 _%$%tl214726215292%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%__match217008217009%_
                                                 _%$%e214721215282%_
                                                 _%$%hd214722215285%_
                                                 _%$%tl214723215287%_
                                                 _%__splice216969216970%_
                                                 _%$%target214724215290%_
                                                 _%$%tl214726215292%_))))
                                        (_%__match217008217009%_
                                         _%$%e214721215282%_
                                         _%$%hd214722215285%_
                                         _%$%tl214723215287%_
                                         _%__splice216969216970%_
                                         _%$%target214724215290%_
                                         _%$%tl214726215292%_))
                                    (_%__match217008217009%_
                                     _%$%e214721215282%_
                                     _%$%hd214722215285%_
                                     _%$%tl214723215287%_
                                     _%__splice216969216970%_
                                     _%$%target214724215290%_
                                     _%$%tl214726215292%_))
                                (_%__match217008217009%_
                                 _%$%e214721215282%_
                                 _%$%hd214722215285%_
                                 _%$%tl214723215287%_
                                 _%__splice216969216970%_
                                 _%$%target214724215290%_
                                 _%$%tl214726215292%_))))
                        (_%__match217008217009%_
                         _%$%e214721215282%_
                         _%$%hd214722215285%_
                         _%$%tl214723215287%_
                         _%__splice216969216970%_
                         _%$%target214724215290%_
                         _%$%tl214726215292%_))))
                (_%__match217008217009%_
                 _%$%e214721215282%_
                 _%$%hd214722215285%_
                 _%$%tl214723215287%_
                 _%__splice216969216970%_
                 _%$%target214724215290%_
                 _%$%tl214726215292%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (_%$%loop214727215295%_
                                     _%$%target214724215290%_
                                     '())))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%__stx216965216966%_))
                              (let ((_%$%e214721215282%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%__stx216965216966%_))))
                                (let ((_%$%tl214723215287%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e214721215282%_)))
                                      (_%$%hd214722215285%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e214721215282%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%hd214722215285%_))
                                      (let ((_%__splice216969216970%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice->vector
                                                _%$%hd214722215285%_
                                                '0))))
                                        (let ((_%$%tl214726215292%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice216969216970%_
                                                  '1)))
                                              (_%$%target214724215290%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice216969216970%_
                                                  '0))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl214726215292%_))
                                              (_%__match216996216997%_
                                               _%$%e214721215282%_
                                               _%$%hd214722215285%_
                                               _%$%tl214723215287%_
                                               _%__splice216969216970%_
                                               _%$%target214724215290%_
                                               _%$%tl214726215292%_)
                                              (_%__match217008217009%_
                                               _%$%e214721215282%_
                                               _%$%hd214722215285%_
                                               _%$%tl214723215287%_
                                               _%__splice216969216970%_
                                               _%$%target214724215290%_
                                               _%$%tl214726215292%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl214723215287%_))
                                          (let ((_%$%e214836214893%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#stx-e
                                                    _%$%tl214723215287%_))))
                                            (let ((_%$%tl214838214898%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e214836214893%_)))
                                                  (_%$%hd214837214896%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e214836214893%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd214837214896%_))
                                                  (let ((_%$%e214839214901%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%hd214837214896%_))))
                                                    (let ((_%$%tl214841214906%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e214839214901%_)))
                                                          (_%$%hd214840214904%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e214839214901%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#identifier?
                                                             _%$%hd214840214904%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-eq? '%#call _%$%hd214840214904%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl214841214906%_))
                          (let ((_%$%e214842214909%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl214841214906%_))))
                            (let ((_%$%tl214844214914%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e214842214909%_)))
                                  (_%$%hd214843214912%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e214842214909%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%hd214843214912%_))
                                  (let ((_%$%e214845214917%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd214843214912%_))))
                                    (let ((_%$%tl214847214922%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e214845214917%_)))
                                          (_%$%hd214846214920%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e214845214917%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#identifier?
                                             _%$%hd214846214920%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#ref
                                                 _%$%hd214846214920%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl214847214922%_))
                                                  (let ((_%$%e214848214925%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl214847214922%_))))
                                                    (let ((_%$%tl214850214930%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e214848214925%_)))
                                                          (_%$%hd214849214928%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e214848214925%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl214850214930%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%tl214844214914%_))
                      (let ((_%$%e214851214933%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl214844214914%_))))
                        (let ((_%$%tl214853214938%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e214851214933%_)))
                              (_%$%hd214852214936%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e214851214933%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%hd214852214936%_))
                              (let ((_%$%e214854214941%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%hd214852214936%_))))
                                (let ((_%$%tl214856214946%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e214854214941%_)))
                                      (_%$%hd214855214944%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e214854214941%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#identifier? _%$%hd214855214944%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-eq?
                                             '%#ref
                                             _%$%hd214855214944%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl214856214946%_))
                                              (let ((_%$%e214857214949%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl214856214946%_))))
                                                (let ((_%$%tl214859214954%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e214857214949%_)))
                                                      (_%$%hd214858214952%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e214857214949%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl214859214954%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%tl214853214938%_))
                                                          (let ((_%$%e214860214957%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%tl214853214938%_))))
                    (let ((_%$%tl214862214962%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e214860214957%_)))
                          (_%$%hd214861214960%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e214860214957%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%hd214861214960%_))
                          (let ((_%$%e214863214965%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%hd214861214960%_))))
                            (let ((_%$%tl214865214970%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e214863214965%_)))
                                  (_%$%hd214864214968%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e214863214965%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#identifier? _%$%hd214864214968%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-eq?
                                         '%#ref
                                         _%$%hd214864214968%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl214865214970%_))
                                          (let ((_%$%e214866214973%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#stx-e
                                                    _%$%tl214865214970%_))))
                                            (let ((_%$%tl214868214978%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e214866214973%_)))
                                                  (_%$%hd214867214976%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e214866214973%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-null?
                                                     _%$%tl214868214978%_))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl214862214962%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl214838214898%_))
                                                          (_%__match217106217107%_
                                                           _%$%e214721215282%_
                                                           _%$%hd214722215285%_
                                                           _%$%tl214723215287%_
                                                           _%$%e214836214893%_
                                                           _%$%hd214837214896%_
                                                           _%$%tl214838214898%_
                                                           _%$%e214839214901%_
                                                           _%$%hd214840214904%_
                                                           _%$%tl214841214906%_
                                                           _%$%e214842214909%_
                                                           _%$%hd214843214912%_
                                                           _%$%tl214844214914%_
                                                           _%$%e214845214917%_
                                                           _%$%hd214846214920%_
                                                           _%$%tl214847214922%_
                                                           _%$%e214848214925%_
                                                           _%$%hd214849214928%_
                                                           _%$%tl214850214930%_
                                                           _%$%e214851214933%_
                                                           _%$%hd214852214936%_
                                                           _%$%tl214853214938%_
                                                           _%$%e214854214941%_
                                                           _%$%hd214855214944%_
                                                           _%$%tl214856214946%_
                                                           _%$%e214857214949%_
                                                           _%$%hd214858214952%_
                                                           _%$%tl214859214954%_
                                                           _%$%e214860214957%_
                                                           _%$%hd214861214960%_
                                                           _%$%tl214862214962%_
                                                           _%$%e214863214965%_
                                                           _%$%hd214864214968%_
                                                           _%$%tl214865214970%_
                                                           _%$%e214866214973%_
                                                           _%$%hd214867214976%_
                                                           _%$%tl214868214978%_)
                                                          (_%__kont216981216982%_))
                                                      (_%__kont216981216982%_))
                                                  (_%__kont216981216982%_))))
                                          (_%__kont216981216982%_))
                                      (_%__kont216981216982%_))
                                  (_%__kont216981216982%_))))
                          (_%__kont216981216982%_))))
                  (_%__kont216981216982%_))
              (_%__kont216981216982%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%__kont216981216982%_))
                                          (_%__kont216981216982%_))
                                      (_%__kont216981216982%_))))
                              (_%__kont216981216982%_))))
                      (_%__kont216981216982%_))
                  (_%__kont216981216982%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont216981216982%_))
                                              (_%__kont216981216982%_))
                                          (_%__kont216981216982%_))))
                                  (_%__kont216981216982%_))))
                          (_%__kont216981216982%_))
                      (_%__kont216981216982%_))
                  (_%__kont216981216982%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont216981216982%_))))
                                          (_%__kont216981216982%_)))))
                              (_%__kont216981216982%_)))))))
                 (_%dispatch-case-e214031%_
                  (lambda (_%hd214178%_ _%body214179%_)
                    (let* ((_%form214181%_
                            (cons _%hd214178%_ (cons _%body214179%_ '())))
                           (_%__stx217109217110%_ _%form214181%_)
                           (_%$%g214185214309%_
                            (lambda ()
                              (let ()
                                (declare (not safe))
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; invalid match target"
                                 _%__stx217109217110%_)))))
                      (let ((_%__kont217111217112%_
                             (lambda (_%$%g214187214674%_
                                      _%$%g214188214675%_
                                      _%$%g214189214676%_)
                               (let ((__tmp218273
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0 '#f '%#ref))
                                            (cons _%$%g214188214675%_ '()))))
                                 (declare (not safe))
                                 (gxc#compile-e__1
                                  _%self214027%_
                                  __tmp218273))))
                            (_%__kont217117217118%_
                             (lambda (_%$%g214232214526%_
                                      _%$%g214233214527%_
                                      _%$%g214234214528%_
                                      _%$%g214235214529%_)
                               (let ((__tmp218274
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0 '#f '%#ref))
                                            (cons _%$%g214232214526%_ '()))))
                                 (declare (not safe))
                                 (gxc#compile-e__1
                                  _%self214027%_
                                  __tmp218274))))
                            (_%__kont217121217122%_
                             (lambda (_%$%g214272214394%_
                                      _%$%g214273214395%_
                                      _%$%g214274214396%_)
                               (let ((__tmp218275
                                      (cons (let ()
                                              (declare (not safe))
                                              (gx#datum->syntax__0 '#f '%#ref))
                                            (cons _%$%g214272214394%_ '()))))
                                 (declare (not safe))
                                 (gxc#compile-e__1
                                  _%self214027%_
                                  __tmp218275)))))
                        (let* ((_%__match217218217219%_
                                (lambda (_%$%e214275214314%_
                                         _%$%hd214276214317%_
                                         _%$%tl214277214319%_
                                         _%$%e214278214322%_
                                         _%$%hd214279214325%_
                                         _%$%tl214280214327%_
                                         _%$%e214281214330%_
                                         _%$%hd214282214333%_
                                         _%$%tl214283214335%_
                                         _%$%e214284214338%_
                                         _%$%hd214285214341%_
                                         _%$%tl214286214343%_
                                         _%$%e214287214346%_
                                         _%$%hd214288214349%_
                                         _%$%tl214289214351%_
                                         _%$%e214290214354%_
                                         _%$%hd214291214357%_
                                         _%$%tl214292214359%_
                                         _%$%e214293214362%_
                                         _%$%hd214294214365%_
                                         _%$%tl214295214367%_
                                         _%$%e214296214370%_
                                         _%$%hd214297214373%_
                                         _%$%tl214298214375%_
                                         _%$%e214299214378%_
                                         _%$%hd214300214381%_
                                         _%$%tl214301214383%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl214295214367%_))
                                      (let ((_%$%e214302214386%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl214295214367%_))))
                                        (let ((_%$%tl214304214391%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e214302214386%_)))
                                              (_%$%hd214303214389%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e214302214386%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl214304214391%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-null?
                                                     _%$%tl214280214327%_))
                                                  (_%__kont217121217122%_
                                                   _%$%hd214300214381%_
                                                   _%$%hd214291214357%_
                                                   _%$%hd214276214317%_)
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g214185214309%_)))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g214185214309%_)))))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g214185214309%_)))))
                               (_%__match217148217149%_
                                (lambda (_%$%e214236214432%_
                                         _%$%hd214237214435%_
                                         _%$%tl214238214437%_
                                         _%__splice217119217120%_
                                         _%$%target214239214440%_
                                         _%$%tl214241214442%_)
                                  (letrec ((_%$%loop214242214445%_
                                            (lambda (_%$%hd214240214448%_
                                                     _%$%arg214246214450%_)
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd214240214448%_))
                                                  (let ((_%$%e214243214452%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%hd214240214448%_))))
                                                    (let ((_%$%lp-tl214245214457%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e214243214452%_)))
                                                          (_%$%lp-hd214244214455%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e214243214452%_))))
                                                      (_%$%loop214242214445%_
                                                       _%$%lp-tl214245214457%_
                                                       (cons _%$%lp-hd214244214455%_
                                                             _%$%arg214246214450%_))))
                                                  (let ((_%$%arg214247214460%_
                                                         (reverse _%$%arg214246214450%_)))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl214238214437%_))
                                                        (let ((_%$%e214248214462%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl214238214437%_))))
                  (let ((_%$%tl214250214467%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e214248214462%_)))
                        (_%$%hd214249214465%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e214248214462%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd214249214465%_))
                        (let ((_%$%e214251214470%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd214249214465%_))))
                          (let ((_%$%tl214253214475%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214251214470%_)))
                                (_%$%hd214252214473%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214251214470%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%hd214252214473%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-eq?
                                       '%#call
                                       _%$%hd214252214473%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl214253214475%_))
                                        (let ((_%$%e214254214478%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl214253214475%_))))
                                          (let ((_%$%tl214256214483%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e214254214478%_)))
                                                (_%$%hd214255214481%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e214254214478%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%hd214255214481%_))
                                                (let ((_%$%e214257214486%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%hd214255214481%_))))
                                                  (let ((_%$%tl214259214491%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e214257214486%_)))
                                                        (_%$%hd214258214489%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e214257214486%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#identifier?
                                                           _%$%hd214258214489%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-eq?
                                                               '%#ref
                                                               _%$%hd214258214489%_))
                                                            (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl214259214491%_))
                        (let ((_%$%e214260214494%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl214259214491%_))))
                          (let ((_%$%tl214262214499%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214260214494%_)))
                                (_%$%hd214261214497%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214260214494%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl214262214499%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%tl214256214483%_))
                                    (let ((_%$%e214263214502%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%tl214256214483%_))))
                                      (let ((_%$%tl214265214507%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e214263214502%_)))
                                            (_%$%hd214264214505%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e214263214502%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%hd214264214505%_))
                                            (let ((_%$%e214266214510%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%hd214264214505%_))))
                                              (let ((_%$%tl214268214515%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e214266214510%_)))
                                                    (_%$%hd214267214513%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e214266214510%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#identifier?
                                                       _%$%hd214267214513%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-eq?
                                                           '%#ref
                                                           _%$%hd214267214513%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%tl214268214515%_))
                                                            (let ((_%$%e214269214518%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl214268214515%_))))
                      (let ((_%$%tl214271214523%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e214269214518%_)))
                            (_%$%hd214270214521%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e214269214518%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl214271214523%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl214250214467%_))
                                (_%__kont217117217118%_
                                 _%$%hd214270214521%_
                                 _%$%hd214261214497%_
                                 _%$%tl214241214442%_
                                 _%$%arg214247214460%_)
                                (_%__match217218217219%_
                                 _%$%e214236214432%_
                                 _%$%hd214237214435%_
                                 _%$%tl214238214437%_
                                 _%$%e214248214462%_
                                 _%$%hd214249214465%_
                                 _%$%tl214250214467%_
                                 _%$%e214251214470%_
                                 _%$%hd214252214473%_
                                 _%$%tl214253214475%_
                                 _%$%e214254214478%_
                                 _%$%hd214255214481%_
                                 _%$%tl214256214483%_
                                 _%$%e214257214486%_
                                 _%$%hd214258214489%_
                                 _%$%tl214259214491%_
                                 _%$%e214260214494%_
                                 _%$%hd214261214497%_
                                 _%$%tl214262214499%_
                                 _%$%e214263214502%_
                                 _%$%hd214264214505%_
                                 _%$%tl214265214507%_
                                 _%$%e214266214510%_
                                 _%$%hd214267214513%_
                                 _%$%tl214268214515%_
                                 _%$%e214269214518%_
                                 _%$%hd214270214521%_
                                 _%$%tl214271214523%_))
                            (let ()
                              (declare (not safe))
                              (_%$%g214185214309%_)))))
                    (let () (declare (not safe)) (_%$%g214185214309%_)))
                (let () (declare (not safe)) (_%$%g214185214309%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g214185214309%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g214185214309%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g214185214309%_)))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g214185214309%_)))))
                        (let () (declare (not safe)) (_%$%g214185214309%_)))
                    (let () (declare (not safe)) (_%$%g214185214309%_)))
                (let () (declare (not safe)) (_%$%g214185214309%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g214185214309%_)))))
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g214185214309%_)))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g214185214309%_)))
                                (let ()
                                  (declare (not safe))
                                  (_%$%g214185214309%_)))))
                        (let () (declare (not safe)) (_%$%g214185214309%_)))))
                (let () (declare (not safe)) (_%$%g214185214309%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (_%$%loop214242214445%_
                                     _%$%target214239214440%_
                                     '()))))
                               (_%__match217136217137%_
                                (lambda (_%$%e214190214566%_
                                         _%$%hd214191214569%_
                                         _%$%tl214192214571%_
                                         _%__splice217113217114%_
                                         _%$%target214193214574%_
                                         _%$%tl214195214576%_)
                                  (letrec ((_%$%loop214196214579%_
                                            (lambda (_%$%hd214194214582%_
                                                     _%$%arg214200214584%_)
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd214194214582%_))
                                                  (let ((_%$%e214197214586%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%hd214194214582%_))))
                                                    (let ((_%$%lp-tl214199214591%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e214197214586%_)))
                                                          (_%$%lp-hd214198214589%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e214197214586%_))))
                                                      (_%$%loop214196214579%_
                                                       _%$%lp-tl214199214591%_
                                                       (cons _%$%lp-hd214198214589%_
                                                             _%$%arg214200214584%_))))
                                                  (let ((_%$%arg214201214594%_
                                                         (reverse _%$%arg214200214584%_)))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl214192214571%_))
                                                        (let ((_%$%e214202214596%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl214192214571%_))))
                  (let ((_%$%tl214204214601%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e214202214596%_)))
                        (_%$%hd214203214599%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e214202214596%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd214203214599%_))
                        (let ((_%$%e214205214604%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd214203214599%_))))
                          (let ((_%$%tl214207214609%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214205214604%_)))
                                (_%$%hd214206214607%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214205214604%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#identifier? _%$%hd214206214607%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-eq?
                                       '%#call
                                       _%$%hd214206214607%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl214207214609%_))
                                        (let ((_%$%e214208214612%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl214207214609%_))))
                                          (let ((_%$%tl214210214617%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e214208214612%_)))
                                                (_%$%hd214209214615%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e214208214612%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%hd214209214615%_))
                                                (let ((_%$%e214211214620%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%hd214209214615%_))))
                                                  (let ((_%$%tl214213214625%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e214211214620%_)))
                                                        (_%$%hd214212214623%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e214211214620%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#identifier?
                                                           _%$%hd214212214623%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-eq?
                                                               '%#ref
                                                               _%$%hd214212214623%_))
                                                            (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl214213214625%_))
                        (let ((_%$%e214214214628%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl214213214625%_))))
                          (let ((_%$%tl214216214633%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214214214628%_)))
                                (_%$%hd214215214631%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214214214628%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl214216214633%_))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair/null? _%$%tl214210214617%_))
                                    (let ((_%__splice217115217116%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#syntax-split-splice->vector
                                              _%$%tl214210214617%_
                                              '0))))
                                      (let ((_%$%tl214219214638%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice217115217116%_
                                                '1)))
                                            (_%$%target214217214636%_
                                             (let ()
                                               (declare (not safe))
                                               (##vector-ref
                                                _%__splice217115217116%_
                                                '0))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl214219214638%_))
                                            (letrec ((_%$%loop214220214641%_
                                                      (lambda (_%$%hd214218214644%_
                                                               _%$%xarg214224214646%_)
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%hd214218214644%_))
                                                            (let ((_%$%e214221214648%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%hd214218214644%_))))
                      (let ((_%$%lp-tl214223214653%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e214221214648%_)))
                            (_%$%lp-hd214222214651%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e214221214648%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%lp-hd214222214651%_))
                            (let ((_%$%e214226214656%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%lp-hd214222214651%_))))
                              (let ((_%$%tl214228214661%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e214226214656%_)))
                                    (_%$%hd214227214659%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e214226214656%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#identifier? _%$%hd214227214659%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-eq?
                                           '%#ref
                                           _%$%hd214227214659%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl214228214661%_))
                                            (let ((_%$%e214229214664%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl214228214661%_))))
                                              (let ((_%$%tl214231214669%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e214229214664%_)))
                                                    (_%$%hd214230214667%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e214229214664%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl214231214669%_))
                                                    (_%$%loop214220214641%_
                                                     _%$%lp-tl214223214653%_
                                                     (cons _%$%hd214230214667%_
                                                           _%$%xarg214224214646%_))
                                                    (_%__match217148217149%_
                                                     _%$%e214190214566%_
                                                     _%$%hd214191214569%_
                                                     _%$%tl214192214571%_
                                                     _%__splice217113217114%_
                                                     _%$%target214193214574%_
                                                     _%$%tl214195214576%_))))
                                            (_%__match217148217149%_
                                             _%$%e214190214566%_
                                             _%$%hd214191214569%_
                                             _%$%tl214192214571%_
                                             _%__splice217113217114%_
                                             _%$%target214193214574%_
                                             _%$%tl214195214576%_))
                                        (_%__match217148217149%_
                                         _%$%e214190214566%_
                                         _%$%hd214191214569%_
                                         _%$%tl214192214571%_
                                         _%__splice217113217114%_
                                         _%$%target214193214574%_
                                         _%$%tl214195214576%_))
                                    (_%__match217148217149%_
                                     _%$%e214190214566%_
                                     _%$%hd214191214569%_
                                     _%$%tl214192214571%_
                                     _%__splice217113217114%_
                                     _%$%target214193214574%_
                                     _%$%tl214195214576%_))))
                            (_%__match217148217149%_
                             _%$%e214190214566%_
                             _%$%hd214191214569%_
                             _%$%tl214192214571%_
                             _%__splice217113217114%_
                             _%$%target214193214574%_
                             _%$%tl214195214576%_))))
                    (let ((_%$%xarg214225214672%_
                           (reverse _%$%xarg214224214646%_)))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl214204214601%_))
                          (_%__kont217111217112%_
                           _%$%xarg214225214672%_
                           _%$%hd214215214631%_
                           _%$%arg214201214594%_)
                          (_%__match217148217149%_
                           _%$%e214190214566%_
                           _%$%hd214191214569%_
                           _%$%tl214192214571%_
                           _%__splice217113217114%_
                           _%$%target214193214574%_
                           _%$%tl214195214576%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%loop214220214641%_
                                               _%$%target214217214636%_
                                               '()))
                                            (_%__match217148217149%_
                                             _%$%e214190214566%_
                                             _%$%hd214191214569%_
                                             _%$%tl214192214571%_
                                             _%__splice217113217114%_
                                             _%$%target214193214574%_
                                             _%$%tl214195214576%_))))
                                    (_%__match217148217149%_
                                     _%$%e214190214566%_
                                     _%$%hd214191214569%_
                                     _%$%tl214192214571%_
                                     _%__splice217113217114%_
                                     _%$%target214193214574%_
                                     _%$%tl214195214576%_))
                                (_%__match217148217149%_
                                 _%$%e214190214566%_
                                 _%$%hd214191214569%_
                                 _%$%tl214192214571%_
                                 _%__splice217113217114%_
                                 _%$%target214193214574%_
                                 _%$%tl214195214576%_))))
                        (_%__match217148217149%_
                         _%$%e214190214566%_
                         _%$%hd214191214569%_
                         _%$%tl214192214571%_
                         _%__splice217113217114%_
                         _%$%target214193214574%_
                         _%$%tl214195214576%_))
                    (_%__match217148217149%_
                     _%$%e214190214566%_
                     _%$%hd214191214569%_
                     _%$%tl214192214571%_
                     _%__splice217113217114%_
                     _%$%target214193214574%_
                     _%$%tl214195214576%_))
                (_%__match217148217149%_
                 _%$%e214190214566%_
                 _%$%hd214191214569%_
                 _%$%tl214192214571%_
                 _%__splice217113217114%_
                 _%$%target214193214574%_
                 _%$%tl214195214576%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%__match217148217149%_
                                                 _%$%e214190214566%_
                                                 _%$%hd214191214569%_
                                                 _%$%tl214192214571%_
                                                 _%__splice217113217114%_
                                                 _%$%target214193214574%_
                                                 _%$%tl214195214576%_))))
                                        (_%__match217148217149%_
                                         _%$%e214190214566%_
                                         _%$%hd214191214569%_
                                         _%$%tl214192214571%_
                                         _%__splice217113217114%_
                                         _%$%target214193214574%_
                                         _%$%tl214195214576%_))
                                    (_%__match217148217149%_
                                     _%$%e214190214566%_
                                     _%$%hd214191214569%_
                                     _%$%tl214192214571%_
                                     _%__splice217113217114%_
                                     _%$%target214193214574%_
                                     _%$%tl214195214576%_))
                                (_%__match217148217149%_
                                 _%$%e214190214566%_
                                 _%$%hd214191214569%_
                                 _%$%tl214192214571%_
                                 _%__splice217113217114%_
                                 _%$%target214193214574%_
                                 _%$%tl214195214576%_))))
                        (_%__match217148217149%_
                         _%$%e214190214566%_
                         _%$%hd214191214569%_
                         _%$%tl214192214571%_
                         _%__splice217113217114%_
                         _%$%target214193214574%_
                         _%$%tl214195214576%_))))
                (_%__match217148217149%_
                 _%$%e214190214566%_
                 _%$%hd214191214569%_
                 _%$%tl214192214571%_
                 _%__splice217113217114%_
                 _%$%target214193214574%_
                 _%$%tl214195214576%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (_%$%loop214196214579%_
                                     _%$%target214193214574%_
                                     '())))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%__stx217109217110%_))
                              (let ((_%$%e214190214566%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%__stx217109217110%_))))
                                (let ((_%$%tl214192214571%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e214190214566%_)))
                                      (_%$%hd214191214569%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e214190214566%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%hd214191214569%_))
                                      (let ((_%__splice217113217114%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice->vector
                                                _%$%hd214191214569%_
                                                '0))))
                                        (let ((_%$%tl214195214576%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice217113217114%_
                                                  '1)))
                                              (_%$%target214193214574%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice217113217114%_
                                                  '0))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl214195214576%_))
                                              (_%__match217136217137%_
                                               _%$%e214190214566%_
                                               _%$%hd214191214569%_
                                               _%$%tl214192214571%_
                                               _%__splice217113217114%_
                                               _%$%target214193214574%_
                                               _%$%tl214195214576%_)
                                              (_%__match217148217149%_
                                               _%$%e214190214566%_
                                               _%$%hd214191214569%_
                                               _%$%tl214192214571%_
                                               _%__splice217113217114%_
                                               _%$%target214193214574%_
                                               _%$%tl214195214576%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl214192214571%_))
                                          (let ((_%$%e214278214322%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#stx-e
                                                    _%$%tl214192214571%_))))
                                            (let ((_%$%tl214280214327%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e214278214322%_)))
                                                  (_%$%hd214279214325%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e214278214322%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd214279214325%_))
                                                  (let ((_%$%e214281214330%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%hd214279214325%_))))
                                                    (let ((_%$%tl214283214335%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e214281214330%_)))
                                                          (_%$%hd214282214333%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e214281214330%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#identifier?
                                                             _%$%hd214282214333%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-eq? '%#call _%$%hd214282214333%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl214283214335%_))
                          (let ((_%$%e214284214338%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl214283214335%_))))
                            (let ((_%$%tl214286214343%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e214284214338%_)))
                                  (_%$%hd214285214341%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e214284214338%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%hd214285214341%_))
                                  (let ((_%$%e214287214346%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd214285214341%_))))
                                    (let ((_%$%tl214289214351%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e214287214346%_)))
                                          (_%$%hd214288214349%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e214287214346%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#identifier?
                                             _%$%hd214288214349%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#ref
                                                 _%$%hd214288214349%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl214289214351%_))
                                                  (let ((_%$%e214290214354%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl214289214351%_))))
                                                    (let ((_%$%tl214292214359%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e214290214354%_)))
                                                          (_%$%hd214291214357%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e214290214354%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl214292214359%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%tl214286214343%_))
                      (let ((_%$%e214293214362%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl214286214343%_))))
                        (let ((_%$%tl214295214367%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e214293214362%_)))
                              (_%$%hd214294214365%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e214293214362%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%hd214294214365%_))
                              (let ((_%$%e214296214370%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%hd214294214365%_))))
                                (let ((_%$%tl214298214375%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e214296214370%_)))
                                      (_%$%hd214297214373%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e214296214370%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#identifier? _%$%hd214297214373%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-eq?
                                             '%#ref
                                             _%$%hd214297214373%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl214298214375%_))
                                              (let ((_%$%e214299214378%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl214298214375%_))))
                                                (let ((_%$%tl214301214383%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e214299214378%_)))
                                                      (_%$%hd214300214381%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e214299214378%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl214301214383%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%tl214295214367%_))
                                                          (let ((_%$%e214302214386%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%tl214295214367%_))))
                    (let ((_%$%tl214304214391%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e214302214386%_)))
                          (_%$%hd214303214389%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e214302214386%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl214304214391%_))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl214280214327%_))
                              (_%__kont217121217122%_
                               _%$%hd214300214381%_
                               _%$%hd214291214357%_
                               _%$%hd214191214569%_)
                              (let ()
                                (declare (not safe))
                                (_%$%g214185214309%_)))
                          (let ()
                            (declare (not safe))
                            (_%$%g214185214309%_)))))
                  (let () (declare (not safe)) (_%$%g214185214309%_)))
              (let () (declare (not safe)) (_%$%g214185214309%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g214185214309%_)))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g214185214309%_)))
                                      (let ()
                                        (declare (not safe))
                                        (_%$%g214185214309%_)))))
                              (let ()
                                (declare (not safe))
                                (_%$%g214185214309%_)))))
                      (let () (declare (not safe)) (_%$%g214185214309%_)))
                  (let () (declare (not safe)) (_%$%g214185214309%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g214185214309%_)))
                                              (let ()
                                                (declare (not safe))
                                                (_%$%g214185214309%_)))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g214185214309%_)))))
                                  (let ()
                                    (declare (not safe))
                                    (_%$%g214185214309%_)))))
                          (let () (declare (not safe)) (_%$%g214185214309%_)))
                      (let () (declare (not safe)) (_%$%g214185214309%_)))
                  (let () (declare (not safe)) (_%$%g214185214309%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let ()
                                                    (declare (not safe))
                                                    (_%$%g214185214309%_)))))
                                          (let ()
                                            (declare (not safe))
                                            (_%$%g214185214309%_))))))
                              (let ()
                                (declare (not safe))
                                (_%$%g214185214309%_))))))))
                 (_%generate1214032%_
                  (lambda (_%args214163%_
                           _%arglen214164%_
                           _%hd214165%_
                           _%body214166%_)
                    (let* ((_%len214168%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-length _%hd214165%_)))
                           (_%condition214173%_
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-list? _%hd214165%_))
                                (if (gxc#current-compile-decls-unsafe?)
                                    (cons '##fx=
                                          (cons _%arglen214164%_
                                                (cons _%len214168%_ '())))
                                    (cons 'let
                                          (cons '()
                                                (cons '(declare (not safe))
                                                      (cons (cons '##fx=
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons _%arglen214164%_ (cons _%len214168%_ '())))
                    '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                (if (> _%len214168%_ '0)
                                    (if (gxc#current-compile-decls-unsafe?)
                                        (cons '##fx>=
                                              (cons _%arglen214164%_
                                                    (cons _%len214168%_ '())))
                                        (cons 'let
                                              (cons '()
                                                    (cons '(declare (not safe))
                                                          (cons (cons '##fx>=
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons _%arglen214164%_ (cons _%len214168%_ '())))
                        '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    '#t)))
                           (_%dispatch214175%_
                            (if (_%dispatch-case?214030%_
                                 _%hd214165%_
                                 _%body214166%_)
                                (_%dispatch-case-e214031%_
                                 _%hd214165%_
                                 _%body214166%_)
                                (gxc#generate-runtime-lambda-form
                                 _%self214027%_
                                 _%hd214165%_
                                 _%body214166%_))))
                      (cons _%condition214173%_
                            (cons (cons 'apply
                                        (cons _%dispatch214175%_
                                              (cons _%args214163%_ '())))
                                  '()))))))
          (let* ((_%$%g214034214062%_
                  (lambda (_%$%g214035214059%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g214035214059%_))))
                 (_%$%g214033214160%_
                  (lambda (_%$%g214035214065%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g214035214065%_))
                        (let ((_%$%e214038214067%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g214035214065%_))))
                          (let ((_%$%hd214039214070%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e214038214067%_)))
                                (_%$%tl214040214072%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e214038214067%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair/null? _%$%tl214040214072%_))
                                (let ((_g218276_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-split-splice
                                          _%$%tl214040214072%_
                                          '0))))
                                  (begin
                                    (let ((_g218277_
                                           (let ()
                                             (declare (not safe))
                                             (if (##values? _g218276_)
                                                 (##values-length _g218276_)
                                                 1))))
                                      (if (not (let ()
                                                 (declare (not safe))
                                                 (##fx= _g218277_ 2)))
                                          (error "Context expects 2 values"
                                                 _g218277_)))
                                    (let ((_%$%target214041214075%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g218276_ 0)))
                                          (_%$%tl214043214077%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g218276_ 1))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl214043214077%_))
                                          (letrec ((_%$%loop214044214080%_
                                                    (lambda (_%$%hd214042214083%_
                                                             _%$%body214048214085%_
                                                             _%$%hd214049214086%_)
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%hd214042214083%_))
                                                          (let ((_%$%e214045214088%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%hd214042214083%_))))
                    (let ((_%$%lp-hd214046214091%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e214045214088%_)))
                          (_%$%lp-tl214047214093%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e214045214088%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%lp-hd214046214091%_))
                          (let ((_%$%e214052214096%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%lp-hd214046214091%_))))
                            (let ((_%$%hd214053214099%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e214052214096%_)))
                                  (_%$%tl214054214101%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e214052214096%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl214054214101%_))
                                  (let ((_%$%e214055214104%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%tl214054214101%_))))
                                    (let ((_%$%hd214056214107%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e214055214104%_)))
                                          (_%$%tl214057214109%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e214055214104%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl214057214109%_))
                                          (_%$%loop214044214080%_
                                           _%$%lp-tl214047214093%_
                                           (cons _%$%hd214056214107%_
                                                 _%$%body214048214085%_)
                                           (cons _%$%hd214053214099%_
                                                 _%$%hd214049214086%_))
                                          (_%$%g214034214062%_
                                           _%$%g214035214065%_))))
                                  (_%$%g214034214062%_ _%$%g214035214065%_))))
                          (_%$%g214034214062%_ _%$%g214035214065%_))))
                  (let ((_%$%body214050214112%_
                         (reverse _%$%body214048214085%_))
                        (_%$%hd214051214113%_ (reverse _%$%hd214049214086%_)))
                    (let ((_%args214135%_
                           (let ()
                             (declare (not safe))
                             (gxc#generate-runtime-temporary__0)))
                          (_%arglen214136%_
                           (let ()
                             (declare (not safe))
                             (gxc#generate-runtime-temporary__0)))
                          (_%name214137%_
                           (let ((_%$e214132%_
                                  (let ((__tmp218278
                                         (let ()
                                           (declare (not safe))
                                           (gxc#current-compile-runtime-names))))
                                    (declare (not safe))
                                    (hash-get __tmp218278 _%stx214028%_))))
                             (if _%$e214132%_
                                 _%$e214132%_
                                 ''case-lambda-dispatch))))
                      (cons 'lambda
                            (cons _%args214135%_
                                  (cons (cons 'let
                                              (cons (cons (cons _%arglen214136%_
                                                                (cons (if (gxc#current-compile-decls-unsafe?)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                  (cons '##length (cons _%args214135%_ '()))
                                  (cons 'let
                                        (cons '()
                                              (cons '(declare (not safe))
                                                    (cons (cons '##length
                                                                (cons _%args214135%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '()))
                  '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                              '()))
                  '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons (cons 'cond
                                                                (let ((__tmp218280
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (map (lambda (_%$%g214138214141%_
                                             _%$%g214139214143%_)
                                      (_%generate1214032%_
                                       _%args214135%_
                                       _%arglen214136%_
                                       _%$%g214138214141%_
                                       _%$%g214139214143%_))
                                    (let ((__tmp218281
                                           (lambda (_%$%g214145214148%_
                                                    _%$%g214146214150%_)
                                             (cons _%$%g214145214148%_
                                                   _%$%g214146214150%_))))
                                      (declare (not safe))
                                      (foldr__0
                                       __tmp218281
                                       '()
                                       _%$%hd214051214113%_))
                                    (let ((__tmp218282
                                           (lambda (_%$%g214152214155%_
                                                    _%$%g214153214157%_)
                                             (cons _%$%g214152214155%_
                                                   _%$%g214153214157%_))))
                                      (declare (not safe))
                                      (foldr__0
                                       __tmp218282
                                       '()
                                       _%$%body214050214112%_))))
                              (__tmp218279
                               (cons (cons 'else
                                           (cons (cons '##raise-wrong-number-of-arguments-exception
                                                       (cons _%name214137%_
                                                             (cons _%args214135%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 '()))
                                     '())))
                          (declare (not safe))
                          (##append __tmp218280 __tmp218279)))
                  '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        '())))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%loop214044214080%_
                                             _%$%target214041214075%_
                                             '()
                                             '()))
                                          (_%$%g214034214062%_
                                           _%$%g214035214065%_)))))
                                (_%$%g214034214062%_ _%$%g214035214065%_))))
                        (_%$%g214034214062%_ _%$%g214035214065%_)))))
            (_%$%g214033214160%_ _%stx214028%_)))))
    (define gxc#generate-runtime-let-values%__%
      (lambda (_%self213264%_ _%stx213265%_ _%compiled-body?213266%_)
        (letrec ((_%generate-simple213268%_
                  (lambda (_%hd214012%_ _%body214013%_)
                    (_%coalesce-boolean213269%_
                     (_%simplify-let213270%_
                      (gxc#generate-runtime-simple-let
                       _%self213264%_
                       'let
                       _%hd214012%_
                       _%body214013%_
                       _%compiled-body?213266%_)))))
                 (_%coalesce-boolean213269%_
                  (lambda (_%code213873%_)
                    (if (let ()
                          (declare (not safe))
                          (gxc#current-compile-boolean-context))
                        (let* ((_%$%code213874213900%_ _%code213873%_)
                               (_%$%else213876213908%_
                                (lambda () _%code213873%_))
                               (_%$%K213878213945%_
                                (lambda (_%expr2213911%_
                                         _%expr1213912%_
                                         _%id213913%_)
                                  (let* ((_%$%expr2213914213922%_
                                          _%expr2213911%_)
                                         (_%$%else213916213930%_
                                          (lambda ()
                                            (cons 'or
                                                  (cons _%expr1213912%_
                                                        (cons _%expr2213911%_
                                                              '())))))
                                         (_%$%K213918213935%_
                                          (lambda (_%exprs213933%_)
                                            (cons 'or
                                                  (cons _%expr1213912%_
                                                        _%exprs213933%_)))))
                                    (if (pair? _%$%expr2213914213922%_)
                                        (let ((_%$%hd213919213938%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%expr2213914213922%_)))
                                              (_%$%tl213920213940%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%expr2213914213922%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (##eq? _%$%hd213919213938%_
                                                       'or))
                                              (let ((_%exprs213943%_
                                                     _%$%tl213920213940%_))
                                                (_%$%K213918213935%_
                                                 _%exprs213943%_))
                                              (_%$%else213916213930%_)))
                                        (_%$%else213916213930%_))))))
                          (if (pair? _%$%code213874213900%_)
                              (let ((_%$%hd213879213948%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%code213874213900%_)))
                                    (_%$%tl213880213950%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%code213874213900%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (##eq? _%$%hd213879213948%_ 'let))
                                    (if (pair? _%$%tl213880213950%_)
                                        (let ((_%$%hd213881213953%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%tl213880213950%_)))
                                              (_%$%tl213882213955%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%tl213880213950%_))))
                                          (if (pair? _%$%hd213881213953%_)
                                              (let ((_%$%hd213893213958%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%hd213881213953%_)))
                                                    (_%$%tl213894213960%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%hd213881213953%_))))
                                                (if (pair? _%$%hd213893213958%_)
                                                    (let ((_%$%hd213895213963%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%hd213893213958%_)))
                                                          (_%$%tl213896213965%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%hd213893213958%_))))
                                                      (let ((_%id213968%_
                                                             _%$%hd213895213963%_))
                                                        (if (pair? _%$%tl213896213965%_)
                                                            (let ((_%$%hd213897213970%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (##car _%$%tl213896213965%_)))
                          (_%$%tl213898213972%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%tl213896213965%_))))
                      (let ((_%expr1213975%_ _%$%hd213897213970%_))
                        (if (null? _%$%tl213898213972%_)
                            (if (null? _%$%tl213894213960%_)
                                (if (pair? _%$%tl213882213955%_)
                                    (let ((_%$%hd213883213977%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%tl213882213955%_)))
                                          (_%$%tl213884213979%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%tl213882213955%_))))
                                      (if (pair? _%$%hd213883213977%_)
                                          (let ((_%$%hd213885213982%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%hd213883213977%_)))
                                                (_%$%tl213886213984%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%hd213883213977%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##eq? _%$%hd213885213982%_
                                                         'if))
                                                (if (pair? _%$%tl213886213984%_)
                                                    (let ((_%$%hd213887213987%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%tl213886213984%_)))
                                                          (_%$%tl213888213989%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%tl213886213984%_))))
                                                      (if (eq? _%$%hd213887213987%_
                                                               _%id213968%_)
                                                          (if (pair? _%$%tl213888213989%_)
                                                              (let ((_%$%hd213889213996%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (let ()
                               (declare (not safe))
                               (##car _%$%tl213888213989%_)))
                            (_%$%tl213890213998%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%tl213888213989%_))))
                        (if (eq? _%$%hd213889213996%_ _%id213968%_)
                            (if (pair? _%$%tl213890213998%_)
                                (let ((_%$%hd213891214005%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%tl213890213998%_)))
                                      (_%$%tl213892214007%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%tl213890213998%_))))
                                  (let ((_%expr2214010%_ _%$%hd213891214005%_))
                                    (if (null? _%$%tl213892214007%_)
                                        (if (null? _%$%tl213884213979%_)
                                            (_%$%K213878213945%_
                                             _%expr2214010%_
                                             _%expr1213975%_
                                             _%id213968%_)
                                            (_%$%else213876213908%_))
                                        (_%$%else213876213908%_))))
                                (_%$%else213876213908%_))
                            (_%$%else213876213908%_)))
                      (_%$%else213876213908%_))
                  (_%$%else213876213908%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%else213876213908%_))
                                                (_%$%else213876213908%_)))
                                          (_%$%else213876213908%_)))
                                    (_%$%else213876213908%_))
                                (_%$%else213876213908%_))
                            (_%$%else213876213908%_))))
                    (_%$%else213876213908%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%else213876213908%_)))
                                              (_%$%else213876213908%_)))
                                        (_%$%else213876213908%_))
                                    (_%$%else213876213908%_)))
                              (_%$%else213876213908%_)))
                        _%code213873%_)))
                 (_%simplify-let213270%_
                  (lambda (_%code213572%_)
                    (let* ((_%$%code213573213645%_ _%code213572%_)
                           (_%$%else213578213653%_ (lambda () _%code213572%_)))
                      (let ((_%$%K213637213853%_
                             (lambda (_%expr213851%_) _%expr213851%_))
                            (_%$%K213620213799%_
                             (lambda (_%body213795%_
                                      _%expr213796%_
                                      _%id213797%_)
                               (cons 'let
                                     (cons (cons (cons _%id213797%_
                                                       (cons _%expr213796%_
                                                             '()))
                                                 '())
                                           _%body213795%_))))
                            (_%$%K213597213723%_
                             (lambda (_%body213717%_
                                      _%expr2213718%_
                                      _%id2213719%_
                                      _%expr1213720%_
                                      _%id1213721%_)
                               (cons 'let*
                                     (cons (cons (cons _%id1213721%_
                                                       (cons _%expr1213720%_
                                                             '()))
                                                 (cons (cons _%id2213719%_
                                                             (cons _%expr2213718%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '()))
               '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           _%body213717%_))))
                            (_%$%K213580213662%_
                             (lambda (_%body213657%_
                                      _%bind213658%_
                                      _%expr1213659%_
                                      _%id1213660%_)
                               (cons 'let*
                                     (cons (cons (cons _%id1213660%_
                                                       (cons _%expr1213659%_
                                                             '()))
                                                 _%bind213658%_)
                                           _%body213657%_)))))
                        (if (pair? _%$%code213573213645%_)
                            (let ((_%$%tl213639213858%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%code213573213645%_)))
                                  (_%$%hd213638213856%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%code213573213645%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (##eq? _%$%hd213638213856%_ 'let))
                                  (if (pair? _%$%tl213639213858%_)
                                      (let ((_%$%tl213641213863%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%tl213639213858%_)))
                                            (_%$%hd213640213861%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%tl213639213858%_))))
                                        (if (null? _%$%hd213640213861%_)
                                            (if (pair? _%$%tl213641213863%_)
                                                (let ((_%$%tl213643213868%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%tl213641213863%_)))
                                                      (_%$%hd213642213866%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%tl213641213863%_))))
                                                  (if (null? _%$%tl213643213868%_)
                                                      (let ((_%expr213871%_
                                                             _%$%hd213642213866%_))
                                                        (_%$%K213637213853%_
                                                         _%expr213871%_))
                                                      (_%$%else213578213653%_)))
                                                (_%$%else213578213653%_))
                                            (if (pair? _%$%hd213640213861%_)
                                                (let ((_%$%tl213632213814%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%hd213640213861%_)))
                                                      (_%$%hd213631213812%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%hd213640213861%_))))
                                                  (if (pair? _%$%hd213631213812%_)
                                                      (let ((_%$%tl213634213819%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%hd213631213812%_)))
                    (_%$%hd213633213817%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%hd213631213812%_))))
                (if (pair? _%$%tl213634213819%_)
                    (let ((_%$%tl213636213826%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%tl213634213819%_)))
                          (_%$%hd213635213824%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%tl213634213819%_))))
                      (if (null? _%$%tl213636213826%_)
                          (if (null? _%$%tl213632213814%_)
                              (if (pair? _%$%tl213641213863%_)
                                  (let ((_%$%tl213626213833%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%tl213641213863%_)))
                                        (_%$%hd213625213831%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%tl213641213863%_))))
                                    (if (pair? _%$%hd213625213831%_)
                                        (let ((_%$%tl213628213838%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%hd213625213831%_)))
                                              (_%$%hd213627213836%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%hd213625213831%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (##eq? _%$%hd213627213836%_
                                                       'let))
                                              (if (pair? _%$%tl213628213838%_)
                                                  (let ((_%$%tl213630213843%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%tl213628213838%_)))
                                                        (_%$%hd213629213841%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%tl213628213838%_))))
                                                    (if (null? _%$%hd213629213841%_)
                                                        (if (null? _%$%tl213626213833%_)
                                                            (let ((_%id213822%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%hd213633213817%_)
                          (_%expr213829%_ _%$%hd213635213824%_)
                          (_%body213846%_ _%$%tl213630213843%_))
                      (_%$%K213620213799%_
                       _%body213846%_
                       _%expr213829%_
                       _%id213822%_))
                    (_%$%else213578213653%_))
                (if (pair? _%$%hd213629213841%_)
                    (let ((_%$%tl213609213772%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%hd213629213841%_)))
                          (_%$%hd213608213770%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%hd213629213841%_))))
                      (if (pair? _%$%hd213608213770%_)
                          (let ((_%$%tl213611213777%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%hd213608213770%_)))
                                (_%$%hd213610213775%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%hd213608213770%_))))
                            (if (pair? _%$%tl213611213777%_)
                                (let ((_%$%tl213613213784%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%tl213611213777%_)))
                                      (_%$%hd213612213782%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%tl213611213777%_))))
                                  (if (null? _%$%tl213613213784%_)
                                      (if (null? _%$%tl213609213772%_)
                                          (if (null? _%$%tl213626213833%_)
                                              (let ((_%id1213746%_
                                                     _%$%hd213633213817%_)
                                                    (_%expr1213753%_
                                                     _%$%hd213635213824%_)
                                                    (_%id2213780%_
                                                     _%$%hd213610213775%_)
                                                    (_%expr2213787%_
                                                     _%$%hd213612213782%_)
                                                    (_%body213789%_
                                                     _%$%tl213630213843%_))
                                                (_%$%K213597213723%_
                                                 _%body213789%_
                                                 _%expr2213787%_
                                                 _%id2213780%_
                                                 _%expr1213753%_
                                                 _%id1213746%_))
                                              (_%$%else213578213653%_))
                                          (_%$%else213578213653%_))
                                      (_%$%else213578213653%_)))
                                (_%$%else213578213653%_)))
                          (_%$%else213578213653%_)))
                    (_%$%else213578213653%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%else213578213653%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (##eq? _%$%hd213627213836%_
                                                           'let*))
                                                  (if (pair? _%$%tl213628213838%_)
                                                      (let ((_%$%tl213590213706%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%tl213628213838%_)))
                    (_%$%hd213589213704%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%tl213628213838%_))))
                (if (null? _%$%tl213626213833%_)
                    (let ((_%id1213685%_ _%$%hd213633213817%_)
                          (_%expr1213692%_ _%$%hd213635213824%_)
                          (_%bind213709%_ _%$%hd213589213704%_)
                          (_%body213711%_ _%$%tl213590213706%_))
                      (_%$%K213580213662%_
                       _%body213711%_
                       _%bind213709%_
                       _%expr1213692%_
                       _%id1213685%_))
                    (_%$%else213578213653%_)))
              (_%$%else213578213653%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%else213578213653%_))))
                                        (_%$%else213578213653%_)))
                                  (_%$%else213578213653%_))
                              (_%$%else213578213653%_))
                          (_%$%else213578213653%_)))
                    (_%$%else213578213653%_)))
              (_%$%else213578213653%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%else213578213653%_))))
                                      (_%$%else213578213653%_))
                                  (_%$%else213578213653%_)))
                            (_%$%else213578213653%_))))))
                 (_%generate-values213271%_
                  (lambda (_%hd213385%_ _%body213386%_)
                    (let _%lp213388%_ ((_%rest213390%_ _%hd213385%_)
                                       (_%bind213391%_ '())
                                       (_%check213392%_ '())
                                       (_%post213393%_ '()))
                      (let* ((_%__stx217438217439%_ _%rest213390%_)
                             (_%$%g213396213407%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; invalid match target"
                                   _%__stx217438217439%_)))))
                        (let ((_%__kont217440217441%_
                               (lambda (_%$%g213398213434%_
                                        _%$%g213399213435%_)
                                 (let* ((_%__stx217394217395%_
                                         _%$%g213399213435%_)
                                        (_%$%g213450213475%_
                                         (lambda ()
                                           (let ()
                                             (declare (not safe))
                                             (gx#raise-syntax-error
                                              '#f
                                              '"Bad syntax; invalid match target"
                                              _%__stx217394217395%_)))))
                                   (let ((_%__kont217396217397%_
                                          (lambda (_%$%g213452213548%_
                                                   _%$%g213453213549%_)
                                            (let ((_%eid213563%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#generate-runtime-binding-id*
                                                      _%$%g213453213549%_)))
                                                  (_%expr213564%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#compile-e__1
                                                      _%self213264%_
                                                      _%$%g213452213548%_))))
                                              (_%lp213388%_
                                               _%$%g213398213434%_
                                               (cons (cons _%eid213563%_
                                                           (cons _%expr213564%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%bind213391%_)
                                               _%check213392%_
                                               _%post213393%_))))
                                         (_%__kont217398217399%_
                                          (lambda (_%$%g213463213496%_
                                                   _%$%g213464213497%_)
                                            (let* ((_%vals213510%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gxc#generate-runtime-temporary__0)))
                                                   (_%check-values213512%_
                                                    (gxc#generate-runtime-check-values
                                                     _%vals213510%_
                                                     _%$%g213464213497%_
                                                     _%$%g213463213496%_))
                                                   (_%refs213514%_
                                                    (gxc#generate-runtime-let-values-bind
                                                     _%vals213510%_
                                                     _%$%g213464213497%_))
                                                   (_%expr213516%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gxc#compile-e__1
                                                       _%self213264%_
                                                       _%$%g213463213496%_))))
                                              (_%lp213388%_
                                               _%$%g213398213434%_
                                               (cons (cons _%vals213510%_
                                                           (cons _%expr213516%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%bind213391%_)
                                               (cons _%check-values213512%_
                                                     _%check213392%_)
                                               (cons _%refs213514%_
                                                     _%post213393%_))))))
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-pair?
                                            _%__stx217394217395%_))
                                         (let ((_%$%e213454213524%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#stx-e
                                                   _%__stx217394217395%_))))
                                           (let ((_%$%tl213456213529%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e213454213524%_)))
                                                 (_%$%hd213455213527%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e213454213524%_))))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair?
                                                    _%$%hd213455213527%_))
                                                 (let ((_%$%e213457213532%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%$%hd213455213527%_))))
                                                   (let ((_%$%tl213459213537%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e213457213532%_)))
                                                         (_%$%hd213458213535%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e213457213532%_))))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-null?
                                                            _%$%tl213459213537%_))
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-pair? _%$%tl213456213529%_))
                     (let ((_%$%e213460213540%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%tl213456213529%_))))
                       (let ((_%$%tl213462213545%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%e213460213540%_)))
                             (_%$%hd213461213543%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%e213460213540%_))))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-null? _%$%tl213462213545%_))
                             (_%__kont217396217397%_
                              _%$%hd213461213543%_
                              _%$%hd213458213535%_)
                             (let ()
                               (declare (not safe))
                               (_%$%g213450213475%_)))))
                     (let () (declare (not safe)) (_%$%g213450213475%_)))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-pair? _%$%tl213456213529%_))
                     (let ((_%$%e213468213488%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%tl213456213529%_))))
                       (let ((_%$%tl213470213493%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%e213468213488%_)))
                             (_%$%hd213469213491%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%e213468213488%_))))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-null? _%$%tl213470213493%_))
                             (_%__kont217398217399%_
                              _%$%hd213469213491%_
                              _%$%hd213455213527%_)
                             (let ()
                               (declare (not safe))
                               (_%$%g213450213475%_)))))
                     (let () (declare (not safe)) (_%$%g213450213475%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-pair?
                                                        _%$%tl213456213529%_))
                                                     (let ((_%$%e213468213488%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%$%tl213456213529%_))))
                                                       (let ((_%$%tl213470213493%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##cdr _%$%e213468213488%_)))
                     (_%$%hd213469213491%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%e213468213488%_))))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-null? _%$%tl213470213493%_))
                     (_%__kont217398217399%_
                      _%$%hd213469213491%_
                      _%$%hd213455213527%_)
                     (let () (declare (not safe)) (_%$%g213450213475%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (let ()
                                                       (declare (not safe))
                                                       (_%$%g213450213475%_))))))
                                         (let ()
                                           (declare (not safe))
                                           (_%$%g213450213475%_)))))))
                              (_%__kont217442217443%_
                               (lambda ()
                                 (let* ((_%body213414%_
                                         (if _%compiled-body?213266%_
                                             _%body213386%_
                                             (let ()
                                               (declare (not safe))
                                               (gxc#compile-e__1
                                                _%self213264%_
                                                _%body213386%_))))
                                        (_%body213416%_
                                         (_%generate-values-post213272%_
                                          _%post213393%_
                                          _%body213414%_))
                                        (_%body213418%_
                                         (_%generate-values-check213273%_
                                          _%check213392%_
                                          _%body213416%_)))
                                   (cons 'let
                                         (cons (reverse _%bind213391%_)
                                               (cons _%body213418%_ '())))))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%__stx217438217439%_))
                              (let ((_%$%e213400213426%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%__stx217438217439%_))))
                                (let ((_%$%tl213402213431%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e213400213426%_)))
                                      (_%$%hd213401213429%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e213400213426%_))))
                                  (_%__kont217440217441%_
                                   _%$%tl213402213431%_
                                   _%$%hd213401213429%_)))
                              (_%__kont217442217443%_)))))))
                 (_%generate-values-post213272%_
                  (lambda (_%post213344%_ _%body213345%_)
                    (let _%lp213347%_ ((_%rest213349%_ _%post213344%_)
                                       (_%body213350%_ _%body213345%_))
                      (let* ((_%$%rest213351213359%_ _%rest213349%_)
                             (_%$%else213353213367%_
                              (lambda () _%body213350%_))
                             (_%$%K213355213373%_
                              (lambda (_%rest213370%_ _%bind213371%_)
                                (_%lp213347%_
                                 _%rest213370%_
                                 (cons 'let
                                       (cons _%bind213371%_
                                             (cons _%body213350%_ '())))))))
                        (if (pair? _%$%rest213351213359%_)
                            (let ((_%$%hd213356213376%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest213351213359%_)))
                                  (_%$%tl213357213378%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest213351213359%_))))
                              (let* ((_%bind213381%_ _%$%hd213356213376%_)
                                     (_%rest213383%_ _%$%tl213357213378%_))
                                (_%$%K213355213373%_
                                 _%rest213383%_
                                 _%bind213381%_)))
                            (_%$%else213353213367%_))))))
                 (_%generate-values-check213273%_
                  (lambda (_%check213341%_ _%body213342%_)
                    (cons 'begin
                          (let ((__tmp218284 (reverse _%check213341%_))
                                (__tmp218283 (cons _%body213342%_ '())))
                            (declare (not safe))
                            (##append __tmp218284 __tmp218283))))))
          (let* ((_%$%g213275213292%_
                  (lambda (_%$%g213276213289%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g213276213289%_))))
                 (_%$%g213274213338%_
                  (lambda (_%$%g213276213295%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g213276213295%_))
                        (let ((_%$%e213279213297%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g213276213295%_))))
                          (let ((_%$%hd213280213300%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e213279213297%_)))
                                (_%$%tl213281213302%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e213279213297%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl213281213302%_))
                                (let ((_%$%e213282213305%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl213281213302%_))))
                                  (let ((_%$%hd213283213308%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e213282213305%_)))
                                        (_%$%tl213284213310%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e213282213305%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl213284213310%_))
                                        (let ((_%$%e213285213313%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl213284213310%_))))
                                          (let ((_%$%hd213286213316%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e213285213313%_)))
                                                (_%$%tl213287213318%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e213285213313%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl213287213318%_))
                                                (if (gxc#generate-runtime-simple-let?
                                                     _%$%hd213283213308%_)
                                                    (_%generate-simple213268%_
                                                     _%$%hd213283213308%_
                                                     _%$%hd213286213316%_)
                                                    (_%generate-values213271%_
                                                     _%$%hd213283213308%_
                                                     _%$%hd213286213316%_))
                                                (_%$%g213275213292%_
                                                 _%$%g213276213295%_))))
                                        (_%$%g213275213292%_
                                         _%$%g213276213295%_))))
                                (_%$%g213275213292%_ _%$%g213276213295%_))))
                        (_%$%g213275213292%_ _%$%g213276213295%_)))))
            (_%$%g213274213338%_ _%stx213265%_)))))
    (define gxc#generate-runtime-let-values%__0
      (lambda (_%self214018%_ _%stx214019%_)
        (let ((_%compiled-body?214021%_ '#f))
          (gxc#generate-runtime-let-values%__%
           _%self214018%_
           _%stx214019%_
           _%compiled-body?214021%_))))
    (define gxc#generate-runtime-let-values%
      (lambda _g218285_
        (let ((_g218286_ (let () (declare (not safe)) (##length _g218285_))))
          (cond ((let () (declare (not safe)) (##fx= _g218286_ 2))
                 (apply gxc#generate-runtime-let-values%__0 _g218285_))
                ((let () (declare (not safe)) (##fx= _g218286_ 3))
                 (apply gxc#generate-runtime-let-values%__% _g218285_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#generate-runtime-let-values%
                  _g218285_))))))
    (define gxc#generate-runtime-let-values-bind
      (lambda (_%vals213158%_ _%hd213159%_)
        (let _%lp213161%_ ((_%rest213163%_ _%hd213159%_)
                           (_%k213164%_ '0)
                           (_%r213165%_ '()))
          (let* ((_%__stx217452217453%_ _%rest213163%_)
                 (_%$%g213170213187%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%__stx217452217453%_)))))
            (let ((_%__kont217454217455%_
                   (lambda (_%$%g213172213250%_)
                     (_%lp213161%_
                      _%$%g213172213250%_
                      (let () (declare (not safe)) (##fx+ _%k213164%_ '1))
                      _%r213165%_)))
                  (_%__kont217456217457%_
                   (lambda (_%$%g213177213223%_ _%$%g213178213224%_)
                     (_%lp213161%_
                      _%$%g213177213223%_
                      (let () (declare (not safe)) (##fx+ _%k213164%_ '1))
                      (cons (cons (let ()
                                    (declare (not safe))
                                    (gxc#generate-runtime-binding-id
                                     _%$%g213178213224%_))
                                  (cons (gxc#generate-runtime-values-ref
                                         _%vals213158%_
                                         _%k213164%_
                                         _%$%g213177213223%_)
                                        '()))
                            _%r213165%_))))
                  (_%__kont217458217459%_
                   (lambda (_%$%g213182213199%_)
                     (let ((__tmp218287
                            (cons (cons (let ()
                                          (declare (not safe))
                                          (gxc#generate-runtime-binding-id
                                           _%$%g213182213199%_))
                                        (cons (gxc#generate-runtime-values->list
                                               _%vals213158%_
                                               _%k213164%_)
                                              '()))
                                  '())))
                       (declare (not safe))
                       (foldl__0 cons __tmp218287 _%r213165%_))))
                  (_%__kont217460217461%_ (lambda () (reverse _%r213165%_))))
              (let ((_%$%g213168213210%_
                     (lambda ()
                       (let ((_%$%g213182213199%_ _%__stx217452217453%_))
                         (if (let ()
                               (declare (not safe))
                               (gx#identifier? _%$%g213182213199%_))
                             (_%__kont217458217459%_ _%$%g213182213199%_)
                             (_%__kont217460217461%_))))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%__stx217452217453%_))
                    (let ((_%$%e213173213239%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%__stx217452217453%_))))
                      (let ((_%$%tl213175213244%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e213173213239%_)))
                            (_%$%hd213174213242%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e213173213239%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-datum? _%$%hd213174213242%_))
                            (let ((_%$%e213176213247%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%hd213174213242%_))))
                              (if (equal? _%$%e213176213247%_ '#f)
                                  (_%__kont217454217455%_ _%$%tl213175213244%_)
                                  (_%__kont217456217457%_
                                   _%$%tl213175213244%_
                                   _%$%hd213174213242%_)))
                            (_%__kont217456217457%_
                             _%$%tl213175213244%_
                             _%$%hd213174213242%_))))
                    (let () (declare (not safe)) (_%$%g213168213210%_)))))))))
    (define gxc#generate-runtime-letrec-values%__%
      (lambda (_%self212837%_ _%stx212838%_ _%compiled-body?212839%_)
        (letrec ((_%generate-simple212841%_
                  (lambda (_%hd213143%_ _%body213144%_)
                    (gxc#generate-runtime-simple-let
                     _%self212837%_
                     'letrec
                     _%hd213143%_
                     _%body213144%_
                     _%compiled-body?212839%_)))
                 (_%generate-values212842%_
                  (lambda (_%hd212922%_ _%body212923%_)
                    (let _%lp212925%_ ((_%rest212927%_ _%hd212922%_)
                                       (_%bind212928%_ '())
                                       (_%check212929%_ '())
                                       (_%post212930%_ '()))
                      (let* ((_%__stx217526217527%_ _%rest212927%_)
                             (_%$%g212933212944%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; invalid match target"
                                   _%__stx217526217527%_)))))
                        (let ((_%__kont217528217529%_
                               (lambda (_%$%g212935212971%_
                                        _%$%g212936212972%_)
                                 (let* ((_%__stx217482217483%_
                                         _%$%g212936212972%_)
                                        (_%$%g212987213012%_
                                         (lambda ()
                                           (let ()
                                             (declare (not safe))
                                             (gx#raise-syntax-error
                                              '#f
                                              '"Bad syntax; invalid match target"
                                              _%__stx217482217483%_)))))
                                   (let ((_%__kont217484217485%_
                                          (lambda (_%$%g212989213119%_
                                                   _%$%g212990213120%_)
                                            (let ((_%eid213134%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#generate-runtime-binding-id*
                                                      _%$%g212990213120%_)))
                                                  (_%expr213135%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#compile-e__1
                                                      _%self212837%_
                                                      _%$%g212989213119%_))))
                                              (_%lp212925%_
                                               _%$%g212935212971%_
                                               (cons (cons _%eid213134%_
                                                           (cons _%expr213135%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     _%bind212928%_)
                                               _%check212929%_
                                               _%post212930%_))))
                                         (_%__kont217486217487%_
                                          (lambda (_%$%g213000213033%_
                                                   _%$%g213001213034%_)
                                            (let* ((_%vals213047%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gxc#generate-runtime-temporary__0)))
                                                   (_%check-values213049%_
                                                    (gxc#generate-runtime-check-values
                                                     _%vals213047%_
                                                     _%$%g213001213034%_
                                                     _%$%g213000213033%_))
                                                   (_%refs213051%_
                                                    (gxc#generate-runtime-let-values-bind
                                                     _%vals213047%_
                                                     _%$%g213001213034%_))
                                                   (_%expr213053%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gxc#compile-e__1
                                                       _%self212837%_
                                                       _%$%g213000213033%_))))
                                              (_%lp212925%_
                                               _%$%g212935212971%_
                                               (let ((__tmp218289
                                                      (cons (cons _%vals213047%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons _%expr213053%_ '()))
                    _%bind212928%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (__tmp218288
                                                      (map (lambda (_%$%e213055213057%_)
                                                             (let* ((_%$%$%e213055213059213068%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%$%e213055213057%_)
                            (_%$%E213061213072%_
                             (lambda ()
                               (let ()
                                 (declare (not safe))
                                 (error '"No clause matching"
                                        _%$%$%e213055213059213068%_
                                        '([eid _])))
                               '#!void))
                            (_%$%K213062213077%_
                             (lambda (_%eid213075%_)
                               (cons _%eid213075%_ (cons '#!void '())))))
                       (if (pair? _%$%$%e213055213059213068%_)
                           (let ((_%$%hd213063213080%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%$%e213055213059213068%_)))
                                 (_%$%tl213064213082%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%$%e213055213059213068%_))))
                             (let ((_%eid213085%_ _%$%hd213063213080%_))
                               (if (pair? _%$%tl213064213082%_)
                                   (let ((_%$%tl213066213087%_
                                          (let ()
                                            (declare (not safe))
                                            (##cdr _%$%tl213064213082%_))))
                                     (if (null? _%$%tl213066213087%_)
                                         (_%$%K213062213077%_ _%eid213085%_)
                                         (_%$%E213061213072%_)))
                                   (_%$%E213061213072%_))))
                           (_%$%E213061213072%_))))
                   _%refs213051%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (declare (not safe))
                                                 (foldl__0
                                                  cons
                                                  __tmp218289
                                                  __tmp218288))
                                               (cons _%check-values213049%_
                                                     _%check212929%_)
                                               (let ()
                                                 (declare (not safe))
                                                 (foldl__0
                                                  cons
                                                  _%refs213051%_
                                                  _%post212930%_)))))))
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-pair?
                                            _%__stx217482217483%_))
                                         (let ((_%$%e212991213095%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#stx-e
                                                   _%__stx217482217483%_))))
                                           (let ((_%$%tl212993213100%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e212991213095%_)))
                                                 (_%$%hd212992213098%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e212991213095%_))))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair?
                                                    _%$%hd212992213098%_))
                                                 (let ((_%$%e212994213103%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%$%hd212992213098%_))))
                                                   (let ((_%$%tl212996213108%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e212994213103%_)))
                                                         (_%$%hd212995213106%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e212994213103%_))))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-null?
                                                            _%$%tl212996213108%_))
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-pair? _%$%tl212993213100%_))
                     (let ((_%$%e212997213111%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%tl212993213100%_))))
                       (let ((_%$%tl212999213116%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%e212997213111%_)))
                             (_%$%hd212998213114%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%e212997213111%_))))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-null? _%$%tl212999213116%_))
                             (_%__kont217484217485%_
                              _%$%hd212998213114%_
                              _%$%hd212995213106%_)
                             (let ()
                               (declare (not safe))
                               (_%$%g212987213012%_)))))
                     (let () (declare (not safe)) (_%$%g212987213012%_)))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-pair? _%$%tl212993213100%_))
                     (let ((_%$%e213005213025%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%tl212993213100%_))))
                       (let ((_%$%tl213007213030%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%e213005213025%_)))
                             (_%$%hd213006213028%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%e213005213025%_))))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-null? _%$%tl213007213030%_))
                             (_%__kont217486217487%_
                              _%$%hd213006213028%_
                              _%$%hd212992213098%_)
                             (let ()
                               (declare (not safe))
                               (_%$%g212987213012%_)))))
                     (let () (declare (not safe)) (_%$%g212987213012%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-pair?
                                                        _%$%tl212993213100%_))
                                                     (let ((_%$%e213005213025%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%$%tl212993213100%_))))
                                                       (let ((_%$%tl213007213030%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##cdr _%$%e213005213025%_)))
                     (_%$%hd213006213028%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%e213005213025%_))))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-null? _%$%tl213007213030%_))
                     (_%__kont217486217487%_
                      _%$%hd213006213028%_
                      _%$%hd212992213098%_)
                     (let () (declare (not safe)) (_%$%g212987213012%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (let ()
                                                       (declare (not safe))
                                                       (_%$%g212987213012%_))))))
                                         (let ()
                                           (declare (not safe))
                                           (_%$%g212987213012%_)))))))
                              (_%__kont217530217531%_
                               (lambda ()
                                 (let* ((_%body212951%_
                                         (if _%compiled-body?212839%_
                                             _%body212923%_
                                             (let ()
                                               (declare (not safe))
                                               (gxc#compile-e__1
                                                _%self212837%_
                                                _%body212923%_))))
                                        (_%body212953%_
                                         (_%generate-values-post212844%_
                                          _%post212930%_
                                          _%body212951%_))
                                        (_%body212955%_
                                         (_%generate-values-check212843%_
                                          _%check212929%_
                                          _%body212953%_)))
                                   (cons 'letrec
                                         (cons (reverse _%bind212928%_)
                                               (cons _%body212955%_ '())))))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%__stx217526217527%_))
                              (let ((_%$%e212937212963%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%__stx217526217527%_))))
                                (let ((_%$%tl212939212968%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e212937212963%_)))
                                      (_%$%hd212938212966%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e212937212963%_))))
                                  (_%__kont217528217529%_
                                   _%$%tl212939212968%_
                                   _%$%hd212938212966%_)))
                              (_%__kont217530217531%_)))))))
                 (_%generate-values-check212843%_
                  (lambda (_%check212919%_ _%body212920%_)
                    (cons 'begin
                          (let ((__tmp218291 (reverse _%check212919%_))
                                (__tmp218290 (cons _%body212920%_ '())))
                            (declare (not safe))
                            (##append __tmp218291 __tmp218290)))))
                 (_%generate-values-post212844%_
                  (lambda (_%post212912%_ _%body212913%_)
                    (cons 'begin
                          (let ((__tmp218293
                                 (let ((__tmp218295
                                        (lambda (_%$%g212914212916%_)
                                          (cons 'set! _%$%g212914212916%_)))
                                       (__tmp218294 (reverse _%post212912%_)))
                                   (declare (not safe))
                                   (##map __tmp218295 __tmp218294)))
                                (__tmp218292 (cons _%body212913%_ '())))
                            (declare (not safe))
                            (##append __tmp218293 __tmp218292))))))
          (let* ((_%$%g212846212863%_
                  (lambda (_%$%g212847212860%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g212847212860%_))))
                 (_%$%g212845212909%_
                  (lambda (_%$%g212847212866%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g212847212866%_))
                        (let ((_%$%e212850212868%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g212847212866%_))))
                          (let ((_%$%hd212851212871%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e212850212868%_)))
                                (_%$%tl212852212873%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e212850212868%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl212852212873%_))
                                (let ((_%$%e212853212876%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl212852212873%_))))
                                  (let ((_%$%hd212854212879%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e212853212876%_)))
                                        (_%$%tl212855212881%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e212853212876%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl212855212881%_))
                                        (let ((_%$%e212856212884%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl212855212881%_))))
                                          (let ((_%$%hd212857212887%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e212856212884%_)))
                                                (_%$%tl212858212889%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e212856212884%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl212858212889%_))
                                                (if (gxc#generate-runtime-simple-let?
                                                     _%$%hd212854212879%_)
                                                    (_%generate-simple212841%_
                                                     _%$%hd212854212879%_
                                                     _%$%hd212857212887%_)
                                                    (_%generate-values212842%_
                                                     _%$%hd212854212879%_
                                                     _%$%hd212857212887%_))
                                                (_%$%g212846212863%_
                                                 _%$%g212847212866%_))))
                                        (_%$%g212846212863%_
                                         _%$%g212847212866%_))))
                                (_%$%g212846212863%_ _%$%g212847212866%_))))
                        (_%$%g212846212863%_ _%$%g212847212866%_)))))
            (_%$%g212845212909%_ _%stx212838%_)))))
    (define gxc#generate-runtime-letrec-values%__0
      (lambda (_%self213149%_ _%stx213150%_)
        (let ((_%compiled-body?213152%_ '#f))
          (gxc#generate-runtime-letrec-values%__%
           _%self213149%_
           _%stx213150%_
           _%compiled-body?213152%_))))
    (define gxc#generate-runtime-letrec-values%
      (lambda _g218296_
        (let ((_g218297_ (let () (declare (not safe)) (##length _g218296_))))
          (cond ((let () (declare (not safe)) (##fx= _g218297_ 2))
                 (apply gxc#generate-runtime-letrec-values%__0 _g218296_))
                ((let () (declare (not safe)) (##fx= _g218297_ 3))
                 (apply gxc#generate-runtime-letrec-values%__% _g218296_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#generate-runtime-letrec-values%
                  _g218296_))))))
    (define gxc#generate-runtime-letrec*-values%
      (lambda (_%self212418%_ _%stx212419%_)
        (letrec ((_%generate-values212421%_
                  (lambda (_%hd212664%_ _%body212665%_)
                    (let _%lp212667%_ ((_%rest212669%_ _%hd212664%_)
                                       (_%bind212670%_ '()))
                      (let* ((_%$%rest212671212679%_ _%rest212669%_)
                             (_%$%else212673212690%_
                              (lambda ()
                                (let ((_%bind212687%_ (reverse _%bind212670%_))
                                      (_%body212688%_
                                       (let ()
                                         (declare (not safe))
                                         (gxc#compile-e__1
                                          _%self212418%_
                                          _%body212665%_))))
                                  (cons 'letrec*
                                        (cons _%bind212687%_
                                              (cons _%body212688%_ '()))))))
                             (_%$%K212675212824%_
                              (lambda (_%rest212693%_ _%hd-bind212694%_)
                                (let* ((_%__stx217540217541%_
                                        _%hd-bind212694%_)
                                       (_%$%g212697212722%_
                                        (lambda ()
                                          (let ()
                                            (declare (not safe))
                                            (gx#raise-syntax-error
                                             '#f
                                             '"Bad syntax; invalid match target"
                                             _%__stx217540217541%_)))))
                                  (let ((_%__kont217542217543%_
                                         (lambda (_%$%g212699212803%_
                                                  _%$%g212700212804%_)
                                           (let ((_%eid212818%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#generate-runtime-binding-id*
                                                     _%$%g212700212804%_)))
                                                 (_%expr212819%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#compile-e__1
                                                     _%self212418%_
                                                     _%$%g212699212803%_))))
                                             (_%lp212667%_
                                              _%rest212693%_
                                              (cons (cons _%eid212818%_
                                                          (cons _%expr212819%_
                                                                '()))
                                                    _%bind212670%_)))))
                                        (_%__kont217544217545%_
                                         (lambda (_%$%g212710212743%_
                                                  _%$%g212711212744%_)
                                           (let* ((_%vals212763%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#generate-runtime-temporary__0)))
                                                  (_%tmp212765%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#generate-runtime-temporary__0)))
                                                  (_%check-values212767%_
                                                   (gxc#generate-runtime-check-values
                                                    _%tmp212765%_
                                                    _%$%g212711212744%_
                                                    _%$%g212710212743%_))
                                                  (_%refs212769%_
                                                   (gxc#generate-runtime-let-values-bind
                                                    _%vals212763%_
                                                    _%$%g212711212744%_))
                                                  (_%expr212771%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#compile-e__1
                                                      _%self212418%_
                                                      _%$%g212710212743%_))))
                                             (_%lp212667%_
                                              _%rest212693%_
                                              (let ((__tmp218298
                                                     (cons (cons _%vals212763%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (cons 'let
                                     (cons (cons (cons _%tmp212765%_
                                                       (cons _%expr212771%_
                                                             '()))
                                                 '())
                                           (cons _%check-values212767%_
                                                 (cons _%tmp212765%_ '()))))
                               '()))
                   _%bind212670%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (declare (not safe))
                                                (foldl__0
                                                 cons
                                                 __tmp218298
                                                 _%refs212769%_)))))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%__stx217540217541%_))
                                        (let ((_%$%e212701212779%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%__stx217540217541%_))))
                                          (let ((_%$%tl212703212784%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e212701212779%_)))
                                                (_%$%hd212702212782%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e212701212779%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%hd212702212782%_))
                                                (let ((_%$%e212704212787%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%hd212702212782%_))))
                                                  (let ((_%$%tl212706212792%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e212704212787%_)))
                                                        (_%$%hd212705212790%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e212704212787%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl212706212792%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%tl212703212784%_))
                                                            (let ((_%$%e212707212795%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl212703212784%_))))
                      (let ((_%$%tl212709212800%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e212707212795%_)))
                            (_%$%hd212708212798%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e212707212795%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl212709212800%_))
                            (_%__kont217542217543%_
                             _%$%hd212708212798%_
                             _%$%hd212705212790%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g212697212722%_)))))
                    (let () (declare (not safe)) (_%$%g212697212722%_)))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%$%tl212703212784%_))
                    (let ((_%$%e212715212735%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl212703212784%_))))
                      (let ((_%$%tl212717212740%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e212715212735%_)))
                            (_%$%hd212716212738%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e212715212735%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl212717212740%_))
                            (_%__kont217544217545%_
                             _%$%hd212716212738%_
                             _%$%hd212702212782%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g212697212722%_)))))
                    (let () (declare (not safe)) (_%$%g212697212722%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%tl212703212784%_))
                                                    (let ((_%$%e212715212735%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%tl212703212784%_))))
                                                      (let ((_%$%tl212717212740%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e212715212735%_)))
                    (_%$%hd212716212738%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e212715212735%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl212717212740%_))
                    (_%__kont217544217545%_
                     _%$%hd212716212738%_
                     _%$%hd212702212782%_)
                    (let () (declare (not safe)) (_%$%g212697212722%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g212697212722%_))))))
                                        (let ()
                                          (declare (not safe))
                                          (_%$%g212697212722%_))))))))
                        (if (pair? _%$%rest212671212679%_)
                            (let ((_%$%hd212676212827%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest212671212679%_)))
                                  (_%$%tl212677212829%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest212671212679%_))))
                              (let* ((_%hd-bind212832%_ _%$%hd212676212827%_)
                                     (_%rest212834%_ _%$%tl212677212829%_))
                                (_%$%K212675212824%_
                                 _%rest212834%_
                                 _%hd-bind212832%_)))
                            (_%$%else212673212690%_))))))
                 (_%generate-letrec?212422%_
                  (lambda (_%hd212554%_)
                    (let _%lp212556%_ ((_%rest212558%_ _%hd212554%_))
                      (let* ((_%$%rest212559212567%_ _%rest212558%_)
                             (_%$%else212561212575%_ (lambda () '#t))
                             (_%$%K212563212652%_
                              (lambda (_%rest212578%_ _%hd-bind212579%_)
                                (let* ((_%$%g212581212598%_
                                        (lambda (_%$%g212582212595%_)
                                          (let ()
                                            (declare (not safe))
                                            (gx#raise-syntax-error
                                             '#f
                                             '"Bad syntax; invalid match target"
                                             _%$%g212582212595%_))))
                                       (_%$%g212580212649%_
                                        (lambda (_%$%g212582212601%_)
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%g212582212601%_))
                                              (let ((_%$%e212585212603%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%g212582212601%_))))
                                                (let ((_%$%hd212586212606%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e212585212603%_)))
                                                      (_%$%tl212587212608%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e212585212603%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%hd212586212606%_))
                                                      (let ((_%$%e212588212611%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%hd212586212606%_))))
                (let ((_%$%hd212589212614%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e212588212611%_)))
                      (_%$%tl212590212616%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e212588212611%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl212590212616%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl212587212608%_))
                          (let ((_%$%e212591212619%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl212587212608%_))))
                            (let ((_%$%hd212592212622%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e212591212619%_)))
                                  (_%$%tl212593212624%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e212591212619%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl212593212624%_))
                                  (if (_%is-lambda-expr?212423%_
                                       _%$%hd212592212622%_)
                                      (_%lp212556%_ _%rest212578%_)
                                      '#f)
                                  (_%$%g212581212598%_ _%$%g212582212601%_))))
                          (_%$%g212581212598%_ _%$%g212582212601%_))
                      (_%$%g212581212598%_ _%$%g212582212601%_))))
              (_%$%g212581212598%_ _%$%g212582212601%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g212581212598%_
                                               _%$%g212582212601%_)))))
                                  (_%$%g212580212649%_ _%hd-bind212579%_)))))
                        (if (pair? _%$%rest212559212567%_)
                            (let ((_%$%hd212564212655%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%rest212559212567%_)))
                                  (_%$%tl212565212657%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%rest212559212567%_))))
                              (let* ((_%hd-bind212660%_ _%$%hd212564212655%_)
                                     (_%rest212662%_ _%$%tl212565212657%_))
                                (_%$%K212563212652%_
                                 _%rest212662%_
                                 _%hd-bind212660%_)))
                            (_%$%else212561212575%_))))))
                 (_%is-lambda-expr?212423%_
                  (lambda (_%expr212491%_)
                    (let* ((_%__stx217584217585%_ _%expr212491%_)
                           (_%$%g212494212508%_
                            (lambda ()
                              (let ()
                                (declare (not safe))
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; invalid match target"
                                 _%__stx217584217585%_)))))
                      (let ((_%__kont217586217587%_
                             (lambda (_%$%g212496212536%_ _%$%g212497212537%_)
                               '#t))
                            (_%__kont217588217589%_ (lambda () '#f)))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%__stx217584217585%_))
                            (let ((_%$%e212498212520%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%__stx217584217585%_))))
                              (let ((_%$%tl212500212525%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e212498212520%_)))
                                    (_%$%hd212499212523%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e212498212520%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#identifier? _%$%hd212499212523%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-eq?
                                           '%#lambda
                                           _%$%hd212499212523%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl212500212525%_))
                                            (let ((_%$%e212501212528%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl212500212525%_))))
                                              (let ((_%$%tl212503212533%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e212501212528%_)))
                                                    (_%$%hd212502212531%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e212501212528%_))))
                                                (_%__kont217586217587%_
                                                 _%$%tl212503212533%_
                                                 _%$%hd212502212531%_)))
                                            (_%__kont217588217589%_))
                                        (_%__kont217588217589%_))
                                    (_%__kont217588217589%_))))
                            (_%__kont217588217589%_)))))))
          (let* ((_%$%g212425212442%_
                  (lambda (_%$%g212426212439%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g212426212439%_))))
                 (_%$%g212424212488%_
                  (lambda (_%$%g212426212445%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g212426212445%_))
                        (let ((_%$%e212429212447%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g212426212445%_))))
                          (let ((_%$%hd212430212450%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e212429212447%_)))
                                (_%$%tl212431212452%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e212429212447%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl212431212452%_))
                                (let ((_%$%e212432212455%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl212431212452%_))))
                                  (let ((_%$%hd212433212458%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e212432212455%_)))
                                        (_%$%tl212434212460%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e212432212455%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl212434212460%_))
                                        (let ((_%$%e212435212463%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl212434212460%_))))
                                          (let ((_%$%hd212436212466%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e212435212463%_)))
                                                (_%$%tl212437212468%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e212435212463%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl212437212468%_))
                                                (if (gxc#generate-runtime-simple-let?
                                                     _%$%hd212433212458%_)
                                                    (if (_%generate-letrec?212422%_
                                                         _%$%hd212433212458%_)
                                                        (gxc#generate-runtime-simple-let
                                                         _%self212418%_
                                                         'letrec
                                                         _%$%hd212433212458%_
                                                         _%$%hd212436212466%_
                                                         '#f)
                                                        (gxc#generate-runtime-simple-let
                                                         _%self212418%_
                                                         'letrec*
                                                         _%$%hd212433212458%_
                                                         _%$%hd212436212466%_
                                                         '#f))
                                                    (_%generate-values212421%_
                                                     _%$%hd212433212458%_
                                                     _%$%hd212436212466%_))
                                                (_%$%g212425212442%_
                                                 _%$%g212426212445%_))))
                                        (_%$%g212425212442%_
                                         _%$%g212426212445%_))))
                                (_%$%g212425212442%_ _%$%g212426212445%_))))
                        (_%$%g212425212442%_ _%$%g212426212445%_)))))
            (_%$%g212424212488%_ _%stx212419%_)))))
    (define gxc#generate-runtime-simple-let?
      (lambda (_%hd212355%_)
        (let _%lp212357%_ ((_%rest212359%_ _%hd212355%_))
          (let* ((_%$%rest212360212376%_ _%rest212359%_)
                 (_%$%else212363212384%_ (lambda () '#f)))
            (let ((_%$%K212366212397%_
                   (lambda (_%rest212395%_) (_%lp212357%_ _%rest212395%_)))
                  (_%$%K212365212389%_ (lambda () '#t)))
              (let ((_%$%try-match212362212392%_
                     (lambda ()
                       (if (null? _%$%rest212360212376%_)
                           (_%$%K212365212389%_)
                           (_%$%else212363212384%_)))))
                (if (pair? _%$%rest212360212376%_)
                    (let ((_%$%tl212368212402%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%rest212360212376%_)))
                          (_%$%hd212367212400%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%rest212360212376%_))))
                      (if (pair? _%$%hd212367212400%_)
                          (let ((_%$%tl212370212407%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%hd212367212400%_)))
                                (_%$%hd212369212405%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%hd212367212400%_))))
                            (if (pair? _%$%hd212369212405%_)
                                (let ((_%$%tl212374212410%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%hd212369212405%_))))
                                  (if (null? _%$%tl212374212410%_)
                                      (if (pair? _%$%tl212370212407%_)
                                          (let ((_%$%tl212372212413%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%tl212370212407%_))))
                                            (if (null? _%$%tl212372212413%_)
                                                (let ((_%rest212416%_
                                                       _%$%tl212368212402%_))
                                                  (_%lp212357%_
                                                   _%rest212416%_))
                                                (_%$%else212363212384%_)))
                                          (_%$%else212363212384%_))
                                      (_%$%else212363212384%_)))
                                (_%$%else212363212384%_)))
                          (_%$%else212363212384%_)))
                    (_%$%try-match212362212392%_))))))))
    (define gxc#generate-runtime-simple-let
      (lambda (_%self212267%_
               _%form212268%_
               _%hd212269%_
               _%body212270%_
               _%compiled-body?212271%_)
        (letrec ((_%generate1212273%_
                  (lambda (_%bind212312%_)
                    (let* ((_%$%bind212313212324%_ _%bind212312%_)
                           (_%$%E212315212327%_
                            (lambda ()
                              (let ()
                                (declare (not safe))
                                (error '"No clause matching"
                                       _%$%bind212313212324%_
                                       '([[id] expr])))
                              '#!void))
                           (_%$%K212316212333%_
                            (lambda (_%expr212330%_ _%id212331%_)
                              (cons (let ()
                                      (declare (not safe))
                                      (gxc#generate-runtime-binding-id*
                                       _%id212331%_))
                                    (cons (let ()
                                            (declare (not safe))
                                            (gxc#compile-e__1
                                             _%self212267%_
                                             _%expr212330%_))
                                          '())))))
                      (if (pair? _%$%bind212313212324%_)
                          (let ((_%$%hd212317212336%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%bind212313212324%_)))
                                (_%$%tl212318212338%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%bind212313212324%_))))
                            (if (pair? _%$%hd212317212336%_)
                                (let ((_%$%hd212321212341%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%hd212317212336%_)))
                                      (_%$%tl212322212343%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%hd212317212336%_))))
                                  (let ((_%id212346%_ _%$%hd212321212341%_))
                                    (if (null? _%$%tl212322212343%_)
                                        (if (pair? _%$%tl212318212338%_)
                                            (let ((_%$%hd212319212348%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%tl212318212338%_)))
                                                  (_%$%tl212320212350%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%tl212318212338%_))))
                                              (let ((_%expr212353%_
                                                     _%$%hd212319212348%_))
                                                (if (null? _%$%tl212320212350%_)
                                                    (_%$%K212316212333%_
                                                     _%expr212353%_
                                                     _%id212346%_)
                                                    (_%$%E212315212327%_))))
                                            (_%$%E212315212327%_))
                                        (_%$%E212315212327%_))))
                                (_%$%E212315212327%_)))
                          (_%$%E212315212327%_))))))
          (let* ((_%bind212275%_ (map _%generate1212273%_ _%hd212269%_))
                 (_%body212277%_
                  (if _%compiled-body?212271%_
                      _%body212270%_
                      (let ()
                        (declare (not safe))
                        (gxc#compile-e__1 _%self212267%_ _%body212270%_))))
                 (_%body212309%_
                  (let* ((_%$%body212278212286%_ _%body212277%_)
                         (_%$%else212280212294%_
                          (lambda () (cons _%body212277%_ '())))
                         (_%$%K212282212299%_
                          (lambda (_%exprs212297%_) _%exprs212297%_)))
                    (if (pair? _%$%body212278212286%_)
                        (let ((_%$%hd212283212302%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%body212278212286%_)))
                              (_%$%tl212284212304%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%body212278212286%_))))
                          (if (let ()
                                (declare (not safe))
                                (##eq? _%$%hd212283212302%_ 'begin))
                              (let ((_%exprs212307%_ _%$%tl212284212304%_))
                                (_%$%K212282212299%_ _%exprs212307%_))
                              (_%$%else212280212294%_)))
                        (_%$%else212280212294%_)))))
            (cons _%form212268%_ (cons _%bind212275%_ _%body212309%_))))))
    (define gxc#generate-runtime-quote%
      (lambda (_%self212167%_ _%stx212168%_)
        (letrec ((_%generate1212170%_
                  (lambda (_%datum212222%_)
                    (if (or (null? _%datum212222%_)
                            (let ()
                              (declare (not safe))
                              (interned-symbol? _%datum212222%_))
                            (let ()
                              (declare (not safe))
                              (gx#self-quoting? _%datum212222%_))
                            (eof-object? _%datum212222%_))
                        _%datum212222%_
                        (if (uninterned-symbol? _%datum212222%_)
                            (let ()
                              (declare (not safe))
                              (gxc#generate-runtime-gensym-reference__%
                               _%datum212222%_
                               '#t))
                            (if (pair? _%datum212222%_)
                                (cons (_%generate1212170%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%datum212222%_)))
                                      (_%generate1212170%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%datum212222%_))))
                                (if (box? _%datum212222%_)
                                    (box (_%generate1212170%_
                                          (unbox _%datum212222%_)))
                                    (if (vector? _%datum212222%_)
                                        (vector-map
                                         _%generate1212170%_
                                         _%datum212222%_)
                                        (if (or (s8vector? _%datum212222%_)
                                                (u8vector? _%datum212222%_)
                                                (s16vector? _%datum212222%_)
                                                (u16vector? _%datum212222%_)
                                                (s32vector? _%datum212222%_)
                                                (u32vector? _%datum212222%_)
                                                (s64vector? _%datum212222%_)
                                                (u64vector? _%datum212222%_)
                                                (f32vector? _%datum212222%_)
                                                (f64vector? _%datum212222%_))
                                            _%datum212222%_
                                            (let ()
                                              (declare (not safe))
                                              (gxc#raise-compile-error
                                               '"Cannot compile non-primitive quote"
                                               _%stx212168%_)))))))))))
          (let* ((_%$%g212172212185%_
                  (lambda (_%$%g212173212182%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g212173212182%_))))
                 (_%$%g212171212219%_
                  (lambda (_%$%g212173212188%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g212173212188%_))
                        (let ((_%$%e212175212190%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g212173212188%_))))
                          (let ((_%$%hd212176212193%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e212175212190%_)))
                                (_%$%tl212177212195%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e212175212190%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl212177212195%_))
                                (let ((_%$%e212178212198%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl212177212195%_))))
                                  (let ((_%$%hd212179212201%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e212178212198%_)))
                                        (_%$%tl212180212203%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e212178212198%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl212180212203%_))
                                        (cons 'quote
                                              (cons (_%generate1212170%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%hd212179212201%_)))
                                                    '()))
                                        (_%$%g212172212185%_
                                         _%$%g212173212188%_))))
                                (_%$%g212172212185%_ _%$%g212173212188%_))))
                        (_%$%g212172212185%_ _%$%g212173212188%_)))))
            (_%$%g212171212219%_ _%stx212168%_)))))
    (define gxc#generate-runtime-call%
      (lambda (_%self211614%_ _%stx211615%_)
        (letrec ((_%compile-call211617%_
                  (lambda (_%rator211904%_ _%rands211905%_)
                    (let ((_%rator211911%_
                           (let ()
                             (declare (not safe))
                             (gxc#compile-e__1
                              _%self211614%_
                              _%rator211904%_)))
                          (_%rands211912%_
                           (map (lambda (_%$%g211906211908%_)
                                  (let ()
                                    (declare (not safe))
                                    (gxc#compile-e__1
                                     _%self211614%_
                                     _%$%g211906211908%_)))
                                _%rands211905%_)))
                      (let* ((_%__stx217631217632%_ _%rator211911%_)
                             (_%$%g211915211967%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; invalid match target"
                                   _%__stx217631217632%_)))))
                        (let ((_%__kont217633217634%_
                               (lambda (_%$%g211917212087%_
                                        _%$%g211918212088%_
                                        _%$%g211919212089%_
                                        _%$%g211920212090%_)
                                 (if (let ((__tmp218301
                                            (let ()
                                              (declare (not safe))
                                              (##length _%rands211912%_)))
                                           (__tmp218299
                                            (length (let ((__tmp218300
                                                           (lambda (_%$%g212126212129%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%g212127212131%_)
                     (cons _%$%g212126212129%_ _%$%g212127212131%_))))
              (declare (not safe))
              (foldr__0 __tmp218300 '() _%$%g211919212089%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                       (declare (not safe))
                                       (##fx= __tmp218301 __tmp218299))
                                     (let* ((_%id212134%_ _%$%g211920212090%_)
                                            (_%args212143%_
                                             (let ((__tmp218302
                                                    (lambda (_%$%g212135212138%_
                                                             _%$%g212136212140%_)
                                                      (cons _%$%g212135212138%_
                                                            _%$%g212136212140%_))))
                                               (declare (not safe))
                                               (foldr__0
                                                __tmp218302
                                                '()
                                                _%$%g211919212089%_)))
                                            (_%body212152%_
                                             (let ((__tmp218303
                                                    (lambda (_%$%g212144212147%_
                                                             _%$%g212145212149%_)
                                                      (cons _%$%g212144212147%_
                                                            _%$%g212145212149%_))))
                                               (declare (not safe))
                                               (foldr__0
                                                __tmp218303
                                                '()
                                                _%$%g211918212088%_)))
                                            (_%init212154%_
                                             (map list
                                                  _%args212143%_
                                                  _%rands211912%_)))
                                       (cons 'let
                                             (cons _%id212134%_
                                                   (cons _%init212154%_
                                                         _%body212152%_))))
                                     (let ((__tmp218304
                                            (let ((__tmp218305
                                                   (lambda (_%$%g212156212159%_
                                                            _%$%g212157212161%_)
                                                     (cons _%$%g212156212159%_
                                                           _%$%g212157212161%_))))
                                              (declare (not safe))
                                              (foldr__0
                                               __tmp218305
                                               '()
                                               _%$%g211919212089%_))))
                                       (declare (not safe))
                                       (gxc#raise-compile-error
                                        '"Illegal loop application; arity mismatch"
                                        _%stx211615%_
                                        __tmp218304
                                        _%rands211912%_)))))
                              (_%__kont217639217640%_
                               (lambda ()
                                 (cons _%rator211911%_ _%rands211912%_))))
                          (let ((_%__match217698217699%_
                                 (lambda (_%$%e211921211979%_
                                          _%$%hd211922211982%_
                                          _%$%tl211923211984%_
                                          _%$%e211924211987%_
                                          _%$%hd211925211990%_
                                          _%$%tl211926211992%_
                                          _%$%e211927211995%_
                                          _%$%hd211928211998%_
                                          _%$%tl211929212000%_
                                          _%$%e211930212003%_
                                          _%$%hd211931212006%_
                                          _%$%tl211932212008%_
                                          _%$%e211933212011%_
                                          _%$%hd211934212014%_
                                          _%$%tl211935212016%_
                                          _%$%e211936212019%_
                                          _%$%hd211937212022%_
                                          _%$%tl211938212024%_
                                          _%$%e211939212027%_
                                          _%$%hd211940212030%_
                                          _%$%tl211941212032%_
                                          _%__splice217635217636%_
                                          _%$%target211942212035%_
                                          _%$%tl211944212037%_)
                                   (letrec ((_%$%loop211945212040%_
                                             (lambda (_%$%hd211943212043%_
                                                      _%$%arg211949212045%_)
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-pair?
                                                      _%$%hd211943212043%_))
                                                   (let ((_%$%e211946212047%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%hd211943212043%_))))
                                                     (let ((_%$%lp-tl211948212052%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e211946212047%_)))
                                                           (_%$%lp-hd211947212050%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e211946212047%_))))
                                                       (_%$%loop211945212040%_
                                                        _%$%lp-tl211948212052%_
                                                        (cons _%$%lp-hd211947212050%_
                                                              _%$%arg211949212045%_))))
                                                   (let ((_%$%arg211950212055%_
                                                          (reverse _%$%arg211949212045%_)))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-pair/null?
                                                            _%$%tl211941212032%_))
                                                         (let ((_%__splice217637217638%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#syntax-split-splice->vector
                           _%$%tl211941212032%_
                           '0))))
                   (let ((_%$%tl211953212059%_
                          (let ()
                            (declare (not safe))
                            (##vector-ref _%__splice217637217638%_ '1)))
                         (_%$%target211951212057%_
                          (let ()
                            (declare (not safe))
                            (##vector-ref _%__splice217637217638%_ '0))))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-null? _%$%tl211953212059%_))
                         (letrec ((_%$%loop211954212062%_
                                   (lambda (_%$%hd211952212065%_
                                            _%$%body211958212067%_)
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-pair? _%$%hd211952212065%_))
                                         (let ((_%$%e211955212069%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#stx-e
                                                   _%$%hd211952212065%_))))
                                           (let ((_%$%lp-tl211957212074%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e211955212069%_)))
                                                 (_%$%lp-hd211956212072%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e211955212069%_))))
                                             (_%$%loop211954212062%_
                                              _%$%lp-tl211957212074%_
                                              (cons _%$%lp-hd211956212072%_
                                                    _%$%body211958212067%_))))
                                         (let ((_%$%body211959212077%_
                                                (reverse _%$%body211958212067%_)))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-null?
                                                  _%$%tl211935212016%_))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-null?
                                                      _%$%tl211929212000%_))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%tl211926211992%_))
                                                       (let ((_%$%e211960212079%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%tl211926211992%_))))
                 (let ((_%$%tl211962212084%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e211960212079%_)))
                       (_%$%hd211961212082%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e211960212079%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-null? _%$%tl211962212084%_))
                       (let ((_%$%g211917212087%_ _%$%hd211961212082%_)
                             (_%$%g211918212088%_ _%$%body211959212077%_)
                             (_%$%g211919212089%_ _%$%arg211950212055%_)
                             (_%$%g211920212090%_ _%$%hd211931212006%_))
                         (if (eq? _%$%g211920212090%_ _%$%g211917212087%_)
                             (_%__kont217633217634%_
                              _%$%g211917212087%_
                              _%$%g211918212088%_
                              _%$%g211919212089%_
                              _%$%g211920212090%_)
                             (_%__kont217639217640%_)))
                       (_%__kont217639217640%_))))
               (_%__kont217639217640%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%__kont217639217640%_))
                                               (_%__kont217639217640%_)))))))
                           (_%$%loop211954212062%_
                            _%$%target211951212057%_
                            '()))
                         (_%__kont217639217640%_))))
                 (_%__kont217639217640%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     (_%$%loop211945212040%_
                                      _%$%target211942212035%_
                                      '())))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%__stx217631217632%_))
                                (let ((_%$%e211921211979%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%__stx217631217632%_))))
                                  (let ((_%$%tl211923211984%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e211921211979%_)))
                                        (_%$%hd211922211982%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e211921211979%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#identifier?
                                           _%$%hd211922211982%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-eq?
                                               'letrec
                                               _%$%hd211922211982%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl211923211984%_))
                                                (let ((_%$%e211924211987%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl211923211984%_))))
                                                  (let ((_%$%tl211926211992%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e211924211987%_)))
                                                        (_%$%hd211925211990%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e211924211987%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd211925211990%_))
                                                        (let ((_%$%e211927211995%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%hd211925211990%_))))
                  (let ((_%$%tl211929212000%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e211927211995%_)))
                        (_%$%hd211928211998%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e211927211995%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd211928211998%_))
                        (let ((_%$%e211930212003%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd211928211998%_))))
                          (let ((_%$%tl211932212008%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e211930212003%_)))
                                (_%$%hd211931212006%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e211930212003%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl211932212008%_))
                                (let ((_%$%e211933212011%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl211932212008%_))))
                                  (let ((_%$%tl211935212016%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e211933212011%_)))
                                        (_%$%hd211934212014%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e211933212011%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%hd211934212014%_))
                                        (let ((_%$%e211936212019%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%hd211934212014%_))))
                                          (let ((_%$%tl211938212024%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e211936212019%_)))
                                                (_%$%hd211937212022%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e211936212019%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#identifier?
                                                   _%$%hd211937212022%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-eq?
                                                       'lambda
                                                       _%$%hd211937212022%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl211938212024%_))
                                                        (let ((_%$%e211939212027%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl211938212024%_))))
                  (let ((_%$%tl211941212032%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e211939212027%_)))
                        (_%$%hd211940212030%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e211939212027%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair/null? _%$%hd211940212030%_))
                        (let ((_%__splice217635217636%_
                               (let ()
                                 (declare (not safe))
                                 (gx#syntax-split-splice->vector
                                  _%$%hd211940212030%_
                                  '0))))
                          (let ((_%$%tl211944212037%_
                                 (let ()
                                   (declare (not safe))
                                   (##vector-ref _%__splice217635217636%_ '1)))
                                (_%$%target211942212035%_
                                 (let ()
                                   (declare (not safe))
                                   (##vector-ref
                                    _%__splice217635217636%_
                                    '0))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-null? _%$%tl211944212037%_))
                                (_%__match217698217699%_
                                 _%$%e211921211979%_
                                 _%$%hd211922211982%_
                                 _%$%tl211923211984%_
                                 _%$%e211924211987%_
                                 _%$%hd211925211990%_
                                 _%$%tl211926211992%_
                                 _%$%e211927211995%_
                                 _%$%hd211928211998%_
                                 _%$%tl211929212000%_
                                 _%$%e211930212003%_
                                 _%$%hd211931212006%_
                                 _%$%tl211932212008%_
                                 _%$%e211933212011%_
                                 _%$%hd211934212014%_
                                 _%$%tl211935212016%_
                                 _%$%e211936212019%_
                                 _%$%hd211937212022%_
                                 _%$%tl211938212024%_
                                 _%$%e211939212027%_
                                 _%$%hd211940212030%_
                                 _%$%tl211941212032%_
                                 _%__splice217635217636%_
                                 _%$%target211942212035%_
                                 _%$%tl211944212037%_)
                                (_%__kont217639217640%_))))
                        (_%__kont217639217640%_))))
                (_%__kont217639217640%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont217639217640%_))
                                                (_%__kont217639217640%_))))
                                        (_%__kont217639217640%_))))
                                (_%__kont217639217640%_))))
                        (_%__kont217639217640%_))))
                (_%__kont217639217640%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%__kont217639217640%_))
                                            (_%__kont217639217640%_))
                                        (_%__kont217639217640%_))))
                                (_%__kont217639217640%_)))))))))
          (let* ((_%$%g211619211642%_
                  (lambda (_%$%g211620211639%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g211620211639%_))))
                 (_%$%g211618211901%_
                  (lambda (_%$%g211620211645%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g211620211645%_))
                        (let ((_%$%e211623211647%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g211620211645%_))))
                          (let ((_%$%hd211624211650%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e211623211647%_)))
                                (_%$%tl211625211652%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e211623211647%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl211625211652%_))
                                (let ((_%$%e211626211655%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl211625211652%_))))
                                  (let ((_%$%hd211627211658%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e211626211655%_)))
                                        (_%$%tl211628211660%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e211626211655%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair/null?
                                           _%$%tl211628211660%_))
                                        (let ((_g218306_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-split-splice
                                                  _%$%tl211628211660%_
                                                  '0))))
                                          (begin
                                            (let ((_g218307_
                                                   (let ()
                                                     (declare (not safe))
                                                     (if (##values? _g218306_)
                                                         (##values-length
                                                          _g218306_)
                                                         1))))
                                              (if (not (let ()
                                                         (declare (not safe))
                                                         (##fx= _g218307_ 2)))
                                                  (error "Context expects 2 values"
                                                         _g218307_)))
                                            (let ((_%$%target211629211663%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##values-ref
                                                      _g218306_
                                                      0)))
                                                  (_%$%tl211631211665%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##values-ref
                                                      _g218306_
                                                      1))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-null?
                                                     _%$%tl211631211665%_))
                                                  (letrec ((_%$%loop211632211668%_
                                                            (lambda (_%$%hd211630211671%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%$%rand211636211673%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%hd211630211671%_))
                          (let ((_%$%e211633211675%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%hd211630211671%_))))
                            (let ((_%$%lp-hd211634211678%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e211633211675%_)))
                                  (_%$%lp-tl211635211680%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e211633211675%_))))
                              (_%$%loop211632211668%_
                               _%$%lp-tl211635211680%_
                               (cons _%$%lp-hd211634211678%_
                                     _%$%rand211636211673%_))))
                          (let ((_%$%rand211637211683%_
                                 (reverse _%$%rand211636211673%_)))
                            (if (gxc#current-compile-decls-unsafe?)
                                (_%compile-call211617%_
                                 _%$%hd211627211658%_
                                 (let ((__tmp218308
                                        (lambda (_%$%g211703211706%_
                                                 _%$%g211704211708%_)
                                          (cons _%$%g211703211706%_
                                                _%$%g211704211708%_))))
                                   (declare (not safe))
                                   (foldr__0
                                    __tmp218308
                                    '()
                                    _%$%rand211637211683%_)))
                                (let* ((_%__stx217747217748%_
                                        _%$%hd211627211658%_)
                                       (_%$%g211712211724%_
                                        (lambda ()
                                          (let ()
                                            (declare (not safe))
                                            (gx#raise-syntax-error
                                             '#f
                                             '"Bad syntax; invalid match target"
                                             _%__stx217747217748%_)))))
                                  (let ((_%__kont217749217750%_
                                         (lambda ()
                                           (let ((_%f211761%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#compile-e__1
                                                     _%self211614%_
                                                     _%$%hd211627211658%_))))
                                             (if (and (let ((__tmp218309
                                                             (symbol->string
                                                              _%f211761%_)))
                                                        (declare (not safe))
                                                        (##string-prefix?
                                                         '"##"
                                                         __tmp218309))
                                                      (not (let ()
                                                             (declare
                                                               (not safe))
                                                             (##memq _%f211761%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             gxc#checked-primitives))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (let _%lp211763%_ ((_%rest211766%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (reverse (let ((__tmp218311
                                             (lambda (_%$%g211883211886%_
                                                      _%$%g211884211888%_)
                                               (cons _%$%g211883211886%_
                                                     _%$%g211884211888%_))))
                                        (declare (not safe))
                                        (foldr__0
                                         __tmp218311
                                         '()
                                         _%$%rand211637211683%_))))
                            (_%bind211768%_ '())
                            (_%args211769%_ '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (let* ((_%$%rest211770211778%_
                                                           _%rest211766%_)
                                                          (_%$%else211772211786%_
                                                           (lambda ()
                                                             (cons 'let
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons _%bind211768%_
                                 (cons '(declare (not safe))
                                       (cons (cons _%f211761%_ _%args211769%_)
                                             '()))))))
                  (_%$%K211774211872%_
                   (lambda (_%rest211789%_ _%e211790%_)
                     (let* ((_%__stx217701217702%_ _%e211790%_)
                            (_%$%g211795211813%_
                             (lambda ()
                               (let ()
                                 (declare (not safe))
                                 (gx#raise-syntax-error
                                  '#f
                                  '"Bad syntax; invalid match target"
                                  _%__stx217701217702%_)))))
                       (let ((_%__kont217703217704%_
                              (lambda ()
                                (_%lp211763%_
                                 _%rest211789%_
                                 _%bind211768%_
                                 (cons (let ()
                                         (declare (not safe))
                                         (gxc#compile-e__0 _%e211790%_))
                                       _%args211769%_))))
                             (_%__kont217705217706%_
                              (lambda ()
                                (_%lp211763%_
                                 _%rest211789%_
                                 _%bind211768%_
                                 (cons (let ()
                                         (declare (not safe))
                                         (gxc#compile-e__0 _%e211790%_))
                                       _%args211769%_))))
                             (_%__kont217707217708%_
                              (lambda ()
                                (let ((_%tmp211820%_
                                       (let ((__tmp218310
                                              (let ()
                                                (declare (not safe))
                                                (##gensym '__tmp))))
                                         (declare (not safe))
                                         (make-symbol__0 __tmp218310))))
                                  (_%lp211763%_
                                   _%rest211789%_
                                   (cons (cons _%tmp211820%_
                                               (cons (let ()
                                                       (declare (not safe))
                                                       (gxc#compile-e__0
                                                        _%e211790%_))
                                                     '()))
                                         _%bind211768%_)
                                   (cons _%tmp211820%_ _%args211769%_))))))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-pair? _%__stx217701217702%_))
                             (let ((_%$%e211797211851%_
                                    (let ()
                                      (declare (not safe))
                                      (gx#stx-e _%__stx217701217702%_))))
                               (let ((_%$%tl211799211856%_
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%$%e211797211851%_)))
                                     (_%$%hd211798211854%_
                                      (let ()
                                        (declare (not safe))
                                        (##car _%$%e211797211851%_))))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#identifier? _%$%hd211798211854%_))
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-eq?
                                            '%#ref
                                            _%$%hd211798211854%_))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-pair?
                                                _%$%tl211799211856%_))
                                             (let ((_%$%e211800211859%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%$%tl211799211856%_))))
                                               (let ((_%$%tl211802211864%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%e211800211859%_)))
                                                     (_%$%hd211801211862%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%e211800211859%_))))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-null?
                                                        _%$%tl211802211864%_))
                                                     (_%__kont217703217704%_)
                                                     (_%__kont217707217708%_))))
                                             (_%__kont217707217708%_))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-eq?
                                                '%#quote
                                                _%$%hd211798211854%_))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair?
                                                    _%$%tl211799211856%_))
                                                 (let ((_%$%e211806211836%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%$%tl211799211856%_))))
                                                   (let ((_%$%tl211808211841%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e211806211836%_)))
                                                         (_%$%hd211807211839%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e211806211836%_))))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-null?
                                                            _%$%tl211808211841%_))
                                                         (_%__kont217705217706%_)
                                                         (_%__kont217707217708%_))))
                                                 (_%__kont217707217708%_))
                                             (_%__kont217707217708%_)))
                                     (_%__kont217707217708%_))))
                             (_%__kont217707217708%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (if (pair? _%$%rest211770211778%_)
                                                         (let ((_%$%hd211775211875%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (##car _%$%rest211770211778%_)))
                       (_%$%tl211776211877%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%rest211770211778%_))))
                   (let* ((_%e211880%_ _%$%hd211775211875%_)
                          (_%rest211882%_ _%$%tl211776211877%_))
                     (_%$%K211774211872%_ _%rest211882%_ _%e211880%_)))
                 (_%$%else211772211786%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%compile-call211617%_
                                                  _%$%hd211627211658%_
                                                  (let ((__tmp218312
                                                         (lambda (_%$%g211890211893%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%$%g211891211895%_)
                   (cons _%$%g211890211893%_ _%$%g211891211895%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (foldr__0
                                                     __tmp218312
                                                     '()
                                                     _%$%rand211637211683%_)))))))
                                        (_%__kont217751217752%_
                                         (lambda ()
                                           (_%compile-call211617%_
                                            _%$%hd211627211658%_
                                            (let ((__tmp218313
                                                   (lambda (_%$%g211730211733%_
                                                            _%$%g211731211735%_)
                                                     (cons _%$%g211730211733%_
                                                           _%$%g211731211735%_))))
                                              (declare (not safe))
                                              (foldr__0
                                               __tmp218313
                                               '()
                                               _%$%rand211637211683%_))))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%__stx217747217748%_))
                                        (let ((_%$%e211714211743%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%__stx217747217748%_))))
                                          (let ((_%$%tl211716211748%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e211714211743%_)))
                                                (_%$%hd211715211746%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e211714211743%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#identifier?
                                                   _%$%hd211715211746%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-eq?
                                                       '%#ref
                                                       _%$%hd211715211746%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%tl211716211748%_))
                                                        (let ((_%$%e211717211751%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%tl211716211748%_))))
                  (let ((_%$%tl211719211756%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e211717211751%_)))
                        (_%$%hd211718211754%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e211717211751%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-null? _%$%tl211719211756%_))
                        (_%__kont217749217750%_)
                        (_%__kont217751217752%_))))
                (_%__kont217751217752%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont217751217752%_))
                                                (_%__kont217751217752%_))))
                                        (_%__kont217751217752%_))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%loop211632211668%_
                                                     _%$%target211629211663%_
                                                     '()))
                                                  (_%$%g211619211642%_
                                                   _%$%g211620211645%_)))))
                                        (_%$%g211619211642%_
                                         _%$%g211620211645%_))))
                                (_%$%g211619211642%_ _%$%g211620211645%_))))
                        (_%$%g211619211642%_ _%$%g211620211645%_)))))
            (_%$%g211618211901%_ _%stx211615%_)))))
    (define gxc#generate-runtime-call-unchecked%
      (lambda (_%self211359%_ _%stx211360%_)
        (let* ((_%__stx217819217820%_ _%stx211360%_)
               (_%$%g211363211392%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx217819217820%_)))))
          (let ((_%__kont217821217822%_
                 (lambda (_%$%g211365211458%_ _%$%g211366211459%_)
                   (if (gxc#current-compile-decls-unsafe?)
                       (gxc#generate-runtime-call%
                        _%self211359%_
                        _%stx211360%_)
                       (let ((_%f211481%_
                              (let ((__tmp218314
                                     (cons (let ()
                                             (declare (not safe))
                                             (gx#datum->syntax__0 '#f '%#ref))
                                           (cons _%$%g211366211459%_ '()))))
                                (declare (not safe))
                                (gxc#compile-e__1
                                 _%self211359%_
                                 __tmp218314))))
                         (let _%lp211483%_ ((_%rest211486%_
                                             (reverse (let ((__tmp218316
                                                             (lambda (_%$%g211603211606%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%$%g211604211608%_)
                       (cons _%$%g211603211606%_ _%$%g211604211608%_))))
                (declare (not safe))
                (foldr__0 __tmp218316 '() _%$%g211365211458%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%bind211488%_ '())
                                            (_%args211489%_ '()))
                           (let* ((_%$%rest211490211498%_ _%rest211486%_)
                                  (_%$%else211492211506%_
                                   (lambda ()
                                     (cons 'let
                                           (cons _%bind211488%_
                                                 (cons '(declare (not safe))
                                                       (cons (cons _%f211481%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%args211489%_)
                     '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                  (_%$%K211494211592%_
                                   (lambda (_%rest211509%_ _%e211510%_)
                                     (let* ((_%__stx217773217774%_ _%e211510%_)
                                            (_%$%g211515211533%_
                                             (lambda ()
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#raise-syntax-error
                                                  '#f
                                                  '"Bad syntax; invalid match target"
                                                  _%__stx217773217774%_)))))
                                       (let ((_%__kont217775217776%_
                                              (lambda ()
                                                (_%lp211483%_
                                                 _%rest211509%_
                                                 _%bind211488%_
                                                 (cons (let ()
                                                         (declare (not safe))
                                                         (gxc#compile-e__0
                                                          _%e211510%_))
                                                       _%args211489%_))))
                                             (_%__kont217777217778%_
                                              (lambda ()
                                                (_%lp211483%_
                                                 _%rest211509%_
                                                 _%bind211488%_
                                                 (cons (let ()
                                                         (declare (not safe))
                                                         (gxc#compile-e__0
                                                          _%e211510%_))
                                                       _%args211489%_))))
                                             (_%__kont217779217780%_
                                              (lambda ()
                                                (let ((_%tmp211540%_
                                                       (let ((__tmp218315
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##gensym '__tmp))))
                 (declare (not safe))
                 (make-symbol__0 __tmp218315))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%lp211483%_
                                                   _%rest211509%_
                                                   (cons (cons _%tmp211540%_
                                                               (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (declare (not safe))
                               (gxc#compile-e__0 _%e211510%_))
                             '()))
                 _%bind211488%_)
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (cons _%tmp211540%_
                                                         _%args211489%_))))))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-pair?
                                                _%__stx217773217774%_))
                                             (let ((_%$%e211517211571%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%__stx217773217774%_))))
                                               (let ((_%$%tl211519211576%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%e211517211571%_)))
                                                     (_%$%hd211518211574%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%e211517211571%_))))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#identifier?
                                                        _%$%hd211518211574%_))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-eq?
                                                            '%#ref
                                                            _%$%hd211518211574%_))
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-pair? _%$%tl211519211576%_))
                     (let ((_%$%e211520211579%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%tl211519211576%_))))
                       (let ((_%$%tl211522211584%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%e211520211579%_)))
                             (_%$%hd211521211582%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%e211520211579%_))))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-null? _%$%tl211522211584%_))
                             (_%__kont217775217776%_)
                             (_%__kont217779217780%_))))
                     (_%__kont217779217780%_))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-eq? '%#quote _%$%hd211518211574%_))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-pair? _%$%tl211519211576%_))
                         (let ((_%$%e211526211556%_
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%tl211519211576%_))))
                           (let ((_%$%tl211528211561%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%e211526211556%_)))
                                 (_%$%hd211527211559%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%e211526211556%_))))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-null? _%$%tl211528211561%_))
                                 (_%__kont217777217778%_)
                                 (_%__kont217779217780%_))))
                         (_%__kont217779217780%_))
                     (_%__kont217779217780%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%__kont217779217780%_))))
                                             (_%__kont217779217780%_)))))))
                             (if (pair? _%$%rest211490211498%_)
                                 (let ((_%$%hd211495211595%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%rest211490211498%_)))
                                       (_%$%tl211496211597%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%rest211490211498%_))))
                                   (let* ((_%e211600%_ _%$%hd211495211595%_)
                                          (_%rest211602%_
                                           _%$%tl211496211597%_))
                                     (_%$%K211494211592%_
                                      _%rest211602%_
                                      _%e211600%_)))
                                 (_%$%else211492211506%_))))))))
                (_%__kont217825217826%_
                 (lambda ()
                   (gxc#generate-runtime-call% _%self211359%_ _%stx211360%_))))
            (let ((_%__match217864217865%_
                   (lambda (_%$%e211367211404%_
                            _%$%hd211368211407%_
                            _%$%tl211369211409%_
                            _%$%e211370211412%_
                            _%$%hd211371211415%_
                            _%$%tl211372211417%_
                            _%$%e211373211420%_
                            _%$%hd211374211423%_
                            _%$%tl211375211425%_
                            _%$%e211376211428%_
                            _%$%hd211377211431%_
                            _%$%tl211378211433%_
                            _%__splice217823217824%_
                            _%$%target211379211436%_
                            _%$%tl211381211438%_)
                     (letrec ((_%$%loop211382211441%_
                               (lambda (_%$%hd211380211444%_
                                        _%$%rand211386211446%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%$%hd211380211444%_))
                                     (let ((_%$%e211383211448%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#stx-e
                                               _%$%hd211380211444%_))))
                                       (let ((_%$%lp-tl211385211453%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e211383211448%_)))
                                             (_%$%lp-hd211384211451%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e211383211448%_))))
                                         (_%$%loop211382211441%_
                                          _%$%lp-tl211385211453%_
                                          (cons _%$%lp-hd211384211451%_
                                                _%$%rand211386211446%_))))
                                     (let ((_%$%rand211387211456%_
                                            (reverse _%$%rand211386211446%_)))
                                       (_%__kont217821217822%_
                                        _%$%rand211387211456%_
                                        _%$%hd211377211431%_))))))
                       (_%$%loop211382211441%_
                        _%$%target211379211436%_
                        '())))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx217819217820%_))
                  (let ((_%$%e211367211404%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx217819217820%_))))
                    (let ((_%$%tl211369211409%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e211367211404%_)))
                          (_%$%hd211368211407%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e211367211404%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl211369211409%_))
                          (let ((_%$%e211370211412%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl211369211409%_))))
                            (let ((_%$%tl211372211417%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e211370211412%_)))
                                  (_%$%hd211371211415%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e211370211412%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%hd211371211415%_))
                                  (let ((_%$%e211373211420%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd211371211415%_))))
                                    (let ((_%$%tl211375211425%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e211373211420%_)))
                                          (_%$%hd211374211423%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e211373211420%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#identifier?
                                             _%$%hd211374211423%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#ref
                                                 _%$%hd211374211423%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl211375211425%_))
                                                  (let ((_%$%e211376211428%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl211375211425%_))))
                                                    (let ((_%$%tl211378211433%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e211376211428%_)))
                                                          (_%$%hd211377211431%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e211376211428%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl211378211433%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair/null? _%$%tl211372211417%_))
                      (let ((_%__splice217823217824%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-split-splice->vector
                                _%$%tl211372211417%_
                                '0))))
                        (let ((_%$%tl211381211438%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice217823217824%_ '1)))
                              (_%$%target211379211436%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice217823217824%_ '0))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl211381211438%_))
                              (_%__match217864217865%_
                               _%$%e211367211404%_
                               _%$%hd211368211407%_
                               _%$%tl211369211409%_
                               _%$%e211370211412%_
                               _%$%hd211371211415%_
                               _%$%tl211372211417%_
                               _%$%e211373211420%_
                               _%$%hd211374211423%_
                               _%$%tl211375211425%_
                               _%$%e211376211428%_
                               _%$%hd211377211431%_
                               _%$%tl211378211433%_
                               _%__splice217823217824%_
                               _%$%target211379211436%_
                               _%$%tl211381211438%_)
                              (_%__kont217825217826%_))))
                      (_%__kont217825217826%_))
                  (_%__kont217825217826%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont217825217826%_))
                                              (_%__kont217825217826%_))
                                          (_%__kont217825217826%_))))
                                  (_%__kont217825217826%_))))
                          (_%__kont217825217826%_))))
                  (_%__kont217825217826%_)))))))
    (define gxc#generate-runtime-if%
      (lambda (_%self211171%_ _%stx211172%_)
        (letrec ((_%simplify211174%_
                  (lambda (_%code211259%_)
                    (let* ((_%$%code211260211278%_ _%code211259%_)
                           (_%$%else211262211286%_ (lambda () _%code211259%_))
                           (_%$%K211264211322%_
                            (lambda (_%expr211289%_ _%test211290%_)
                              (let* ((_%$%expr211291211299%_ _%expr211289%_)
                                     (_%$%else211293211307%_
                                      (lambda ()
                                        (cons 'and
                                              (cons _%test211290%_
                                                    (cons _%expr211289%_
                                                          '())))))
                                     (_%$%K211295211312%_
                                      (lambda (_%exprs211310%_)
                                        (cons 'and
                                              (cons _%test211290%_
                                                    _%exprs211310%_)))))
                                (if (pair? _%$%expr211291211299%_)
                                    (let ((_%$%hd211296211315%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%expr211291211299%_)))
                                          (_%$%tl211297211317%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%expr211291211299%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (##eq? _%$%hd211296211315%_ 'and))
                                          (let ((_%exprs211320%_
                                                 _%$%tl211297211317%_))
                                            (_%$%K211295211312%_
                                             _%exprs211320%_))
                                          (_%$%else211293211307%_)))
                                    (_%$%else211293211307%_))))))
                      (if (pair? _%$%code211260211278%_)
                          (let ((_%$%hd211265211325%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%code211260211278%_)))
                                (_%$%tl211266211327%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%code211260211278%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (##eq? _%$%hd211265211325%_ 'if))
                                (if (pair? _%$%tl211266211327%_)
                                    (let ((_%$%hd211267211330%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%tl211266211327%_)))
                                          (_%$%tl211268211332%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%tl211266211327%_))))
                                      (let ((_%test211335%_
                                             _%$%hd211267211330%_))
                                        (if (pair? _%$%tl211268211332%_)
                                            (let ((_%$%hd211269211337%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%tl211268211332%_)))
                                                  (_%$%tl211270211339%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%tl211268211332%_))))
                                              (let ((_%expr211342%_
                                                     _%$%hd211269211337%_))
                                                (if (pair? _%$%tl211270211339%_)
                                                    (let ((_%$%hd211271211344%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%tl211270211339%_)))
                                                          (_%$%tl211272211346%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%tl211270211339%_))))
                                                      (if (pair? _%$%hd211271211344%_)
                                                          (let ((_%$%hd211273211349%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##car _%$%hd211271211344%_)))
                        (_%$%tl211274211351%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%hd211271211344%_))))
                    (if (let ()
                          (declare (not safe))
                          (##eq? _%$%hd211273211349%_ 'quote))
                        (if (pair? _%$%tl211274211351%_)
                            (let ((_%$%hd211275211354%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%tl211274211351%_)))
                                  (_%$%tl211276211356%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%tl211274211351%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (##eq? _%$%hd211275211354%_ '#f))
                                  (if (null? _%$%tl211276211356%_)
                                      (if (null? _%$%tl211272211346%_)
                                          (_%$%K211264211322%_
                                           _%expr211342%_
                                           _%test211335%_)
                                          (_%$%else211262211286%_))
                                      (_%$%else211262211286%_))
                                  (_%$%else211262211286%_)))
                            (_%$%else211262211286%_))
                        (_%$%else211262211286%_)))
                  (_%$%else211262211286%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%else211262211286%_))))
                                            (_%$%else211262211286%_))))
                                    (_%$%else211262211286%_))
                                (_%$%else211262211286%_)))
                          (_%$%else211262211286%_))))))
          (let* ((_%$%g211176211197%_
                  (lambda (_%$%g211177211194%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g211177211194%_))))
                 (_%$%g211175211256%_
                  (lambda (_%$%g211177211200%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g211177211200%_))
                        (let ((_%$%e211181211202%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g211177211200%_))))
                          (let ((_%$%hd211182211205%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e211181211202%_)))
                                (_%$%tl211183211207%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e211181211202%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl211183211207%_))
                                (let ((_%$%e211184211210%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl211183211207%_))))
                                  (let ((_%$%hd211185211213%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e211184211210%_)))
                                        (_%$%tl211186211215%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e211184211210%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl211186211215%_))
                                        (let ((_%$%e211187211218%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl211186211215%_))))
                                          (let ((_%$%hd211188211221%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e211187211218%_)))
                                                (_%$%tl211189211223%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e211187211218%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl211189211223%_))
                                                (let ((_%$%e211190211226%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl211189211223%_))))
                                                  (let ((_%$%hd211191211229%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e211190211226%_)))
                                                        (_%$%tl211192211231%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e211190211226%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl211192211231%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gxc#current-compile-boolean-context))
                                                            (_%simplify211174%_
                                                             (cons 'if
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons (let ()
                                   (declare (not safe))
                                   (gxc#compile-e__1
                                    _%self211171%_
                                    _%$%hd211185211213%_))
                                 (cons (let ()
                                         (declare (not safe))
                                         (gxc#compile-e__1
                                          _%self211171%_
                                          _%$%hd211188211221%_))
                                       (cons (let ()
                                               (declare (not safe))
                                               (gxc#compile-e__1
                                                _%self211171%_
                                                _%$%hd211191211229%_))
                                             '())))))
                    (cons 'if
                          (cons (let ((__tmp218317
                                       (lambda ()
                                         (let ()
                                           (declare (not safe))
                                           (gxc#compile-e__1
                                            _%self211171%_
                                            _%$%hd211185211213%_)))))
                                  (declare (not safe))
                                  (call-with-parameters__1
                                   __tmp218317
                                   gxc#current-compile-boolean-context
                                   '#t))
                                (cons (let ()
                                        (declare (not safe))
                                        (gxc#compile-e__1
                                         _%self211171%_
                                         _%$%hd211188211221%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gxc#compile-e__1
                                               _%self211171%_
                                               _%$%hd211191211229%_))
                                            '())))))
                (_%$%g211176211197%_ _%$%g211177211200%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g211176211197%_
                                                 _%$%g211177211200%_))))
                                        (_%$%g211176211197%_
                                         _%$%g211177211200%_))))
                                (_%$%g211176211197%_ _%$%g211177211200%_))))
                        (_%$%g211176211197%_ _%$%g211177211200%_)))))
            (_%$%g211175211256%_ _%stx211172%_)))))
    (define gxc#generate-runtime-ref%
      (lambda (_%self211119%_ _%stx211120%_)
        (let* ((_%$%g211122211135%_
                (lambda (_%$%g211123211132%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g211123211132%_))))
               (_%$%g211121211168%_
                (lambda (_%$%g211123211138%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g211123211138%_))
                      (let ((_%$%e211125211140%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g211123211138%_))))
                        (let ((_%$%hd211126211143%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e211125211140%_)))
                              (_%$%tl211127211145%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e211125211140%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl211127211145%_))
                              (let ((_%$%e211128211148%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl211127211145%_))))
                                (let ((_%$%hd211129211151%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e211128211148%_)))
                                      (_%$%tl211130211153%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e211128211148%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl211130211153%_))
                                      (let ()
                                        (declare (not safe))
                                        (gxc#generate-runtime-binding-id
                                         _%$%hd211129211151%_))
                                      (_%$%g211122211135%_
                                       _%$%g211123211138%_))))
                              (_%$%g211122211135%_ _%$%g211123211138%_))))
                      (_%$%g211122211135%_ _%$%g211123211138%_)))))
          (_%$%g211121211168%_ _%stx211120%_))))
    (define gxc#generate-runtime-setq%
      (lambda (_%self211051%_ _%stx211052%_)
        (let* ((_%$%g211054211071%_
                (lambda (_%$%g211055211068%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g211055211068%_))))
               (_%$%g211053211116%_
                (lambda (_%$%g211055211074%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g211055211074%_))
                      (let ((_%$%e211058211076%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g211055211074%_))))
                        (let ((_%$%hd211059211079%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e211058211076%_)))
                              (_%$%tl211060211081%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e211058211076%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl211060211081%_))
                              (let ((_%$%e211061211084%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl211060211081%_))))
                                (let ((_%$%hd211062211087%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e211061211084%_)))
                                      (_%$%tl211063211089%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e211061211084%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl211063211089%_))
                                      (let ((_%$%e211064211092%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl211063211089%_))))
                                        (let ((_%$%hd211065211095%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e211064211092%_)))
                                              (_%$%tl211066211097%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e211064211092%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl211066211097%_))
                                              (cons 'set!
                                                    (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gxc#generate-runtime-binding-id
                                                             _%$%hd211062211087%_))
                                                          (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gxc#compile-e__1
                           _%self211051%_
                           _%$%hd211065211095%_))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g211054211071%_
                                               _%$%g211055211074%_))))
                                      (_%$%g211054211071%_
                                       _%$%g211055211074%_))))
                              (_%$%g211054211071%_ _%$%g211055211074%_))))
                      (_%$%g211054211071%_ _%$%g211055211074%_)))))
          (_%$%g211053211116%_ _%stx211052%_))))
    (define gxc#generate-runtime-struct-instancep%
      (lambda (_%self210862%_ _%stx210863%_)
        (let* ((_%$%g210865210882%_
                (lambda (_%$%g210866210879%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g210866210879%_))))
               (_%$%g210864211048%_
                (lambda (_%$%g210866210885%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g210866210885%_))
                      (let ((_%$%e210869210887%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g210866210885%_))))
                        (let ((_%$%hd210870210890%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e210869210887%_)))
                              (_%$%tl210871210892%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e210869210887%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl210871210892%_))
                              (let ((_%$%e210872210895%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl210871210892%_))))
                                (let ((_%$%hd210873210898%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210872210895%_)))
                                      (_%$%tl210874210900%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210872210895%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl210874210900%_))
                                      (let ((_%$%e210875210903%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl210874210900%_))))
                                        (let ((_%$%hd210876210906%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e210875210903%_)))
                                              (_%$%tl210877210908%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e210875210903%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl210877210908%_))
                                              (if (gxc#current-compile-decls-unsafe?)
                                                  (cons '##structure-instance-of?
                                                        (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gxc#compile-e__1 _%self210862%_ _%$%hd210876210906%_))
                      (cons (let ()
                              (declare (not safe))
                              (gxc#compile-e__1
                               _%self210862%_
                               _%$%hd210873210898%_))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let _%lp210927%_ ((_%rest210930%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons _%$%hd210873210898%_
                                    (cons _%$%hd210876210906%_ '())))
                             (_%bind210932%_ '())
                             (_%args210933%_ '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let* ((_%$%rest210934210942%_
                                                            _%rest210930%_)
                                                           (_%$%else210936210950%_
                                                            (lambda ()
                                                              (cons 'let
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons _%bind210932%_
                                  (cons '(declare (not safe))
                                        (cons (cons '##structure-instance-of?
                                                    _%args210933%_)
                                              '()))))))
                   (_%$%K210938211036%_
                    (lambda (_%rest210953%_ _%e210954%_)
                      (let* ((_%__stx217867217868%_ _%e210954%_)
                             (_%$%g210959210977%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; invalid match target"
                                   _%__stx217867217868%_)))))
                        (let ((_%__kont217869217870%_
                               (lambda ()
                                 (_%lp210927%_
                                  _%rest210953%_
                                  _%bind210932%_
                                  (cons (let ()
                                          (declare (not safe))
                                          (gxc#compile-e__0 _%e210954%_))
                                        _%args210933%_))))
                              (_%__kont217871217872%_
                               (lambda ()
                                 (_%lp210927%_
                                  _%rest210953%_
                                  _%bind210932%_
                                  (cons (let ()
                                          (declare (not safe))
                                          (gxc#compile-e__0 _%e210954%_))
                                        _%args210933%_))))
                              (_%__kont217873217874%_
                               (lambda ()
                                 (let ((_%tmp210984%_
                                        (let ((__tmp218318
                                               (let ()
                                                 (declare (not safe))
                                                 (##gensym '__tmp))))
                                          (declare (not safe))
                                          (make-symbol__0 __tmp218318))))
                                   (_%lp210927%_
                                    _%rest210953%_
                                    (cons (cons _%tmp210984%_
                                                (cons (let ()
                                                        (declare (not safe))
                                                        (gxc#compile-e__0
                                                         _%e210954%_))
                                                      '()))
                                          _%bind210932%_)
                                    (cons _%tmp210984%_ _%args210933%_))))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%__stx217867217868%_))
                              (let ((_%$%e210961211015%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%__stx217867217868%_))))
                                (let ((_%$%tl210963211020%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210961211015%_)))
                                      (_%$%hd210962211018%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210961211015%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#identifier? _%$%hd210962211018%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-eq?
                                             '%#ref
                                             _%$%hd210962211018%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl210963211020%_))
                                              (let ((_%$%e210964211023%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl210963211020%_))))
                                                (let ((_%$%tl210966211028%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e210964211023%_)))
                                                      (_%$%hd210965211026%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e210964211023%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl210966211028%_))
                                                      (_%__kont217869217870%_)
                                                      (_%__kont217873217874%_))))
                                              (_%__kont217873217874%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#quote
                                                 _%$%hd210962211018%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl210963211020%_))
                                                  (let ((_%$%e210970211000%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl210963211020%_))))
                                                    (let ((_%$%tl210972211005%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e210970211000%_)))
                                                          (_%$%hd210971211003%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e210970211000%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl210972211005%_))
                                                          (_%__kont217871217872%_)
                                                          (_%__kont217873217874%_))))
                                                  (_%__kont217873217874%_))
                                              (_%__kont217873217874%_)))
                                      (_%__kont217873217874%_))))
                              (_%__kont217873217874%_)))))))
              (if (pair? _%$%rest210934210942%_)
                  (let ((_%$%hd210939211039%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest210934210942%_)))
                        (_%$%tl210940211041%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest210934210942%_))))
                    (let* ((_%e211044%_ _%$%hd210939211039%_)
                           (_%rest211046%_ _%$%tl210940211041%_))
                      (_%$%K210938211036%_ _%rest211046%_ _%e211044%_)))
                  (_%$%else210936210950%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g210865210882%_
                                               _%$%g210866210885%_))))
                                      (_%$%g210865210882%_
                                       _%$%g210866210885%_))))
                              (_%$%g210865210882%_ _%$%g210866210885%_))))
                      (_%$%g210865210882%_ _%$%g210866210885%_)))))
          (_%$%g210864211048%_ _%stx210863%_))))
    (define gxc#generate-runtime-struct-direct-instancep%
      (lambda (_%self210673%_ _%stx210674%_)
        (let* ((_%$%g210676210693%_
                (lambda (_%$%g210677210690%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g210677210690%_))))
               (_%$%g210675210859%_
                (lambda (_%$%g210677210696%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g210677210696%_))
                      (let ((_%$%e210680210698%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g210677210696%_))))
                        (let ((_%$%hd210681210701%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e210680210698%_)))
                              (_%$%tl210682210703%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e210680210698%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl210682210703%_))
                              (let ((_%$%e210683210706%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl210682210703%_))))
                                (let ((_%$%hd210684210709%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210683210706%_)))
                                      (_%$%tl210685210711%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210683210706%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl210685210711%_))
                                      (let ((_%$%e210686210714%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl210685210711%_))))
                                        (let ((_%$%hd210687210717%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e210686210714%_)))
                                              (_%$%tl210688210719%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e210686210714%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl210688210719%_))
                                              (if (gxc#current-compile-decls-unsafe?)
                                                  (cons '##structure-direct-instance-of?
                                                        (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gxc#compile-e__1 _%self210673%_ _%$%hd210687210717%_))
                      (cons (let ()
                              (declare (not safe))
                              (gxc#compile-e__1
                               _%self210673%_
                               _%$%hd210684210709%_))
                            '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let _%lp210738%_ ((_%rest210741%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons _%$%hd210684210709%_
                                    (cons _%$%hd210687210717%_ '())))
                             (_%bind210743%_ '())
                             (_%args210744%_ '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let* ((_%$%rest210745210753%_
                                                            _%rest210741%_)
                                                           (_%$%else210747210761%_
                                                            (lambda ()
                                                              (cons 'let
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (cons _%bind210743%_
                                  (cons '(declare (not safe))
                                        (cons (cons '##structure-direct-instance-of?
                                                    _%args210744%_)
                                              '()))))))
                   (_%$%K210749210847%_
                    (lambda (_%rest210764%_ _%e210765%_)
                      (let* ((_%__stx217913217914%_ _%e210765%_)
                             (_%$%g210770210788%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; invalid match target"
                                   _%__stx217913217914%_)))))
                        (let ((_%__kont217915217916%_
                               (lambda ()
                                 (_%lp210738%_
                                  _%rest210764%_
                                  _%bind210743%_
                                  (cons (let ()
                                          (declare (not safe))
                                          (gxc#compile-e__0 _%e210765%_))
                                        _%args210744%_))))
                              (_%__kont217917217918%_
                               (lambda ()
                                 (_%lp210738%_
                                  _%rest210764%_
                                  _%bind210743%_
                                  (cons (let ()
                                          (declare (not safe))
                                          (gxc#compile-e__0 _%e210765%_))
                                        _%args210744%_))))
                              (_%__kont217919217920%_
                               (lambda ()
                                 (let ((_%tmp210795%_
                                        (let ((__tmp218319
                                               (let ()
                                                 (declare (not safe))
                                                 (##gensym '__tmp))))
                                          (declare (not safe))
                                          (make-symbol__0 __tmp218319))))
                                   (_%lp210738%_
                                    _%rest210764%_
                                    (cons (cons _%tmp210795%_
                                                (cons (let ()
                                                        (declare (not safe))
                                                        (gxc#compile-e__0
                                                         _%e210765%_))
                                                      '()))
                                          _%bind210743%_)
                                    (cons _%tmp210795%_ _%args210744%_))))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%__stx217913217914%_))
                              (let ((_%$%e210772210826%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%__stx217913217914%_))))
                                (let ((_%$%tl210774210831%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210772210826%_)))
                                      (_%$%hd210773210829%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210772210826%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#identifier? _%$%hd210773210829%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-eq?
                                             '%#ref
                                             _%$%hd210773210829%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl210774210831%_))
                                              (let ((_%$%e210775210834%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl210774210831%_))))
                                                (let ((_%$%tl210777210839%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e210775210834%_)))
                                                      (_%$%hd210776210837%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e210775210834%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl210777210839%_))
                                                      (_%__kont217915217916%_)
                                                      (_%__kont217919217920%_))))
                                              (_%__kont217919217920%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#quote
                                                 _%$%hd210773210829%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl210774210831%_))
                                                  (let ((_%$%e210781210811%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl210774210831%_))))
                                                    (let ((_%$%tl210783210816%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e210781210811%_)))
                                                          (_%$%hd210782210814%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e210781210811%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl210783210816%_))
                                                          (_%__kont217917217918%_)
                                                          (_%__kont217919217920%_))))
                                                  (_%__kont217919217920%_))
                                              (_%__kont217919217920%_)))
                                      (_%__kont217919217920%_))))
                              (_%__kont217919217920%_)))))))
              (if (pair? _%$%rest210745210753%_)
                  (let ((_%$%hd210750210850%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest210745210753%_)))
                        (_%$%tl210751210852%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest210745210753%_))))
                    (let* ((_%e210855%_ _%$%hd210750210850%_)
                           (_%rest210857%_ _%$%tl210751210852%_))
                      (_%$%K210749210847%_ _%rest210857%_ _%e210855%_)))
                  (_%$%else210747210761%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g210676210693%_
                                               _%$%g210677210696%_))))
                                      (_%$%g210676210693%_
                                       _%$%g210677210696%_))))
                              (_%$%g210676210693%_ _%$%g210677210696%_))))
                      (_%$%g210676210693%_ _%$%g210677210696%_)))))
          (_%$%g210675210859%_ _%stx210674%_))))
    (define gxc#generate-runtime-struct-ref%
      (lambda (_%self210589%_ _%stx210590%_)
        (let* ((_%$%g210592210613%_
                (lambda (_%$%g210593210610%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g210593210610%_))))
               (_%$%g210591210670%_
                (lambda (_%$%g210593210616%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g210593210616%_))
                      (let ((_%$%e210597210618%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g210593210616%_))))
                        (let ((_%$%hd210598210621%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e210597210618%_)))
                              (_%$%tl210599210623%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e210597210618%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl210599210623%_))
                              (let ((_%$%e210600210626%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl210599210623%_))))
                                (let ((_%$%hd210601210629%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210600210626%_)))
                                      (_%$%tl210602210631%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210600210626%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl210602210631%_))
                                      (let ((_%$%e210603210634%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl210602210631%_))))
                                        (let ((_%$%hd210604210637%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e210603210634%_)))
                                              (_%$%tl210605210639%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e210603210634%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl210605210639%_))
                                              (let ((_%$%e210606210642%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl210605210639%_))))
                                                (let ((_%$%hd210607210645%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e210606210642%_)))
                                                      (_%$%tl210608210647%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e210606210642%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl210608210647%_))
                                                      (cons '##structure-ref
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (gxc#compile-e__1
                             _%self210589%_
                             _%$%hd210607210645%_))
                          (cons (let ()
                                  (declare (not safe))
                                  (gxc#compile-e__1
                                   _%self210589%_
                                   _%$%hd210604210637%_))
                                (cons (let ()
                                        (declare (not safe))
                                        (gxc#compile-e__1
                                         _%self210589%_
                                         _%$%hd210601210629%_))
                                      (cons ''#f '())))))
              (_%$%g210592210613%_ _%$%g210593210616%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g210592210613%_
                                               _%$%g210593210616%_))))
                                      (_%$%g210592210613%_
                                       _%$%g210593210616%_))))
                              (_%$%g210592210613%_ _%$%g210593210616%_))))
                      (_%$%g210592210613%_ _%$%g210593210616%_)))))
          (_%$%g210591210670%_ _%stx210590%_))))
    (define gxc#generate-runtime-struct-setq%
      (lambda (_%self210489%_ _%stx210490%_)
        (let* ((_%$%g210492210517%_
                (lambda (_%$%g210493210514%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g210493210514%_))))
               (_%$%g210491210586%_
                (lambda (_%$%g210493210520%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g210493210520%_))
                      (let ((_%$%e210498210522%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g210493210520%_))))
                        (let ((_%$%hd210499210525%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e210498210522%_)))
                              (_%$%tl210500210527%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e210498210522%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl210500210527%_))
                              (let ((_%$%e210501210530%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl210500210527%_))))
                                (let ((_%$%hd210502210533%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210501210530%_)))
                                      (_%$%tl210503210535%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210501210530%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl210503210535%_))
                                      (let ((_%$%e210504210538%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl210503210535%_))))
                                        (let ((_%$%hd210505210541%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e210504210538%_)))
                                              (_%$%tl210506210543%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e210504210538%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl210506210543%_))
                                              (let ((_%$%e210507210546%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl210506210543%_))))
                                                (let ((_%$%hd210508210549%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e210507210546%_)))
                                                      (_%$%tl210509210551%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e210507210546%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl210509210551%_))
                                                      (let ((_%$%e210510210554%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%tl210509210551%_))))
                (let ((_%$%hd210511210557%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e210510210554%_)))
                      (_%$%tl210512210559%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e210510210554%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl210512210559%_))
                      (cons '##structure-set!
                            (cons (let ()
                                    (declare (not safe))
                                    (gxc#compile-e__1
                                     _%self210489%_
                                     _%$%hd210508210549%_))
                                  (cons (let ()
                                          (declare (not safe))
                                          (gxc#compile-e__1
                                           _%self210489%_
                                           _%$%hd210511210557%_))
                                        (cons (let ()
                                                (declare (not safe))
                                                (gxc#compile-e__1
                                                 _%self210489%_
                                                 _%$%hd210505210541%_))
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (gxc#compile-e__1
                                                       _%self210489%_
                                                       _%$%hd210502210533%_))
                                                    (cons ''#f '()))))))
                      (_%$%g210492210517%_ _%$%g210493210520%_))))
              (_%$%g210492210517%_ _%$%g210493210520%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g210492210517%_
                                               _%$%g210493210520%_))))
                                      (_%$%g210492210517%_
                                       _%$%g210493210520%_))))
                              (_%$%g210492210517%_ _%$%g210493210520%_))))
                      (_%$%g210492210517%_ _%$%g210493210520%_)))))
          (_%$%g210491210586%_ _%stx210490%_))))
    (define gxc#generate-runtime-struct-direct-ref%
      (lambda (_%self210405%_ _%stx210406%_)
        (let* ((_%$%g210408210429%_
                (lambda (_%$%g210409210426%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g210409210426%_))))
               (_%$%g210407210486%_
                (lambda (_%$%g210409210432%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g210409210432%_))
                      (let ((_%$%e210413210434%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g210409210432%_))))
                        (let ((_%$%hd210414210437%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e210413210434%_)))
                              (_%$%tl210415210439%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e210413210434%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl210415210439%_))
                              (let ((_%$%e210416210442%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl210415210439%_))))
                                (let ((_%$%hd210417210445%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210416210442%_)))
                                      (_%$%tl210418210447%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210416210442%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl210418210447%_))
                                      (let ((_%$%e210419210450%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl210418210447%_))))
                                        (let ((_%$%hd210420210453%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e210419210450%_)))
                                              (_%$%tl210421210455%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e210419210450%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl210421210455%_))
                                              (let ((_%$%e210422210458%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl210421210455%_))))
                                                (let ((_%$%hd210423210461%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e210422210458%_)))
                                                      (_%$%tl210424210463%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e210422210458%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl210424210463%_))
                                                      (cons '##direct-structure-ref
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (gxc#compile-e__1
                             _%self210405%_
                             _%$%hd210423210461%_))
                          (cons (let ()
                                  (declare (not safe))
                                  (gxc#compile-e__1
                                   _%self210405%_
                                   _%$%hd210420210453%_))
                                (cons (let ()
                                        (declare (not safe))
                                        (gxc#compile-e__1
                                         _%self210405%_
                                         _%$%hd210417210445%_))
                                      (cons ''#f '())))))
              (_%$%g210408210429%_ _%$%g210409210432%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g210408210429%_
                                               _%$%g210409210432%_))))
                                      (_%$%g210408210429%_
                                       _%$%g210409210432%_))))
                              (_%$%g210408210429%_ _%$%g210409210432%_))))
                      (_%$%g210408210429%_ _%$%g210409210432%_)))))
          (_%$%g210407210486%_ _%stx210406%_))))
    (define gxc#generate-runtime-struct-direct-setq%
      (lambda (_%self210305%_ _%stx210306%_)
        (let* ((_%$%g210308210333%_
                (lambda (_%$%g210309210330%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g210309210330%_))))
               (_%$%g210307210402%_
                (lambda (_%$%g210309210336%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g210309210336%_))
                      (let ((_%$%e210314210338%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g210309210336%_))))
                        (let ((_%$%hd210315210341%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e210314210338%_)))
                              (_%$%tl210316210343%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e210314210338%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl210316210343%_))
                              (let ((_%$%e210317210346%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl210316210343%_))))
                                (let ((_%$%hd210318210349%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210317210346%_)))
                                      (_%$%tl210319210351%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210317210346%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl210319210351%_))
                                      (let ((_%$%e210320210354%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl210319210351%_))))
                                        (let ((_%$%hd210321210357%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e210320210354%_)))
                                              (_%$%tl210322210359%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e210320210354%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl210322210359%_))
                                              (let ((_%$%e210323210362%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl210322210359%_))))
                                                (let ((_%$%hd210324210365%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e210323210362%_)))
                                                      (_%$%tl210325210367%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e210323210362%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl210325210367%_))
                                                      (let ((_%$%e210326210370%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%tl210325210367%_))))
                (let ((_%$%hd210327210373%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e210326210370%_)))
                      (_%$%tl210328210375%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e210326210370%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl210328210375%_))
                      (cons '##direct-structure-set!
                            (cons (let ()
                                    (declare (not safe))
                                    (gxc#compile-e__1
                                     _%self210305%_
                                     _%$%hd210324210365%_))
                                  (cons (let ()
                                          (declare (not safe))
                                          (gxc#compile-e__1
                                           _%self210305%_
                                           _%$%hd210327210373%_))
                                        (cons (let ()
                                                (declare (not safe))
                                                (gxc#compile-e__1
                                                 _%self210305%_
                                                 _%$%hd210321210357%_))
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (gxc#compile-e__1
                                                       _%self210305%_
                                                       _%$%hd210318210349%_))
                                                    (cons ''#f '()))))))
                      (_%$%g210308210333%_ _%$%g210309210336%_))))
              (_%$%g210308210333%_ _%$%g210309210336%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g210308210333%_
                                               _%$%g210309210336%_))))
                                      (_%$%g210308210333%_
                                       _%$%g210309210336%_))))
                              (_%$%g210308210333%_ _%$%g210309210336%_))))
                      (_%$%g210308210333%_ _%$%g210309210336%_)))))
          (_%$%g210307210402%_ _%stx210306%_))))
    (define gxc#generate-runtime-struct-unchecked-ref%
      (lambda (_%self210100%_ _%stx210101%_)
        (let* ((_%$%g210103210124%_
                (lambda (_%$%g210104210121%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g210104210121%_))))
               (_%$%g210102210302%_
                (lambda (_%$%g210104210127%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g210104210127%_))
                      (let ((_%$%e210108210129%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g210104210127%_))))
                        (let ((_%$%hd210109210132%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e210108210129%_)))
                              (_%$%tl210110210134%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e210108210129%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl210110210134%_))
                              (let ((_%$%e210111210137%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl210110210134%_))))
                                (let ((_%$%hd210112210140%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e210111210137%_)))
                                      (_%$%tl210113210142%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e210111210137%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl210113210142%_))
                                      (let ((_%$%e210114210145%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl210113210142%_))))
                                        (let ((_%$%hd210115210148%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e210114210145%_)))
                                              (_%$%tl210116210150%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e210114210145%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl210116210150%_))
                                              (let ((_%$%e210117210153%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl210116210150%_))))
                                                (let ((_%$%hd210118210156%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e210117210153%_)))
                                                      (_%$%tl210119210158%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e210117210153%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl210119210158%_))
                                                      (if (gxc#current-compile-decls-unsafe?)
                                                          (cons '##unchecked-structure-ref
                                                                (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                (declare (not safe))
                                (gxc#compile-e__1
                                 _%self210100%_
                                 _%$%hd210118210156%_))
                              (cons (let ()
                                      (declare (not safe))
                                      (gxc#compile-e__1
                                       _%self210100%_
                                       _%$%hd210115210148%_))
                                    (cons ''#f (cons ''#f '())))))
                  (let _%lp210181%_ ((_%rest210184%_
                                      (cons _%$%hd210115210148%_
                                            (cons _%$%hd210118210156%_ '())))
                                     (_%bind210186%_ '())
                                     (_%args210187%_ '()))
                    (let* ((_%$%rest210188210196%_ _%rest210184%_)
                           (_%$%else210190210204%_
                            (lambda ()
                              (cons 'let
                                    (cons _%bind210186%_
                                          (cons '(declare (not safe))
                                                (cons (cons '##unchecked-structure-ref
                                                            (let ((__tmp218320
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons ''#f (cons ''#f '()))))
                      (declare (not safe))
                      (##append _%args210187%_ __tmp218320)))
              '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                           (_%$%K210192210290%_
                            (lambda (_%rest210207%_ _%e210208%_)
                              (let* ((_%__stx217959217960%_ _%e210208%_)
                                     (_%$%g210213210231%_
                                      (lambda ()
                                        (let ()
                                          (declare (not safe))
                                          (gx#raise-syntax-error
                                           '#f
                                           '"Bad syntax; invalid match target"
                                           _%__stx217959217960%_)))))
                                (let ((_%__kont217961217962%_
                                       (lambda ()
                                         (_%lp210181%_
                                          _%rest210207%_
                                          _%bind210186%_
                                          (cons (let ()
                                                  (declare (not safe))
                                                  (gxc#compile-e__0
                                                   _%e210208%_))
                                                _%args210187%_))))
                                      (_%__kont217963217964%_
                                       (lambda ()
                                         (_%lp210181%_
                                          _%rest210207%_
                                          _%bind210186%_
                                          (cons (let ()
                                                  (declare (not safe))
                                                  (gxc#compile-e__0
                                                   _%e210208%_))
                                                _%args210187%_))))
                                      (_%__kont217965217966%_
                                       (lambda ()
                                         (let ((_%tmp210238%_
                                                (let ((__tmp218321
                                                       (let ()
                                                         (declare (not safe))
                                                         (##gensym '__tmp))))
                                                  (declare (not safe))
                                                  (make-symbol__0
                                                   __tmp218321))))
                                           (_%lp210181%_
                                            _%rest210207%_
                                            (cons (cons _%tmp210238%_
                                                        (cons (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gxc#compile-e__0 _%e210208%_))
                      '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  _%bind210186%_)
                                            (cons _%tmp210238%_
                                                  _%args210187%_))))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%__stx217959217960%_))
                                      (let ((_%$%e210215210269%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%__stx217959217960%_))))
                                        (let ((_%$%tl210217210274%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e210215210269%_)))
                                              (_%$%hd210216210272%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e210215210269%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#identifier?
                                                 _%$%hd210216210272%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-eq?
                                                     '%#ref
                                                     _%$%hd210216210272%_))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl210217210274%_))
                                                      (let ((_%$%e210218210277%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%tl210217210274%_))))
                (let ((_%$%tl210220210282%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e210218210277%_)))
                      (_%$%hd210219210280%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e210218210277%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl210220210282%_))
                      (_%__kont217961217962%_)
                      (_%__kont217965217966%_))))
              (_%__kont217965217966%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-eq?
                                                         '%#quote
                                                         _%$%hd210216210272%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%tl210217210274%_))
                                                          (let ((_%$%e210224210254%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%tl210217210274%_))))
                    (let ((_%$%tl210226210259%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e210224210254%_)))
                          (_%$%hd210225210257%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e210224210254%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl210226210259%_))
                          (_%__kont217963217964%_)
                          (_%__kont217965217966%_))))
                  (_%__kont217965217966%_))
              (_%__kont217965217966%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%__kont217965217966%_))))
                                      (_%__kont217965217966%_)))))))
                      (if (pair? _%$%rest210188210196%_)
                          (let ((_%$%hd210193210293%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%rest210188210196%_)))
                                (_%$%tl210194210295%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%rest210188210196%_))))
                            (let* ((_%e210298%_ _%$%hd210193210293%_)
                                   (_%rest210300%_ _%$%tl210194210295%_))
                              (_%$%K210192210290%_
                               _%rest210300%_
                               _%e210298%_)))
                          (_%$%else210190210204%_)))))
              (_%$%g210103210124%_ _%$%g210104210127%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g210103210124%_
                                               _%$%g210104210127%_))))
                                      (_%$%g210103210124%_
                                       _%$%g210104210127%_))))
                              (_%$%g210103210124%_ _%$%g210104210127%_))))
                      (_%$%g210103210124%_ _%$%g210104210127%_)))))
          (_%$%g210102210302%_ _%stx210101%_))))
    (define gxc#generate-runtime-struct-unchecked-setq%
      (lambda (_%self209879%_ _%stx209880%_)
        (let* ((_%$%g209882209907%_
                (lambda (_%$%g209883209904%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g209883209904%_))))
               (_%$%g209881210097%_
                (lambda (_%$%g209883209910%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g209883209910%_))
                      (let ((_%$%e209888209912%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g209883209910%_))))
                        (let ((_%$%hd209889209915%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e209888209912%_)))
                              (_%$%tl209890209917%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e209888209912%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl209890209917%_))
                              (let ((_%$%e209891209920%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl209890209917%_))))
                                (let ((_%$%hd209892209923%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e209891209920%_)))
                                      (_%$%tl209893209925%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e209891209920%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl209893209925%_))
                                      (let ((_%$%e209894209928%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl209893209925%_))))
                                        (let ((_%$%hd209895209931%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e209894209928%_)))
                                              (_%$%tl209896209933%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e209894209928%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl209896209933%_))
                                              (let ((_%$%e209897209936%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl209896209933%_))))
                                                (let ((_%$%hd209898209939%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e209897209936%_)))
                                                      (_%$%tl209899209941%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e209897209936%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%$%tl209899209941%_))
                                                      (let ((_%$%e209900209944%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%$%tl209899209941%_))))
                (let ((_%$%hd209901209947%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e209900209944%_)))
                      (_%$%tl209902209949%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e209900209944%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl209902209949%_))
                      (if (gxc#current-compile-decls-unsafe?)
                          (cons '##unchecked-structure-set!
                                (cons (let ()
                                        (declare (not safe))
                                        (gxc#compile-e__1
                                         _%self209879%_
                                         _%$%hd209898209939%_))
                                      (cons (let ()
                                              (declare (not safe))
                                              (gxc#compile-e__1
                                               _%self209879%_
                                               _%$%hd209901209947%_))
                                            (cons (let ()
                                                    (declare (not safe))
                                                    (gxc#compile-e__1
                                                     _%self209879%_
                                                     _%$%hd209895209931%_))
                                                  (cons ''#f
                                                        (cons ''#f '()))))))
                          (let _%lp209976%_ ((_%rest209979%_
                                              (cons _%$%hd209895209931%_
                                                    (cons _%$%hd209901209947%_
                                                          (cons _%$%hd209898209939%_
                                                                '()))))
                                             (_%bind209981%_ '())
                                             (_%args209982%_ '()))
                            (let* ((_%$%rest209983209991%_ _%rest209979%_)
                                   (_%$%else209985209999%_
                                    (lambda ()
                                      (cons 'let
                                            (cons _%bind209981%_
                                                  (cons '(declare (not safe))
                                                        (cons (cons '##unchecked-structure-set!
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (let ((__tmp218322 (cons ''#f (cons ''#f '()))))
                              (declare (not safe))
                              (##append _%args209982%_ __tmp218322)))
                      '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                   (_%$%K209987210085%_
                                    (lambda (_%rest210002%_ _%e210003%_)
                                      (let* ((_%__stx218005218006%_
                                              _%e210003%_)
                                             (_%$%g210008210026%_
                                              (lambda ()
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#raise-syntax-error
                                                   '#f
                                                   '"Bad syntax; invalid match target"
                                                   _%__stx218005218006%_)))))
                                        (let ((_%__kont218007218008%_
                                               (lambda ()
                                                 (_%lp209976%_
                                                  _%rest210002%_
                                                  _%bind209981%_
                                                  (cons (let ()
                                                          (declare (not safe))
                                                          (gxc#compile-e__0
                                                           _%e210003%_))
                                                        _%args209982%_))))
                                              (_%__kont218009218010%_
                                               (lambda ()
                                                 (_%lp209976%_
                                                  _%rest210002%_
                                                  _%bind209981%_
                                                  (cons (let ()
                                                          (declare (not safe))
                                                          (gxc#compile-e__0
                                                           _%e210003%_))
                                                        _%args209982%_))))
                                              (_%__kont218011218012%_
                                               (lambda ()
                                                 (let ((_%tmp210033%_
                                                        (let ((__tmp218323
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##gensym '__tmp))))
                  (declare (not safe))
                  (make-symbol__0 __tmp218323))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%lp209976%_
                                                    _%rest210002%_
                                                    (cons (cons _%tmp210033%_
                                                                (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                (declare (not safe))
                                (gxc#compile-e__0 _%e210003%_))
                              '()))
                  _%bind209981%_)
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons _%tmp210033%_
                                                          _%args209982%_))))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%__stx218005218006%_))
                                              (let ((_%$%e210010210064%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%__stx218005218006%_))))
                                                (let ((_%$%tl210012210069%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e210010210064%_)))
                                                      (_%$%hd210011210067%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e210010210064%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#identifier?
                                                         _%$%hd210011210067%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-eq?
                                                             '%#ref
                                                             _%$%hd210011210067%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%tl210012210069%_))
                      (let ((_%$%e210013210072%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl210012210069%_))))
                        (let ((_%$%tl210015210077%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e210013210072%_)))
                              (_%$%hd210014210075%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e210013210072%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl210015210077%_))
                              (_%__kont218007218008%_)
                              (_%__kont218011218012%_))))
                      (_%__kont218011218012%_))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-eq? '%#quote _%$%hd210011210067%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl210012210069%_))
                          (let ((_%$%e210019210049%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl210012210069%_))))
                            (let ((_%$%tl210021210054%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e210019210049%_)))
                                  (_%$%hd210020210052%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e210019210049%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl210021210054%_))
                                  (_%__kont218009218010%_)
                                  (_%__kont218011218012%_))))
                          (_%__kont218011218012%_))
                      (_%__kont218011218012%_)))
              (_%__kont218011218012%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%__kont218011218012%_)))))))
                              (if (pair? _%$%rest209983209991%_)
                                  (let ((_%$%hd209988210088%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%rest209983209991%_)))
                                        (_%$%tl209989210090%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%rest209983209991%_))))
                                    (let* ((_%e210093%_ _%$%hd209988210088%_)
                                           (_%rest210095%_
                                            _%$%tl209989210090%_))
                                      (_%$%K209987210085%_
                                       _%rest210095%_
                                       _%e210093%_)))
                                  (_%$%else209985209999%_)))))
                      (_%$%g209882209907%_ _%$%g209883209910%_))))
              (_%$%g209882209907%_ _%$%g209883209910%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g209882209907%_
                                               _%$%g209883209910%_))))
                                      (_%$%g209882209907%_
                                       _%$%g209883209910%_))))
                              (_%$%g209882209907%_ _%$%g209883209910%_))))
                      (_%$%g209882209907%_ _%$%g209883209910%_)))))
          (_%$%g209881210097%_ _%stx209880%_))))
    (define gxc#generate-runtime-loader-import%
      (lambda (_%self209718%_ _%stx209719%_)
        (letrec ((_%import-set-template209721%_
                  (lambda (_%in209824%_ _%phi209825%_)
                    (let ((_%iphi209827%_
                           (fx+ _%phi209825%_
                                (##direct-structure-ref
                                 _%in209824%_
                                 '2
                                 gx#import-set::t
                                 '#f)))
                          (_%imports209828%_
                           (##structure-ref
                            (##direct-structure-ref
                             _%in209824%_
                             '1
                             gx#import-set::t
                             '#f)
                            '8
                            gx#module-context::t
                            '#f)))
                      (let _%lp209830%_ ((_%rest209832%_ _%imports209828%_)
                                         (_%r209833%_ '()))
                        (let* ((_%$%rest209834209842%_ _%rest209832%_)
                               (_%$%else209836209850%_ (lambda () _%r209833%_))
                               (_%$%K209838209867%_
                                (lambda (_%rest209853%_ _%in209854%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (##structure-instance-of?
                                         _%in209854%_
                                         'gx#module-context::t))
                                      (if (let ()
                                            (declare (not safe))
                                            (##fxzero? _%iphi209827%_))
                                          (_%lp209830%_
                                           _%rest209853%_
                                           (cons _%in209854%_ _%r209833%_))
                                          (_%lp209830%_
                                           _%rest209853%_
                                           _%r209833%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (##structure-direct-instance-of?
                                             _%in209854%_
                                             'gx#module-import::t))
                                          (let ((_%iphi209858%_
                                                 (fx+ _%phi209825%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##unchecked-structure-ref
                                                         _%in209854%_
                                                         '3
                                                         '#f
                                                         '#f)))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##fxzero? _%iphi209858%_))
                                                (_%lp209830%_
                                                 _%rest209853%_
                                                 (cons (##direct-structure-ref
                                                        (let ()
                                                          (declare (not safe))
                                                          (##unchecked-structure-ref
                                                           _%in209854%_
                                                           '1
                                                           '#f
                                                           '#f))
                                                        '1
                                                        gx#module-export::t
                                                        '#f)
                                                       _%r209833%_))
                                                (_%lp209830%_
                                                 _%rest209853%_
                                                 _%r209833%_)))
                                          (if (let ()
                                                (declare (not safe))
                                                (##structure-direct-instance-of?
                                                 _%in209854%_
                                                 'gx#import-set::t))
                                              (let ((_%xphi209861%_
                                                     (fx+ _%iphi209827%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##unchecked-structure-ref
                                                             _%in209854%_
                                                             '2
                                                             '#f
                                                             '#f)))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (##fxzero?
                                                       _%xphi209861%_))
                                                    (_%lp209830%_
                                                     _%rest209853%_
                                                     (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (##unchecked-structure-ref
                                                              _%in209854%_
                                                              '1
                                                              '#f
                                                              '#f))
                                                           _%r209833%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (##fxpositive?
                                                           _%xphi209861%_))
                                                        (_%lp209830%_
                                                         _%rest209853%_
                                                         (let ((__tmp218324
                                                                (_%import-set-template209721%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%in209854%_
                         _%iphi209827%_)))
                   (declare (not safe))
                   (foldl__0 cons _%r209833%_ __tmp218324)))
                (_%lp209830%_ _%rest209853%_ _%r209833%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%lp209830%_
                                               _%rest209853%_
                                               _%r209833%_)))))))
                          (if (pair? _%$%rest209834209842%_)
                              (let ((_%$%hd209839209870%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest209834209842%_)))
                                    (_%$%tl209840209872%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest209834209842%_))))
                                (let* ((_%in209875%_ _%$%hd209839209870%_)
                                       (_%rest209877%_ _%$%tl209840209872%_))
                                  (_%$%K209838209867%_
                                   _%rest209877%_
                                   _%in209875%_)))
                              (_%$%else209836209850%_))))))))
          (let* ((_%$%g209723209733%_
                  (lambda (_%$%g209724209730%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g209724209730%_))))
                 (_%$%g209722209821%_
                  (lambda (_%$%g209724209736%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g209724209736%_))
                        (let ((_%$%e209726209738%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g209724209736%_))))
                          (let ((_%$%hd209727209741%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e209726209738%_)))
                                (_%$%tl209728209743%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e209726209738%_))))
                            (let ((_%ht209757%_
                                   (let ()
                                     (declare (not safe))
                                     (make-hash-table-eq))))
                              (let _%lp209759%_ ((_%rest209761%_
                                                  _%$%tl209728209743%_)
                                                 (_%loads209762%_ '()))
                                (letrec ((_%K209764%_
                                          (lambda (_%ctx209814%_
                                                   _%rest209815%_)
                                            (let ((_%id209817%_
                                                   (##structure-ref
                                                    _%ctx209814%_
                                                    '1
                                                    gx#expander-context::t
                                                    '#f)))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (__hash-get
                                                     _%ht209757%_
                                                     _%id209817%_))
                                                  (_%lp209759%_
                                                   _%rest209815%_
                                                   _%loads209762%_)
                                                  (let ((_%rt209819%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gxc#module-id->path-string
                                                            _%id209817%_))))
                                                    (let ()
                                                      (declare (not safe))
                                                      (__hash-put!
                                                       _%ht209757%_
                                                       _%id209817%_
                                                       _%rt209819%_))
                                                    (_%lp209759%_
                                                     _%rest209815%_
                                                     (cons _%rt209819%_
                                                           _%loads209762%_))))))))
                                  (let* ((_%$%rest209765209773%_
                                          _%rest209761%_)
                                         (_%$%else209767209785%_
                                          (lambda ()
                                            (cons 'begin
                                                  (let ((__tmp218326
                                                         (lambda (_%$%g209780209782%_)
                                                           (list 'load-module
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%$%g209780209782%_)))
                (__tmp218325 (reverse _%loads209762%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (##map __tmp218326
                                                           __tmp218325)))))
                                         (_%$%K209769209802%_
                                          (lambda (_%rest209788%_ _%in209789%_)
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##structure-instance-of?
                                                   _%in209789%_
                                                   'gx#module-context::t))
                                                (_%K209764%_
                                                 _%in209789%_
                                                 _%rest209788%_)
                                                (if (let ()
                                                      (declare (not safe))
                                                      (##structure-direct-instance-of?
                                                       _%in209789%_
                                                       'gx#module-import::t))
                                                    (if (fxzero? (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (declare (not safe))
                           (##unchecked-structure-ref
                            _%in209789%_
                            '3
                            '#f
                            '#f)))
                (_%K209764%_
                 (##direct-structure-ref
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-ref _%in209789%_ '1 '#f '#f))
                  '1
                  gx#module-export::t
                  '#f)
                 _%rest209788%_)
                (_%lp209759%_ _%rest209788%_ _%loads209762%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (##structure-direct-instance-of?
                                                           _%in209789%_
                                                           'gx#import-set::t))
                                                        (let ((_%phi209794%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (##unchecked-structure-ref _%in209789%_ '2 '#f '#f))))
                  (if (fxzero? _%phi209794%_)
                      (_%K209764%_
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref _%in209789%_ '1 '#f '#f))
                       _%rest209788%_)
                      (if (fxpositive? _%phi209794%_)
                          (let ((_%deps209798%_
                                 (_%import-set-template209721%_
                                  _%in209789%_
                                  '0)))
                            (_%lp209759%_
                             (let ()
                               (declare (not safe))
                               (foldl__0 cons _%rest209788%_ _%deps209798%_))
                             _%loads209762%_))
                          (_%lp209759%_ _%rest209788%_ _%loads209762%_))))
                (let ()
                  (declare (not safe))
                  (gxc#raise-compile-error
                   '"Unexpected import"
                   _%stx209719%_
                   _%in209789%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    (if (pair? _%$%rest209765209773%_)
                                        (let ((_%$%hd209770209805%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%rest209765209773%_)))
                                              (_%$%tl209771209807%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%rest209765209773%_))))
                                          (let* ((_%in209810%_
                                                  _%$%hd209770209805%_)
                                                 (_%rest209812%_
                                                  _%$%tl209771209807%_))
                                            (_%$%K209769209802%_
                                             _%rest209812%_
                                             _%in209810%_)))
                                        (_%$%else209767209785%_))))))))
                        (_%$%g209723209733%_ _%$%g209724209736%_)))))
            (_%$%g209722209821%_ _%stx209719%_)))))
    (define gxc#generate-runtime-quote-syntax%
      (lambda (_%self209532%_ _%stx209533%_)
        (letrec ((_%add-lift!209535%_
                  (lambda (_%expr209716%_)
                    (set-box!
                     (let () (declare (not safe)) (gxc#current-compile-lift))
                     (cons _%expr209716%_
                           (unbox (let ()
                                    (declare (not safe))
                                    (gxc#current-compile-lift)))))))
                 (_%generate-syntax-quote209536%_
                  (lambda (_%id209713%_ _%marks209714%_)
                    (cons '##structure
                          (cons 'gx#syntax-quote::t
                                (cons (cons 'quote (cons _%id209713%_ '()))
                                      (cons '#f
                                            (cons '(gx#current-expander-context)
                                                  (cons _%marks209714%_
                                                        '()))))))))
                 (_%generate-simple209537%_
                  (lambda (_%stxq209708%_)
                    (let ((_%gid209710%_
                           (let ()
                             (declare (not safe))
                             (gxc#generate-runtime-temporary__% '#t)))
                          (_%qid209711%_
                           (let ()
                             (declare (not safe))
                             (gxc#generate-runtime-identifier
                              _%stxq209708%_))))
                      (_%add-lift!209535%_
                       (cons 'define
                             (cons _%gid209710%_
                                   (cons (_%generate-syntax-quote209536%_
                                          _%qid209711%_
                                          ''())
                                         '()))))
                      (let ((__tmp218327
                             (let ()
                               (declare (not safe))
                               (gxc#current-compile-identifiers))))
                        (declare (not safe))
                        (hash-put! __tmp218327 _%stxq209708%_ _%gid209710%_))
                      _%gid209710%_)))
                 (_%generate-serialized209538%_
                  (lambda (_%stxq209698%_ _%marks209699%_)
                    (let* ((_%mark-refs209701%_
                            (map _%generate-mark209539%_ _%marks209699%_))
                           (_%gid209703%_
                            (let ()
                              (declare (not safe))
                              (gxc#generate-runtime-temporary__% '#t)))
                           (_%qid209705%_
                            (let ()
                              (declare (not safe))
                              (gxc#generate-runtime-identifier
                               _%stxq209698%_))))
                      (_%add-lift!209535%_
                       (cons 'define
                             (cons _%gid209703%_
                                   (cons (_%generate-syntax-quote209536%_
                                          _%qid209705%_
                                          (cons 'list _%mark-refs209701%_))
                                         '()))))
                      (let ((__tmp218328
                             (let ()
                               (declare (not safe))
                               (gxc#current-compile-identifiers))))
                        (declare (not safe))
                        (hash-put! __tmp218328 _%stxq209698%_ _%gid209703%_))
                      _%gid209703%_)))
                 (_%generate-mark209539%_
                  (lambda (_%mark209683%_)
                    (let ((_%$e209685%_
                           (let ((__tmp218329
                                  (let ()
                                    (declare (not safe))
                                    (gxc#current-compile-marks))))
                             (declare (not safe))
                             (hash-get __tmp218329 _%mark209683%_))))
                      (if _%$e209685%_
                          _%$e209685%_
                          (let* ((_%gid209689%_
                                  (let ()
                                    (declare (not safe))
                                    (gxc#generate-runtime-temporary__% '#t)))
                                 (_%repr209691%_
                                  (_%serialize-mark209540%_ _%mark209683%_))
                                 (_%ctx209693%_
                                  (let ((__tmp218330
                                         (##structure-ref
                                          _%mark209683%_
                                          '2
                                          gx#expander-mark::t
                                          '#f)))
                                    (declare (not safe))
                                    (gx#core-context-top__1 __tmp218330)))
                                 (_%ctx-ref209695%_
                                  (if (eq? _%ctx209693%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#current-expander-context)))
                                      '(gx#current-expander-context)
                                      (cons 'gx#import-module
                                            (cons (cons 'quote
                                                        (cons (_%context-ref209541%_
                                                               _%ctx209693%_)
                                                              '()))
                                                  '())))))
                            (let ((__tmp218331
                                   (let ()
                                     (declare (not safe))
                                     (gxc#current-compile-marks))))
                              (declare (not safe))
                              (hash-put!
                               __tmp218331
                               _%mark209683%_
                               _%gid209689%_))
                            (_%add-lift!209535%_
                             (cons 'define
                                   (cons _%gid209689%_
                                         (cons (cons 'gx#core-deserialize-mark
                                                     (cons (cons 'quote
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons _%repr209691%_ '()))
                   (cons _%ctx-ref209695%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               '()))))
                            _%gid209689%_)))))
                 (_%serialize-mark209540%_
                  (lambda (_%mark209631%_)
                    (letrec ((_%quote-e209633%_
                              (lambda (_%sym209681%_)
                                (if (let ()
                                      (declare (not safe))
                                      (interned-symbol? _%sym209681%_))
                                    _%sym209681%_
                                    (let ()
                                      (declare (not safe))
                                      (gxc#generate-runtime-gensym-reference__0
                                       _%sym209681%_))))))
                      (let* ((_%$%mark209634209643%_ _%mark209631%_)
                             (_%$%E209636209646%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (error '"No clause matching"
                                         _%$%mark209634209643%_
                                         '((expander-mark
                                            subst
                                            ctx
                                            phi
                                            trace))))
                                '#!void))
                             (_%$%K209637209658%_
                              (lambda (_%trace209649%_
                                       _%phi209650%_
                                       _%ctx209651%_
                                       _%subst209652%_)
                                (let ((_%subs209654%_
                                       (if _%subst209652%_
                                           (let ()
                                             (declare (not safe))
                                             (hash->list _%subst209652%_))
                                           '())))
                                  (cons _%phi209650%_
                                        (let ((__tmp218332
                                               (lambda (_%pair209656%_)
                                                 (cons (_%quote-e209633%_
                                                        (car _%pair209656%_))
                                                       (_%quote-e209633%_
                                                        (cdr _%pair209656%_))))))
                                          (declare (not safe))
                                          (##map __tmp218332
                                                 _%subs209654%_)))))))
                        (if (let ()
                              (declare (not safe))
                              (##structure-instance-of?
                               _%$%mark209634209643%_
                               'gx#expander-mark::t))
                            (let* ((_%$%e209638209661%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%$%mark209634209643%_
                                       '1
                                       '#f
                                       '#f)))
                                   (_%subst209664%_ _%$%e209638209661%_)
                                   (_%$%e209639209666%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%$%mark209634209643%_
                                       '2
                                       '#f
                                       '#f)))
                                   (_%ctx209669%_ _%$%e209639209666%_)
                                   (_%$%e209640209671%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%$%mark209634209643%_
                                       '3
                                       '#f
                                       '#f)))
                                   (_%phi209674%_ _%$%e209640209671%_)
                                   (_%$%e209641209676%_
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%$%mark209634209643%_
                                       '4
                                       '#f
                                       '#f)))
                                   (_%trace209679%_ _%$%e209641209676%_))
                              (_%$%K209637209658%_
                               _%trace209679%_
                               _%phi209674%_
                               _%ctx209669%_
                               _%subst209664%_))
                            (_%$%E209636209646%_))))))
                 (_%context-ref209541%_
                  (lambda (_%ctx209618%_)
                    (if (let ((__tmp218333
                               (##structure-ref
                                _%ctx209618%_
                                '3
                                gx#phi-context::t
                                '#f)))
                          (declare (not safe))
                          (##structure-instance-of?
                           __tmp218333
                           'gx#module-context::t))
                        (let ((_%ctx-ref209620%_
                               (_%context-ref-nested209543%_ _%ctx209618%_))
                              (_%ctx-origin209621%_
                               (_%context-ref-origin209542%_ _%ctx209618%_))
                              (_%origin209622%_
                               (_%context-ref-origin209542%_
                                (let ()
                                  (declare (not safe))
                                  (gx#current-expander-context)))))
                          (if (eq? _%origin209622%_ _%ctx-origin209621%_)
                              (let ((_%ref209624%_
                                     (_%context-ref-nested209543%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#current-expander-context)))))
                                (let _%lp209626%_ ((_%ref209628%_
                                                    (cdr _%ref209624%_))
                                                   (_%ctx-ref209629%_
                                                    (cdr _%ctx-ref209620%_)))
                                  (if (and (pair? _%ref209628%_)
                                           (eq? (let ()
                                                  (declare (not safe))
                                                  (##car _%ref209628%_))
                                                (car _%ctx-ref209629%_)))
                                      (_%lp209626%_
                                       (cdr _%ref209628%_)
                                       (cdr _%ctx-ref209629%_))
                                      (cons '#f _%ctx-ref209629%_))))
                              _%ctx-ref209620%_))
                        (let ((__tmp218334
                               (##structure-ref
                                _%ctx209618%_
                                '1
                                gx#expander-context::t
                                '#f)))
                          (declare (not safe))
                          (make-symbol__1 '":" __tmp218334)))))
                 (_%context-ref-origin209542%_
                  (lambda (_%ctx209610%_)
                    (let _%lp209612%_ ((_%ctx209614%_ _%ctx209610%_))
                      (let ((_%super209616%_
                             (##structure-ref
                              _%ctx209614%_
                              '3
                              gx#phi-context::t
                              '#f)))
                        (if (let ()
                              (declare (not safe))
                              (##structure-instance-of?
                               _%super209616%_
                               'gx#module-context::t))
                            (_%lp209612%_ _%super209616%_)
                            _%ctx209614%_)))))
                 (_%context-ref-nested209543%_
                  (lambda (_%ctx209601%_)
                    (let _%lp209603%_ ((_%ctx209605%_ _%ctx209601%_)
                                       (_%r209606%_ '()))
                      (let ((_%super209608%_
                             (##structure-ref
                              _%ctx209605%_
                              '3
                              gx#phi-context::t
                              '#f)))
                        (if (let ()
                              (declare (not safe))
                              (##structure-instance-of?
                               _%super209608%_
                               'gx#module-context::t))
                            (_%lp209603%_
                             _%super209608%_
                             (cons (car (##structure-ref
                                         _%ctx209605%_
                                         '7
                                         gx#module-context::t
                                         '#f))
                                   _%r209606%_))
                            (cons (let ((__tmp218335
                                         (##structure-ref
                                          _%ctx209605%_
                                          '1
                                          gx#expander-context::t
                                          '#f)))
                                    (declare (not safe))
                                    (make-symbol__1 '":" __tmp218335))
                                  _%r209606%_)))))))
          (let* ((_%$%g209545209558%_
                  (lambda (_%$%g209546209555%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g209546209555%_))))
                 (_%$%g209544209598%_
                  (lambda (_%$%g209546209561%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g209546209561%_))
                        (let ((_%$%e209548209563%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g209546209561%_))))
                          (let ((_%$%hd209549209566%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e209548209563%_)))
                                (_%$%tl209550209568%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e209548209563%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl209550209568%_))
                                (let ((_%$%e209551209571%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl209550209568%_))))
                                  (let ((_%$%hd209552209574%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e209551209571%_)))
                                        (_%$%tl209553209576%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e209551209571%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl209553209576%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#identifier?
                                               _%$%hd209552209574%_))
                                            (let ((_%$e209592%_
                                                   (let ((__tmp218336
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gxc#current-compile-identifiers))))
                                                     (declare (not safe))
                                                     (hash-get
                                                      __tmp218336
                                                      _%$%hd209552209574%_))))
                                              (if _%$e209592%_
                                                  _%$e209592%_
                                                  (let ((_%marks209596%_
                                                         (##direct-structure-ref
                                                          _%$%hd209552209574%_
                                                          '4
                                                          gx#syntax-quote::t
                                                          '#f)))
                                                    (if (null? _%marks209596%_)
                                                        (_%generate-simple209537%_
                                                         _%$%hd209552209574%_)
                                                        (_%generate-serialized209538%_
                                                         _%$%hd209552209574%_
                                                         _%marks209596%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (gxc#raise-compile-error
                                               '"Cannot quote non-identifier syntax"
                                               _%$%hd209552209574%_)))
                                        (_%$%g209545209558%_
                                         _%$%g209546209561%_))))
                                (_%$%g209545209558%_ _%$%g209546209561%_))))
                        (_%$%g209545209558%_ _%$%g209546209561%_)))))
            (_%$%g209544209598%_ _%stx209533%_)))))
    (define gxc#generate-runtime-phi-define-runtime%
      (lambda (_%self209464%_ _%stx209465%_)
        (let* ((_%$%g209467209484%_
                (lambda (_%$%g209468209481%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g209468209481%_))))
               (_%$%g209466209529%_
                (lambda (_%$%g209468209487%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g209468209487%_))
                      (let ((_%$%e209471209489%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g209468209487%_))))
                        (let ((_%$%hd209472209492%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e209471209489%_)))
                              (_%$%tl209473209494%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e209471209489%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl209473209494%_))
                              (let ((_%$%e209474209497%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl209473209494%_))))
                                (let ((_%$%hd209475209500%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e209474209497%_)))
                                      (_%$%tl209476209502%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e209474209497%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl209476209502%_))
                                      (let ((_%$%e209477209505%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl209476209502%_))))
                                        (let ((_%$%hd209478209508%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e209477209505%_)))
                                              (_%$%tl209479209510%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e209477209505%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl209479209510%_))
                                              (cons 'define
                                                    (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%hd209475209500%_))
                                                          (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gxc#compile-e__1
                           _%self209464%_
                           _%$%hd209478209508%_))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g209467209484%_
                                               _%$%g209468209487%_))))
                                      (_%$%g209467209484%_
                                       _%$%g209468209487%_))))
                              (_%$%g209467209484%_ _%$%g209468209487%_))))
                      (_%$%g209467209484%_ _%$%g209468209487%_)))))
          (_%$%g209466209529%_ _%stx209465%_))))
    (define gxc#generate-meta-begin%
      (lambda (_%self209413%_ _%stx209414%_)
        (let* ((_%$%g209416209426%_
                (lambda (_%$%g209417209423%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g209417209423%_))))
               (_%$%g209415209461%_
                (lambda (_%$%g209417209429%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g209417209429%_))
                      (let ((_%$%e209419209431%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g209417209429%_))))
                        (let ((_%$%hd209420209434%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e209419209431%_)))
                              (_%$%tl209421209436%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e209419209431%_))))
                          (let* ((_%c-body209453%_
                                  (map (lambda (_%$%g209448209450%_)
                                         (let ()
                                           (declare (not safe))
                                           (gxc#compile-e__1
                                            _%self209413%_
                                            _%$%g209448209450%_)))
                                       _%$%tl209421209436%_))
                                 (_%c-body209458%_
                                  (let ((__tmp218337
                                         (lambda (_%$obj209455%_)
                                           (not (eq? _%$obj209455%_
                                                     '#!void)))))
                                    (declare (not safe))
                                    (##filter __tmp218337 _%c-body209453%_))))
                            (cons '%#begin _%c-body209458%_))))
                      (_%$%g209416209426%_ _%$%g209417209429%_)))))
          (_%$%g209415209461%_ _%stx209414%_))))
    (define gxc#generate-meta-begin-syntax%
      (lambda (_%self209318%_ _%stx209319%_)
        (let* ((_%$%g209321209331%_
                (lambda (_%$%g209322209328%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g209322209328%_))))
               (_%$%g209320209410%_
                (lambda (_%$%g209322209334%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g209322209334%_))
                      (let ((_%$%e209324209336%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g209322209334%_))))
                        (let ((_%$%hd209325209339%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e209324209336%_)))
                              (_%$%tl209326209341%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e209324209336%_))))
                          (let* ((_%phi209354%_
                                  (let ((__tmp218338
                                         (let ()
                                           (declare (not safe))
                                           (gx#current-expander-phi))))
                                    (declare (not safe))
                                    (##fx+ __tmp218338 '1)))
                                 (_%block209356%_
                                  (gxc#meta-state-begin-phi!
                                   (let ()
                                     (declare (not safe))
                                     (slot-ref__0 _%self209318%_ 'state))
                                   _%phi209354%_))
                                 (_%compiled209359%_
                                  (let ((__tmp218339
                                         (lambda ()
                                           (gxc#apply-generate-meta-phi__%
                                            '#f
                                            (let ()
                                              (declare (not safe))
                                              (slot-ref__0
                                               _%self209318%_
                                               'state))
                                            (cons (let ()
                                                    (declare (not safe))
                                                    (gx#datum->syntax__0
                                                     '#f
                                                     '%#begin))
                                                  _%$%tl209326209341%_)))))
                                    (declare (not safe))
                                    (call-with-parameters__1
                                     __tmp218339
                                     gx#current-expander-phi
                                     _%phi209354%_)))
                                 (_%$%g209362209372%_
                                  (lambda (_%$%g209363209369%_)
                                    (let ()
                                      (declare (not safe))
                                      (gx#raise-syntax-error
                                       '#f
                                       '"Bad syntax; invalid match target"
                                       _%$%g209363209369%_))))
                                 (_%$%g209361209407%_
                                  (lambda (_%$%g209363209375%_)
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%g209363209375%_))
                                        (let ((_%$%e209365209377%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%g209363209375%_))))
                                          (let ((_%$%hd209366209380%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e209365209377%_)))
                                                (_%$%tl209367209382%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e209365209377%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#identifier?
                                                   _%$%hd209366209380%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-eq?
                                                       '%#begin
                                                       _%$%hd209366209380%_))
                                                    (let ((_%c-body209402%_
                                                           (filter (lambda (_%$obj209399%_)
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (not (eq? _%$obj209399%_ '#!void)))
                           _%$%tl209367209382%_)))
              (if _%block209356%_
                  (cons '%#begin-syntax
                        (cons (cons '%#call
                                    (cons (cons '%#ref (cons 'load-module '()))
                                          (cons (cons '%#quote
                                                      (cons _%block209356%_
                                                            '()))
                                                '())))
                              _%c-body209402%_))
                  (if (null? _%c-body209402%_)
                      '#!void
                      (cons '%#begin-syntax _%c-body209402%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%g209362209372%_
                                                     _%$%g209363209375%_))
                                                (_%$%g209362209372%_
                                                 _%$%g209363209375%_))))
                                        (_%$%g209362209372%_
                                         _%$%g209363209375%_)))))
                            (_%$%g209361209407%_ _%compiled209359%_))))
                      (_%$%g209321209331%_ _%$%g209322209334%_)))))
          (_%$%g209320209410%_ _%stx209319%_))))
    (define gxc#generate-meta-module%
      (lambda (_%self209249%_ _%stx209250%_)
        (gxc#meta-state-end-phi!
         (let () (declare (not safe)) (slot-ref__0 _%self209249%_ 'state)))
        (let* ((_%$%g209252209266%_
                (lambda (_%$%g209253209263%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g209253209263%_))))
               (_%$%g209251209315%_
                (lambda (_%$%g209253209269%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g209253209269%_))
                      (let ((_%$%e209256209271%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g209253209269%_))))
                        (let ((_%$%hd209257209274%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e209256209271%_)))
                              (_%$%tl209258209276%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e209256209271%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl209258209276%_))
                              (let ((_%$%e209259209279%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl209258209276%_))))
                                (let ((_%$%hd209260209282%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e209259209279%_)))
                                      (_%$%tl209261209284%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e209259209279%_))))
                                  (let ((_%key209301%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#core-identifier-key
                                            _%$%hd209260209282%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (interned-symbol? _%key209301%_))
                                        '#!void
                                        (let ()
                                          (declare (not safe))
                                          (gxc#raise-compile-error
                                           '"Cannot compile module with uninterned id"
                                           _%stx209250%_
                                           _%$%hd209260209282%_
                                           _%key209301%_)))
                                    (let* ((_%ctx209303%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#syntax-local-e__0
                                               _%$%hd209260209282%_)))
                                           (_%code209306%_
                                            (let ((__tmp218340
                                                   (lambda ()
                                                     (let ((__tmp218341
                                                            (##structure-ref
                                                             _%ctx209303%_
                                                             '11
                                                             gx#module-context::t
                                                             '#f)))
                                                       (declare (not safe))
                                                       (gxc#compile-e__1
                                                        _%self209249%_
                                                        __tmp218341)))))
                                              (declare (not safe))
                                              (call-with-parameters__1
                                               __tmp218340
                                               gx#current-expander-context
                                               _%ctx209303%_)))
                                           (_%rt209308%_
                                            (let ((__tmp218342
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#current-compile-runtime-sections))))
                                              (declare (not safe))
                                              (hash-get
                                               __tmp218342
                                               _%ctx209303%_)))
                                           (_%loader209310%_
                                            (if _%rt209308%_
                                                (cons (cons '%#call
                                                            (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                (cons 'load-module '()))
                          (cons (cons '%#quote (cons _%rt209308%_ '())) '())))
              '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '()))
                                           (_%modid209312%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#stx-e
                                               _%$%hd209260209282%_))))
                                      (gxc#meta-state-end-phi!
                                       (let ()
                                         (declare (not safe))
                                         (slot-ref__0 _%self209249%_ 'state)))
                                      (cons '%#module
                                            (cons _%modid209312%_
                                                  (cons _%code209306%_
                                                        _%loader209310%_)))))))
                              (_%$%g209252209266%_ _%$%g209253209269%_))))
                      (_%$%g209252209266%_ _%$%g209253209269%_)))))
          (_%$%g209251209315%_ _%stx209250%_))))
    (define gxc#generate-meta-import-path
      (lambda (_%ctx209236%_ _%context-chain209237%_)
        (let _%lp209239%_ ((_%ctx209241%_ _%ctx209236%_) (_%path209242%_ '()))
          (let ((_%super209244%_
                 (##structure-ref _%ctx209241%_ '3 gx#phi-context::t '#f)))
            (if (memq _%super209244%_ _%context-chain209237%_)
                (cons '#f
                      (cons (car (##structure-ref
                                  _%ctx209241%_
                                  '7
                                  gx#module-context::t
                                  '#f))
                            _%path209242%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of?
                       _%super209244%_
                       'gx#module-context::t))
                    (_%lp209239%_
                     _%super209244%_
                     (cons (car (##structure-ref
                                 _%ctx209241%_
                                 '7
                                 gx#module-context::t
                                 '#f))
                           _%path209242%_))
                    (cons (let ((__tmp218343
                                 (##structure-ref
                                  _%ctx209241%_
                                  '1
                                  gx#expander-context::t
                                  '#f)))
                            (declare (not safe))
                            (make-symbol__1 '":" __tmp218343))
                          _%path209242%_)))))))
    (define gxc#current-context-chain
      (lambda ()
        (let _%lp209229%_ ((_%ctx209231%_
                            (let ()
                              (declare (not safe))
                              (gx#current-expander-context)))
                           (_%r209232%_ '()))
          (if (let ()
                (declare (not safe))
                (##structure-instance-of? _%ctx209231%_ 'gx#module-context::t))
              (_%lp209229%_
               (let ()
                 (declare (not safe))
                 (##unchecked-structure-ref _%ctx209231%_ '3 '#f '#f))
               (cons _%ctx209231%_ _%r209232%_))
              _%r209232%_))))
    (define gxc#generate-meta-import%
      (lambda (_%self208994%_ _%stx208995%_)
        (letrec* ((_%context-chain208997%_ (gxc#current-context-chain))
                  (_%make-import-spec208998%_
                   (lambda (_%in209166%_)
                     (let* ((_%$%in209167209179%_ _%in209166%_)
                            (_%$%E209169209182%_
                             (lambda ()
                               (let ()
                                 (declare (not safe))
                                 (error '"No clause matching"
                                        _%$%in209167209179%_
                                        '((module-import
                                           (module-export
                                            src-ctx
                                            src-key
                                            src-phi
                                            src-name)
                                           name
                                           phi))))
                               '#!void))
                            (_%$%K209170209192%_
                             (lambda (_%phi209185%_
                                      _%name209186%_
                                      _%src-name209187%_
                                      _%src-phi209188%_
                                      _%src-key209189%_
                                      _%src-ctx209190%_)
                               (cons _%phi209185%_
                                     (cons (let ()
                                             (declare (not safe))
                                             (gxc#generate-runtime-identifier-key
                                              _%name209186%_))
                                           (cons _%src-phi209188%_
                                                 (cons (let ()
                                                         (declare (not safe))
                                                         (gxc#generate-runtime-identifier-key
                                                          _%src-name209187%_))
                                                       '())))))))
                       (if (let ()
                             (declare (not safe))
                             (##structure-direct-instance-of?
                              _%$%in209167209179%_
                              'gx#module-import::t))
                           (let ((_%$%e209171209195%_
                                  (let ()
                                    (declare (not safe))
                                    (##unchecked-structure-ref
                                     _%$%in209167209179%_
                                     '1
                                     '#f
                                     '#f))))
                             (if (let ()
                                   (declare (not safe))
                                   (##structure-direct-instance-of?
                                    _%$%e209171209195%_
                                    'gx#module-export::t))
                                 (let* ((_%$%e209174209198%_
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%$%e209171209195%_
                                            '1
                                            '#f
                                            '#f)))
                                        (_%src-ctx209201%_ _%$%e209174209198%_)
                                        (_%$%e209175209203%_
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%$%e209171209195%_
                                            '2
                                            '#f
                                            '#f)))
                                        (_%src-key209206%_ _%$%e209175209203%_)
                                        (_%$%e209176209208%_
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%$%e209171209195%_
                                            '3
                                            '#f
                                            '#f)))
                                        (_%src-phi209211%_ _%$%e209176209208%_)
                                        (_%$%e209177209213%_
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%$%e209171209195%_
                                            '4
                                            '#f
                                            '#f)))
                                        (_%src-name209216%_
                                         _%$%e209177209213%_)
                                        (_%$%e209172209218%_
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%$%in209167209179%_
                                            '2
                                            '#f
                                            '#f)))
                                        (_%name209221%_ _%$%e209172209218%_)
                                        (_%$%e209173209223%_
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%$%in209167209179%_
                                            '3
                                            '#f
                                            '#f)))
                                        (_%phi209226%_ _%$%e209173209223%_))
                                   (_%$%K209170209192%_
                                    _%phi209226%_
                                    _%name209221%_
                                    _%src-name209216%_
                                    _%src-phi209211%_
                                    _%src-key209206%_
                                    _%src-ctx209201%_))
                                 (_%$%E209169209182%_)))
                           (_%$%E209169209182%_)))))
                  (_%make-import-path208999%_
                   (lambda (_%ctx209164%_)
                     (gxc#generate-meta-import-path
                      _%ctx209164%_
                      _%context-chain208997%_)))
                  (_%make-import-spec-in209000%_
                   (lambda (_%ctx209161%_ _%in209162%_)
                     (cons 'spec:
                           (cons (_%make-import-path208999%_ _%ctx209161%_)
                                 (reverse _%in209162%_))))))
          (gxc#meta-state-end-phi!
           (let () (declare (not safe)) (slot-ref__0 _%self208994%_ 'state)))
          (let* ((_%$%g209002209012%_
                  (lambda (_%$%g209003209009%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g209003209009%_))))
                 (_%$%g209001209158%_
                  (lambda (_%$%g209003209015%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g209003209015%_))
                        (let ((_%$%e209005209017%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g209003209015%_))))
                          (let ((_%$%hd209006209020%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e209005209017%_)))
                                (_%$%tl209007209022%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e209005209017%_))))
                            (let _%lp209036%_ ((_%rest209038%_
                                                _%$%tl209007209022%_)
                                               (_%current-src209039%_ '#f)
                                               (_%current-in209040%_ '())
                                               (_%r209041%_ '()))
                              (let* ((_%$%rest209042209050%_ _%rest209038%_)
                                     (_%$%else209044209060%_
                                      (lambda ()
                                        (let ((_%r209058%_
                                               (if _%current-src209039%_
                                                   (cons (_%make-import-spec-in209000%_
                                                          _%current-src209039%_
                                                          _%current-in209040%_)
                                                         _%r209041%_)
                                                   _%r209041%_)))
                                          (cons '%#import
                                                (reverse _%r209058%_)))))
                                     (_%$%K209046209146%_
                                      (lambda (_%rest209063%_ _%in209064%_)
                                        (if (let ()
                                              (declare (not safe))
                                              (##structure-direct-instance-of?
                                               _%in209064%_
                                               'gx#module-import::t))
                                            (let* ((_%$%in209066209073%_
                                                    _%in209064%_)
                                                   (_%$%E209068209076%_
                                                    (lambda ()
                                                      (let ()
                                                        (declare (not safe))
                                                        (error '"No clause matching"
                                                               _%$%in209066209073%_
                                                               '((module-import
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (module-export src-ctx)))))
              '#!void))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%K209069209084%_
                                                    (lambda (_%src-ctx209079%_)
                                                      (if (eq? _%current-src209039%_
                                                               _%src-ctx209079%_)
                                                          (_%lp209036%_
                                                           _%rest209063%_
                                                           _%current-src209039%_
                                                           (cons (_%make-import-spec208998%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%in209064%_)
                         _%current-in209040%_)
                   _%r209041%_)
                  (if _%current-src209039%_
                      (_%lp209036%_
                       _%rest209063%_
                       _%src-ctx209079%_
                       (cons (_%make-import-spec208998%_ _%in209064%_) '())
                       (cons (_%make-import-spec-in209000%_
                              _%current-src209039%_
                              _%current-in209040%_)
                             _%r209041%_))
                      (_%lp209036%_
                       _%rest209063%_
                       _%src-ctx209079%_
                       (cons (_%make-import-spec208998%_ _%in209064%_) '())
                       _%r209041%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%e209070209087%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##unchecked-structure-ref
                                                       _%$%in209066209073%_
                                                       '1
                                                       '#f
                                                       '#f))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (##structure-direct-instance-of?
                                                     _%$%e209070209087%_
                                                     'gx#module-export::t))
                                                  (let* ((_%$%e209071209090%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##unchecked-structure-ref
                                                             _%$%e209070209087%_
                                                             '1
                                                             '#f
                                                             '#f)))
                                                         (_%src-ctx209093%_
                                                          _%$%e209071209090%_))
                                                    (_%$%K209069209084%_
                                                     _%src-ctx209093%_))
                                                  (_%$%E209068209076%_)))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##structure-direct-instance-of?
                                                   _%in209064%_
                                                   'gx#import-set::t))
                                                (let* ((_%phi209096%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##unchecked-structure-ref
                                                           _%in209064%_
                                                           '2
                                                           '#f
                                                           '#f)))
                                                       (_%src209098%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##unchecked-structure-ref
                                                           _%in209064%_
                                                           '1
                                                           '#f
                                                           '#f)))
                                                       (_%src-in209138%_
                                                        (let* ((_%$%g209099209108%_
                                                                (_%make-import-path208999%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%src209098%_))
                       (_%$%E209102209112%_
                        (lambda ()
                          (let ()
                            (declare (not safe))
                            (error '"No clause matching"
                                   _%$%g209099209108%_
                                   '([path])
                                   '(path)))
                          '#!void)))
                  (let ((_%$%K209104209128%_
                         (lambda (_%path209126%_) _%path209126%_))
                        (_%$%K209103209118%_
                         (lambda (_%path209116%_) (cons 'in: _%path209116%_))))
                    (if (pair? _%$%g209099209108%_)
                        (let ((_%$%tl209106209133%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%g209099209108%_)))
                              (_%$%hd209105209131%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%g209099209108%_))))
                          (if (null? _%$%tl209106209133%_)
                              (let ((_%path209136%_ _%$%hd209105209131%_))
                                (_%$%K209104209128%_ _%path209136%_))
                              (let ((_%path209121%_ _%$%g209099209108%_))
                                (_%$%K209103209118%_ _%path209121%_))))
                        (let ((_%path209121%_ _%$%g209099209108%_))
                          (_%$%K209103209118%_ _%path209121%_))))))
               (_%r209140%_
                (if _%current-src209039%_
                    (cons (_%make-import-spec-in209000%_
                           _%current-src209039%_
                           _%current-in209040%_)
                          _%r209041%_)
                    _%r209041%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%lp209036%_
                                                   _%rest209063%_
                                                   '#f
                                                   '()
                                                   (cons (if (fxzero? _%phi209096%_)
                                                             _%src-in209138%_
                                                             (cons 'phi:
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons _%phi209096%_ (cons _%src-in209138%_ '()))))
                 _%r209140%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if (let ()
                                                      (declare (not safe))
                                                      (##structure-instance-of?
                                                       _%in209064%_
                                                       'gx#module-context::t))
                                                    (let ((_%r209144%_
                                                           (if _%current-src209039%_
                                                               (cons (_%make-import-spec-in209000%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%current-src209039%_
                              _%current-in209040%_)
                             _%r209041%_)
                       _%r209041%_)))
              (_%lp209036%_
               _%rest209063%_
               '#f
               '()
               (cons (cons 'runtime: (_%make-import-path208999%_ _%in209064%_))
                     _%r209144%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '#!void))))))
                                (if (pair? _%$%rest209042209050%_)
                                    (let ((_%$%hd209047209149%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%rest209042209050%_)))
                                          (_%$%tl209048209151%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%rest209042209050%_))))
                                      (let* ((_%in209154%_
                                              _%$%hd209047209149%_)
                                             (_%rest209156%_
                                              _%$%tl209048209151%_))
                                        (_%$%K209046209146%_
                                         _%rest209156%_
                                         _%in209154%_)))
                                    (_%$%else209044209060%_))))))
                        (_%$%g209002209012%_ _%$%g209003209015%_)))))
            (_%$%g209001209158%_ _%stx208995%_)))))
    (define gxc#generate-meta-export%
      (lambda (_%self208804%_ _%stx208805%_)
        (letrec* ((_%context-chain208807%_ (gxc#current-context-chain))
                  (_%make-import-path208808%_
                   (lambda (_%ctx208992%_)
                     (gxc#generate-meta-import-path
                      _%ctx208992%_
                      _%context-chain208807%_))))
          (let* ((_%$%g208810208820%_
                  (lambda (_%$%g208811208817%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g208811208817%_))))
                 (_%$%g208809208989%_
                  (lambda (_%$%g208811208823%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g208811208823%_))
                        (let ((_%$%e208813208825%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g208811208823%_))))
                          (let ((_%$%hd208814208828%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e208813208825%_)))
                                (_%$%tl208815208830%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e208813208825%_))))
                            (let _%lp208844%_ ((_%rest208846%_
                                                _%$%tl208815208830%_)
                                               (_%r208847%_ '()))
                              (let* ((_%$%rest208848208856%_ _%rest208846%_)
                                     (_%$%else208850208864%_
                                      (lambda ()
                                        (cons '%#export
                                              (reverse _%r208847%_))))
                                     (_%$%K208852208977%_
                                      (lambda (_%rest208867%_ _%out208868%_)
                                        (let* ((_%$%out208869208882%_
                                                _%out208868%_)
                                               (_%$%E208872208886%_
                                                (lambda ()
                                                  (let ()
                                                    (declare (not safe))
                                                    (error '"No clause matching"
                                                           _%$%out208869208882%_
                                                           '((module-export
                                                              _
                                                              key
                                                              phi
                                                              name))
                                                           '((export-set
                                                              src
                                                              phi))))
                                                  '#!void)))
                                          (let ((_%$%K208876208956%_
                                                 (lambda (_%name208952%_
                                                          _%phi208953%_
                                                          _%key208954%_)
                                                   (_%lp208844%_
                                                    _%rest208867%_
                                                    (cons (cons 'spec:
                                                                (cons _%phi208953%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons (let ()
                                      (declare (not safe))
                                      (gxc#generate-runtime-identifier-key
                                       _%key208954%_))
                                    (cons (let ()
                                            (declare (not safe))
                                            (gxc#generate-runtime-identifier-key
                                             _%name208952%_))
                                          '()))))
                  _%r208847%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%K208873208936%_
                                                 (lambda (_%phi208890%_
                                                          _%src208891%_)
                                                   (let* ((_%out208931%_
                                                           (if _%src208891%_
                                                               (cons 'import:
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (cons (let* ((_%$%g208892208901%_
                                           (_%make-import-path208808%_
                                            _%src208891%_))
                                          (_%$%E208895208905%_
                                           (lambda ()
                                             (let ()
                                               (declare (not safe))
                                               (error '"No clause matching"
                                                      _%$%g208892208901%_
                                                      '([path])
                                                      '(path)))
                                             '#!void)))
                                     (let ((_%$%K208897208921%_
                                            (lambda (_%path208919%_)
                                              _%path208919%_))
                                           (_%$%K208896208911%_
                                            (lambda (_%path208909%_)
                                              (cons 'in: _%path208909%_))))
                                       (if (pair? _%$%g208892208901%_)
                                           (let ((_%$%tl208899208926%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%g208892208901%_)))
                                                 (_%$%hd208898208924%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%g208892208901%_))))
                                             (if (null? _%$%tl208899208926%_)
                                                 (let ((_%path208929%_
                                                        _%$%hd208898208924%_))
                                                   (_%$%K208897208921%_
                                                    _%path208929%_))
                                                 (let ((_%path208914%_
                                                        _%$%g208892208901%_))
                                                   (_%$%K208896208911%_
                                                    _%path208914%_))))
                                           (let ((_%path208914%_
                                                  _%$%g208892208901%_))
                                             (_%$%K208896208911%_
                                              _%path208914%_)))))
                                   '()))
                       '#t))
                  (_%out208933%_
                   (if (fxzero? _%phi208890%_)
                       _%out208931%_
                       (cons 'phi:
                             (cons _%phi208890%_ (cons _%out208931%_ '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%lp208844%_
                                                      _%rest208867%_
                                                      (cons _%out208933%_
                                                            _%r208847%_))))))
                                            (let ((_%$%try-match208871208949%_
                                                   (lambda ()
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (##structure-direct-instance-of?
                                                            _%$%out208869208882%_
                                                            'gx#export-set::t))
                                                         (let* ((_%$%e208874208939%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (##unchecked-structure-ref
                            _%$%out208869208882%_
                            '1
                            '#f
                            '#f)))
                        (_%$%e208875208944%_
                         (let ()
                           (declare (not safe))
                           (##unchecked-structure-ref
                            _%$%out208869208882%_
                            '2
                            '#f
                            '#f))))
                   (let ((_%src208942%_ _%$%e208874208939%_)
                         (_%phi208947%_ _%$%e208875208944%_))
                     (_%$%K208873208936%_ _%phi208947%_ _%src208942%_)))
                 (_%$%E208872208886%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (if (let ()
                                                    (declare (not safe))
                                                    (##structure-direct-instance-of?
                                                     _%$%out208869208882%_
                                                     'gx#module-export::t))
                                                  (let* ((_%$%e208877208959%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##unchecked-structure-ref
                                                             _%$%out208869208882%_
                                                             '1
                                                             '#f
                                                             '#f)))
                                                         (_%$%e208878208962%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##unchecked-structure-ref
                                                             _%$%out208869208882%_
                                                             '2
                                                             '#f
                                                             '#f)))
                                                         (_%$%e208879208967%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##unchecked-structure-ref
                                                             _%$%out208869208882%_
                                                             '3
                                                             '#f
                                                             '#f)))
                                                         (_%$%e208880208972%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##unchecked-structure-ref
                                                             _%$%out208869208882%_
                                                             '4
                                                             '#f
                                                             '#f))))
                                                    (let ((_%key208965%_
                                                           _%$%e208878208962%_)
                                                          (_%phi208970%_
                                                           _%$%e208879208967%_)
                                                          (_%name208975%_
                                                           _%$%e208880208972%_))
                                                      (_%$%K208876208956%_
                                                       _%name208975%_
                                                       _%phi208970%_
                                                       _%key208965%_)))
                                                  (_%$%try-match208871208949%_))))))))
                                (if (pair? _%$%rest208848208856%_)
                                    (let ((_%$%hd208853208980%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%rest208848208856%_)))
                                          (_%$%tl208854208982%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%rest208848208856%_))))
                                      (let* ((_%out208985%_
                                              _%$%hd208853208980%_)
                                             (_%rest208987%_
                                              _%$%tl208854208982%_))
                                        (_%$%K208852208977%_
                                         _%rest208987%_
                                         _%out208985%_)))
                                    (_%$%else208850208864%_))))))
                        (_%$%g208810208820%_ _%$%g208811208823%_)))))
            (_%$%g208809208989%_ _%stx208805%_)))))
    (define gxc#generate-meta-provide%
      (lambda (_%self208765%_ _%stx208766%_)
        (gxc#meta-state-end-phi!
         (let () (declare (not safe)) (slot-ref__0 _%self208765%_ 'state)))
        (let* ((_%$%g208768208778%_
                (lambda (_%$%g208769208775%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g208769208775%_))))
               (_%$%g208767208801%_
                (lambda (_%$%g208769208781%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g208769208781%_))
                      (let ((_%$%e208771208783%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g208769208781%_))))
                        (let ((_%$%hd208772208786%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e208771208783%_)))
                              (_%$%tl208773208788%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e208771208783%_))))
                          (cons '%#provide
                                (map gxc#generate-runtime-identifier
                                     _%$%tl208773208788%_))))
                      (_%$%g208768208778%_ _%$%g208769208781%_)))))
          (_%$%g208767208801%_ _%stx208766%_))))
    (define gxc#generate-meta-extern%
      (lambda (_%self208640%_ _%stx208641%_)
        (letrec ((_%generate1208643%_
                  (lambda (_%id208760%_ _%eid208761%_)
                    (let ((_%eid208763%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%eid208761%_))))
                      (if (let ()
                            (declare (not safe))
                            (interned-symbol? _%eid208763%_))
                          '#!void
                          (let ()
                            (declare (not safe))
                            (gxc#raise-compile-error
                             '"Cannot compile extern reference"
                             _%stx208641%_
                             _%eid208763%_)))
                      (cons (let ()
                              (declare (not safe))
                              (gxc#generate-runtime-identifier _%id208760%_))
                            (cons _%eid208763%_ '()))))))
          (let* ((_%$%g208645208673%_
                  (lambda (_%$%g208646208670%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g208646208670%_))))
                 (_%$%g208644208757%_
                  (lambda (_%$%g208646208676%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g208646208676%_))
                        (let ((_%$%e208649208678%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g208646208676%_))))
                          (let ((_%$%hd208650208681%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e208649208678%_)))
                                (_%$%tl208651208683%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e208649208678%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair/null? _%$%tl208651208683%_))
                                (let ((_g218344_
                                       (let ()
                                         (declare (not safe))
                                         (gx#syntax-split-splice
                                          _%$%tl208651208683%_
                                          '0))))
                                  (begin
                                    (let ((_g218345_
                                           (let ()
                                             (declare (not safe))
                                             (if (##values? _g218344_)
                                                 (##values-length _g218344_)
                                                 1))))
                                      (if (not (let ()
                                                 (declare (not safe))
                                                 (##fx= _g218345_ 2)))
                                          (error "Context expects 2 values"
                                                 _g218345_)))
                                    (let ((_%$%target208652208686%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g218344_ 0)))
                                          (_%$%tl208654208688%_
                                           (let ()
                                             (declare (not safe))
                                             (##values-ref _g218344_ 1))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl208654208688%_))
                                          (letrec ((_%$%loop208655208691%_
                                                    (lambda (_%$%hd208653208694%_
                                                             _%$%eid208659208696%_
                                                             _%$%id208660208697%_)
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%hd208653208694%_))
                                                          (let ((_%$%e208656208699%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%hd208653208694%_))))
                    (let ((_%$%lp-hd208657208702%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e208656208699%_)))
                          (_%$%lp-tl208658208704%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e208656208699%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%lp-hd208657208702%_))
                          (let ((_%$%e208663208707%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%lp-hd208657208702%_))))
                            (let ((_%$%hd208664208710%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e208663208707%_)))
                                  (_%$%tl208665208712%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e208663208707%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%tl208665208712%_))
                                  (let ((_%$%e208666208715%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%tl208665208712%_))))
                                    (let ((_%$%hd208667208718%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e208666208715%_)))
                                          (_%$%tl208668208720%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e208666208715%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl208668208720%_))
                                          (_%$%loop208655208691%_
                                           _%$%lp-tl208658208704%_
                                           (cons _%$%hd208667208718%_
                                                 _%$%eid208659208696%_)
                                           (cons _%$%hd208664208710%_
                                                 _%$%id208660208697%_))
                                          (_%$%g208645208673%_
                                           _%$%g208646208676%_))))
                                  (_%$%g208645208673%_ _%$%g208646208676%_))))
                          (_%$%g208645208673%_ _%$%g208646208676%_))))
                  (let ((_%$%eid208661208723%_ (reverse _%$%eid208659208696%_))
                        (_%$%id208662208724%_ (reverse _%$%id208660208697%_)))
                    (cons '%#extern
                          (map _%generate1208643%_
                               (let ((__tmp218346
                                      (lambda (_%$%g208742208745%_
                                               _%$%g208743208747%_)
                                        (cons _%$%g208742208745%_
                                              _%$%g208743208747%_))))
                                 (declare (not safe))
                                 (foldr__0
                                  __tmp218346
                                  '()
                                  _%$%id208662208724%_))
                               (let ((__tmp218347
                                      (lambda (_%$%g208749208752%_
                                               _%$%g208750208754%_)
                                        (cons _%$%g208749208752%_
                                              _%$%g208750208754%_))))
                                 (declare (not safe))
                                 (foldr__0
                                  __tmp218347
                                  '()
                                  _%$%eid208661208723%_)))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (_%$%loop208655208691%_
                                             _%$%target208652208686%_
                                             '()
                                             '()))
                                          (_%$%g208645208673%_
                                           _%$%g208646208676%_)))))
                                (_%$%g208645208673%_ _%$%g208646208676%_))))
                        (_%$%g208645208673%_ _%$%g208646208676%_)))))
            (_%$%g208644208757%_ _%stx208641%_)))))
    (define gxc#generate-meta-define-runtime%
      (lambda (_%self208568%_ _%stx208569%_)
        (let* ((_%$%g208571208588%_
                (lambda (_%$%g208572208585%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g208572208585%_))))
               (_%$%g208570208637%_
                (lambda (_%$%g208572208591%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g208572208591%_))
                      (let ((_%$%e208575208593%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g208572208591%_))))
                        (let ((_%$%hd208576208596%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e208575208593%_)))
                              (_%$%tl208577208598%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e208575208593%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl208577208598%_))
                              (let ((_%$%e208578208601%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl208577208598%_))))
                                (let ((_%$%hd208579208604%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e208578208601%_)))
                                      (_%$%tl208580208606%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e208578208601%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl208580208606%_))
                                      (let ((_%$%e208581208609%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl208580208606%_))))
                                        (let ((_%$%hd208582208612%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e208581208609%_)))
                                              (_%$%tl208583208614%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e208581208609%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl208583208614%_))
                                              (let ((_%ident208633%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gxc#generate-runtime-identifier
                                                        _%$%hd208579208604%_)))
                                                    (_%eid208634%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%hd208582208612%_)))
                                                    (_%props208635%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gxc#runtime-identifier-properties
                                                        _%$%hd208579208604%_))))
                                                (cons '%#define-runtime
                                                      (cons _%ident208633%_
                                                            (cons _%eid208634%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%props208635%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g208571208588%_
                                               _%$%g208572208591%_))))
                                      (_%$%g208571208588%_
                                       _%$%g208572208591%_))))
                              (_%$%g208571208588%_ _%$%g208572208591%_))))
                      (_%$%g208571208588%_ _%$%g208572208591%_)))))
          (_%$%g208570208637%_ _%stx208569%_))))
    (define gxc#generate-meta-define-values%
      (lambda (_%self208357%_ _%stx208358%_)
        (letrec ((_%generate1208360%_
                  (lambda (_%id208562%_)
                    (let ((_%eid208564%_
                           (let ()
                             (declare (not safe))
                             (gxc#generate-runtime-binding-id _%id208562%_)))
                          (_%ident208565%_
                           (let ()
                             (declare (not safe))
                             (gxc#generate-runtime-identifier _%id208562%_)))
                          (_%props208566%_
                           (let ()
                             (declare (not safe))
                             (gxc#runtime-identifier-properties
                              _%id208562%_))))
                      (cons '%#define-runtime
                            (cons _%ident208565%_
                                  (cons _%eid208564%_ _%props208566%_))))))
                 (_%generate*208361%_
                  (lambda (_%all208530%_)
                    (let* ((_%$%all208531208539%_ _%all208530%_)
                           (_%$%else208533208547%_
                            (lambda () (cons '%#begin _%all208530%_)))
                           (_%$%K208535208552%_
                            (lambda (_%one208550%_) _%one208550%_)))
                      (if (pair? _%$%all208531208539%_)
                          (let ((_%$%hd208536208555%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%all208531208539%_)))
                                (_%$%tl208537208557%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%all208531208539%_))))
                            (let ((_%one208560%_ _%$%hd208536208555%_))
                              (if (null? _%$%tl208537208557%_)
                                  (_%$%K208535208552%_ _%one208560%_)
                                  (_%$%else208533208547%_))))
                          (_%$%else208533208547%_))))))
          (let* ((_%$%g208363208380%_
                  (lambda (_%$%g208364208377%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g208364208377%_))))
                 (_%$%g208362208527%_
                  (lambda (_%$%g208364208383%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g208364208383%_))
                        (let ((_%$%e208367208385%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g208364208383%_))))
                          (let ((_%$%hd208368208388%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e208367208385%_)))
                                (_%$%tl208369208390%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e208367208385%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl208369208390%_))
                                (let ((_%$%e208370208393%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl208369208390%_))))
                                  (let ((_%$%hd208371208396%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e208370208393%_)))
                                        (_%$%tl208372208398%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e208370208393%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl208372208398%_))
                                        (let ((_%$%e208373208401%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl208372208398%_))))
                                          (let ((_%$%hd208374208404%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e208373208401%_)))
                                                (_%$%tl208375208406%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e208373208401%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl208375208406%_))
                                                (let _%lp208426%_ ((_%rest208428%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%hd208371208396%_)
                           (_%r208429%_ '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let* ((_%__stx218084218085%_
                                                          _%rest208428%_)
                                                         (_%$%g208434208451%_
                                                          (lambda ()
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#raise-syntax-error
                                                               '#f
                                                               '"Bad syntax; invalid match target"
                                                               _%__stx218084218085%_)))))
                                                    (let ((_%__kont218086218087%_
                                                           (lambda (_%$%g208436208514%_)
                                                             (_%lp208426%_
                                                              _%$%g208436208514%_
                                                              _%r208429%_)))
                                                          (_%__kont218088218089%_
                                                           (lambda (_%$%g208441208487%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%g208442208488%_)
                     (_%lp208426%_
                      _%$%g208441208487%_
                      (cons (_%generate1208360%_ _%$%g208442208488%_)
                            _%r208429%_))))
                  (_%__kont218090218091%_
                   (lambda (_%$%g208446208463%_)
                     (_%generate*208361%_
                      (let ((__tmp218348
                             (cons (_%generate1208360%_ _%$%g208446208463%_)
                                   '())))
                        (declare (not safe))
                        (foldl__0 cons __tmp218348 _%r208429%_)))))
                  (_%__kont218092218093%_
                   (lambda () (_%generate*208361%_ (reverse! _%r208429%_)))))
              (let ((_%$%g208432208474%_
                     (lambda ()
                       (let ((_%$%g208446208463%_ _%__stx218084218085%_))
                         (if (let ()
                               (declare (not safe))
                               (gx#identifier? _%$%g208446208463%_))
                             (_%__kont218090218091%_ _%$%g208446208463%_)
                             (_%__kont218092218093%_))))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%__stx218084218085%_))
                    (let ((_%$%e208437208503%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%__stx218084218085%_))))
                      (let ((_%$%tl208439208508%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e208437208503%_)))
                            (_%$%hd208438208506%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e208437208503%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-datum? _%$%hd208438208506%_))
                            (let ((_%$%e208440208511%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%hd208438208506%_))))
                              (if (equal? _%$%e208440208511%_ '#f)
                                  (_%__kont218086218087%_ _%$%tl208439208508%_)
                                  (_%__kont218088218089%_
                                   _%$%tl208439208508%_
                                   _%$%hd208438208506%_)))
                            (_%__kont218088218089%_
                             _%$%tl208439208508%_
                             _%$%hd208438208506%_))))
                    (_%$%g208432208474%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g208363208380%_
                                                 _%$%g208364208383%_))))
                                        (_%$%g208363208380%_
                                         _%$%g208364208383%_))))
                                (_%$%g208363208380%_ _%$%g208364208383%_))))
                        (_%$%g208363208380%_ _%$%g208364208383%_)))))
            (_%$%g208362208527%_ _%stx208358%_)))))
    (define gxc#generate-meta-define-syntax%
      (lambda (_%self208254%_ _%stx208255%_)
        (let* ((_%$%g208257208274%_
                (lambda (_%$%g208258208271%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g208258208271%_))))
               (_%$%g208256208354%_
                (lambda (_%$%g208258208277%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g208258208277%_))
                      (let ((_%$%e208261208279%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g208258208277%_))))
                        (let ((_%$%hd208262208282%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e208261208279%_)))
                              (_%$%tl208263208284%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e208261208279%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl208263208284%_))
                              (let ((_%$%e208264208287%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl208263208284%_))))
                                (let ((_%$%hd208265208290%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e208264208287%_)))
                                      (_%$%tl208266208292%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e208264208287%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl208266208292%_))
                                      (let ((_%$%e208267208295%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl208266208292%_))))
                                        (let ((_%$%hd208268208298%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e208267208295%_)))
                                              (_%$%tl208269208300%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e208267208295%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl208269208300%_))
                                              (let* ((_%eid208319%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gxc#generate-runtime-binding-id
                                                         _%$%hd208265208290%_)))
                                                     (_%phi208321%_
                                                      (let ((__tmp218349
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#current-expander-phi))))
                (declare (not safe))
                (##fx+ __tmp218349 '1)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%block208323%_
                                                      (gxc#meta-state-begin-phi!
                                                       (let ()
                                                         (declare (not safe))
                                                         (slot-ref__0
                                                          _%self208254%_
                                                          'state))
                                                       _%phi208321%_)))
                                                (let* ((_%$%g208326208333%_
                                                        (lambda (_%$%g208327208330%_)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#raise-syntax-error
                                                             '#f
                                                             '"Bad syntax; invalid match target"
                                                             _%$%g208327208330%_))))
                                                       (_%$%g208325208351%_
                                                        (lambda (_%$%g208327208336%_)
                                                          (gxc#meta-state-add-phi!
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (slot-ref__0
                                                              _%self208254%_
                                                              'state))
                                                           _%phi208321%_
                                                           (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (declare (not safe))
                           (gx#datum->syntax__0 '#f '%#define-runtime))
                         (cons _%$%g208327208336%_
                               (cons _%$%hd208268208298%_ '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%g208325208351%_
                                                   _%eid208319%_))
                                                (if _%block208323%_
                                                    (cons '%#begin
                                                          (cons (cons '%#begin-syntax
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons (cons '%#call
                                          (cons (cons '%#ref
                                                      (cons 'load-module '()))
                                                (cons (cons '%#quote
                                                            (cons _%block208323%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    '()))
                        (cons (cons '%#define-syntax
                                    (cons (let ()
                                            (declare (not safe))
                                            (gxc#generate-runtime-identifier
                                             _%$%hd208265208290%_))
                                          (cons _%eid208319%_ '())))
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (cons '%#define-syntax
                                                          (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gxc#generate-runtime-identifier
                           _%$%hd208265208290%_))
                        (cons _%eid208319%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g208257208274%_
                                               _%$%g208258208277%_))))
                                      (_%$%g208257208274%_
                                       _%$%g208258208277%_))))
                              (_%$%g208257208274%_ _%$%g208258208277%_))))
                      (_%$%g208257208274%_ _%$%g208258208277%_)))))
          (_%$%g208256208354%_ _%stx208255%_))))
    (define gxc#generate-meta-define-alias%
      (lambda (_%self208186%_ _%stx208187%_)
        (let* ((_%$%g208189208206%_
                (lambda (_%$%g208190208203%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g208190208203%_))))
               (_%$%g208188208251%_
                (lambda (_%$%g208190208209%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g208190208209%_))
                      (let ((_%$%e208193208211%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g208190208209%_))))
                        (let ((_%$%hd208194208214%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e208193208211%_)))
                              (_%$%tl208195208216%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e208193208211%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl208195208216%_))
                              (let ((_%$%e208196208219%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl208195208216%_))))
                                (let ((_%$%hd208197208222%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e208196208219%_)))
                                      (_%$%tl208198208224%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e208196208219%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl208198208224%_))
                                      (let ((_%$%e208199208227%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl208198208224%_))))
                                        (let ((_%$%hd208200208230%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e208199208227%_)))
                                              (_%$%tl208201208232%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e208199208227%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl208201208232%_))
                                              (cons '%#define-alias
                                                    (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gxc#generate-runtime-identifier
                                                             _%$%hd208197208222%_))
                                                          (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gxc#generate-runtime-identifier
                           _%$%hd208200208230%_))
                        '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g208189208206%_
                                               _%$%g208190208209%_))))
                                      (_%$%g208189208206%_
                                       _%$%g208190208209%_))))
                              (_%$%g208189208206%_ _%$%g208190208209%_))))
                      (_%$%g208189208206%_ _%$%g208190208209%_)))))
          (_%$%g208188208251%_ _%stx208187%_))))
    (define gxc#generate-meta-phi-define-values%
      (lambda (_%self208183%_ _%stx208184%_)
        (gxc#meta-state-add-phi!
         (let () (declare (not safe)) (slot-ref__0 _%self208183%_ 'state))
         (let () (declare (not safe)) (gx#current-expander-phi))
         _%stx208184%_)
        (gxc#generate-meta-define-values% _%self208183%_ _%stx208184%_)))
    (define gxc#generate-meta-phi-expr
      (lambda (_%self208180%_ _%stx208181%_)
        (gxc#meta-state-add-phi!
         (let () (declare (not safe)) (slot-ref__0 _%self208180%_ 'state))
         (let () (declare (not safe)) (gx#current-expander-phi))
         _%stx208181%_)
        '#!void))
    (define gxc#meta-state::t
      (let ((__tmp218351 (list)) (__tmp218350 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#meta-state::t
         'meta-state
         __tmp218351
         '(src n open blocks)
         __tmp218350
         ':init!)))
    (define gxc#meta-state?
      (let () (declare (not safe)) (__make-class-predicate gxc#meta-state::t)))
    (define gxc#make-meta-state
      (lambda _%$args208177%_
        (apply make-instance gxc#meta-state::t _%$args208177%_)))
    (define gxc#meta-state-src
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#meta-state::t 'src)))
    (define gxc#meta-state-n
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#meta-state::t 'n)))
    (define gxc#meta-state-open
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#meta-state::t 'open)))
    (define gxc#meta-state-blocks
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#meta-state::t 'blocks)))
    (define gxc#meta-state-src-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#meta-state::t 'src)))
    (define gxc#meta-state-n-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#meta-state::t 'n)))
    (define gxc#meta-state-open-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#meta-state::t 'open)))
    (define gxc#meta-state-blocks-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#meta-state::t 'blocks)))
    (define gxc#&meta-state-src
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#meta-state::t 'src)))
    (define gxc#&meta-state-n
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#meta-state::t 'n)))
    (define gxc#&meta-state-open
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#meta-state::t 'open)))
    (define gxc#&meta-state-blocks
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#meta-state::t 'blocks)))
    (define gxc#&meta-state-src-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#meta-state::t 'src)))
    (define gxc#&meta-state-n-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#meta-state::t 'n)))
    (define gxc#&meta-state-open-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#meta-state::t 'open)))
    (define gxc#&meta-state-blocks-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#meta-state::t 'blocks)))
    (define gxc#meta-state:::init!
      (lambda (_%self208163%_ _%ctx208164%_)
        (let ((_%self208167%_ _%self208163%_))
          (if (let ((__tmp218352
                     (let ()
                       (declare (not safe))
                       (##structure-length _%self208167%_))))
                (declare (not safe))
                (##fx< '4 __tmp218352))
              (begin
                (let ((__tmp218353
                       (let ((__tmp218354
                              (##structure-ref
                               _%ctx208164%_
                               '1
                               gx#expander-context::t
                               '#f)))
                         (declare (not safe))
                         (gxc#module-id->path-string __tmp218354))))
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%self208167%_
                   __tmp218353
                   '1
                   '#f
                   '#f))
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-set! _%self208167%_ '1 '2 '#f '#f))
                (let ((__tmp218355
                       (let () (declare (not safe)) (make-hash-table-eq))))
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%self208167%_
                   __tmp218355
                   '3
                   '#f
                   '#f))
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-set! _%self208167%_ '() '4 '#f '#f))
                '#!void)
              (let ((__tmp218356
                     (let ()
                       (declare (not safe))
                       (##structure-length _%self208167%_))))
                (declare (not safe))
                (error '"struct-instance-init!: too many arguments for struct"
                       _%self208167%_
                       '4
                       __tmp218356))))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#meta-state::t ':init! gxc#meta-state:::init! '#f))
    (define gxc#meta-state-block::t
      (let ((__tmp218358 (list)) (__tmp218357 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#meta-state-block::t
         'meta-state-block
         __tmp218358
         '(ctx phi n code)
         __tmp218357
         '#f)))
    (define gxc#meta-state-block?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#meta-state-block::t)))
    (define gxc#make-meta-state-block
      (lambda _%$args208038%_
        (apply make-instance gxc#meta-state-block::t _%$args208038%_)))
    (define gxc#meta-state-block-ctx
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#meta-state-block::t 'ctx)))
    (define gxc#meta-state-block-phi
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#meta-state-block::t 'phi)))
    (define gxc#meta-state-block-n
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#meta-state-block::t 'n)))
    (define gxc#meta-state-block-code
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#meta-state-block::t 'code)))
    (define gxc#meta-state-block-ctx-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#meta-state-block::t 'ctx)))
    (define gxc#meta-state-block-phi-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#meta-state-block::t 'phi)))
    (define gxc#meta-state-block-n-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#meta-state-block::t 'n)))
    (define gxc#meta-state-block-code-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#meta-state-block::t 'code)))
    (define gxc#&meta-state-block-ctx
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#meta-state-block::t 'ctx)))
    (define gxc#&meta-state-block-phi
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#meta-state-block::t 'phi)))
    (define gxc#&meta-state-block-n
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#meta-state-block::t 'n)))
    (define gxc#&meta-state-block-code
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#meta-state-block::t 'code)))
    (define gxc#&meta-state-block-ctx-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#meta-state-block::t 'ctx)))
    (define gxc#&meta-state-block-phi-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#meta-state-block::t 'phi)))
    (define gxc#&meta-state-block-n-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#meta-state-block::t 'n)))
    (define gxc#&meta-state-block-code-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#meta-state-block::t 'code)))
    (define gxc#meta-state-begin-phi!
      (lambda (_%state207998%_ _%phi207999%_)
        (let* ((_%$%state208000208008%_ _%state207998%_)
               (_%$%E208002208011%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (error '"No clause matching"
                           _%$%state208000208008%_
                           '((meta-state src n open))))
                  '#!void))
               (_%$%K208003208020%_
                (lambda (_%open208014%_ _%n208015%_ _%src208016%_)
                  (if (let ()
                        (declare (not safe))
                        (hash-get _%open208014%_ _%phi207999%_))
                      '#f
                      (let ((_%block-ref208018%_
                             (let ((__tmp218359 (number->string _%n208015%_)))
                               (declare (not safe))
                               (##string-append
                                _%src208016%_
                                '"~"
                                __tmp218359))))
                        (##structure-set!
                         _%state207998%_
                         (let () (declare (not safe)) (##fx+ _%n208015%_ '1))
                         '2
                         gxc#meta-state::t
                         '#f)
                        (let ((__tmp218360
                               (let ((__tmp218361
                                      (let ()
                                        (declare (not safe))
                                        (gx#current-expander-context))))
                                 (declare (not safe))
                                 (##structure
                                  gxc#meta-state-block::t
                                  __tmp218361
                                  _%phi207999%_
                                  _%n208015%_
                                  '()))))
                          (declare (not safe))
                          (hash-put! _%open208014%_ _%phi207999%_ __tmp218360))
                        _%block-ref208018%_)))))
          (if (let ()
                (declare (not safe))
                (##structure-instance-of?
                 _%$%state208000208008%_
                 'gxc#meta-state::t))
              (let* ((_%$%e208004208023%_
                      (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref
                         _%$%state208000208008%_
                         '1
                         '#f
                         '#f)))
                     (_%src208026%_ _%$%e208004208023%_)
                     (_%$%e208005208028%_
                      (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref
                         _%$%state208000208008%_
                         '2
                         '#f
                         '#f)))
                     (_%n208031%_ _%$%e208005208028%_)
                     (_%$%e208006208033%_
                      (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref
                         _%$%state208000208008%_
                         '3
                         '#f
                         '#f)))
                     (_%open208036%_ _%$%e208006208033%_))
                (_%$%K208003208020%_ _%open208036%_ _%n208031%_ _%src208026%_))
              (_%$%E208002208011%_)))))
    (define gxc#meta-state-add-phi!
      (lambda (_%state207992%_ _%phi207993%_ _%stx207994%_)
        (let ((_%block207996%_
               (let ((__tmp218362
                      (##structure-ref
                       _%state207992%_
                       '3
                       gxc#meta-state::t
                       '#f)))
                 (declare (not safe))
                 (hash-get __tmp218362 _%phi207993%_))))
          (##structure-set!
           _%block207996%_
           (cons _%stx207994%_
                 (##structure-ref
                  _%block207996%_
                  '4
                  gxc#meta-state-block::t
                  '#f))
           '4
           gxc#meta-state-block::t
           '#f))))
    (define gxc#meta-state-end-phi!
      (lambda (_%state207986%_)
        (##structure-set!
         _%state207986%_
         (let ((__tmp218365
                (lambda (_%_207988%_ _%block207989%_ _%r207990%_)
                  (cons _%block207989%_ _%r207990%_)))
               (__tmp218364
                (##structure-ref _%state207986%_ '4 gxc#meta-state::t '#f))
               (__tmp218363
                (##structure-ref _%state207986%_ '3 gxc#meta-state::t '#f)))
           (declare (not safe))
           (hash-fold __tmp218365 __tmp218364 __tmp218363))
         '4
         gxc#meta-state::t
         '#f)
        (##structure-set!
         _%state207986%_
         (let () (declare (not safe)) (make-hash-table-eq))
         '3
         gxc#meta-state::t
         '#f)))
    (define gxc#meta-state-end!
      (lambda (_%state207939%_)
        (gxc#meta-state-end-phi! _%state207939%_)
        (let ((__tmp218367
               (lambda (_%block207941%_ _%r207942%_)
                 (let* ((_%$%block207943207952%_ _%block207941%_)
                        (_%$%E207945207955%_
                         (lambda ()
                           (let ()
                             (declare (not safe))
                             (error '"No clause matching"
                                    _%$%block207943207952%_
                                    '((meta-state-block ctx phi n code))))
                           '#!void))
                        (_%$%K207946207963%_
                         (lambda (_%code207958%_
                                  _%n207959%_
                                  _%phi207960%_
                                  _%ctx207961%_)
                           (if (null? _%code207958%_)
                               _%r207942%_
                               (cons (cons _%ctx207961%_
                                           (cons _%phi207960%_
                                                 (cons _%n207959%_
                                                       (cons (cons '%#begin
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (reverse _%code207958%_))
                     '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                     _%r207942%_)))))
                   (if (let ()
                         (declare (not safe))
                         (##structure-instance-of?
                          _%$%block207943207952%_
                          'gxc#meta-state-block::t))
                       (let* ((_%$%e207947207966%_
                               (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%$%block207943207952%_
                                  '1
                                  '#f
                                  '#f)))
                              (_%ctx207969%_ _%$%e207947207966%_)
                              (_%$%e207948207971%_
                               (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%$%block207943207952%_
                                  '2
                                  '#f
                                  '#f)))
                              (_%phi207974%_ _%$%e207948207971%_)
                              (_%$%e207949207976%_
                               (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%$%block207943207952%_
                                  '3
                                  '#f
                                  '#f)))
                              (_%n207979%_ _%$%e207949207976%_)
                              (_%$%e207950207981%_
                               (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%$%block207943207952%_
                                  '4
                                  '#f
                                  '#f)))
                              (_%code207984%_ _%$%e207950207981%_))
                         (_%$%K207946207963%_
                          _%code207984%_
                          _%n207979%_
                          _%phi207974%_
                          _%ctx207969%_))
                       (_%$%E207945207955%_)))))
              (__tmp218366
               (##structure-ref _%state207939%_ '4 gxc#meta-state::t '#f)))
          (declare (not safe))
          (foldl__0 __tmp218367 '() __tmp218366))))
    (define gxc#collect-expression-refs
      (lambda (_%stx207935%_)
        (let ((_%ht207937%_
               (let () (declare (not safe)) (make-hash-table-eq))))
          (gxc#apply-collect-expression-refs__% '#f _%ht207937%_ _%stx207935%_)
          _%ht207937%_)))
    (define gxc#collect-refs-ref%
      (lambda (_%self207878%_ _%stx207879%_)
        (let* ((_%$%g207881207894%_
                (lambda (_%$%g207882207891%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g207882207891%_))))
               (_%$%g207880207932%_
                (lambda (_%$%g207882207897%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g207882207897%_))
                      (let ((_%$%e207884207899%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g207882207897%_))))
                        (let ((_%$%hd207885207902%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e207884207899%_)))
                              (_%$%tl207886207904%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e207884207899%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl207886207904%_))
                              (let ((_%$%e207887207907%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl207886207904%_))))
                                (let ((_%$%hd207888207910%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e207887207907%_)))
                                      (_%$%tl207889207912%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e207887207907%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl207889207912%_))
                                      (let* ((_%bind207927%_
                                              (let ()
                                                (declare (not safe))
                                                (gx#resolve-identifier__0
                                                 _%$%hd207888207910%_)))
                                             (_%eid207929%_
                                              (if _%bind207927%_
                                                  (##structure-ref
                                                   _%bind207927%_
                                                   '1
                                                   gx#binding::t
                                                   '#f)
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#stx-e
                                                     _%$%hd207888207910%_))))
                                             (__tmp218368
                                              (let ()
                                                (declare (not safe))
                                                (slot-ref__0
                                                 _%self207878%_
                                                 'table))))
                                        (declare (not safe))
                                        (hash-put!
                                         __tmp218368
                                         _%eid207929%_
                                         _%eid207929%_))
                                      (_%$%g207881207894%_
                                       _%$%g207882207897%_))))
                              (_%$%g207881207894%_ _%$%g207882207897%_))))
                      (_%$%g207881207894%_ _%$%g207882207897%_)))))
          (_%$%g207880207932%_ _%stx207879%_))))
    (define gxc#collect-refs-setq%
      (lambda (_%self207805%_ _%stx207806%_)
        (let* ((_%$%g207808207825%_
                (lambda (_%$%g207809207822%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g207809207822%_))))
               (_%$%g207807207875%_
                (lambda (_%$%g207809207828%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g207809207828%_))
                      (let ((_%$%e207812207830%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g207809207828%_))))
                        (let ((_%$%hd207813207833%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e207812207830%_)))
                              (_%$%tl207814207835%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e207812207830%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl207814207835%_))
                              (let ((_%$%e207815207838%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl207814207835%_))))
                                (let ((_%$%hd207816207841%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e207815207838%_)))
                                      (_%$%tl207817207843%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e207815207838%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl207817207843%_))
                                      (let ((_%$%e207818207846%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl207817207843%_))))
                                        (let ((_%$%hd207819207849%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e207818207846%_)))
                                              (_%$%tl207820207851%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e207818207846%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl207820207851%_))
                                              (let* ((_%bind207870%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#resolve-identifier__0
                                                         _%$%hd207816207841%_)))
                                                     (_%eid207872%_
                                                      (if _%bind207870%_
                                                          (##structure-ref
                                                           _%bind207870%_
                                                           '1
                                                           gx#binding::t
                                                           '#f)
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%hd207816207841%_)))))
                                                (let ((__tmp218369
                                                       (let ()
                                                         (declare (not safe))
                                                         (slot-ref__0
                                                          _%self207805%_
                                                          'table))))
                                                  (declare (not safe))
                                                  (hash-put!
                                                   __tmp218369
                                                   _%eid207872%_
                                                   _%eid207872%_))
                                                (let ()
                                                  (declare (not safe))
                                                  (gxc#compile-e__1
                                                   _%self207805%_
                                                   _%$%hd207819207849%_)))
                                              (_%$%g207808207825%_
                                               _%$%g207809207828%_))))
                                      (_%$%g207808207825%_
                                       _%$%g207809207828%_))))
                              (_%$%g207808207825%_ _%$%g207809207828%_))))
                      (_%$%g207808207825%_ _%$%g207809207828%_)))))
          (_%$%g207807207875%_ _%stx207806%_))))
    (define gxc#find-runtime-begin%
      (lambda (_%self207762%_ _%stx207763%_)
        (let* ((_%$%g207765207775%_
                (lambda (_%$%g207766207772%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g207766207772%_))))
               (_%$%g207764207802%_
                (lambda (_%$%g207766207778%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g207766207778%_))
                      (let ((_%$%e207768207780%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g207766207778%_))))
                        (let ((_%$%hd207769207783%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e207768207780%_)))
                              (_%$%tl207770207785%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e207768207780%_))))
                          (let ((__tmp218370
                                 (lambda (_%$%g207797207799%_)
                                   (let ()
                                     (declare (not safe))
                                     (gxc#compile-e__1
                                      _%self207762%_
                                      _%$%g207797207799%_)))))
                            (declare (not safe))
                            (ormap__0 __tmp218370 _%$%tl207770207785%_))))
                      (_%$%g207765207775%_ _%$%g207766207778%_)))))
          (_%$%g207764207802%_ _%stx207763%_))))
    (define gxc#count-values-single%
      (lambda (_%self207759%_ _%stx207760%_) '1))
    (define gxc#count-values-call%
      (lambda (_%self207627%_ _%stx207628%_)
        (let* ((_%__stx218114218115%_ _%stx207628%_)
               (_%$%g207631207660%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx218114218115%_)))))
          (let ((_%__kont218116218117%_
                 (lambda (_%$%g207633207726%_ _%$%g207634207727%_)
                   (length (let ((__tmp218371
                                  (lambda (_%$%g207748207751%_
                                           _%$%g207749207753%_)
                                    (cons _%$%g207748207751%_
                                          _%$%g207749207753%_))))
                             (declare (not safe))
                             (foldr__0 __tmp218371 '() _%$%g207633207726%_)))))
                (_%__kont218120218121%_ (lambda () '#f)))
            (let ((_%__match218159218160%_
                   (lambda (_%$%e207635207672%_
                            _%$%hd207636207675%_
                            _%$%tl207637207677%_
                            _%$%e207638207680%_
                            _%$%hd207639207683%_
                            _%$%tl207640207685%_
                            _%$%e207641207688%_
                            _%$%hd207642207691%_
                            _%$%tl207643207693%_
                            _%$%e207644207696%_
                            _%$%hd207645207699%_
                            _%$%tl207646207701%_
                            _%__splice218118218119%_
                            _%$%target207647207704%_
                            _%$%tl207649207706%_)
                     (letrec ((_%$%loop207650207709%_
                               (lambda (_%$%hd207648207712%_
                                        _%$%rand207654207714%_)
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%$%hd207648207712%_))
                                     (let ((_%$%e207651207716%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#stx-e
                                               _%$%hd207648207712%_))))
                                       (let ((_%$%lp-tl207653207721%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e207651207716%_)))
                                             (_%$%lp-hd207652207719%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e207651207716%_))))
                                         (_%$%loop207650207709%_
                                          _%$%lp-tl207653207721%_
                                          (cons _%$%lp-hd207652207719%_
                                                _%$%rand207654207714%_))))
                                     (let ((_%$%rand207655207724%_
                                            (reverse _%$%rand207654207714%_)))
                                       (let ((_%$%g207633207726%_
                                              _%$%rand207655207724%_)
                                             (_%$%g207634207727%_
                                              _%$%hd207645207699%_))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#free-identifier=?
                                                _%$%g207634207727%_
                                                'values))
                                             (_%__kont218116218117%_
                                              _%$%g207633207726%_
                                              _%$%g207634207727%_)
                                             (_%__kont218120218121%_))))))))
                       (_%$%loop207650207709%_
                        _%$%target207647207704%_
                        '())))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx218114218115%_))
                  (let ((_%$%e207635207672%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx218114218115%_))))
                    (let ((_%$%tl207637207677%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e207635207672%_)))
                          (_%$%hd207636207675%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e207635207672%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl207637207677%_))
                          (let ((_%$%e207638207680%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl207637207677%_))))
                            (let ((_%$%tl207640207685%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e207638207680%_)))
                                  (_%$%hd207639207683%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e207638207680%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%hd207639207683%_))
                                  (let ((_%$%e207641207688%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd207639207683%_))))
                                    (let ((_%$%tl207643207693%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e207641207688%_)))
                                          (_%$%hd207642207691%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e207641207688%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#identifier?
                                             _%$%hd207642207691%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#ref
                                                 _%$%hd207642207691%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl207643207693%_))
                                                  (let ((_%$%e207644207696%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl207643207693%_))))
                                                    (let ((_%$%tl207646207701%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e207644207696%_)))
                                                          (_%$%hd207645207699%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e207644207696%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl207646207701%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair/null? _%$%tl207640207685%_))
                      (let ((_%__splice218118218119%_
                             (let ()
                               (declare (not safe))
                               (gx#syntax-split-splice->vector
                                _%$%tl207640207685%_
                                '0))))
                        (let ((_%$%tl207649207706%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice218118218119%_ '1)))
                              (_%$%target207647207704%_
                               (let ()
                                 (declare (not safe))
                                 (##vector-ref _%__splice218118218119%_ '0))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-null? _%$%tl207649207706%_))
                              (_%__match218159218160%_
                               _%$%e207635207672%_
                               _%$%hd207636207675%_
                               _%$%tl207637207677%_
                               _%$%e207638207680%_
                               _%$%hd207639207683%_
                               _%$%tl207640207685%_
                               _%$%e207641207688%_
                               _%$%hd207642207691%_
                               _%$%tl207643207693%_
                               _%$%e207644207696%_
                               _%$%hd207645207699%_
                               _%$%tl207646207701%_
                               _%__splice218118218119%_
                               _%$%target207647207704%_
                               _%$%tl207649207706%_)
                              (_%__kont218120218121%_))))
                      (_%__kont218120218121%_))
                  (_%__kont218120218121%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont218120218121%_))
                                              (_%__kont218120218121%_))
                                          (_%__kont218120218121%_))))
                                  (_%__kont218120218121%_))))
                          (_%__kont218120218121%_))))
                  (_%__kont218120218121%_)))))))
    (define gxc#count-values-if%
      (lambda (_%self207532%_ _%stx207533%_)
        (let* ((_%$%g207535207556%_
                (lambda (_%$%g207536207553%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g207536207553%_))))
               (_%$%g207534207624%_
                (lambda (_%$%g207536207559%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g207536207559%_))
                      (let ((_%$%e207540207561%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g207536207559%_))))
                        (let ((_%$%hd207541207564%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e207540207561%_)))
                              (_%$%tl207542207566%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e207540207561%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl207542207566%_))
                              (let ((_%$%e207543207569%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl207542207566%_))))
                                (let ((_%$%hd207544207572%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e207543207569%_)))
                                      (_%$%tl207545207574%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e207543207569%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl207545207574%_))
                                      (let ((_%$%e207546207577%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl207545207574%_))))
                                        (let ((_%$%hd207547207580%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e207546207577%_)))
                                              (_%$%tl207548207582%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e207546207577%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl207548207582%_))
                                              (let ((_%$%e207549207585%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl207548207582%_))))
                                                (let ((_%$%hd207550207588%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e207549207585%_)))
                                                      (_%$%tl207551207590%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e207549207585%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl207551207590%_))
                                                      (let ((_%$%c1207612207614%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gxc#compile-e__1
                        _%self207532%_
                        _%$%hd207547207580%_))))
                (if _%$%c1207612207614%_
                    (let* ((_%c1207616%_ _%$%c1207612207614%_)
                           (_%$%c2207617207619%_
                            (let ()
                              (declare (not safe))
                              (gxc#compile-e__1
                               _%self207532%_
                               _%$%hd207550207588%_))))
                      (if _%$%c2207617207619%_
                          (let ((_%c2207621%_ _%$%c2207617207619%_))
                            (if (fx= _%c1207616%_ _%c2207621%_)
                                _%c1207616%_
                                '#f))
                          '#f))
                    '#f))
              (_%$%g207535207556%_ _%$%g207536207559%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%$%g207535207556%_
                                               _%$%g207536207559%_))))
                                      (_%$%g207535207556%_
                                       _%$%g207536207559%_))))
                              (_%$%g207535207556%_ _%$%g207536207559%_))))
                      (_%$%g207535207556%_ _%$%g207536207559%_)))))
          (_%$%g207534207624%_ _%stx207533%_))))))
