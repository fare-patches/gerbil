(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/method::timestamp 1795039817)
  (begin
    (define gxc#current-compile-method (make-parameter '#f))
    (define gxc#compile-e__0
      (lambda (_%stx206874%_)
        (if gxc#__DEBUG-COMPILE
            (let ((__tmp207096
                   (let ()
                     (declare (not safe))
                     (gx#syntax->datum _%stx206874%_))))
              (declare (not safe))
              (displayln '"@compile " __tmp207096))
            '#!void)
        (let* ((_%self206876%_
                (let () (declare (not safe)) (gxc#current-compile-method)))
               (_%$e206878%_
                (let ((__tmp207097 (gxc#stx-car-e _%stx206874%_)))
                  (declare (not safe))
                  (method-ref _%self206876%_ __tmp207097))))
          (if _%$e206878%_
              (let ()
                (declare (not safe))
                (let ((_%$e206884%_ (gx#stx-source _%stx206874%_)))
                  (if _%$e206884%_
                      (call-with-parameters__1
                       (lambda () (_%$e206878%_ _%self206876%_ _%stx206874%_))
                       gxc#current-compile-context
                       (cons (list '@ _%$e206884%_)
                             (let ((_%$e206891%_
                                    (gxc#current-compile-context)))
                               (if _%$e206891%_ _%$e206891%_ '()))))
                      (_%$e206878%_ _%self206876%_ _%stx206874%_))))
              (let ((__tmp207099 (gxc#stx-car-e _%stx206874%_))
                    (__tmp207098
                     (let ()
                       (declare (not safe))
                       (gx#syntax->datum _%stx206874%_))))
                (declare (not safe))
                (error '"missing method"
                       _%self206876%_
                       __tmp207099
                       __tmp207098))))))
    (define gxc#compile-e__1
      (lambda (_%self206896%_ _%stx206897%_)
        (if gxc#__DEBUG-COMPILE
            (let ((__tmp207100
                   (let ()
                     (declare (not safe))
                     (gx#syntax->datum _%stx206897%_))))
              (declare (not safe))
              (displayln '"@compile " __tmp207100))
            '#!void)
        (let ((_%$e206899%_
               (let ((__tmp207101 (gxc#stx-car-e _%stx206897%_)))
                 (declare (not safe))
                 (method-ref _%self206896%_ __tmp207101))))
          (if _%$e206899%_
              (let ()
                (declare (not safe))
                (let ((_%$e206905%_ (gx#stx-source _%stx206897%_)))
                  (if _%$e206905%_
                      (call-with-parameters__1
                       (lambda () (_%$e206899%_ _%self206896%_ _%stx206897%_))
                       gxc#current-compile-context
                       (cons (list '@ _%$e206905%_)
                             (let ((_%$e206912%_
                                    (gxc#current-compile-context)))
                               (if _%$e206912%_ _%$e206912%_ '()))))
                      (_%$e206899%_ _%self206896%_ _%stx206897%_))))
              (let ((__tmp207103 (gxc#stx-car-e _%stx206897%_))
                    (__tmp207102
                     (let ()
                       (declare (not safe))
                       (gx#syntax->datum _%stx206897%_))))
                (declare (not safe))
                (error '"missing method"
                       _%self206896%_
                       __tmp207103
                       __tmp207102))))))
    (define gxc#compile-e
      (lambda _g207104_
        (let ((_g207105_ (let () (declare (not safe)) (##length _g207104_))))
          (cond ((let () (declare (not safe)) (##fx= _g207105_ 1))
                 (apply gxc#compile-e__0 _g207104_))
                ((let () (declare (not safe)) (##fx= _g207105_ 2))
                 (apply gxc#compile-e__1 _g207104_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#compile-e
                  _g207104_))))))
    (define gxc#stx-car-e
      (lambda (_%stx206872%_)
        (let ((__tmp207106
               (car (let () (declare (not safe)) (gx#stx-e _%stx206872%_)))))
          (declare (not safe))
          (gx#stx-e __tmp207106))))
    (define gxc#void-method (lambda (_%self206869%_ _%stx206870%_) '#!void))
    (define gxc#false-method (lambda (_%self206866%_ _%stx206867%_) '#f))
    (define gxc#true-method (lambda (_%self206863%_ _%stx206864%_) '#t))
    (define gxc#identity-method
      (lambda (_%self206860%_ _%stx206861%_) _%stx206861%_))
    (define gxc#::void-expression::t
      (let ((__tmp207107 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::void-expression::t
         '::void-expression
         __tmp207107
         '()
         '()
         '#f)))
    (define gxc#::void-expression?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::void-expression::t)))
    (define gxc#make-::void-expression
      (lambda _%$args206857%_
        (apply make-instance gxc#::void-expression::t _%$args206857%_)))
    (define gxc#::void-expression-bind-methods!
      (let ((__tmp207108
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#begin-annotation
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#lambda
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#case-lambda
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#let-values
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#letrec-values
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#letrec*-values
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#quote
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#quote-syntax
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#call
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#call-unchecked
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#if
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#ref
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#set!
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#struct-instance?
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#struct-direct-instance?
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#struct-ref
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#struct-set!
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#struct-direct-ref
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#struct-direct-set!
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#struct-unchecked-ref
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-expression::t
                  '%#struct-unchecked-set!
                  gxc#void-method)))))
        (declare (not safe))
        (__make-atomic-promise __tmp207108)))
    (define gxc#::void-special-form::t
      (let ((__tmp207109 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::void-special-form::t
         '::void-special-form
         __tmp207109
         '()
         '()
         '#f)))
    (define gxc#::void-special-form?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::void-special-form::t)))
    (define gxc#make-::void-special-form
      (lambda _%$args206853%_
        (apply make-instance gxc#::void-special-form::t _%$args206853%_)))
    (define gxc#::void-special-form-bind-methods!
      (let ((__tmp207110
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#begin
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#begin-syntax
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#begin-foreign
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#module
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#import
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#export
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#provide
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#extern
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#define-values
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#define-syntax
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#define-alias
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#define-runtime
                  gxc#void-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::void-special-form::t
                  '%#declare
                  gxc#void-method)))))
        (declare (not safe))
        (__make-atomic-promise __tmp207110)))
    (define gxc#::void::t
      (let ((__tmp207111
             (list gxc#::void-special-form::t gxc#::void-expression::t)))
        (declare (not safe))
        (make-class-type 'gxc#::void::t '::void __tmp207111 '() '() '#f)))
    (define gxc#::void?
      (let () (declare (not safe)) (__make-class-predicate gxc#::void::t)))
    (define gxc#make-::void
      (lambda _%$args206849%_
        (apply make-instance gxc#::void::t _%$args206849%_)))
    (define gxc#::void-bind-methods!
      (let ((__tmp207112
             (lambda ()
               (force gxc#::void-special-form-bind-methods!)
               (force gxc#::void-expression-bind-methods!))))
        (declare (not safe))
        (__make-atomic-promise __tmp207112)))
    (define gxc#::false-expression::t
      (let ((__tmp207113 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::false-expression::t
         '::false-expression
         __tmp207113
         '()
         '()
         '#f)))
    (define gxc#::false-expression?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::false-expression::t)))
    (define gxc#make-::false-expression
      (lambda _%$args206845%_
        (apply make-instance gxc#::false-expression::t _%$args206845%_)))
    (define gxc#::false-expression-bind-methods!
      (let ((__tmp207114
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#begin-annotation
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#lambda
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#case-lambda
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#let-values
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#letrec-values
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#letrec*-values
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#quote
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#quote-syntax
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#call
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#call-unchecked
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#if
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#ref
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#set!
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#struct-instance?
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#struct-direct-instance?
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#struct-ref
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#struct-set!
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#struct-direct-ref
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#struct-direct-set!
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#struct-unchecked-ref
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-expression::t
                  '%#struct-unchecked-set!
                  gxc#false-method)))))
        (declare (not safe))
        (__make-atomic-promise __tmp207114)))
    (define gxc#::false-special-form::t
      (let ((__tmp207115 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::false-special-form::t
         '::false-special-form
         __tmp207115
         '()
         '()
         '#f)))
    (define gxc#::false-special-form?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::false-special-form::t)))
    (define gxc#make-::false-special-form
      (lambda _%$args206841%_
        (apply make-instance gxc#::false-special-form::t _%$args206841%_)))
    (define gxc#::false-special-form-bind-methods!
      (let ((__tmp207116
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#begin
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#begin-syntax
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#begin-foreign
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#module
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#import
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#export
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#provide
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#extern
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#define-values
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#define-syntax
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#define-alias
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#define-runtime
                  gxc#false-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::false-special-form::t
                  '%#declare
                  gxc#false-method)))))
        (declare (not safe))
        (__make-atomic-promise __tmp207116)))
    (define gxc#::false::t
      (let ((__tmp207117
             (list gxc#::false-special-form::t gxc#::false-expression::t)))
        (declare (not safe))
        (make-class-type 'gxc#::false::t '::false __tmp207117 '() '() '#f)))
    (define gxc#::false?
      (let () (declare (not safe)) (__make-class-predicate gxc#::false::t)))
    (define gxc#make-::false
      (lambda _%$args206837%_
        (apply make-instance gxc#::false::t _%$args206837%_)))
    (define gxc#::false-bind-methods!
      (let ((__tmp207118
             (lambda ()
               (force gxc#::false-special-form-bind-methods!)
               (force gxc#::false-expression-bind-methods!))))
        (declare (not safe))
        (__make-atomic-promise __tmp207118)))
    (define gxc#::identity-expression::t
      (let ((__tmp207119 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::identity-expression::t
         '::identity-expression
         __tmp207119
         '()
         '()
         '#f)))
    (define gxc#::identity-expression?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::identity-expression::t)))
    (define gxc#make-::identity-expression
      (lambda _%$args206833%_
        (apply make-instance gxc#::identity-expression::t _%$args206833%_)))
    (define gxc#::identity-expression-bind-methods!
      (let ((__tmp207120
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#begin-annotation
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#lambda
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#case-lambda
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#let-values
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#letrec-values
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#letrec*-values
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#quote
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#quote-syntax
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#call
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#call-unchecked
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#if
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#ref
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#set!
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#struct-instance?
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#struct-direct-instance?
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#struct-ref
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#struct-set!
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#struct-direct-ref
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#struct-direct-set!
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#struct-unchecked-ref
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-expression::t
                  '%#struct-unchecked-set!
                  gxc#identity-method)))))
        (declare (not safe))
        (__make-atomic-promise __tmp207120)))
    (define gxc#::identity-special-form::t
      (let ((__tmp207121 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::identity-special-form::t
         '::identity-special-form
         __tmp207121
         '()
         '()
         '#f)))
    (define gxc#::identity-special-form?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::identity-special-form::t)))
    (define gxc#make-::identity-special-form
      (lambda _%$args206829%_
        (apply make-instance gxc#::identity-special-form::t _%$args206829%_)))
    (define gxc#::identity-special-form-bind-methods!
      (let ((__tmp207122
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#begin
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#begin-syntax
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#begin-foreign
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#module
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#import
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#export
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#provide
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#extern
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#define-values
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#define-syntax
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#define-alias
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#define-runtime
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::identity-special-form::t
                  '%#declare
                  gxc#identity-method)))))
        (declare (not safe))
        (__make-atomic-promise __tmp207122)))
    (define gxc#::identity::t
      (let ((__tmp207123
             (list gxc#::identity-special-form::t
                   gxc#::identity-expression::t)))
        (declare (not safe))
        (make-class-type
         'gxc#::identity::t
         '::identity
         __tmp207123
         '()
         '()
         '#f)))
    (define gxc#::identity?
      (let () (declare (not safe)) (__make-class-predicate gxc#::identity::t)))
    (define gxc#make-::identity
      (lambda _%$args206825%_
        (apply make-instance gxc#::identity::t _%$args206825%_)))
    (define gxc#::identity-bind-methods!
      (let ((__tmp207124
             (lambda ()
               (force gxc#::identity-special-form-bind-methods!)
               (force gxc#::identity-expression-bind-methods!))))
        (declare (not safe))
        (__make-atomic-promise __tmp207124)))
    (define gxc#::basic-xform-expression::t
      (let ((__tmp207125 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#::basic-xform-expression::t
         '::basic-xform-expression
         __tmp207125
         '()
         '()
         '#f)))
    (define gxc#::basic-xform-expression?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::basic-xform-expression::t)))
    (define gxc#make-::basic-xform-expression
      (lambda _%$args206821%_
        (apply make-instance gxc#::basic-xform-expression::t _%$args206821%_)))
    (define gxc#::basic-xform-expression-bind-methods!
      (let ((__tmp207126
             (lambda ()
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#begin-annotation
                  gxc#xform-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#lambda
                  gxc#xform-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#case-lambda
                  gxc#xform-case-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#let-values
                  gxc#xform-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#letrec-values
                  gxc#xform-letrec-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#letrec*-values
                  gxc#xform-letrec-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#quote
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#quote-syntax
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#call
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#call-unchecked
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#if
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#ref
                  gxc#identity-method))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#set!
                  gxc#xform-setq%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#struct-instance?
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#struct-direct-instance?
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#struct-ref
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#struct-set!
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#struct-direct-ref
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#struct-direct-set!
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#struct-unchecked-ref
                  gxc#xform-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform-expression::t
                  '%#struct-unchecked-set!
                  gxc#xform-operands)))))
        (declare (not safe))
        (__make-atomic-promise __tmp207126)))
    (define gxc#::basic-xform::t
      (let ((__tmp207127
             (list gxc#::basic-xform-expression::t gxc#::identity::t)))
        (declare (not safe))
        (make-class-type
         'gxc#::basic-xform::t
         '::basic-xform
         __tmp207127
         '()
         '()
         '#f)))
    (define gxc#::basic-xform?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::basic-xform::t)))
    (define gxc#make-::basic-xform
      (lambda _%$args206817%_
        (apply make-instance gxc#::basic-xform::t _%$args206817%_)))
    (define gxc#::basic-xform-bind-methods!
      (let ((__tmp207128
             (lambda ()
               (force gxc#::basic-xform-expression-bind-methods!)
               (force gxc#::identity-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform::t
                  '%#begin
                  gxc#xform-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform::t
                  '%#begin-syntax
                  gxc#xform-begin-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform::t
                  '%#module
                  gxc#xform-module%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform::t
                  '%#define-values
                  gxc#xform-define-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::basic-xform::t
                  '%#define-syntax
                  gxc#xform-define-syntax%)))))
        (declare (not safe))
        (__make-atomic-promise __tmp207128)))
    (define gxc#apply-begin%
      (lambda (_%self206773%_ _%stx206774%_)
        (let* ((_%$%g206776206786%_
                (lambda (_%$%g206777206783%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206777206783%_))))
               (_%$%g206775206813%_
                (lambda (_%$%g206777206789%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206777206789%_))
                      (let ((_%$%e206779206791%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206777206789%_))))
                        (let ((_%$%hd206780206794%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206779206791%_)))
                              (_%$%tl206781206796%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206779206791%_))))
                          (for-each
                           (lambda (_%$%g206808206810%_)
                             (gxc#compile-e__1
                              _%self206773%_
                              _%$%g206808206810%_))
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl206781206796%_)))))
                      (_%$%g206776206786%_ _%$%g206777206789%_)))))
          (_%$%g206775206813%_ _%stx206774%_))))
    (define gxc#apply-last-begin%
      (lambda (_%self206734%_ _%stx206735%_)
        (let* ((_%$%g206737206747%_
                (lambda (_%$%g206738206744%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206738206744%_))))
               (_%$%g206736206770%_
                (lambda (_%$%g206738206750%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206738206750%_))
                      (let ((_%$%e206740206752%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206738206750%_))))
                        (let ((_%$%hd206741206755%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206740206752%_)))
                              (_%$%tl206742206757%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206740206752%_))))
                          (gxc#compile-e__1
                           _%self206734%_
                           (last _%$%tl206742206757%_))))
                      (_%$%g206737206747%_ _%$%g206738206750%_)))))
          (_%$%g206736206770%_ _%stx206735%_))))
    (define gxc#apply-begin-syntax%
      (lambda (_%self206730%_ _%stx206731%_)
        (let ((__tmp207131
               (lambda () (gxc#apply-begin% _%self206730%_ _%stx206731%_)))
              (__tmp207129
               (let ((__tmp207130
                      (let () (declare (not safe)) (gx#current-expander-phi))))
                 (declare (not safe))
                 (##fx+ __tmp207130 '1))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp207131
           gx#current-expander-phi
           __tmp207129))))
    (define gxc#apply-module%
      (lambda (_%self206669%_ _%stx206670%_)
        (let* ((_%$%g206672206686%_
                (lambda (_%$%g206673206683%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206673206683%_))))
               (_%$%g206671206727%_
                (lambda (_%$%g206673206689%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206673206689%_))
                      (let ((_%$%e206676206691%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206673206689%_))))
                        (let ((_%$%hd206677206694%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206676206691%_)))
                              (_%$%tl206678206696%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206676206691%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206678206696%_))
                              (let ((_%$%e206679206699%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206678206696%_))))
                                (let ((_%$%hd206680206702%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206679206699%_)))
                                      (_%$%tl206681206704%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206679206699%_))))
                                  (let* ((_%ctx206721%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#syntax-local-e__0
                                             _%$%hd206680206702%_)))
                                         (_%ctx-stx206723%_
                                          (##structure-ref
                                           _%ctx206721%_
                                           '11
                                           gx#module-context::t
                                           '#f))
                                         (__tmp207132
                                          (lambda ()
                                            (gxc#compile-e__1
                                             _%self206669%_
                                             _%ctx-stx206723%_))))
                                    (declare (not safe))
                                    (call-with-parameters__1
                                     __tmp207132
                                     gx#current-expander-context
                                     _%ctx206721%_))))
                              (_%$%g206672206686%_ _%$%g206673206689%_))))
                      (_%$%g206672206686%_ _%$%g206673206689%_)))))
          (_%$%g206671206727%_ _%stx206670%_))))
    (define gxc#apply-begin-annotation%
      (lambda (_%self206601%_ _%stx206602%_)
        (let* ((_%$%g206604206621%_
                (lambda (_%$%g206605206618%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206605206618%_))))
               (_%$%g206603206666%_
                (lambda (_%$%g206605206624%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206605206624%_))
                      (let ((_%$%e206608206626%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206605206624%_))))
                        (let ((_%$%hd206609206629%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206608206626%_)))
                              (_%$%tl206610206631%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206608206626%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206610206631%_))
                              (let ((_%$%e206611206634%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206610206631%_))))
                                (let ((_%$%hd206612206637%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206611206634%_)))
                                      (_%$%tl206613206639%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206611206634%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl206613206639%_))
                                      (let ((_%$%e206614206642%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl206613206639%_))))
                                        (let ((_%$%hd206615206645%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e206614206642%_)))
                                              (_%$%tl206616206647%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e206614206642%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl206616206647%_))
                                              (gxc#compile-e__1
                                               _%self206601%_
                                               _%$%hd206615206645%_)
                                              (_%$%g206604206621%_
                                               _%$%g206605206624%_))))
                                      (_%$%g206604206621%_
                                       _%$%g206605206624%_))))
                              (_%$%g206604206621%_ _%$%g206605206624%_))))
                      (_%$%g206604206621%_ _%$%g206605206624%_)))))
          (_%$%g206603206666%_ _%stx206602%_))))
    (define gxc#apply-define-values%
      (lambda (_%self206533%_ _%stx206534%_)
        (let* ((_%$%g206536206553%_
                (lambda (_%$%g206537206550%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206537206550%_))))
               (_%$%g206535206598%_
                (lambda (_%$%g206537206556%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206537206556%_))
                      (let ((_%$%e206540206558%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206537206556%_))))
                        (let ((_%$%hd206541206561%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206540206558%_)))
                              (_%$%tl206542206563%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206540206558%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206542206563%_))
                              (let ((_%$%e206543206566%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206542206563%_))))
                                (let ((_%$%hd206544206569%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206543206566%_)))
                                      (_%$%tl206545206571%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206543206566%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl206545206571%_))
                                      (let ((_%$%e206546206574%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl206545206571%_))))
                                        (let ((_%$%hd206547206577%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e206546206574%_)))
                                              (_%$%tl206548206579%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e206546206574%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl206548206579%_))
                                              (gxc#compile-e__1
                                               _%self206533%_
                                               _%$%hd206547206577%_)
                                              (_%$%g206536206553%_
                                               _%$%g206537206556%_))))
                                      (_%$%g206536206553%_
                                       _%$%g206537206556%_))))
                              (_%$%g206536206553%_ _%$%g206537206556%_))))
                      (_%$%g206536206553%_ _%$%g206537206556%_)))))
          (_%$%g206535206598%_ _%stx206534%_))))
    (define gxc#apply-define-syntax%
      (lambda (_%self206464%_ _%stx206465%_)
        (let* ((_%$%g206467206484%_
                (lambda (_%$%g206468206481%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206468206481%_))))
               (_%$%g206466206530%_
                (lambda (_%$%g206468206487%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206468206487%_))
                      (let ((_%$%e206471206489%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206468206487%_))))
                        (let ((_%$%hd206472206492%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206471206489%_)))
                              (_%$%tl206473206494%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206471206489%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206473206494%_))
                              (let ((_%$%e206474206497%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206473206494%_))))
                                (let ((_%$%hd206475206500%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206474206497%_)))
                                      (_%$%tl206476206502%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206474206497%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl206476206502%_))
                                      (let ((_%$%e206477206505%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl206476206502%_))))
                                        (let ((_%$%hd206478206508%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e206477206505%_)))
                                              (_%$%tl206479206510%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e206477206505%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl206479206510%_))
                                              (let ((__tmp207135
                                                     (lambda ()
                                                       (gxc#compile-e__1
                                                        _%self206464%_
                                                        _%$%hd206478206508%_)))
                                                    (__tmp207133
                                                     (let ((__tmp207134
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#current-expander-phi))))
                                                       (declare (not safe))
                                                       (##fx+ __tmp207134
                                                              '1))))
                                                (declare (not safe))
                                                (call-with-parameters__1
                                                 __tmp207135
                                                 gx#current-expander-phi
                                                 __tmp207133))
                                              (_%$%g206467206484%_
                                               _%$%g206468206487%_))))
                                      (_%$%g206467206484%_
                                       _%$%g206468206487%_))))
                              (_%$%g206467206484%_ _%$%g206468206487%_))))
                      (_%$%g206467206484%_ _%$%g206468206487%_)))))
          (_%$%g206466206530%_ _%stx206465%_))))
    (define gxc#apply-body-lambda%
      (lambda (_%self206396%_ _%stx206397%_)
        (let* ((_%$%g206399206416%_
                (lambda (_%$%g206400206413%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206400206413%_))))
               (_%$%g206398206461%_
                (lambda (_%$%g206400206419%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206400206419%_))
                      (let ((_%$%e206403206421%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206400206419%_))))
                        (let ((_%$%hd206404206424%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206403206421%_)))
                              (_%$%tl206405206426%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206403206421%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206405206426%_))
                              (let ((_%$%e206406206429%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206405206426%_))))
                                (let ((_%$%hd206407206432%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206406206429%_)))
                                      (_%$%tl206408206434%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206406206429%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl206408206434%_))
                                      (let ((_%$%e206409206437%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl206408206434%_))))
                                        (let ((_%$%hd206410206440%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e206409206437%_)))
                                              (_%$%tl206411206442%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e206409206437%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl206411206442%_))
                                              (gxc#compile-e__1
                                               _%self206396%_
                                               _%$%hd206410206440%_)
                                              (_%$%g206399206416%_
                                               _%$%g206400206419%_))))
                                      (_%$%g206399206416%_
                                       _%$%g206400206419%_))))
                              (_%$%g206399206416%_ _%$%g206400206419%_))))
                      (_%$%g206399206416%_ _%$%g206400206419%_)))))
          (_%$%g206398206461%_ _%stx206397%_))))
    (define gxc#apply-body-case-lambda%
      (lambda (_%self206282%_ _%stx206283%_)
        (let* ((_%$%g206285206313%_
                (lambda (_%$%g206286206310%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206286206310%_))))
               (_%$%g206284206393%_
                (lambda (_%$%g206286206316%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206286206316%_))
                      (let ((_%$%e206289206318%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206286206316%_))))
                        (let ((_%$%hd206290206321%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206289206318%_)))
                              (_%$%tl206291206323%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206289206318%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl206291206323%_))
                              (let ((_g207136_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice
                                        _%$%tl206291206323%_
                                        '0))))
                                (begin
                                  (let ((_g207137_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g207136_)
                                               (##values-length _g207136_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g207137_ 2)))
                                        (error "Context expects 2 values"
                                               _g207137_)))
                                  (let ((_%$%target206292206326%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g207136_ 0)))
                                        (_%$%tl206294206328%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g207136_ 1))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl206294206328%_))
                                        (letrec ((_%$%loop206295206331%_
                                                  (lambda (_%$%hd206293206334%_
                                                           _%$%body206299206336%_
                                                           _%$%hd206300206337%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd206293206334%_))
                                                        (let ((_%$%e206296206339%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%hd206293206334%_))))
                  (let ((_%$%lp-hd206297206342%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e206296206339%_)))
                        (_%$%lp-tl206298206344%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e206296206339%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%lp-hd206297206342%_))
                        (let ((_%$%e206303206347%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%lp-hd206297206342%_))))
                          (let ((_%$%hd206304206350%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e206303206347%_)))
                                (_%$%tl206305206352%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e206303206347%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl206305206352%_))
                                (let ((_%$%e206306206355%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl206305206352%_))))
                                  (let ((_%$%hd206307206358%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e206306206355%_)))
                                        (_%$%tl206308206360%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e206306206355%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl206308206360%_))
                                        (_%$%loop206295206331%_
                                         _%$%lp-tl206298206344%_
                                         (cons _%$%hd206307206358%_
                                               _%$%body206299206336%_)
                                         (cons _%$%hd206304206350%_
                                               _%$%hd206300206337%_))
                                        (_%$%g206285206313%_
                                         _%$%g206286206316%_))))
                                (_%$%g206285206313%_ _%$%g206286206316%_))))
                        (_%$%g206285206313%_ _%$%g206286206316%_))))
                (let ((_%$%body206301206363%_ (reverse _%$%body206299206336%_))
                      (_%$%hd206302206364%_ (reverse _%$%hd206300206337%_)))
                  (for-each
                   (lambda (_%$%g206381206383%_)
                     (gxc#compile-e__1 _%self206282%_ _%$%g206381206383%_))
                   (let ((__tmp207138
                          (lambda (_%$%g206385206388%_ _%$%g206386206390%_)
                            (cons _%$%g206385206388%_ _%$%g206386206390%_))))
                     (declare (not safe))
                     (foldr__0 __tmp207138 '() _%$%body206301206363%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop206295206331%_
                                           _%$%target206292206326%_
                                           '()
                                           '()))
                                        (_%$%g206285206313%_
                                         _%$%g206286206316%_)))))
                              (_%$%g206285206313%_ _%$%g206286206316%_))))
                      (_%$%g206285206313%_ _%$%g206286206316%_)))))
          (_%$%g206284206393%_ _%stx206283%_))))
    (define gxc#apply-body-let-values%
      (lambda (_%self206139%_ _%stx206140%_)
        (let* ((_%$%g206142206177%_
                (lambda (_%$%g206143206174%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206143206174%_))))
               (_%$%g206141206279%_
                (lambda (_%$%g206143206180%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206143206180%_))
                      (let ((_%$%e206147206182%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206143206180%_))))
                        (let ((_%$%hd206148206185%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206147206182%_)))
                              (_%$%tl206149206187%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206147206182%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206149206187%_))
                              (let ((_%$%e206150206190%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206149206187%_))))
                                (let ((_%$%hd206151206193%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206150206190%_)))
                                      (_%$%tl206152206195%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206150206190%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%hd206151206193%_))
                                      (let ((_g207139_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice
                                                _%$%hd206151206193%_
                                                '0))))
                                        (begin
                                          (let ((_g207140_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g207139_)
                                                       (##values-length
                                                        _g207139_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g207140_ 2)))
                                                (error "Context expects 2 values"
                                                       _g207140_)))
                                          (let ((_%$%target206153206198%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g207139_ 0)))
                                                (_%$%tl206155206200%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g207139_
                                                    1))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl206155206200%_))
                                                (letrec ((_%$%loop206156206203%_
                                                          (lambda (_%$%hd206154206206%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%expr206160206208%_
                           _%$%hd206161206209%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd206154206206%_))
                        (let ((_%$%e206157206211%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd206154206206%_))))
                          (let ((_%$%lp-hd206158206214%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e206157206211%_)))
                                (_%$%lp-tl206159206216%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e206157206211%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%lp-hd206158206214%_))
                                (let ((_%$%e206164206219%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%lp-hd206158206214%_))))
                                  (let ((_%$%hd206165206222%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e206164206219%_)))
                                        (_%$%tl206166206224%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e206164206219%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl206166206224%_))
                                        (let ((_%$%e206167206227%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl206166206224%_))))
                                          (let ((_%$%hd206168206230%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e206167206227%_)))
                                                (_%$%tl206169206232%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e206167206227%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl206169206232%_))
                                                (_%$%loop206156206203%_
                                                 _%$%lp-tl206159206216%_
                                                 (cons _%$%hd206168206230%_
                                                       _%$%expr206160206208%_)
                                                 (cons _%$%hd206165206222%_
                                                       _%$%hd206161206209%_))
                                                (_%$%g206142206177%_
                                                 _%$%g206143206180%_))))
                                        (_%$%g206142206177%_
                                         _%$%g206143206180%_))))
                                (_%$%g206142206177%_ _%$%g206143206180%_))))
                        (let ((_%$%expr206162206235%_
                               (reverse _%$%expr206160206208%_))
                              (_%$%hd206163206236%_
                               (reverse _%$%hd206161206209%_)))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206152206195%_))
                              (let ((_%$%e206170206238%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206152206195%_))))
                                (let ((_%$%hd206171206241%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206170206238%_)))
                                      (_%$%tl206172206243%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206170206238%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl206172206243%_))
                                      (for-each
                                       (lambda (_%$%g206267206269%_)
                                         (gxc#compile-e__1
                                          _%self206139%_
                                          _%$%g206267206269%_))
                                       (let ((__tmp207142
                                              (lambda (_%$%g206271206274%_
                                                       _%$%g206272206276%_)
                                                (cons _%$%g206271206274%_
                                                      _%$%g206272206276%_)))
                                             (__tmp207141
                                              (cons _%$%hd206171206241%_ '())))
                                         (declare (not safe))
                                         (foldr__0
                                          __tmp207142
                                          __tmp207141
                                          _%$%expr206162206235%_)))
                                      (_%$%g206142206177%_
                                       _%$%g206143206180%_))))
                              (_%$%g206142206177%_ _%$%g206143206180%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop206156206203%_
                                                   _%$%target206153206198%_
                                                   '()
                                                   '()))
                                                (_%$%g206142206177%_
                                                 _%$%g206143206180%_)))))
                                      (_%$%g206142206177%_
                                       _%$%g206143206180%_))))
                              (_%$%g206142206177%_ _%$%g206143206180%_))))
                      (_%$%g206142206177%_ _%$%g206143206180%_)))))
          (_%$%g206141206279%_ _%stx206140%_))))
    (define gxc#apply-body-last-let-values%
      (lambda (_%self206084%_ _%stx206085%_)
        (let* ((_%$%g206087206101%_
                (lambda (_%$%g206088206098%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206088206098%_))))
               (_%$%g206086206136%_
                (lambda (_%$%g206088206104%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206088206104%_))
                      (let ((_%$%e206091206106%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206088206104%_))))
                        (let ((_%$%hd206092206109%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206091206106%_)))
                              (_%$%tl206093206111%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206091206106%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206093206111%_))
                              (let ((_%$%e206094206114%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206093206111%_))))
                                (let ((_%$%hd206095206117%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206094206114%_)))
                                      (_%$%tl206096206119%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206094206114%_))))
                                  (gxc#compile-e__1
                                   _%self206084%_
                                   (last _%$%tl206096206119%_))))
                              (_%$%g206087206101%_ _%$%g206088206104%_))))
                      (_%$%g206087206101%_ _%$%g206088206104%_)))))
          (_%$%g206086206136%_ _%stx206085%_))))
    (define gxc#apply-body-setq%
      (lambda (_%self206016%_ _%stx206017%_)
        (let* ((_%$%g206019206036%_
                (lambda (_%$%g206020206033%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g206020206033%_))))
               (_%$%g206018206081%_
                (lambda (_%$%g206020206039%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g206020206039%_))
                      (let ((_%$%e206023206041%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g206020206039%_))))
                        (let ((_%$%hd206024206044%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e206023206041%_)))
                              (_%$%tl206025206046%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e206023206041%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl206025206046%_))
                              (let ((_%$%e206026206049%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl206025206046%_))))
                                (let ((_%$%hd206027206052%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e206026206049%_)))
                                      (_%$%tl206028206054%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e206026206049%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl206028206054%_))
                                      (let ((_%$%e206029206057%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl206028206054%_))))
                                        (let ((_%$%hd206030206060%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e206029206057%_)))
                                              (_%$%tl206031206062%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e206029206057%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl206031206062%_))
                                              (gxc#compile-e__1
                                               _%self206016%_
                                               _%$%hd206030206060%_)
                                              (_%$%g206019206036%_
                                               _%$%g206020206039%_))))
                                      (_%$%g206019206036%_
                                       _%$%g206020206039%_))))
                              (_%$%g206019206036%_ _%$%g206020206039%_))))
                      (_%$%g206019206036%_ _%$%g206020206039%_)))))
          (_%$%g206018206081%_ _%stx206017%_))))
    (define gxc#apply-operands
      (lambda (_%self205931%_ _%stx205932%_)
        (let* ((_%$%g205934205953%_
                (lambda (_%$%g205935205950%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205935205950%_))))
               (_%$%g205933206013%_
                (lambda (_%$%g205935205956%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205935205956%_))
                      (let ((_%$%e205937205958%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205935205956%_))))
                        (let ((_%$%hd205938205961%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205937205958%_)))
                              (_%$%tl205939205963%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205937205958%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl205939205963%_))
                              (let ((_g207143_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice
                                        _%$%tl205939205963%_
                                        '0))))
                                (begin
                                  (let ((_g207144_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g207143_)
                                               (##values-length _g207143_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g207144_ 2)))
                                        (error "Context expects 2 values"
                                               _g207144_)))
                                  (let ((_%$%target205940205966%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g207143_ 0)))
                                        (_%$%tl205942205968%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g207143_ 1))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl205942205968%_))
                                        (letrec ((_%$%loop205943205971%_
                                                  (lambda (_%$%hd205941205974%_
                                                           _%$%rands205947205976%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd205941205974%_))
                                                        (let ((_%$%e205944205978%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%hd205941205974%_))))
                  (let ((_%$%lp-hd205945205981%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e205944205978%_)))
                        (_%$%lp-tl205946205983%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e205944205978%_))))
                    (_%$%loop205943205971%_
                     _%$%lp-tl205946205983%_
                     (cons _%$%lp-hd205945205981%_ _%$%rands205947205976%_))))
                (let ((_%$%rands205948205986%_
                       (reverse _%$%rands205947205976%_)))
                  (for-each
                   (lambda (_%$%g206001206003%_)
                     (gxc#compile-e__1 _%self205931%_ _%$%g206001206003%_))
                   (let ((__tmp207145
                          (lambda (_%$%g206005206008%_ _%$%g206006206010%_)
                            (cons _%$%g206005206008%_ _%$%g206006206010%_))))
                     (declare (not safe))
                     (foldr__0 __tmp207145 '() _%$%rands205948205986%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop205943205971%_
                                           _%$%target205940205966%_
                                           '()))
                                        (_%$%g205934205953%_
                                         _%$%g205935205956%_)))))
                              (_%$%g205934205953%_ _%$%g205935205956%_))))
                      (_%$%g205934205953%_ _%$%g205935205956%_)))))
          (_%$%g205933206013%_ _%stx205932%_))))
    (define gxc#xform-wrap-source
      (lambda (_%stx205928%_ _%src-stx205929%_)
        (let ((__tmp207146
               (let ()
                 (declare (not safe))
                 (gx#stx-source _%src-stx205929%_))))
          (declare (not safe))
          (gx#stx-wrap-source _%stx205928%_ __tmp207146))))
    (define gxc#xform-wrap-apply
      (lambda (_%stx205924%_ _%src-stx205925%_ _%ctx205926%_)
        (gxc#compile-e__1
         _%ctx205926%_
         (gxc#xform-wrap-source _%stx205924%_ _%src-stx205925%_))))
    (define gxc#xform-begin%
      (lambda (_%self205879%_ _%stx205880%_)
        (let* ((_%$%g205882205892%_
                (lambda (_%$%g205883205889%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205883205889%_))))
               (_%$%g205881205921%_
                (lambda (_%$%g205883205895%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205883205895%_))
                      (let ((_%$%e205885205897%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205883205895%_))))
                        (let ((_%$%hd205886205900%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205885205897%_)))
                              (_%$%tl205887205902%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205885205897%_))))
                          (let ((_%forms205919%_
                                 (map (lambda (_%$%g205914205916%_)
                                        (gxc#compile-e__1
                                         _%self205879%_
                                         _%$%g205914205916%_))
                                      _%$%tl205887205902%_)))
                            (gxc#xform-wrap-source
                             (cons '%#begin _%forms205919%_)
                             _%stx205880%_))))
                      (_%$%g205882205892%_ _%$%g205883205895%_)))))
          (_%$%g205881205921%_ _%stx205880%_))))
    (define gxc#xform-begin-syntax%
      (lambda (_%self205833%_ _%stx205834%_)
        (let* ((_%$%g205836205846%_
                (lambda (_%$%g205837205843%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205837205843%_))))
               (_%$%g205835205876%_
                (lambda (_%$%g205837205849%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205837205849%_))
                      (let ((_%$%e205839205851%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205837205849%_))))
                        (let ((_%$%hd205840205854%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205839205851%_)))
                              (_%$%tl205841205856%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205839205851%_))))
                          (let ((__tmp207149
                                 (lambda ()
                                   (let ((_%forms205874%_
                                          (map (lambda (_%$%g205869205871%_)
                                                 (gxc#compile-e__1
                                                  _%self205833%_
                                                  _%$%g205869205871%_))
                                               _%$%tl205841205856%_)))
                                     (gxc#xform-wrap-source
                                      (cons '%#begin-syntax _%forms205874%_)
                                      _%stx205834%_))))
                                (__tmp207147
                                 (let ((__tmp207148
                                        (let ()
                                          (declare (not safe))
                                          (gx#current-expander-phi))))
                                   (declare (not safe))
                                   (##fx+ __tmp207148 '1))))
                            (declare (not safe))
                            (call-with-parameters__1
                             __tmp207149
                             gx#current-expander-phi
                             __tmp207147))))
                      (_%$%g205836205846%_ _%$%g205837205849%_)))))
          (_%$%g205835205876%_ _%stx205834%_))))
    (define gxc#xform-module%
      (lambda (_%self205770%_ _%stx205771%_)
        (let* ((_%$%g205773205787%_
                (lambda (_%$%g205774205784%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205774205784%_))))
               (_%$%g205772205830%_
                (lambda (_%$%g205774205790%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205774205790%_))
                      (let ((_%$%e205777205792%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205774205790%_))))
                        (let ((_%$%hd205778205795%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205777205792%_)))
                              (_%$%tl205779205797%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205777205792%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl205779205797%_))
                              (let ((_%$%e205780205800%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl205779205797%_))))
                                (let ((_%$%hd205781205803%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e205780205800%_)))
                                      (_%$%tl205782205805%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e205780205800%_))))
                                  (let* ((_%ctx205822%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#syntax-local-e__0
                                             _%$%hd205781205803%_)))
                                         (_%code205824%_
                                          (##structure-ref
                                           _%ctx205822%_
                                           '11
                                           gx#module-context::t
                                           '#f))
                                         (_%code205827%_
                                          (let ((__tmp207150
                                                 (lambda ()
                                                   (gxc#compile-e__1
                                                    _%self205770%_
                                                    _%code205824%_))))
                                            (declare (not safe))
                                            (call-with-parameters__1
                                             __tmp207150
                                             gx#current-expander-context
                                             _%ctx205822%_))))
                                    (##structure-set!
                                     _%ctx205822%_
                                     _%code205827%_
                                     '11
                                     gx#module-context::t
                                     '#f)
                                    (gxc#xform-wrap-source
                                     (cons '%#module
                                           (cons _%$%hd205781205803%_
                                                 (cons _%code205827%_ '())))
                                     _%stx205771%_))))
                              (_%$%g205773205787%_ _%$%g205774205790%_))))
                      (_%$%g205773205787%_ _%$%g205774205790%_)))))
          (_%$%g205772205830%_ _%stx205771%_))))
    (define gxc#xform-define-values%
      (lambda (_%self205700%_ _%stx205701%_)
        (let* ((_%$%g205703205720%_
                (lambda (_%$%g205704205717%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205704205717%_))))
               (_%$%g205702205767%_
                (lambda (_%$%g205704205723%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205704205723%_))
                      (let ((_%$%e205707205725%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205704205723%_))))
                        (let ((_%$%hd205708205728%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205707205725%_)))
                              (_%$%tl205709205730%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205707205725%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl205709205730%_))
                              (let ((_%$%e205710205733%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl205709205730%_))))
                                (let ((_%$%hd205711205736%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e205710205733%_)))
                                      (_%$%tl205712205738%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e205710205733%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl205712205738%_))
                                      (let ((_%$%e205713205741%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl205712205738%_))))
                                        (let ((_%$%hd205714205744%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e205713205741%_)))
                                              (_%$%tl205715205746%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e205713205741%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl205715205746%_))
                                              (let ((_%expr205765%_
                                                     (gxc#compile-e__1
                                                      _%self205700%_
                                                      _%$%hd205714205744%_)))
                                                (gxc#xform-wrap-source
                                                 (cons '%#define-values
                                                       (cons _%$%hd205711205736%_
                                                             (cons _%expr205765%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 _%stx205701%_))
                                              (_%$%g205703205720%_
                                               _%$%g205704205723%_))))
                                      (_%$%g205703205720%_
                                       _%$%g205704205723%_))))
                              (_%$%g205703205720%_ _%$%g205704205723%_))))
                      (_%$%g205703205720%_ _%$%g205704205723%_)))))
          (_%$%g205702205767%_ _%stx205701%_))))
    (define gxc#xform-define-syntax%
      (lambda (_%self205629%_ _%stx205630%_)
        (let* ((_%$%g205632205649%_
                (lambda (_%$%g205633205646%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205633205646%_))))
               (_%$%g205631205697%_
                (lambda (_%$%g205633205652%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205633205652%_))
                      (let ((_%$%e205636205654%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205633205652%_))))
                        (let ((_%$%hd205637205657%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205636205654%_)))
                              (_%$%tl205638205659%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205636205654%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl205638205659%_))
                              (let ((_%$%e205639205662%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl205638205659%_))))
                                (let ((_%$%hd205640205665%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e205639205662%_)))
                                      (_%$%tl205641205667%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e205639205662%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl205641205667%_))
                                      (let ((_%$%e205642205670%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl205641205667%_))))
                                        (let ((_%$%hd205643205673%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e205642205670%_)))
                                              (_%$%tl205644205675%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e205642205670%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl205644205675%_))
                                              (let ((__tmp207153
                                                     (lambda ()
                                                       (let ((_%expr205695%_
                                                              (gxc#compile-e__1
                                                               _%self205629%_
                                                               _%$%hd205643205673%_)))
                                                         (gxc#xform-wrap-source
                                                          (cons '%#define-syntax
                                                                (cons _%$%hd205640205665%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons _%expr205695%_ '())))
                  _%stx205630%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (__tmp207151
                                                     (let ((__tmp207152
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#current-expander-phi))))
                                                       (declare (not safe))
                                                       (##fx+ __tmp207152
                                                              '1))))
                                                (declare (not safe))
                                                (call-with-parameters__1
                                                 __tmp207153
                                                 gx#current-expander-phi
                                                 __tmp207151))
                                              (_%$%g205632205649%_
                                               _%$%g205633205652%_))))
                                      (_%$%g205632205649%_
                                       _%$%g205633205652%_))))
                              (_%$%g205632205649%_ _%$%g205633205652%_))))
                      (_%$%g205632205649%_ _%$%g205633205652%_)))))
          (_%$%g205631205697%_ _%stx205630%_))))
    (define gxc#xform-begin-annotation%
      (lambda (_%self205559%_ _%stx205560%_)
        (let* ((_%$%g205562205579%_
                (lambda (_%$%g205563205576%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205563205576%_))))
               (_%$%g205561205626%_
                (lambda (_%$%g205563205582%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205563205582%_))
                      (let ((_%$%e205566205584%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205563205582%_))))
                        (let ((_%$%hd205567205587%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205566205584%_)))
                              (_%$%tl205568205589%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205566205584%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl205568205589%_))
                              (let ((_%$%e205569205592%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl205568205589%_))))
                                (let ((_%$%hd205570205595%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e205569205592%_)))
                                      (_%$%tl205571205597%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e205569205592%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl205571205597%_))
                                      (let ((_%$%e205572205600%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl205571205597%_))))
                                        (let ((_%$%hd205573205603%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e205572205600%_)))
                                              (_%$%tl205574205605%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e205572205600%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl205574205605%_))
                                              (let ((_%expr205624%_
                                                     (gxc#compile-e__1
                                                      _%self205559%_
                                                      _%$%hd205573205603%_)))
                                                (gxc#xform-wrap-source
                                                 (cons '%#begin-annotation
                                                       (cons _%$%hd205570205595%_
                                                             (cons _%expr205624%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 _%stx205560%_))
                                              (_%$%g205562205579%_
                                               _%$%g205563205582%_))))
                                      (_%$%g205562205579%_
                                       _%$%g205563205582%_))))
                              (_%$%g205562205579%_ _%$%g205563205582%_))))
                      (_%$%g205562205579%_ _%$%g205563205582%_)))))
          (_%$%g205561205626%_ _%stx205560%_))))
    (define gxc#xform-lambda%
      (lambda (_%self205497%_ _%stx205498%_)
        (let* ((_%$%g205500205514%_
                (lambda (_%$%g205501205511%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205501205511%_))))
               (_%$%g205499205556%_
                (lambda (_%$%g205501205517%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205501205517%_))
                      (let ((_%$%e205504205519%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205501205517%_))))
                        (let ((_%$%hd205505205522%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205504205519%_)))
                              (_%$%tl205506205524%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205504205519%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl205506205524%_))
                              (let ((_%$%e205507205527%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl205506205524%_))))
                                (let ((_%$%hd205508205530%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e205507205527%_)))
                                      (_%$%tl205509205532%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e205507205527%_))))
                                  (let ((__tmp207155
                                         (lambda ()
                                           (let ((_%body205554%_
                                                  (map (lambda (_%$%g205549205551%_)
                                                         (gxc#compile-e__1
                                                          _%self205497%_
                                                          _%$%g205549205551%_))
                                                       _%$%tl205509205532%_)))
                                             (gxc#xform-wrap-source
                                              (cons '%#lambda
                                                    (cons _%$%hd205508205530%_
                                                          _%body205554%_))
                                              _%stx205498%_))))
                                        (__tmp207154
                                         (gxc#xform-let-locals
                                          _%$%hd205508205530%_)))
                                    (declare (not safe))
                                    (call-with-parameters__1
                                     __tmp207155
                                     gxc#current-compile-local-env
                                     __tmp207154))))
                              (_%$%g205500205514%_ _%$%g205501205517%_))))
                      (_%$%g205500205514%_ _%$%g205501205517%_)))))
          (_%$%g205499205556%_ _%stx205498%_))))
    (define gxc#xform-case-lambda%
      (lambda (_%self205405%_ _%stx205406%_)
        (letrec ((_%clause-e205408%_
                  (lambda (_%clause205449%_)
                    (let* ((_%$%g205451205462%_
                            (lambda (_%$%g205452205459%_)
                              (let ()
                                (declare (not safe))
                                (gx#raise-syntax-error
                                 '#f
                                 '"Bad syntax; invalid match target"
                                 _%$%g205452205459%_))))
                           (_%$%g205450205494%_
                            (lambda (_%$%g205452205465%_)
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%g205452205465%_))
                                  (let ((_%$%e205455205467%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%g205452205465%_))))
                                    (let ((_%$%hd205456205470%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e205455205467%_)))
                                          (_%$%tl205457205472%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e205455205467%_))))
                                      (let ((__tmp207157
                                             (lambda ()
                                               (let ((_%body205492%_
                                                      (map (lambda (_%$%g205487205489%_)
                                                             (gxc#compile-e__1
                                                              _%self205405%_
                                                              _%$%g205487205489%_))
                                                           _%$%tl205457205472%_)))
                                                 (cons _%$%hd205456205470%_
                                                       _%body205492%_))))
                                            (__tmp207156
                                             (gxc#xform-let-locals
                                              _%$%hd205456205470%_)))
                                        (declare (not safe))
                                        (call-with-parameters__1
                                         __tmp207157
                                         gxc#current-compile-local-env
                                         __tmp207156))))
                                  (_%$%g205451205462%_ _%$%g205452205465%_)))))
                      (_%$%g205450205494%_ _%clause205449%_)))))
          (let* ((_%$%g205410205420%_
                  (lambda (_%$%g205411205417%_)
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%$%g205411205417%_))))
                 (_%$%g205409205446%_
                  (lambda (_%$%g205411205423%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%g205411205423%_))
                        (let ((_%$%e205413205425%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%g205411205423%_))))
                          (let ((_%$%hd205414205428%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e205413205425%_)))
                                (_%$%tl205415205430%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e205413205425%_))))
                            (let ((_%clauses205444%_
                                   (map _%clause-e205408%_
                                        _%$%tl205415205430%_)))
                              (gxc#xform-wrap-source
                               (cons '%#case-lambda _%clauses205444%_)
                               _%stx205406%_))))
                        (_%$%g205410205420%_ _%$%g205411205423%_)))))
            (_%$%g205409205446%_ _%stx205406%_)))))
    (define gxc#xform-let-values%
      (lambda (_%self205165%_ _%stx205166%_)
        (let* ((_%$%g205168205201%_
                (lambda (_%$%g205169205198%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g205169205198%_))))
               (_%$%g205167205402%_
                (lambda (_%$%g205169205204%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g205169205204%_))
                      (let ((_%$%e205174205206%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g205169205204%_))))
                        (let ((_%$%hd205175205209%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e205174205206%_)))
                              (_%$%tl205176205211%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e205174205206%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl205176205211%_))
                              (let ((_%$%e205177205214%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl205176205211%_))))
                                (let ((_%$%hd205178205217%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e205177205214%_)))
                                      (_%$%tl205179205219%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e205177205214%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%hd205178205217%_))
                                      (let ((_g207158_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice
                                                _%$%hd205178205217%_
                                                '0))))
                                        (begin
                                          (let ((_g207159_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g207158_)
                                                       (##values-length
                                                        _g207158_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g207159_ 2)))
                                                (error "Context expects 2 values"
                                                       _g207159_)))
                                          (let ((_%$%target205180205222%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g207158_ 0)))
                                                (_%$%tl205182205224%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g207158_
                                                    1))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl205182205224%_))
                                                (letrec ((_%$%loop205183205227%_
                                                          (lambda (_%$%hd205181205230%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%expr205187205232%_
                           _%$%hd205188205233%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd205181205230%_))
                        (let ((_%$%e205184205235%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd205181205230%_))))
                          (let ((_%$%lp-hd205185205238%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e205184205235%_)))
                                (_%$%lp-tl205186205240%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e205184205235%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%lp-hd205185205238%_))
                                (let ((_%$%e205191205243%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%lp-hd205185205238%_))))
                                  (let ((_%$%hd205192205246%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e205191205243%_)))
                                        (_%$%tl205193205248%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e205191205243%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl205193205248%_))
                                        (let ((_%$%e205194205251%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl205193205248%_))))
                                          (let ((_%$%hd205195205254%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e205194205251%_)))
                                                (_%$%tl205196205256%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e205194205251%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl205196205256%_))
                                                (_%$%loop205183205227%_
                                                 _%$%lp-tl205186205240%_
                                                 (cons _%$%hd205195205254%_
                                                       _%$%expr205187205232%_)
                                                 (cons _%$%hd205192205246%_
                                                       _%$%hd205188205233%_))
                                                (_%$%g205168205201%_
                                                 _%$%g205169205204%_))))
                                        (_%$%g205168205201%_
                                         _%$%g205169205204%_))))
                                (_%$%g205168205201%_ _%$%g205169205204%_))))
                        (let ((_%$%expr205189205259%_
                               (reverse _%$%expr205187205232%_))
                              (_%$%hd205190205260%_
                               (reverse _%$%hd205188205233%_)))
                          (let* ((_%$%g205284205300%_
                                  (lambda (_%$%g205285205297%_)
                                    (let ()
                                      (declare (not safe))
                                      (gx#raise-syntax-error
                                       '#f
                                       '"Bad syntax; invalid match target"
                                       _%$%g205285205297%_))))
                                 (_%$%g205283205388%_
                                  (lambda (_%$%g205285205303%_)
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair/null?
                                           _%$%g205285205303%_))
                                        (let ((_g207160_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-split-splice
                                                  _%$%g205285205303%_
                                                  '0))))
                                          (begin
                                            (let ((_g207161_
                                                   (let ()
                                                     (declare (not safe))
                                                     (if (##values? _g207160_)
                                                         (##values-length
                                                          _g207160_)
                                                         1))))
                                              (if (not (let ()
                                                         (declare (not safe))
                                                         (##fx= _g207161_ 2)))
                                                  (error "Context expects 2 values"
                                                         _g207161_)))
                                            (let ((_%$%target205287205305%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##values-ref
                                                      _g207160_
                                                      0)))
                                                  (_%$%tl205289205307%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##values-ref
                                                      _g207160_
                                                      1))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-null?
                                                     _%$%tl205289205307%_))
                                                  (letrec ((_%$%loop205290205310%_
                                                            (lambda (_%$%hd205288205313%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%$%expr205294205315%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%hd205288205313%_))
                          (let ((_%$%e205291205317%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#syntax-e _%$%hd205288205313%_))))
                            (let ((_%$%lp-hd205292205320%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e205291205317%_)))
                                  (_%$%lp-tl205293205322%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e205291205317%_))))
                              (_%$%loop205290205310%_
                               _%$%lp-tl205293205322%_
                               (cons _%$%lp-hd205292205320%_
                                     _%$%expr205294205315%_))))
                          (let ((_%$%expr205295205325%_
                                 (reverse _%$%expr205294205315%_)))
                            (let ((__tmp207164
                                   (lambda ()
                                     (let* ((_%$%g205341205348%_
                                             (lambda (_%$%g205342205345%_)
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#raise-syntax-error
                                                  '#f
                                                  '"Bad syntax; invalid match target"
                                                  _%$%g205342205345%_))))
                                            (_%$%g205340205374%_
                                             (lambda (_%$%g205342205351%_)
                                               (gxc#xform-wrap-source
                                                (cons _%$%hd205175205209%_
                                                      (cons (begin
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#syntax-check-splice-targets
                         _%$%expr205295205325%_
                         _%$%hd205190205260%_))
                      (let ((__tmp207165
                             (lambda (_%$%g205363205367%_
                                      _%$%g205364205369%_
                                      _%$%g205365205371%_)
                               (cons (cons _%$%g205364205369%_
                                           (cons _%$%g205363205367%_ '()))
                                     _%$%g205365205371%_))))
                        (declare (not safe))
                        (foldr__1
                         __tmp207165
                         '()
                         _%$%expr205295205325%_
                         _%$%hd205190205260%_)))
                    _%$%g205342205351%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                _%stx205166%_))))
                                       (_%$%g205340205374%_
                                        (map (lambda (_%$%g205376205378%_)
                                               (gxc#compile-e__1
                                                _%self205165%_
                                                _%$%g205376205378%_))
                                             _%$%tl205179205219%_)))))
                                  (__tmp207162
                                   (gxc#xform-let-locals
                                    (let ((__tmp207163
                                           (lambda (_%$%g205380205383%_
                                                    _%$%g205381205385%_)
                                             (cons _%$%g205380205383%_
                                                   _%$%g205381205385%_))))
                                      (declare (not safe))
                                      (foldr__0
                                       __tmp207163
                                       '()
                                       _%$%hd205190205260%_)))))
                              (declare (not safe))
                              (call-with-parameters__1
                               __tmp207164
                               gxc#current-compile-local-env
                               __tmp207162)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$%loop205290205310%_
                                                     _%$%target205287205305%_
                                                     '()))
                                                  (_%$%g205284205300%_
                                                   _%$%g205285205303%_)))))
                                        (_%$%g205284205300%_
                                         _%$%g205285205303%_)))))
                            (_%$%g205283205388%_
                             (map (lambda (_%$%g205390205392%_)
                                    (gxc#compile-e__1
                                     _%self205165%_
                                     _%$%g205390205392%_))
                                  (let ((__tmp207166
                                         (lambda (_%$%g205394205397%_
                                                  _%$%g205395205399%_)
                                           (cons _%$%g205394205397%_
                                                 _%$%g205395205399%_))))
                                    (declare (not safe))
                                    (foldr__0
                                     __tmp207166
                                     '()
                                     _%$%expr205189205259%_))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop205183205227%_
                                                   _%$%target205180205222%_
                                                   '()
                                                   '()))
                                                (_%$%g205168205201%_
                                                 _%$%g205169205204%_)))))
                                      (_%$%g205168205201%_
                                       _%$%g205169205204%_))))
                              (_%$%g205168205201%_ _%$%g205169205204%_))))
                      (_%$%g205168205201%_ _%$%g205169205204%_)))))
          (_%$%g205167205402%_ _%stx205166%_))))
    (define gxc#xform-letrec-values%
      (lambda (_%self204925%_ _%stx204926%_)
        (let* ((_%$%g204928204961%_
                (lambda (_%$%g204929204958%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g204929204958%_))))
               (_%$%g204927205162%_
                (lambda (_%$%g204929204964%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g204929204964%_))
                      (let ((_%$%e204934204966%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g204929204964%_))))
                        (let ((_%$%hd204935204969%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e204934204966%_)))
                              (_%$%tl204936204971%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e204934204966%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl204936204971%_))
                              (let ((_%$%e204937204974%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl204936204971%_))))
                                (let ((_%$%hd204938204977%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e204937204974%_)))
                                      (_%$%tl204939204979%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e204937204974%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%hd204938204977%_))
                                      (let ((_g207167_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice
                                                _%$%hd204938204977%_
                                                '0))))
                                        (begin
                                          (let ((_g207168_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g207167_)
                                                       (##values-length
                                                        _g207167_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g207168_ 2)))
                                                (error "Context expects 2 values"
                                                       _g207168_)))
                                          (let ((_%$%target204940204982%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g207167_ 0)))
                                                (_%$%tl204942204984%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g207167_
                                                    1))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl204942204984%_))
                                                (letrec ((_%$%loop204943204987%_
                                                          (lambda (_%$%hd204941204990%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%expr204947204992%_
                           _%$%hd204948204993%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd204941204990%_))
                        (let ((_%$%e204944204995%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd204941204990%_))))
                          (let ((_%$%lp-hd204945204998%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e204944204995%_)))
                                (_%$%lp-tl204946205000%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e204944204995%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%lp-hd204945204998%_))
                                (let ((_%$%e204951205003%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%lp-hd204945204998%_))))
                                  (let ((_%$%hd204952205006%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e204951205003%_)))
                                        (_%$%tl204953205008%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e204951205003%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl204953205008%_))
                                        (let ((_%$%e204954205011%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl204953205008%_))))
                                          (let ((_%$%hd204955205014%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e204954205011%_)))
                                                (_%$%tl204956205016%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e204954205011%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl204956205016%_))
                                                (_%$%loop204943204987%_
                                                 _%$%lp-tl204946205000%_
                                                 (cons _%$%hd204955205014%_
                                                       _%$%expr204947204992%_)
                                                 (cons _%$%hd204952205006%_
                                                       _%$%hd204948204993%_))
                                                (_%$%g204928204961%_
                                                 _%$%g204929204964%_))))
                                        (_%$%g204928204961%_
                                         _%$%g204929204964%_))))
                                (_%$%g204928204961%_ _%$%g204929204964%_))))
                        (let ((_%$%expr204949205019%_
                               (reverse _%$%expr204947204992%_))
                              (_%$%hd204950205020%_
                               (reverse _%$%hd204948204993%_)))
                          (let ((__tmp207171
                                 (lambda ()
                                   (let* ((_%$%g205045205061%_
                                           (lambda (_%$%g205046205058%_)
                                             (let ()
                                               (declare (not safe))
                                               (gx#raise-syntax-error
                                                '#f
                                                '"Bad syntax; invalid match target"
                                                _%$%g205046205058%_))))
                                          (_%$%g205044205141%_
                                           (lambda (_%$%g205046205064%_)
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair/null?
                                                    _%$%g205046205064%_))
                                                 (let ((_g207172_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#syntax-split-splice
                                                           _%$%g205046205064%_
                                                           '0))))
                                                   (begin
                                                     (let ((_g207173_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (if (##values?
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _g207172_)
                          (##values-length _g207172_)
                          1))))
               (if (not (let () (declare (not safe)) (##fx= _g207173_ 2)))
                   (error "Context expects 2 values" _g207173_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (let ((_%$%target205048205066%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##values-ref
                                                               _g207172_
                                                               0)))
                                                           (_%$%tl205050205068%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##values-ref
                                                               _g207172_
                                                               1))))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-null?
                                                              _%$%tl205050205068%_))
                                                           (letrec ((_%$%loop205051205071%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (lambda (_%$%hd205049205074%_
                                      _%$%expr205055205076%_)
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%hd205049205074%_))
                                   (let ((_%$%e205052205078%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#syntax-e
                                             _%$%hd205049205074%_))))
                                     (let ((_%$%lp-hd205053205081%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e205052205078%_)))
                                           (_%$%lp-tl205054205083%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e205052205078%_))))
                                       (_%$%loop205051205071%_
                                        _%$%lp-tl205054205083%_
                                        (cons _%$%lp-hd205053205081%_
                                              _%$%expr205055205076%_))))
                                   (let* ((_%$%expr205056205086%_
                                           (reverse _%$%expr205055205076%_))
                                          (_%$%g205102205109%_
                                           (lambda (_%$%g205103205106%_)
                                             (let ()
                                               (declare (not safe))
                                               (gx#raise-syntax-error
                                                '#f
                                                '"Bad syntax; invalid match target"
                                                _%$%g205103205106%_))))
                                          (_%$%g205101205134%_
                                           (lambda (_%$%g205103205112%_)
                                             (gxc#xform-wrap-source
                                              (cons _%$%hd204935204969%_
                                                    (cons (begin
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#syntax-check-splice-targets
                                                               _%$%expr205056205086%_
                                                               _%$%hd204950205020%_))
                                                            (let ((__tmp207174
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (lambda (_%$%g205123205127%_
                                    _%$%g205124205129%_
                                    _%$%g205125205131%_)
                             (cons (cons _%$%g205124205129%_
                                         (cons _%$%g205123205127%_ '()))
                                   _%$%g205125205131%_))))
                      (declare (not safe))
                      (foldr__1
                       __tmp207174
                       '()
                       _%$%expr205056205086%_
                       _%$%hd204950205020%_)))
                  _%$%g205103205112%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              _%stx204926%_))))
                                     (_%$%g205101205134%_
                                      (map (lambda (_%$%g205136205138%_)
                                             (gxc#compile-e__1
                                              _%self204925%_
                                              _%$%g205136205138%_))
                                           _%$%tl204939204979%_)))))))
                     (_%$%loop205051205071%_ _%$%target205048205066%_ '()))
                   (_%$%g205045205061%_ _%$%g205046205064%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g205045205061%_
                                                  _%$%g205046205064%_)))))
                                     (_%$%g205044205141%_
                                      (map (lambda (_%$%g205143205145%_)
                                             (gxc#compile-e__1
                                              _%self204925%_
                                              _%$%g205143205145%_))
                                           (let ((__tmp207175
                                                  (lambda (_%$%g205147205150%_
                                                           _%$%g205148205152%_)
                                                    (cons _%$%g205147205150%_
                                                          _%$%g205148205152%_))))
                                             (declare (not safe))
                                             (foldr__0
                                              __tmp207175
                                              '()
                                              _%$%expr204949205019%_)))))))
                                (__tmp207169
                                 (gxc#xform-let-locals
                                  (let ((__tmp207170
                                         (lambda (_%$%g205154205157%_
                                                  _%$%g205155205159%_)
                                           (cons _%$%g205154205157%_
                                                 _%$%g205155205159%_))))
                                    (declare (not safe))
                                    (foldr__0
                                     __tmp207170
                                     '()
                                     _%$%hd204950205020%_)))))
                            (declare (not safe))
                            (call-with-parameters__1
                             __tmp207171
                             gxc#current-compile-local-env
                             __tmp207169)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop204943204987%_
                                                   _%$%target204940204982%_
                                                   '()
                                                   '()))
                                                (_%$%g204928204961%_
                                                 _%$%g204929204964%_)))))
                                      (_%$%g204928204961%_
                                       _%$%g204929204964%_))))
                              (_%$%g204928204961%_ _%$%g204929204964%_))))
                      (_%$%g204928204961%_ _%$%g204929204964%_)))))
          (_%$%g204927205162%_ _%stx204926%_))))
    (define gxc#xform-let-locals
      (lambda (_%bindings204792%_)
        (letrec ((_%flatten204794%_
                  (lambda (_%maybe-lst204852%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#identifier? _%maybe-lst204852%_))
                        (cons _%maybe-lst204852%_ '())
                        (let _%loop204854%_ ((_%rest204856%_
                                              _%maybe-lst204852%_)
                                             (_%result204857%_ '()))
                          (let* ((_%__stx207061207062%_ _%rest204856%_)
                                 (_%$%g204861204873%_
                                  (lambda ()
                                    (let ()
                                      (declare (not safe))
                                      (gx#raise-syntax-error
                                       '#f
                                       '"Bad syntax; invalid match target"
                                       _%__stx207061207062%_)))))
                            (let ((_%__kont207063207064%_
                                   (lambda (_%$%g204863204911%_
                                            _%$%g204864204912%_)
                                     (_%loop204854%_
                                      _%$%g204863204911%_
                                      (let ((__tmp207176
                                             (_%flatten204794%_
                                              _%$%g204864204912%_)))
                                        (declare (not safe))
                                        (foldl__0
                                         cons
                                         _%result204857%_
                                         __tmp207176)))))
                                  (_%__kont207065207066%_
                                   (lambda (_%$%g204868204885%_)
                                     (cons _%$%g204868204885%_
                                           _%result204857%_)))
                                  (_%__kont207067207068%_
                                   (lambda () _%result204857%_)))
                              (let ((_%$%g204859204898%_
                                     (lambda ()
                                       (let ((_%$%g204868204885%_
                                              _%__stx207061207062%_))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#identifier?
                                                _%$%g204868204885%_))
                                             (_%__kont207065207066%_
                                              _%$%g204868204885%_)
                                             (_%__kont207067207068%_))))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%__stx207061207062%_))
                                    (let ((_%$%e204865204903%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e
                                              _%__stx207061207062%_))))
                                      (let ((_%$%tl204867204908%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e204865204903%_)))
                                            (_%$%hd204866204906%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e204865204903%_))))
                                        (_%__kont207063207064%_
                                         _%$%tl204867204908%_
                                         _%$%hd204866204906%_)))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g204859204898%_)))))))))))
          (let _%loop204796%_ ((_%rest204798%_
                                (_%flatten204794%_ _%bindings204792%_))
                               (_%locals204799%_
                                (let ()
                                  (declare (not safe))
                                  (gxc#current-compile-local-env))))
            (let* ((_%$%rest204800204811%_ _%rest204798%_)
                   (_%$%E204804204815%_
                    (lambda ()
                      (let ()
                        (declare (not safe))
                        (error '"No clause matching"
                               _%$%rest204800204811%_
                               '([(? identifier? id) . rest])
                               '((? identifier? id))
                               '(_)))
                      '#!void)))
              (let ((_%$%K204807204840%_
                     (lambda (_%rest204837%_ _%id204838%_)
                       (_%loop204796%_
                        _%rest204837%_
                        (cons (let ()
                                (declare (not safe))
                                (gxc#identifier-symbol _%id204838%_))
                              _%locals204799%_))))
                    (_%$%K204806204829%_
                     (lambda (_%id204827%_)
                       (cons (let ()
                               (declare (not safe))
                               (gxc#identifier-symbol _%id204827%_))
                             _%locals204799%_)))
                    (_%$%K204805204820%_ (lambda () _%locals204799%_)))
                (let ((_%$%try-match204802204834%_
                       (lambda ()
                         (if (let ()
                               (declare (not safe))
                               (gx#identifier? _%$%rest204800204811%_))
                             (let ((_%id204832%_ _%$%rest204800204811%_))
                               (_%$%K204806204829%_ _%id204832%_))
                             (_%$%K204805204820%_)))))
                  (if (pair? _%$%rest204800204811%_)
                      (let ((_%$%tl204809204845%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%rest204800204811%_)))
                            (_%$%hd204808204843%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%rest204800204811%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#identifier? _%$%hd204808204843%_))
                            (let ((_%id204848%_ _%$%hd204808204843%_)
                                  (_%rest204850%_ _%$%tl204809204845%_))
                              (_%$%K204807204840%_
                               _%rest204850%_
                               _%id204848%_))
                            (_%$%try-match204802204834%_)))
                      (_%$%try-match204802204834%_)))))))))
    (define gxc#xform-operands
      (lambda (_%self204744%_ _%stx204745%_)
        (let* ((_%$%g204747204758%_
                (lambda (_%$%g204748204755%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g204748204755%_))))
               (_%$%g204746204789%_
                (lambda (_%$%g204748204761%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g204748204761%_))
                      (let ((_%$%e204751204763%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g204748204761%_))))
                        (let ((_%$%hd204752204766%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e204751204763%_)))
                              (_%$%tl204753204768%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e204751204763%_))))
                          (let ((_%rands204787%_
                                 (map (lambda (_%$%g204782204784%_)
                                        (gxc#compile-e__1
                                         _%self204744%_
                                         _%$%g204782204784%_))
                                      _%$%tl204753204768%_)))
                            (gxc#xform-wrap-source
                             (cons _%$%hd204752204766%_ _%rands204787%_)
                             _%stx204745%_))))
                      (_%$%g204747204758%_ _%$%g204748204761%_)))))
          (_%$%g204746204789%_ _%stx204745%_))))
    (define gxc#xform-call% gxc#xform-operands)
    (define gxc#xform-setq%
      (lambda (_%self204674%_ _%stx204675%_)
        (let* ((_%$%g204677204694%_
                (lambda (_%$%g204678204691%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g204678204691%_))))
               (_%$%g204676204741%_
                (lambda (_%$%g204678204697%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g204678204697%_))
                      (let ((_%$%e204681204699%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g204678204697%_))))
                        (let ((_%$%hd204682204702%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e204681204699%_)))
                              (_%$%tl204683204704%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e204681204699%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl204683204704%_))
                              (let ((_%$%e204684204707%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl204683204704%_))))
                                (let ((_%$%hd204685204710%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e204684204707%_)))
                                      (_%$%tl204686204712%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e204684204707%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl204686204712%_))
                                      (let ((_%$%e204687204715%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl204686204712%_))))
                                        (let ((_%$%hd204688204718%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e204687204715%_)))
                                              (_%$%tl204689204720%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e204687204715%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl204689204720%_))
                                              (let ((_%expr204739%_
                                                     (gxc#compile-e__1
                                                      _%self204674%_
                                                      _%$%hd204688204718%_)))
                                                (gxc#xform-wrap-source
                                                 (cons '%#set!
                                                       (cons _%$%hd204685204710%_
                                                             (cons _%expr204739%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 _%stx204675%_))
                                              (_%$%g204677204694%_
                                               _%$%g204678204697%_))))
                                      (_%$%g204677204694%_
                                       _%$%g204678204697%_))))
                              (_%$%g204677204694%_ _%$%g204678204697%_))))
                      (_%$%g204677204694%_ _%$%g204678204697%_)))))
          (_%$%g204676204741%_ _%stx204675%_))))))
