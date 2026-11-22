(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/optimize-xform::timestamp 1795039819)
  (begin
    (define gxc#::collect-mutators::t
      (let ((__tmp226990 (list gxc#::void::t))
            (__tmp226989 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::collect-mutators::t
         '::collect-mutators
         __tmp226990
         '()
         __tmp226989
         '#f)))
    (define gxc#::collect-mutators?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::collect-mutators::t)))
    (define gxc#make-::collect-mutators
      (lambda _%$args226974%_
        (apply make-instance gxc#::collect-mutators::t _%$args226974%_)))
    (define gxc#::collect-mutators-bind-methods!
      (let ((__tmp226991
             (lambda ()
               (force gxc#::void-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#begin
                  gxc#apply-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#begin-syntax
                  gxc#apply-begin-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#begin-annotation
                  gxc#apply-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#module
                  gxc#apply-module%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#define-values
                  gxc#apply-define-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#define-syntax
                  gxc#apply-define-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#lambda
                  gxc#apply-body-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#case-lambda
                  gxc#apply-body-case-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#let-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#letrec-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#letrec*-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#call
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#call-unchecked
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#if
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#set!
                  gxc#collect-mutators-setq%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#struct-instance?
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#struct-direct-instance?
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#struct-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#struct-set!
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#struct-direct-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#struct-direct-set!
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#struct-unchecked-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-mutators::t
                  '%#struct-unchecked-set!
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::collect-mutators::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp226991)))
    (define gxc#apply-collect-mutators
      (lambda (_%stx226966%_)
        (force gxc#::collect-mutators-bind-methods!)
        (let* ((_%self226969%_
                (let ((__obj226977
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::collect-mutators::t))))
                  __obj226977))
               (__tmp226992
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self226969%_ _%stx226966%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp226992
           gxc#current-compile-method
           _%self226969%_))))
    (define gxc#::expression-subst::t
      (let ((__tmp226994 (list gxc#::basic-xform-expression::t))
            (__tmp226993 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::expression-subst::t
         '::expression-subst
         __tmp226994
         '(id new-id)
         __tmp226993
         '#f)))
    (define gxc#::expression-subst?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::expression-subst::t)))
    (define gxc#make-::expression-subst
      (lambda _%$args226963%_
        (apply make-instance gxc#::expression-subst::t _%$args226963%_)))
    (define gxc#::expression-subst-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::expression-subst::t 'id)))
    (define gxc#::expression-subst-new-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::expression-subst::t 'new-id)))
    (define gxc#::expression-subst-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::expression-subst::t 'id)))
    (define gxc#::expression-subst-new-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::expression-subst::t 'new-id)))
    (define gxc#&::expression-subst-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#::expression-subst::t 'id)))
    (define gxc#&::expression-subst-new-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::expression-subst::t
         'new-id)))
    (define gxc#&::expression-subst-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#::expression-subst::t 'id)))
    (define gxc#&::expression-subst-new-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::expression-subst::t
         'new-id)))
    (define gxc#::expression-subst-bind-methods!
      (let ((__tmp226995
             (lambda ()
               (force gxc#::basic-xform-expression-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::expression-subst::t
                  '%#begin
                  gxc#xform-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::expression-subst::t
                  '%#ref
                  gxc#expression-subst-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::expression-subst::t
                  '%#set!
                  gxc#expression-subst-setq%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::expression-subst::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp226995)))
    (define gxc#apply-expression-subst__%
      (lambda (_%@@keywords226935%_
               _%$%id226931226936%_
               _%$%new-id226932226937%_
               _%stx226938%_)
        (let* ((_%id226941%_
                (if (eq? _%$%id226931226936%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'id:))
                    _%$%id226931226936%_))
               (_%new-id226943%_
                (if (eq? _%$%new-id226932226937%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'new-id:))
                    _%$%new-id226932226937%_)))
          (force gxc#::expression-subst-bind-methods!)
          (let* ((_%self226945%_
                  (let ((__obj226979
                         (let ()
                           (declare (not safe))
                           (##structure gxc#::expression-subst::t '#f '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj226979
                       _%id226941%_
                       '1
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj226979
                       _%new-id226943%_
                       '2
                       '#f
                       '#f))
                    __obj226979))
                 (__tmp226996
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self226945%_ _%stx226938%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp226996
             gxc#current-compile-method
             _%self226945%_)))))
    (define gxc#apply-expression-subst__@
      (lambda (_%@@keywords226952%_ . _%args226953%_)
        (apply gxc#apply-expression-subst__%
               _%@@keywords226952%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords226952%_ 'id: absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords226952%_
                  'new-id:
                  absent-value))
               _%args226953%_)))
    (define gxc#apply-expression-subst
      (lambda _%$%args226933226959%_
        (apply keyword-dispatch
               '#(id: new-id:)
               gxc#apply-expression-subst__@
               _%$%args226933226959%_)))
    (define gxc#::expression-subst*::t
      (let ((__tmp226998 (list gxc#::basic-xform-expression::t))
            (__tmp226997 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::expression-subst*::t
         '::expression-subst*
         __tmp226998
         '(subst)
         __tmp226997
         '#f)))
    (define gxc#::expression-subst*?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::expression-subst*::t)))
    (define gxc#make-::expression-subst*
      (lambda _%$args226927%_
        (apply make-instance gxc#::expression-subst*::t _%$args226927%_)))
    (define gxc#::expression-subst*-subst
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::expression-subst*::t 'subst)))
    (define gxc#::expression-subst*-subst-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::expression-subst*::t 'subst)))
    (define gxc#&::expression-subst*-subst
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::expression-subst*::t
         'subst)))
    (define gxc#&::expression-subst*-subst-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::expression-subst*::t
         'subst)))
    (define gxc#::expression-subst*-bind-methods!
      (let ((__tmp226999
             (lambda ()
               (force gxc#::basic-xform-expression-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::expression-subst*::t
                  '%#begin
                  gxc#xform-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::expression-subst*::t
                  '%#ref
                  gxc#expression-subst*-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::expression-subst*::t
                  '%#set!
                  gxc#expression-subst*-setq%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::expression-subst*::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp226999)))
    (define gxc#apply-expression-subst*__%
      (lambda (_%@@keywords226902%_ _%$%subst226899226903%_ _%stx226904%_)
        (let ((_%subst226907%_
               (if (eq? _%$%subst226899226903%_ absent-value)
                   (let ()
                     (declare (not safe))
                     (error '"Missing required keyword argument" 'subst:))
                   _%$%subst226899226903%_)))
          (force gxc#::expression-subst*-bind-methods!)
          (let* ((_%self226909%_
                  (let ((__obj226981
                         (let ()
                           (declare (not safe))
                           (##structure gxc#::expression-subst*::t '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj226981
                       _%subst226907%_
                       '1
                       '#f
                       '#f))
                    __obj226981))
                 (__tmp227000
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self226909%_ _%stx226904%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp227000
             gxc#current-compile-method
             _%self226909%_)))))
    (define gxc#apply-expression-subst*__@
      (lambda (_%@@keywords226916%_ . _%args226917%_)
        (apply gxc#apply-expression-subst*__%
               _%@@keywords226916%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords226916%_
                  'subst:
                  absent-value))
               _%args226917%_)))
    (define gxc#apply-expression-subst*
      (lambda _%$%args226900226923%_
        (apply keyword-dispatch
               '#(subst:)
               gxc#apply-expression-subst*__@
               _%$%args226900226923%_)))
    (define gxc#::inline-subst::t
      (let ((__tmp227002 (list gxc#::basic-xform-expression::t))
            (__tmp227001 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::inline-subst::t
         '::inline-subst
         __tmp227002
         '(subst)
         __tmp227001
         '#f)))
    (define gxc#::inline-subst?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::inline-subst::t)))
    (define gxc#make-::inline-subst
      (lambda _%$args226895%_
        (apply make-instance gxc#::inline-subst::t _%$args226895%_)))
    (define gxc#::inline-subst-subst
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::inline-subst::t 'subst)))
    (define gxc#::inline-subst-subst-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::inline-subst::t 'subst)))
    (define gxc#&::inline-subst-subst
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#::inline-subst::t 'subst)))
    (define gxc#&::inline-subst-subst-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#::inline-subst::t 'subst)))
    (define gxc#::inline-subst-bind-methods!
      (let ((__tmp227003
             (lambda ()
               (force gxc#::basic-xform-expression-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::inline-subst::t
                  '%#begin
                  gxc#xform-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::inline-subst::t
                  '%#ref
                  gxc#inline-subst-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::inline-subst::t
                  '%#set!
                  gxc#inline-subst-setq%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::inline-subst::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp227003)))
    (define gxc#apply-inline-subst__%
      (lambda (_%@@keywords226870%_ _%$%subst226867226871%_ _%stx226872%_)
        (let ((_%subst226875%_
               (if (eq? _%$%subst226867226871%_ absent-value)
                   (let ()
                     (declare (not safe))
                     (error '"Missing required keyword argument" 'subst:))
                   _%$%subst226867226871%_)))
          (force gxc#::inline-subst-bind-methods!)
          (let* ((_%self226877%_
                  (let ((__obj226983
                         (let ()
                           (declare (not safe))
                           (##structure gxc#::inline-subst::t '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj226983
                       _%subst226875%_
                       '1
                       '#f
                       '#f))
                    __obj226983))
                 (__tmp227004
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self226877%_ _%stx226872%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp227004
             gxc#current-compile-method
             _%self226877%_)))))
    (define gxc#apply-inline-subst__@
      (lambda (_%@@keywords226884%_ . _%args226885%_)
        (apply gxc#apply-inline-subst__%
               _%@@keywords226884%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords226884%_
                  'subst:
                  absent-value))
               _%args226885%_)))
    (define gxc#apply-inline-subst
      (lambda _%$%args226868226891%_
        (apply keyword-dispatch
               '#(subst:)
               gxc#apply-inline-subst__@
               _%$%args226868226891%_)))
    (define gxc#::find-expression::t
      (let ((__tmp227005 (list gxc#::false-expression::t)))
        (declare (not safe))
        (make-class-type
         'gxc#::find-expression::t
         '::find-expression
         __tmp227005
         '()
         '()
         '#f)))
    (define gxc#::find-expression?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::find-expression::t)))
    (define gxc#make-::find-expression
      (lambda _%$args226863%_
        (apply make-instance gxc#::find-expression::t _%$args226863%_)))
    (define gxc#::find-expression-bind-methods!
      (let ((__tmp227006
             (lambda ()
               (force gxc#::false-expression-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#begin
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#begin-annotation
                  gxc#apply-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#lambda
                  gxc#apply-body-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#case-lambda
                  gxc#apply-body-case-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#let-values
                  gxc#find-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#letrec-values
                  gxc#find-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#letrec*-values
                  gxc#find-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#call
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#call-unchecked
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#if
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#set!
                  gxc#apply-body-setq%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#struct-instance?
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#struct-direct-instance?
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#struct-ref
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#struct-set!
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#struct-direct-ref
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#struct-direct-set!
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#struct-unchecked-ref
                  gxc#find-body%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-expression::t
                  '%#struct-unchecked-set!
                  gxc#find-body%)))))
        (declare (not safe))
        (__make-atomic-promise __tmp227006)))
    (define gxc#::find-var-refs::t
      (let ((__tmp227008 (list gxc#::find-expression::t))
            (__tmp227007 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::find-var-refs::t
         '::find-var-refs
         __tmp227008
         '(ids)
         __tmp227007
         '#f)))
    (define gxc#::find-var-refs?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::find-var-refs::t)))
    (define gxc#make-::find-var-refs
      (lambda _%$args226859%_
        (apply make-instance gxc#::find-var-refs::t _%$args226859%_)))
    (define gxc#::find-var-refs-ids
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::find-var-refs::t 'ids)))
    (define gxc#::find-var-refs-ids-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::find-var-refs::t 'ids)))
    (define gxc#&::find-var-refs-ids
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#::find-var-refs::t 'ids)))
    (define gxc#&::find-var-refs-ids-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#::find-var-refs::t 'ids)))
    (define gxc#::find-var-refs-bind-methods!
      (let ((__tmp227009
             (lambda ()
               (force gxc#::find-expression-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-var-refs::t
                  '%#ref
                  gxc#find-var-refs-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::find-var-refs::t
                  '%#set!
                  gxc#find-var-refs-setq%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::find-var-refs::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp227009)))
    (define gxc#apply-find-var-refs__%
      (lambda (_%@@keywords226834%_ _%$%ids226831226835%_ _%stx226836%_)
        (let ((_%ids226839%_
               (if (eq? _%$%ids226831226835%_ absent-value)
                   (let ()
                     (declare (not safe))
                     (error '"Missing required keyword argument" 'ids:))
                   _%$%ids226831226835%_)))
          (force gxc#::find-var-refs-bind-methods!)
          (let* ((_%self226841%_
                  (let ((__obj226986
                         (let ()
                           (declare (not safe))
                           (##structure gxc#::find-var-refs::t '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj226986
                       _%ids226839%_
                       '1
                       '#f
                       '#f))
                    __obj226986))
                 (__tmp227010
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self226841%_ _%stx226836%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp227010
             gxc#current-compile-method
             _%self226841%_)))))
    (define gxc#apply-find-var-refs__@
      (lambda (_%@@keywords226848%_ . _%args226849%_)
        (apply gxc#apply-find-var-refs__%
               _%@@keywords226848%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref _%@@keywords226848%_ 'ids: absent-value))
               _%args226849%_)))
    (define gxc#apply-find-var-refs
      (lambda _%$%args226832226855%_
        (apply keyword-dispatch
               '#(ids:)
               gxc#apply-find-var-refs__@
               _%$%args226832226855%_)))
    (define gxc#::collect-runtime-refs::t
      (let ((__tmp227012 (list gxc#::collect-expression-refs::t))
            (__tmp227011 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::collect-runtime-refs::t
         '::collect-runtime-refs
         __tmp227012
         '()
         __tmp227011
         '#f)))
    (define gxc#::collect-runtime-refs?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::collect-runtime-refs::t)))
    (define gxc#make-::collect-runtime-refs
      (lambda _%$args226827%_
        (apply make-instance gxc#::collect-runtime-refs::t _%$args226827%_)))
    (define gxc#::collect-runtime-refs-table
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::collect-runtime-refs::t 'table)))
    (define gxc#::collect-runtime-refs-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::collect-runtime-refs::t 'table)))
    (define gxc#&::collect-runtime-refs-table
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::collect-runtime-refs::t
         'table)))
    (define gxc#&::collect-runtime-refs-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::collect-runtime-refs::t
         'table)))
    (define gxc#::collect-runtime-refs-bind-methods!
      (let ((__tmp227013
             (lambda ()
               (force gxc#::collect-expression-refs-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-runtime-refs::t
                  '%#ref
                  gxc#collect-runtime-refs-ref%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-runtime-refs::t
                  '%#set!
                  gxc#collect-runtime-refs-setq%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::collect-runtime-refs::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp227013)))
    (define gxc#apply-collect-runtime-refs__%
      (lambda (_%@@keywords226802%_ _%$%table226799226803%_ _%stx226804%_)
        (let ((_%table226807%_
               (if (eq? _%$%table226799226803%_ absent-value)
                   (let ()
                     (declare (not safe))
                     (error '"Missing required keyword argument" 'table:))
                   _%$%table226799226803%_)))
          (force gxc#::collect-runtime-refs-bind-methods!)
          (let* ((_%self226809%_
                  (let ((__obj226988
                         (let ()
                           (declare (not safe))
                           (##structure gxc#::collect-runtime-refs::t '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj226988
                       _%table226807%_
                       '1
                       '#f
                       '#f))
                    __obj226988))
                 (__tmp227014
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self226809%_ _%stx226804%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp227014
             gxc#current-compile-method
             _%self226809%_)))))
    (define gxc#apply-collect-runtime-refs__@
      (lambda (_%@@keywords226816%_ . _%args226817%_)
        (apply gxc#apply-collect-runtime-refs__%
               _%@@keywords226816%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords226816%_
                  'table:
                  absent-value))
               _%args226817%_)))
    (define gxc#apply-collect-runtime-refs
      (lambda _%$%args226800226823%_
        (apply keyword-dispatch
               '#(table:)
               gxc#apply-collect-runtime-refs__@
               _%$%args226800226823%_)))
    (define gxc#collect-mutators-setq%
      (lambda (_%self226728%_ _%stx226729%_)
        (let* ((_%$%g226731226748%_
                (lambda (_%$%g226732226745%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226732226745%_))))
               (_%$%g226730226795%_
                (lambda (_%$%g226732226751%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226732226751%_))
                      (let ((_%$%e226735226753%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226732226751%_))))
                        (let ((_%$%hd226736226756%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226735226753%_)))
                              (_%$%tl226737226758%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226735226753%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226737226758%_))
                              (let ((_%$%e226738226761%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226737226758%_))))
                                (let ((_%$%hd226739226764%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226738226761%_)))
                                      (_%$%tl226740226766%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226738226761%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl226740226766%_))
                                      (let ((_%$%e226741226769%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl226740226766%_))))
                                        (let ((_%$%hd226742226772%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e226741226769%_)))
                                              (_%$%tl226743226774%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e226741226769%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl226743226774%_))
                                              (let ((_%sym226793%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gxc#identifier-symbol
                                                        _%$%hd226739226764%_))))
                                                (let ()
                                                  (declare (not safe))
                                                  (gxc#verbose
                                                   '"collect mutator "
                                                   _%sym226793%_))
                                                (let ((__tmp227015
                                                       (let ()
                                                         (declare (not safe))
                                                         (gxc#current-compile-mutators))))
                                                  (declare (not safe))
                                                  (hash-put!
                                                   __tmp227015
                                                   _%sym226793%_
                                                   '#t))
                                                (let ()
                                                  (declare (not safe))
                                                  (gxc#compile-e__1
                                                   _%self226728%_
                                                   _%$%hd226742226772%_)))
                                              (_%$%g226731226748%_
                                               _%$%g226732226751%_))))
                                      (_%$%g226731226748%_
                                       _%$%g226732226751%_))))
                              (_%$%g226731226748%_ _%$%g226732226751%_))))
                      (_%$%g226731226748%_ _%$%g226732226751%_)))))
          (_%$%g226730226795%_ _%stx226729%_))))
    (define gxc#expression-subst-ref%
      (lambda (_%self226676%_ _%stx226677%_)
        (let* ((_%$%g226679226692%_
                (lambda (_%$%g226680226689%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226680226689%_))))
               (_%$%g226678226725%_
                (lambda (_%$%g226680226695%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226680226695%_))
                      (let ((_%$%e226682226697%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226680226695%_))))
                        (let ((_%$%hd226683226700%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226682226697%_)))
                              (_%$%tl226684226702%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226682226697%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226684226702%_))
                              (let ((_%$%e226685226705%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226684226702%_))))
                                (let ((_%$%hd226686226708%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226685226705%_)))
                                      (_%$%tl226687226710%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226685226705%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl226687226710%_))
                                      (if (let ((__tmp227016
                                                 (let ()
                                                   (declare (not safe))
                                                   (slot-ref__0
                                                    _%self226676%_
                                                    'id))))
                                            (declare (not safe))
                                            (gx#free-identifier=?
                                             _%$%hd226686226708%_
                                             __tmp227016))
                                          (let ((__tmp227017
                                                 (cons '%#ref
                                                       (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (slot-ref__0 _%self226676%_ 'new-id))
                     '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (declare (not safe))
                                            (gxc#xform-wrap-source
                                             __tmp227017
                                             _%stx226677%_))
                                          _%stx226677%_)
                                      (_%$%g226679226692%_
                                       _%$%g226680226695%_))))
                              (_%$%g226679226692%_ _%$%g226680226695%_))))
                      (_%$%g226679226692%_ _%$%g226680226695%_)))))
          (_%$%g226678226725%_ _%stx226677%_))))
    (define gxc#expression-subst*-ref%
      (lambda (_%self226616%_ _%stx226617%_)
        (let* ((_%$%g226619226632%_
                (lambda (_%$%g226620226629%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226620226629%_))))
               (_%$%g226618226673%_
                (lambda (_%$%g226620226635%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226620226635%_))
                      (let ((_%$%e226622226637%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226620226635%_))))
                        (let ((_%$%hd226623226640%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226622226637%_)))
                              (_%$%tl226624226642%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226622226637%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226624226642%_))
                              (let ((_%$%e226625226645%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226624226642%_))))
                                (let ((_%$%hd226626226648%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226625226645%_)))
                                      (_%$%tl226627226650%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226625226645%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl226627226650%_))
                                      (let ((_%$e226667%_
                                             (let ((__tmp227019
                                                    (lambda (_%sub226665%_)
                                                      (let ((__tmp227020
                                                             (car _%sub226665%_)))
                                                        (declare (not safe))
                                                        (gx#free-identifier=?
                                                         _%$%hd226626226648%_
                                                         __tmp227020))))
                                                   (__tmp227018
                                                    (let ()
                                                      (declare (not safe))
                                                      (slot-ref__0
                                                       _%self226616%_
                                                       'subst))))
                                               (declare (not safe))
                                               (__find __tmp227019
                                                       __tmp227018))))
                                        (if _%$e226667%_
                                            (let ((__tmp227021
                                                   (cons '%#ref
                                                         (cons (cdr _%$e226667%_)
                                                               '()))))
                                              (declare (not safe))
                                              (gxc#xform-wrap-source
                                               __tmp227021
                                               _%stx226617%_))
                                            _%stx226617%_))
                                      (_%$%g226619226632%_
                                       _%$%g226620226635%_))))
                              (_%$%g226619226632%_ _%$%g226620226635%_))))
                      (_%$%g226619226632%_ _%$%g226620226635%_)))))
          (_%$%g226618226673%_ _%stx226617%_))))
    (define gxc#expression-subst-setq%
      (lambda (_%self226545%_ _%stx226546%_)
        (let* ((_%$%g226548226565%_
                (lambda (_%$%g226549226562%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226549226562%_))))
               (_%$%g226547226613%_
                (lambda (_%$%g226549226568%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226549226568%_))
                      (let ((_%$%e226552226570%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226549226568%_))))
                        (let ((_%$%hd226553226573%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226552226570%_)))
                              (_%$%tl226554226575%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226552226570%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226554226575%_))
                              (let ((_%$%e226555226578%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226554226575%_))))
                                (let ((_%$%hd226556226581%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226555226578%_)))
                                      (_%$%tl226557226583%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226555226578%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl226557226583%_))
                                      (let ((_%$%e226558226586%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl226557226583%_))))
                                        (let ((_%$%hd226559226589%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e226558226586%_)))
                                              (_%$%tl226560226591%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e226558226586%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl226560226591%_))
                                              (let ((_%new-expr226610%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gxc#compile-e__1
                                                        _%self226545%_
                                                        _%$%hd226559226589%_)))
                                                    (_%new-xid226611%_
                                                     (if (let ((__tmp227022
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (slot-ref__0 _%self226545%_ 'id))))
                   (declare (not safe))
                   (gx#free-identifier=? _%$%hd226556226581%_ __tmp227022))
                 (let ()
                   (declare (not safe))
                   (slot-ref__0 _%self226545%_ 'new-id))
                 _%$%hd226556226581%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (let ((__tmp227023
                                                       (cons '%#set!
                                                             (cons _%new-xid226611%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons _%new-expr226610%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (gxc#xform-wrap-source
                                                   __tmp227023
                                                   _%stx226546%_)))
                                              (_%$%g226548226565%_
                                               _%$%g226549226568%_))))
                                      (_%$%g226548226565%_
                                       _%$%g226549226568%_))))
                              (_%$%g226548226565%_ _%$%g226549226568%_))))
                      (_%$%g226548226565%_ _%$%g226549226568%_)))))
          (_%$%g226547226613%_ _%stx226546%_))))
    (define gxc#expression-subst*-setq%
      (lambda (_%self226468%_ _%stx226469%_)
        (let* ((_%$%g226471226488%_
                (lambda (_%$%g226472226485%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226472226485%_))))
               (_%$%g226470226542%_
                (lambda (_%$%g226472226491%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226472226491%_))
                      (let ((_%$%e226475226493%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226472226491%_))))
                        (let ((_%$%hd226476226496%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226475226493%_)))
                              (_%$%tl226477226498%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226475226493%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226477226498%_))
                              (let ((_%$%e226478226501%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226477226498%_))))
                                (let ((_%$%hd226479226504%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226478226501%_)))
                                      (_%$%tl226480226506%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226478226501%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl226480226506%_))
                                      (let ((_%$%e226481226509%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl226480226506%_))))
                                        (let ((_%$%hd226482226512%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e226481226509%_)))
                                              (_%$%tl226483226514%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e226481226509%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl226483226514%_))
                                              (let ((_%new-expr226539%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gxc#compile-e__1
                                                        _%self226468%_
                                                        _%$%hd226482226512%_)))
                                                    (_%new-xid226540%_
                                                     (let ((_%$e226535%_
                                                            (let ((__tmp227025
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (lambda (_%sub226533%_)
                             (let ((__tmp227026 (car _%sub226533%_)))
                               (declare (not safe))
                               (gx#free-identifier=?
                                _%$%hd226479226504%_
                                __tmp227026))))
                          (__tmp227024
                           (let ()
                             (declare (not safe))
                             (slot-ref__0 _%self226468%_ 'subst))))
                      (declare (not safe))
                      (__find __tmp227025 __tmp227024))))
               (if _%$e226535%_ (cdr _%$e226535%_) _%$%hd226479226504%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (let ((__tmp227027
                                                       (cons '%#set!
                                                             (cons _%new-xid226540%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons _%new-expr226539%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (declare (not safe))
                                                  (gxc#xform-wrap-source
                                                   __tmp227027
                                                   _%stx226469%_)))
                                              (_%$%g226471226488%_
                                               _%$%g226472226491%_))))
                                      (_%$%g226471226488%_
                                       _%$%g226472226491%_))))
                              (_%$%g226471226488%_ _%$%g226472226491%_))))
                      (_%$%g226471226488%_ _%$%g226472226491%_)))))
          (_%$%g226470226542%_ _%stx226469%_))))
    (define gxc#inline-subst-ref%
      (lambda (_%self226408%_ _%stx226409%_)
        (let* ((_%$%g226411226424%_
                (lambda (_%$%g226412226421%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226412226421%_))))
               (_%$%g226410226465%_
                (lambda (_%$%g226412226427%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226412226427%_))
                      (let ((_%$%e226414226429%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226412226427%_))))
                        (let ((_%$%hd226415226432%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226414226429%_)))
                              (_%$%tl226416226434%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226414226429%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226416226434%_))
                              (let ((_%$%e226417226437%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226416226434%_))))
                                (let ((_%$%hd226418226440%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226417226437%_)))
                                      (_%$%tl226419226442%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226417226437%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl226419226442%_))
                                      (let ((_%$e226459%_
                                             (let ((__tmp227029
                                                    (lambda (_%sub226457%_)
                                                      (let ((__tmp227030
                                                             (car _%sub226457%_)))
                                                        (declare (not safe))
                                                        (gx#free-identifier=?
                                                         _%$%hd226418226440%_
                                                         __tmp227030))))
                                                   (__tmp227028
                                                    (let ()
                                                      (declare (not safe))
                                                      (slot-ref__0
                                                       _%self226408%_
                                                       'subst))))
                                               (declare (not safe))
                                               (__find __tmp227029
                                                       __tmp227028))))
                                        (if _%$e226459%_
                                            (let ((__tmp227031
                                                   (cdr _%$e226459%_)))
                                              (declare (not safe))
                                              (gxc#xform-wrap-source
                                               __tmp227031
                                               _%stx226409%_))
                                            _%stx226409%_))
                                      (_%$%g226411226424%_
                                       _%$%g226412226427%_))))
                              (_%$%g226411226424%_ _%$%g226412226427%_))))
                      (_%$%g226411226424%_ _%$%g226412226427%_)))))
          (_%$%g226410226465%_ _%stx226409%_))))
    (define gxc#inline-subst-setq%
      (lambda (_%self226338%_ _%stx226339%_)
        (let* ((_%$%g226341226358%_
                (lambda (_%$%g226342226355%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226342226355%_))))
               (_%$%g226340226405%_
                (lambda (_%$%g226342226361%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226342226361%_))
                      (let ((_%$%e226345226363%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226342226361%_))))
                        (let ((_%$%hd226346226366%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226345226363%_)))
                              (_%$%tl226347226368%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226345226363%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226347226368%_))
                              (let ((_%$%e226348226371%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226347226368%_))))
                                (let ((_%$%hd226349226374%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226348226371%_)))
                                      (_%$%tl226350226376%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226348226371%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl226350226376%_))
                                      (let ((_%$%e226351226379%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl226350226376%_))))
                                        (let ((_%$%hd226352226382%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e226351226379%_)))
                                              (_%$%tl226353226384%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e226351226379%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl226353226384%_))
                                              (if (let ((__tmp227033
                                                         (lambda (_%sub226403%_)
                                                           (let ((__tmp227034
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (car _%sub226403%_)))
                     (declare (not safe))
                     (gx#free-identifier=? _%$%hd226349226374%_ __tmp227034))))
                (__tmp227032
                 (let ()
                   (declare (not safe))
                   (slot-ref__0 _%self226338%_ 'subst))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (__find __tmp227033
                                                            __tmp227032))
                                                  (let ()
                                                    (declare (not safe))
                                                    (gxc#raise-compile-error
                                                     '"mutating inline substitution"
                                                     _%stx226339%_
                                                     _%$%hd226349226374%_))
                                                  (let ((__tmp227035
                                                         (cons '%#set!
                                                               (cons _%$%hd226349226374%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (cons (let ()
                                     (declare (not safe))
                                     (gxc#compile-e__1
                                      _%self226338%_
                                      _%$%hd226352226382%_))
                                   '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (gxc#xform-wrap-source
                                                     __tmp227035
                                                     _%stx226339%_)))
                                              (_%$%g226341226358%_
                                               _%$%g226342226361%_))))
                                      (_%$%g226341226358%_
                                       _%$%g226342226361%_))))
                              (_%$%g226341226358%_ _%$%g226342226361%_))))
                      (_%$%g226341226358%_ _%$%g226342226361%_)))))
          (_%$%g226340226405%_ _%stx226339%_))))
    (define gxc#collect-runtime-refs-ref%
      (lambda (_%self226284%_ _%stx226285%_)
        (let* ((_%$%g226287226300%_
                (lambda (_%$%g226288226297%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226288226297%_))))
               (_%$%g226286226335%_
                (lambda (_%$%g226288226303%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226288226303%_))
                      (let ((_%$%e226290226305%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226288226303%_))))
                        (let ((_%$%hd226291226308%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226290226305%_)))
                              (_%$%tl226292226310%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226290226305%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226292226310%_))
                              (let ((_%$%e226293226313%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226292226310%_))))
                                (let ((_%$%hd226294226316%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226293226313%_)))
                                      (_%$%tl226295226318%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226293226313%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl226295226318%_))
                                      (let* ((_%eid226333%_
                                              (let ()
                                                (declare (not safe))
                                                (gxc#identifier-symbol
                                                 _%$%hd226294226316%_)))
                                             (__tmp227036
                                              (let ()
                                                (declare (not safe))
                                                (slot-ref__0
                                                 _%self226284%_
                                                 'table))))
                                        (declare (not safe))
                                        (hash-update!__%
                                         __tmp227036
                                         _%eid226333%_
                                         1+
                                         '0))
                                      (_%$%g226287226300%_
                                       _%$%g226288226303%_))))
                              (_%$%g226287226300%_ _%$%g226288226303%_))))
                      (_%$%g226287226300%_ _%$%g226288226303%_)))))
          (_%$%g226286226335%_ _%stx226285%_))))
    (define gxc#collect-runtime-refs-setq%
      (lambda (_%self226214%_ _%stx226215%_)
        (let* ((_%$%g226217226234%_
                (lambda (_%$%g226218226231%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226218226231%_))))
               (_%$%g226216226281%_
                (lambda (_%$%g226218226237%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226218226237%_))
                      (let ((_%$%e226221226239%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226218226237%_))))
                        (let ((_%$%hd226222226242%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226221226239%_)))
                              (_%$%tl226223226244%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226221226239%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl226223226244%_))
                              (let ((_%$%e226224226247%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl226223226244%_))))
                                (let ((_%$%hd226225226250%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226224226247%_)))
                                      (_%$%tl226226226252%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226224226247%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl226226226252%_))
                                      (let ((_%$%e226227226255%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl226226226252%_))))
                                        (let ((_%$%hd226228226258%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e226227226255%_)))
                                              (_%$%tl226229226260%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e226227226255%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl226229226260%_))
                                              (let ((_%eid226279%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gxc#identifier-symbol
                                                        _%$%hd226225226250%_))))
                                                (let ((__tmp227037
                                                       (let ()
                                                         (declare (not safe))
                                                         (slot-ref__0
                                                          _%self226214%_
                                                          'table))))
                                                  (declare (not safe))
                                                  (hash-update!__%
                                                   __tmp227037
                                                   _%eid226279%_
                                                   1+
                                                   '0))
                                                (let ()
                                                  (declare (not safe))
                                                  (gxc#compile-e__1
                                                   _%self226214%_
                                                   _%$%hd226228226258%_)))
                                              (_%$%g226217226234%_
                                               _%$%g226218226237%_))))
                                      (_%$%g226217226234%_
                                       _%$%g226218226237%_))))
                              (_%$%g226217226234%_ _%$%g226218226237%_))))
                      (_%$%g226217226234%_ _%$%g226218226237%_)))))
          (_%$%g226216226281%_ _%stx226215%_))))
    (define gxc#find-body%
      (lambda (_%self226129%_ _%stx226130%_)
        (let* ((_%$%g226132226151%_
                (lambda (_%$%g226133226148%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g226133226148%_))))
               (_%$%g226131226211%_
                (lambda (_%$%g226133226154%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g226133226154%_))
                      (let ((_%$%e226135226156%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g226133226154%_))))
                        (let ((_%$%hd226136226159%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e226135226156%_)))
                              (_%$%tl226137226161%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e226135226156%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair/null? _%$%tl226137226161%_))
                              (let ((_g227038_
                                     (let ()
                                       (declare (not safe))
                                       (gx#syntax-split-splice
                                        _%$%tl226137226161%_
                                        '0))))
                                (begin
                                  (let ((_g227039_
                                         (let ()
                                           (declare (not safe))
                                           (if (##values? _g227038_)
                                               (##values-length _g227038_)
                                               1))))
                                    (if (not (let ()
                                               (declare (not safe))
                                               (##fx= _g227039_ 2)))
                                        (error "Context expects 2 values"
                                               _g227039_)))
                                  (let ((_%$%target226138226164%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g227038_ 0)))
                                        (_%$%tl226140226166%_
                                         (let ()
                                           (declare (not safe))
                                           (##values-ref _g227038_ 1))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl226140226166%_))
                                        (letrec ((_%$%loop226141226169%_
                                                  (lambda (_%$%hd226139226172%_
                                                           _%$%expr226145226174%_)
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair?
                                                           _%$%hd226139226172%_))
                                                        (let ((_%$%e226142226176%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-e _%$%hd226139226172%_))))
                  (let ((_%$%lp-hd226143226179%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e226142226176%_)))
                        (_%$%lp-tl226144226181%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e226142226176%_))))
                    (_%$%loop226141226169%_
                     _%$%lp-tl226144226181%_
                     (cons _%$%lp-hd226143226179%_ _%$%expr226145226174%_))))
                (let ((_%$%expr226146226184%_
                       (reverse _%$%expr226145226174%_)))
                  (let ((__tmp227042
                         (lambda (_%$%g226199226201%_)
                           (let ()
                             (declare (not safe))
                             (gxc#compile-e__1
                              _%self226129%_
                              _%$%g226199226201%_))))
                        (__tmp227040
                         (let ((__tmp227041
                                (lambda (_%$%g226203226206%_
                                         _%$%g226204226208%_)
                                  (cons _%$%g226203226206%_
                                        _%$%g226204226208%_))))
                           (declare (not safe))
                           (foldr__0 __tmp227041 '() _%$%expr226146226184%_))))
                    (declare (not safe))
                    (ormap__0 __tmp227042 __tmp227040)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                          (_%$%loop226141226169%_
                                           _%$%target226138226164%_
                                           '()))
                                        (_%$%g226132226151%_
                                         _%$%g226133226154%_)))))
                              (_%$%g226132226151%_ _%$%g226133226154%_))))
                      (_%$%g226132226151%_ _%$%g226133226154%_)))))
          (_%$%g226131226211%_ _%stx226130%_))))
    (define gxc#find-let-values%
      (lambda (_%self225983%_ _%stx225984%_)
        (let* ((_%$%g225986226021%_
                (lambda (_%$%g225987226018%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g225987226018%_))))
               (_%$%g225985226126%_
                (lambda (_%$%g225987226024%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g225987226024%_))
                      (let ((_%$%e225991226026%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g225987226024%_))))
                        (let ((_%$%hd225992226029%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e225991226026%_)))
                              (_%$%tl225993226031%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e225991226026%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl225993226031%_))
                              (let ((_%$%e225994226034%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl225993226031%_))))
                                (let ((_%$%hd225995226037%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e225994226034%_)))
                                      (_%$%tl225996226039%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e225994226034%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%hd225995226037%_))
                                      (let ((_g227043_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice
                                                _%$%hd225995226037%_
                                                '0))))
                                        (begin
                                          (let ((_g227044_
                                                 (let ()
                                                   (declare (not safe))
                                                   (if (##values? _g227043_)
                                                       (##values-length
                                                        _g227043_)
                                                       1))))
                                            (if (not (let ()
                                                       (declare (not safe))
                                                       (##fx= _g227044_ 2)))
                                                (error "Context expects 2 values"
                                                       _g227044_)))
                                          (let ((_%$%target225997226042%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref _g227043_ 0)))
                                                (_%$%tl225999226044%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##values-ref
                                                    _g227043_
                                                    1))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl225999226044%_))
                                                (letrec ((_%$%loop226000226047%_
                                                          (lambda (_%$%hd225998226050%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%expr226004226052%_
                           _%$%bind226005226053%_)
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%hd225998226050%_))
                        (let ((_%$%e226001226055%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%hd225998226050%_))))
                          (let ((_%$%lp-hd226002226058%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e226001226055%_)))
                                (_%$%lp-tl226003226060%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e226001226055%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%lp-hd226002226058%_))
                                (let ((_%$%e226008226063%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%lp-hd226002226058%_))))
                                  (let ((_%$%hd226009226066%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e226008226063%_)))
                                        (_%$%tl226010226068%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e226008226063%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%tl226010226068%_))
                                        (let ((_%$%e226011226071%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%tl226010226068%_))))
                                          (let ((_%$%hd226012226074%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e226011226071%_)))
                                                (_%$%tl226013226076%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e226011226071%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl226013226076%_))
                                                (_%$%loop226000226047%_
                                                 _%$%lp-tl226003226060%_
                                                 (cons _%$%hd226012226074%_
                                                       _%$%expr226004226052%_)
                                                 (cons _%$%hd226009226066%_
                                                       _%$%bind226005226053%_))
                                                (_%$%g225986226021%_
                                                 _%$%g225987226024%_))))
                                        (_%$%g225986226021%_
                                         _%$%g225987226024%_))))
                                (_%$%g225986226021%_ _%$%g225987226024%_))))
                        (let ((_%$%expr226006226079%_
                               (reverse _%$%expr226004226052%_))
                              (_%$%bind226007226080%_
                               (reverse _%$%bind226005226053%_)))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl225996226039%_))
                              (let ((_%$%e226014226082%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl225996226039%_))))
                                (let ((_%$%hd226015226085%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e226014226082%_)))
                                      (_%$%tl226016226087%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e226014226082%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl226016226087%_))
                                      (let ((_%$e226123%_
                                             (let ((__tmp227047
                                                    (lambda (_%$%g226111226113%_)
                                                      (let ()
                                                        (declare (not safe))
                                                        (gxc#compile-e__1
                                                         _%self225983%_
                                                         _%$%g226111226113%_))))
                                                   (__tmp227045
                                                    (let ((__tmp227046
                                                           (lambda (_%$%g226115226118%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%g226116226120%_)
                     (cons _%$%g226115226118%_ _%$%g226116226120%_))))
              (declare (not safe))
              (foldr__0 __tmp227046 '() _%$%expr226006226079%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (declare (not safe))
                                               (ormap__0
                                                __tmp227047
                                                __tmp227045))))
                                        (if _%$e226123%_
                                            _%$e226123%_
                                            (let ()
                                              (declare (not safe))
                                              (gxc#compile-e__1
                                               _%self225983%_
                                               _%$%hd226015226085%_))))
                                      (_%$%g225986226021%_
                                       _%$%g225987226024%_))))
                              (_%$%g225986226021%_ _%$%g225987226024%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%$%loop226000226047%_
                                                   _%$%target225997226042%_
                                                   '()
                                                   '()))
                                                (_%$%g225986226021%_
                                                 _%$%g225987226024%_)))))
                                      (_%$%g225986226021%_
                                       _%$%g225987226024%_))))
                              (_%$%g225986226021%_ _%$%g225987226024%_))))
                      (_%$%g225986226021%_ _%$%g225987226024%_)))))
          (_%$%g225985226126%_ _%stx225984%_))))
    (define gxc#find-var-refs-ref%
      (lambda (_%self225927%_ _%stx225928%_)
        (let* ((_%$%g225930225943%_
                (lambda (_%$%g225931225940%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g225931225940%_))))
               (_%$%g225929225980%_
                (lambda (_%$%g225931225946%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g225931225946%_))
                      (let ((_%$%e225933225948%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g225931225946%_))))
                        (let ((_%$%hd225934225951%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e225933225948%_)))
                              (_%$%tl225935225953%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e225933225948%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl225935225953%_))
                              (let ((_%$%e225936225956%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl225935225953%_))))
                                (let ((_%$%hd225937225959%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e225936225956%_)))
                                      (_%$%tl225938225961%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e225936225956%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl225938225961%_))
                                      (let ((__tmp227049
                                             (lambda (_%$%g225975225977%_)
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#free-identifier=?
                                                  _%$%hd225937225959%_
                                                  _%$%g225975225977%_))))
                                            (__tmp227048
                                             (let ()
                                               (declare (not safe))
                                               (slot-ref__0
                                                _%self225927%_
                                                'ids))))
                                        (declare (not safe))
                                        (__find __tmp227049 __tmp227048))
                                      (_%$%g225930225943%_
                                       _%$%g225931225946%_))))
                              (_%$%g225930225943%_ _%$%g225931225946%_))))
                      (_%$%g225930225943%_ _%$%g225931225946%_)))))
          (_%$%g225929225980%_ _%stx225928%_))))
    (define gxc#find-var-refs-setq%
      (lambda (_%self225852%_ _%stx225853%_)
        (let* ((_%$%g225855225872%_
                (lambda (_%$%g225856225869%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g225856225869%_))))
               (_%$%g225854225924%_
                (lambda (_%$%g225856225875%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g225856225875%_))
                      (let ((_%$%e225859225877%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g225856225875%_))))
                        (let ((_%$%hd225860225880%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e225859225877%_)))
                              (_%$%tl225861225882%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e225859225877%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl225861225882%_))
                              (let ((_%$%e225862225885%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl225861225882%_))))
                                (let ((_%$%hd225863225888%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e225862225885%_)))
                                      (_%$%tl225864225890%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e225862225885%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl225864225890%_))
                                      (let ((_%$%e225865225893%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl225864225890%_))))
                                        (let ((_%$%hd225866225896%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e225865225893%_)))
                                              (_%$%tl225867225898%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e225865225893%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl225867225898%_))
                                              (let ((_%$e225921%_
                                                     (let ((__tmp227051
                                                            (lambda (_%$%g225916225918%_)
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#free-identifier=?
                         _%$%hd225863225888%_
                         _%$%g225916225918%_))))
                   (__tmp227050
                    (let ()
                      (declare (not safe))
                      (slot-ref__0 _%self225852%_ 'ids))))
               (declare (not safe))
               (__find __tmp227051 __tmp227050))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if _%$e225921%_
                                                    _%$e225921%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gxc#compile-e__1
                                                       _%self225852%_
                                                       _%$%hd225866225896%_))))
                                              (_%$%g225855225872%_
                                               _%$%g225856225875%_))))
                                      (_%$%g225855225872%_
                                       _%$%g225856225875%_))))
                              (_%$%g225855225872%_ _%$%g225856225875%_))))
                      (_%$%g225855225872%_ _%$%g225856225875%_)))))
          (_%$%g225854225924%_ _%stx225853%_))))))
