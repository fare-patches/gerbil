(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/optimize-spec::timestamp 1795039821)
  (begin
    (define gxc#::generate-method-specializers::t
      (let ((__tmp250389 (list gxc#::identity::t))
            (__tmp250388 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::generate-method-specializers::t
         '::generate-method-specializers
         __tmp250389
         '()
         __tmp250388
         '#f)))
    (define gxc#::generate-method-specializers?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::generate-method-specializers::t)))
    (define gxc#make-::generate-method-specializers
      (lambda _%$args249186%_
        (apply make-instance
               gxc#::generate-method-specializers::t
               _%$args249186%_)))
    (define gxc#::generate-method-specializers-bind-methods!
      (let ((__tmp250390
             (lambda ()
               (force gxc#::identity-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-method-specializers::t
                  '%#begin
                  gxc#xform-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-method-specializers::t
                  '%#begin-syntax
                  gxc#xform-begin-syntax%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-method-specializers::t
                  '%#module
                  gxc#xform-module%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::generate-method-specializers::t
                  '%#define-values
                  gxc#generate-method-specializers-define-values%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::generate-method-specializers::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp250390)))
    (define gxc#apply-generate-method-specializers
      (lambda (_%stx249178%_)
        (force gxc#::generate-method-specializers-bind-methods!)
        (let* ((_%self249181%_
                (let ((__obj250381
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::generate-method-specializers::t))))
                  __obj250381))
               (__tmp250391
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self249181%_ _%stx249178%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp250391
           gxc#current-compile-method
           _%self249181%_))))
    (define gxc#::extract-receiver::t
      (let ((__tmp250393 (list gxc#::false::t))
            (__tmp250392 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::extract-receiver::t
         '::extract-receiver
         __tmp250393
         '()
         __tmp250392
         '#f)))
    (define gxc#::extract-receiver?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::extract-receiver::t)))
    (define gxc#make-::extract-receiver
      (lambda _%$args249175%_
        (apply make-instance gxc#::extract-receiver::t _%$args249175%_)))
    (define gxc#::extract-receiver-bind-methods!
      (let ((__tmp250394
             (lambda ()
               (force gxc#::false-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::extract-receiver::t
                  '%#begin
                  gxc#apply-last-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::extract-receiver::t
                  '%#begin-annotation
                  gxc#extract-receiver-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::extract-receiver::t
                  '%#let-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::extract-receiver::t
                  '%#letrec-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::extract-receiver::t
                  '%#letrec*-values
                  gxc#apply-body-last-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::extract-receiver::t
                  '%#if
                  gxc#extract-receiver-if%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::extract-receiver::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp250394)))
    (define gxc#apply-extract-receiver
      (lambda (_%stx249167%_)
        (force gxc#::extract-receiver-bind-methods!)
        (let* ((_%self249170%_
                (let ((__obj250383
                       (let ()
                         (declare (not safe))
                         (##structure gxc#::extract-receiver::t))))
                  __obj250383))
               (__tmp250395
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gxc#compile-e__1 _%self249170%_ _%stx249167%_)))))
          (declare (not safe))
          (call-with-parameters__1
           __tmp250395
           gxc#current-compile-method
           _%self249170%_))))
    (define gxc#::collect-object-refs::t
      (let ((__tmp250397 (list gxc#::void::t))
            (__tmp250396 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::collect-object-refs::t
         '::collect-object-refs
         __tmp250397
         '(receiver methods slots)
         __tmp250396
         '#f)))
    (define gxc#::collect-object-refs?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::collect-object-refs::t)))
    (define gxc#make-::collect-object-refs
      (lambda _%$args249164%_
        (apply make-instance gxc#::collect-object-refs::t _%$args249164%_)))
    (define gxc#::collect-object-refs-receiver
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::collect-object-refs::t 'receiver)))
    (define gxc#::collect-object-refs-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::collect-object-refs::t 'methods)))
    (define gxc#::collect-object-refs-slots
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::collect-object-refs::t 'slots)))
    (define gxc#::collect-object-refs-receiver-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::collect-object-refs::t 'receiver)))
    (define gxc#::collect-object-refs-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::collect-object-refs::t 'methods)))
    (define gxc#::collect-object-refs-slots-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::collect-object-refs::t 'slots)))
    (define gxc#&::collect-object-refs-receiver
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::collect-object-refs::t
         'receiver)))
    (define gxc#&::collect-object-refs-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::collect-object-refs::t
         'methods)))
    (define gxc#&::collect-object-refs-slots
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::collect-object-refs::t
         'slots)))
    (define gxc#&::collect-object-refs-receiver-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::collect-object-refs::t
         'receiver)))
    (define gxc#&::collect-object-refs-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::collect-object-refs::t
         'methods)))
    (define gxc#&::collect-object-refs-slots-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::collect-object-refs::t
         'slots)))
    (define gxc#::collect-object-refs-bind-methods!
      (let ((__tmp250398
             (lambda ()
               (force gxc#::void-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#begin
                  gxc#apply-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#begin-annotation
                  gxc#apply-begin-annotation%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#lambda
                  gxc#apply-body-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#case-lambda
                  gxc#apply-body-case-lambda%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#let-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#letrec-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#letrec*-values
                  gxc#apply-body-let-values%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#call
                  gxc#collect-object-refs-call%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#if
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#set!
                  gxc#apply-body-setq%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#struct-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#struct-set!
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#struct-direct-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#struct-direct-set!
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#struct-unchecked-ref
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::collect-object-refs::t
                  '%#struct-unchecked-set!
                  gxc#apply-operands))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::collect-object-refs::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp250398)))
    (define gxc#apply-collect-object-refs__%
      (lambda (_%@@keywords249133%_
               _%$%receiver249128249134%_
               _%$%methods249129249135%_
               _%$%slots249130249136%_
               _%stx249137%_)
        (let* ((_%receiver249140%_
                (if (eq? _%$%receiver249128249134%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'receiver:))
                    _%$%receiver249128249134%_))
               (_%methods249142%_
                (if (eq? _%$%methods249129249135%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'methods:))
                    _%$%methods249129249135%_))
               (_%slots249144%_
                (if (eq? _%$%slots249130249136%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'slots:))
                    _%$%slots249130249136%_)))
          (force gxc#::collect-object-refs-bind-methods!)
          (let* ((_%self249146%_
                  (let ((__obj250385
                         (let ()
                           (declare (not safe))
                           (##structure
                            gxc#::collect-object-refs::t
                            '#f
                            '#f
                            '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj250385
                       _%receiver249140%_
                       '1
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj250385
                       _%methods249142%_
                       '2
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj250385
                       _%slots249144%_
                       '3
                       '#f
                       '#f))
                    __obj250385))
                 (__tmp250399
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self249146%_ _%stx249137%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp250399
             gxc#current-compile-method
             _%self249146%_)))))
    (define gxc#apply-collect-object-refs__@
      (lambda (_%@@keywords249153%_ . _%args249154%_)
        (apply gxc#apply-collect-object-refs__%
               _%@@keywords249153%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords249153%_
                  'receiver:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords249153%_
                  'methods:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords249153%_
                  'slots:
                  absent-value))
               _%args249154%_)))
    (define gxc#apply-collect-object-refs
      (lambda _%$%args249131249160%_
        (apply keyword-dispatch
               '#(receiver: slots: methods:)
               gxc#apply-collect-object-refs__@
               _%$%args249131249160%_)))
    (define gxc#::subst-object-refs::t
      (let ((__tmp250401 (list gxc#::basic-xform-expression::t))
            (__tmp250400 (cons (cons 'final: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#::subst-object-refs::t
         '::subst-object-refs
         __tmp250401
         '(receiver klass methods slots)
         __tmp250400
         '#f)))
    (define gxc#::subst-object-refs?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#::subst-object-refs::t)))
    (define gxc#make-::subst-object-refs
      (lambda _%$args249124%_
        (apply make-instance gxc#::subst-object-refs::t _%$args249124%_)))
    (define gxc#::subst-object-refs-receiver
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::subst-object-refs::t 'receiver)))
    (define gxc#::subst-object-refs-klass
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::subst-object-refs::t 'klass)))
    (define gxc#::subst-object-refs-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::subst-object-refs::t 'methods)))
    (define gxc#::subst-object-refs-slots
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#::subst-object-refs::t 'slots)))
    (define gxc#::subst-object-refs-receiver-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::subst-object-refs::t 'receiver)))
    (define gxc#::subst-object-refs-klass-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::subst-object-refs::t 'klass)))
    (define gxc#::subst-object-refs-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::subst-object-refs::t 'methods)))
    (define gxc#::subst-object-refs-slots-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#::subst-object-refs::t 'slots)))
    (define gxc#&::subst-object-refs-receiver
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::subst-object-refs::t
         'receiver)))
    (define gxc#&::subst-object-refs-klass
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::subst-object-refs::t
         'klass)))
    (define gxc#&::subst-object-refs-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::subst-object-refs::t
         'methods)))
    (define gxc#&::subst-object-refs-slots
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#::subst-object-refs::t
         'slots)))
    (define gxc#&::subst-object-refs-receiver-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::subst-object-refs::t
         'receiver)))
    (define gxc#&::subst-object-refs-klass-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::subst-object-refs::t
         'klass)))
    (define gxc#&::subst-object-refs-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::subst-object-refs::t
         'methods)))
    (define gxc#&::subst-object-refs-slots-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#::subst-object-refs::t
         'slots)))
    (define gxc#::subst-object-refs-bind-methods!
      (let ((__tmp250402
             (lambda ()
               (force gxc#::basic-xform-expression-bind-methods!)
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::subst-object-refs::t
                  '%#begin
                  gxc#xform-begin%))
               (let ()
                 (declare (not safe))
                 (bind-method!__0
                  gxc#::subst-object-refs::t
                  '%#call
                  gxc#subst-object-refs-call%))
               (let ()
                 (declare (not safe))
                 (__seal-class! gxc#::subst-object-refs::t)))))
        (declare (not safe))
        (__make-atomic-promise __tmp250402)))
    (define gxc#apply-subst-object-refs__%
      (lambda (_%@@keywords249090%_
               _%$%receiver249084249091%_
               _%$%klass249085249092%_
               _%$%methods249086249093%_
               _%$%slots249087249094%_
               _%stx249095%_)
        (let* ((_%receiver249098%_
                (if (eq? _%$%receiver249084249091%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'receiver:))
                    _%$%receiver249084249091%_))
               (_%klass249100%_
                (if (eq? _%$%klass249085249092%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'klass:))
                    _%$%klass249085249092%_))
               (_%methods249102%_
                (if (eq? _%$%methods249086249093%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'methods:))
                    _%$%methods249086249093%_))
               (_%slots249104%_
                (if (eq? _%$%slots249087249094%_ absent-value)
                    (let ()
                      (declare (not safe))
                      (error '"Missing required keyword argument" 'slots:))
                    _%$%slots249087249094%_)))
          (force gxc#::subst-object-refs-bind-methods!)
          (let* ((_%self249106%_
                  (let ((__obj250387
                         (let ()
                           (declare (not safe))
                           (##structure
                            gxc#::subst-object-refs::t
                            '#f
                            '#f
                            '#f
                            '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj250387
                       _%receiver249098%_
                       '1
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj250387
                       _%klass249100%_
                       '2
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj250387
                       _%methods249102%_
                       '3
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj250387
                       _%slots249104%_
                       '4
                       '#f
                       '#f))
                    __obj250387))
                 (__tmp250403
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gxc#compile-e__1 _%self249106%_ _%stx249095%_)))))
            (declare (not safe))
            (call-with-parameters__1
             __tmp250403
             gxc#current-compile-method
             _%self249106%_)))))
    (define gxc#apply-subst-object-refs__@
      (lambda (_%@@keywords249113%_ . _%args249114%_)
        (apply gxc#apply-subst-object-refs__%
               _%@@keywords249113%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords249113%_
                  'receiver:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords249113%_
                  'klass:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords249113%_
                  'methods:
                  absent-value))
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords249113%_
                  'slots:
                  absent-value))
               _%args249114%_)))
    (define gxc#apply-subst-object-refs
      (lambda _%$%args249088249120%_
        (apply keyword-dispatch
               '#(receiver: methods: slots: klass:)
               gxc#apply-subst-object-refs__@
               _%$%args249088249120%_)))
    (define gxc#generate-method-specializers-define-values%
      (lambda (_%self246215%_ _%stx246216%_)
        (letrec ((_%generate-method-bind246218%_
                  (lambda (_%$klass249076%_
                           _%$method-table249077%_
                           _%id249078%_
                           _%$id249079%_)
                    (let ((_%$tmp249081%_
                           (let ((__tmp250404
                                  (let ()
                                    (declare (not safe))
                                    (##gensym '__method))))
                             (declare (not safe))
                             (make-symbol__0 __tmp250404))))
                      (cons (cons _%$id249079%_ '())
                            (cons (cons '%#call
                                        (cons (cons '%#ref
                                                    (cons 'make-promise '()))
                                              (cons (cons '%#lambda
                                                          (cons '()
                                                                (cons (cons '%#let-values
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                    (cons (cons (cons (cons _%$tmp249081%_ '())
                                                      (cons (cons '%#call
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons (cons '%#ref (cons 'symbolic-table-ref '()))
                                (cons (cons '%#ref
                                            (cons _%$method-table249077%_ '()))
                                      (cons (cons '%#quote
                                                  (cons _%id249078%_ '()))
                                            (cons (cons '%#quote
                                                        (cons '#f '()))
                                                  '())))))
                    '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '())
                                          (cons (cons '%#if
                                                      (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons _%$tmp249081%_ '()))
                    (cons (cons '%#ref (cons _%$tmp249081%_ '()))
                          (cons (cons '%#call
                                      (cons (cons '%#ref (cons 'error '()))
                                            (cons (cons '%#quote
                                                        (cons '"Missing method"
                                                              '()))
                                                  (cons (cons '%#quote
                                                              (cons _%id249078%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '()))
                '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '())))
                              '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '())))
                                  '())))))
                 (_%generate-slot-bind246219%_
                  (lambda (_%$klass249070%_ _%id249071%_ _%$id249072%_)
                    (let ((_%$tmp249074%_
                           (let ((__tmp250405
                                  (let ()
                                    (declare (not safe))
                                    (##gensym '__slot))))
                             (declare (not safe))
                             (make-symbol__0 __tmp250405))))
                      (cons (cons _%$id249072%_ '())
                            (cons (cons '%#let-values
                                        (cons (cons (cons (cons _%$tmp249074%_
                                                                '())
                                                          (cons (cons '%#call
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons (cons '%#ref (cons 'class-slot-offset '()))
                                    (cons (cons '%#ref
                                                (cons _%$klass249070%_ '()))
                                          (cons (cons '%#quote
                                                      (cons _%id249071%_ '()))
                                                '()))))
                        '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '())
                                              (cons (cons '%#if
                                                          (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (cons _%$tmp249074%_ '()))
                        (cons (cons '%#ref (cons _%$tmp249074%_ '()))
                              (cons (cons '%#call
                                          (cons (cons '%#ref (cons 'error '()))
                                                (cons (cons '%#quote
                                                            (cons '"Unknown slot"
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          '()))
              (cons (cons '%#quote (cons _%id249071%_ '())) '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                    '()))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    '())))
                                  '())))))
                 (_%generate-specializer-impl246220%_
                  (lambda (_%$klass249064%_
                           _%$method-table249065%_
                           _%methods-bind249066%_
                           _%slots-bind249067%_
                           _%specializer-impl249068%_)
                    (let ((__tmp250406
                           (cons '%#lambda
                                 (cons (cons _%$klass249064%_
                                             (cons _%$method-table249065%_
                                                   '()))
                                       (cons (cons '%#let-values
                                                   (cons (append _%methods-bind249066%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%slots-bind249067%_)
                 (cons _%specializer-impl249068%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             '())))))
                      (declare (not safe))
                      (gxc#xform-wrap-source __tmp250406 _%stx246216%_))))
                 (_%generate-specializer-def246221%_
                  (lambda (_%id249060%_
                           _%specializer-id249061%_
                           _%specializer-impl249062%_)
                    (let ((__tmp250407
                           (cons '%#begin
                                 (cons _%stx246216%_
                                       (cons (let ((__tmp250408
                                                    (cons '%#define-values
                                                          (cons (cons _%specializer-id249061%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              '())
                        (cons _%specializer-impl249062%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (declare (not safe))
                                               (gxc#xform-wrap-source
                                                __tmp250408
                                                _%stx246216%_))
                                             (cons (let ((__tmp250409
                                                          (cons '%#call
                                                                (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                    (cons 'bind-specializer! '()))
                              (cons (cons '%#ref (cons _%id249060%_ '()))
                                    (cons (cons '%#ref
                                                (cons _%specializer-id249061%_
                                                      '()))
                                          '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (gxc#xform-wrap-source
                                                      __tmp250409
                                                      _%stx246216%_))
                                                   '()))))))
                      (declare (not safe))
                      (gxc#xform-wrap-source __tmp250407 _%stx246216%_)))))
          (let* ((_%__stx249275249276%_ _%stx246216%_)
                 (_%$%g246224246244%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%__stx249275249276%_)))))
            (let ((_%__kont249277249278%_
                   (lambda (_%$%g246226246288%_ _%$%g246227246289%_)
                     (let ((_%method-calls246308%_
                            (let () (declare (not safe)) (make-hash-table-eq)))
                           (_%slot-refs246309%_
                            (let () (declare (not safe)) (make-hash-table-eq)))
                           (_%empty246310%_
                            (let ()
                              (declare (not safe))
                              (make-hash-table-eq))))
                       (letrec ((_%no-specializer?246312%_
                                 (lambda ()
                                   (if (let ((__tmp250410
                                              (let ()
                                                (declare (not safe))
                                                (__hash-length
                                                 _%method-calls246308%_))))
                                         (declare (not safe))
                                         (##fxzero? __tmp250410))
                                       (let ((__tmp250411
                                              (let ()
                                                (declare (not safe))
                                                (__hash-length
                                                 _%slot-refs246309%_))))
                                         (declare (not safe))
                                         (##fxzero? __tmp250411))
                                       '#f))))
                         (if (let ()
                               (declare (not safe))
                               (gxc#lambda-expr? _%$%g246226246288%_))
                             (let* ((_%__stx249189249190%_ _%$%g246226246288%_)
                                    (_%$%g246696246714%_
                                     (lambda ()
                                       (let ()
                                         (declare (not safe))
                                         (gx#raise-syntax-error
                                          '#f
                                          '"Bad syntax; invalid match target"
                                          _%__stx249189249190%_)))))
                               (let ((_%__kont249191249192%_
                                      (lambda (_%$%g246698246750%_
                                               _%$%g246699246751%_
                                               _%$%g246700246752%_)
                                        (let ((_%receiver246772%_
                                               (let ((_%$e246769%_
                                                      (gxc#apply-extract-receiver
                                                       (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#datum->syntax__0 '#f '%#begin))
                     _%$%g246698246750%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (if _%$e246769%_
                                                     _%$e246769%_
                                                     _%$%g246700246752%_))))
                                          (for-each
                                           (lambda (_%$%g246773246775%_)
                                             (gxc#apply-collect-object-refs__%
                                              '#f
                                              _%receiver246772%_
                                              _%method-calls246308%_
                                              _%slot-refs246309%_
                                              _%$%g246773246775%_))
                                           _%$%g246698246750%_)
                                          (if (_%no-specializer?246312%_)
                                              _%stx246216%_
                                              (let* ((_%specializer-id246784%_
                                                      (let* ((_%id246778%_
                                                              (let ((__tmp250412
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g246227246289%_))))
                        (declare (not safe))
                        (make-symbol__1 __tmp250412 '"::specialize")))
                     (_%specializer-id246781%_
                      (let ((__tmp250413
                             (let ()
                               (declare (not safe))
                               (gx#stx-source _%stx246216%_))))
                        (declare (not safe))
                        (gx#core-quote-syntax__1 _%id246778%_ __tmp250413))))
                (let ()
                  (declare (not safe))
                  (gx#core-bind-runtime!__0 _%specializer-id246781%_))
                _%specializer-id246781%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$klass246786%_
                                                      (let ((__tmp250414
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##gensym '__klass))))
                (declare (not safe))
                (make-symbol__0 __tmp250414)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$method-table246788%_
                                                      (let ((__tmp250415
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##gensym '__method-table))))
                (declare (not safe))
                (make-symbol__0 __tmp250415)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%methods246790%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (__hash-keys
                                                         _%method-calls246308%_)))
                                                     (_%$methods246794%_
                                                      (let ((__tmp250416
                                                             (lambda (_%id246792%_)
                                                               (let ((__tmp250417
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (gensym _%id246792%_)))
                         (declare (not safe))
                         (make-symbol__1 '"__" __tmp250417)))))
                (declare (not safe))
                (##map __tmp250416 _%methods246790%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%_246803%_
                                                      (let ((__tmp250418
                                                             (lambda (_%$%g246795246798%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%$%g246796246800%_)
                       (let ()
                         (declare (not safe))
                         (__hash-put!
                          _%method-calls246308%_
                          _%$%g246795246798%_
                          _%$%g246796246800%_)))))
                (declare (not safe))
                (##for-each __tmp250418 _%methods246790%_ _%$methods246794%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%methods-bind246813%_
                                                      (let ((__tmp250419
                                                             (lambda (_%$%g246805246808%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%$%g246806246810%_)
                       (_%generate-method-bind246218%_
                        _%$klass246786%_
                        _%$method-table246788%_
                        _%$%g246805246808%_
                        _%$%g246806246810%_))))
                (declare (not safe))
                (##map __tmp250419 _%methods246790%_ _%$methods246794%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%slots246815%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (__hash-keys
                                                         _%slot-refs246309%_)))
                                                     (_%$slots246819%_
                                                      (let ((__tmp250420
                                                             (lambda (_%id246817%_)
                                                               (let ((__tmp250421
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (gensym _%id246817%_)))
                         (declare (not safe))
                         (make-symbol__1 '"__" __tmp250421)))))
                (declare (not safe))
                (##map __tmp250420 _%slots246815%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%_246828%_
                                                      (let ((__tmp250422
                                                             (lambda (_%$%g246820246823%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%$%g246821246825%_)
                       (let ()
                         (declare (not safe))
                         (__hash-put!
                          _%slot-refs246309%_
                          _%$%g246820246823%_
                          _%$%g246821246825%_)))))
                (declare (not safe))
                (##for-each __tmp250422 _%slots246815%_ _%$slots246819%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%slots-bind246837%_
                                                      (let ((__tmp250423
                                                             (lambda (_%$%g246829246832%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              _%$%g246830246834%_)
                       (_%generate-slot-bind246219%_
                        _%$klass246786%_
                        _%$%g246829246832%_
                        _%$%g246830246834%_))))
                (declare (not safe))
                (##map __tmp250423 _%slots246815%_ _%$slots246819%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%specializer-body246843%_
                                                      (map (lambda (_%$%g246838246840%_)
                                                             (gxc#apply-subst-object-refs__%
                                                              '#f
                                                              _%receiver246772%_
                                                              _%$klass246786%_
                                                              _%method-calls246308%_
                                                              _%slot-refs246309%_
                                                              _%$%g246838246840%_))
                                                           _%$%g246698246750%_))
                                                     (_%specializer-impl246845%_
                                                      (let ((__tmp250424
                                                             (cons '%#lambda
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (cons (cons _%$%g246700246752%_ _%$%g246699246751%_)
                                 _%specializer-body246843%_))))
                (declare (not safe))
                (gxc#xform-wrap-source __tmp250424 _%stx246216%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%specializer-impl246847%_
                                                      (_%generate-specializer-impl246220%_
                                                       _%$klass246786%_
                                                       _%$method-table246788%_
                                                       _%methods-bind246813%_
                                                       _%slots-bind246837%_
                                                       _%specializer-impl246845%_)))
                                                (let ((__tmp250426
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%g246227246289%_)))
                                                      (__tmp250425
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%specializer-id246784%_))))
                                                  (declare (not safe))
                                                  (gxc#verbose
                                                   '"generate method specializer "
                                                   __tmp250426
                                                   '" => "
                                                   __tmp250425))
                                                (_%generate-specializer-def246221%_
                                                 _%$%g246227246289%_
                                                 _%specializer-id246784%_
                                                 _%specializer-impl246847%_))))))
                                     (_%__kont249193249194%_
                                      (lambda () _%stx246216%_)))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%__stx249189249190%_))
                                     (let ((_%$%e246701246726%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#stx-e
                                               _%__stx249189249190%_))))
                                       (let ((_%$%tl246703246731%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e246701246726%_)))
                                             (_%$%hd246702246729%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e246701246726%_))))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-pair?
                                                _%$%tl246703246731%_))
                                             (let ((_%$%e246704246734%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%$%tl246703246731%_))))
                                               (let ((_%$%tl246706246739%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%e246704246734%_)))
                                                     (_%$%hd246705246737%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%e246704246734%_))))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-pair?
                                                        _%$%hd246705246737%_))
                                                     (let ((_%$%e246707246742%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%$%hd246705246737%_))))
                                                       (let ((_%$%tl246709246747%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##cdr _%$%e246707246742%_)))
                     (_%$%hd246708246745%_
                      (let ()
                        (declare (not safe))
                        (##car _%$%e246707246742%_))))
                 (_%__kont249191249192%_
                  _%$%tl246706246739%_
                  _%$%tl246709246747%_
                  _%$%hd246708246745%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%__kont249193249194%_))))
                                             (_%__kont249193249194%_))))
                                     (_%__kont249193249194%_))))
                             (if (let ()
                                   (declare (not safe))
                                   (gxc#case-lambda-expr? _%$%g246226246288%_))
                                 (let* ((_%$%g246854246873%_
                                         (lambda (_%$%g246855246870%_)
                                           (let ()
                                             (declare (not safe))
                                             (gx#raise-syntax-error
                                              '#f
                                              '"Bad syntax; invalid match target"
                                              _%$%g246855246870%_))))
                                        (_%$%g246853247169%_
                                         (lambda (_%$%g246855246876%_)
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-pair?
                                                  _%$%g246855246876%_))
                                               (let ((_%$%e246857246878%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%g246855246876%_))))
                                                 (let ((_%$%hd246858246881%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e246857246878%_)))
                                                       (_%$%tl246859246883%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e246857246878%_))))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair/null?
                                                          _%$%tl246859246883%_))
                                                       (let ((_g250427_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#syntax-split-splice _%$%tl246859246883%_ '0))))
                 (begin
                   (let ((_g250428_
                          (let ()
                            (declare (not safe))
                            (if (##values? _g250427_)
                                (##values-length _g250427_)
                                1))))
                     (if (not (let ()
                                (declare (not safe))
                                (##fx= _g250428_ 2)))
                         (error "Context expects 2 values" _g250428_)))
                   (let ((_%$%target246860246886%_
                          (let ()
                            (declare (not safe))
                            (##values-ref _g250427_ 0)))
                         (_%$%tl246862246888%_
                          (let ()
                            (declare (not safe))
                            (##values-ref _g250427_ 1))))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-null? _%$%tl246862246888%_))
                         (letrec ((_%$%loop246863246891%_
                                   (lambda (_%$%hd246861246894%_
                                            _%$%clause246867246896%_)
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-pair? _%$%hd246861246894%_))
                                         (let ((_%$%e246864246898%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#stx-e
                                                   _%$%hd246861246894%_))))
                                           (let ((_%$%lp-hd246865246901%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e246864246898%_)))
                                                 (_%$%lp-tl246866246903%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e246864246898%_))))
                                             (_%$%loop246863246891%_
                                              _%$%lp-tl246866246903%_
                                              (cons _%$%lp-hd246865246901%_
                                                    _%$%clause246867246896%_))))
                                         (let ((_%$%clause246868246906%_
                                                (reverse _%$%clause246867246896%_)))
                                           (for-each
                                            (lambda (_%clause246922%_)
                                              (let* ((_%__stx249215249216%_
                                                      _%clause246922%_)
                                                     (_%$%g246925246940%_
                                                      (lambda ()
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#raise-syntax-error
                                                           '#f
                                                           '"Bad syntax; invalid match target"
                                                           _%__stx249215249216%_)))))
                                                (let ((_%__kont249217249218%_
                                                       (lambda (_%$%g246927246968%_
                                                                _%$%g246928246969%_
                                                                _%$%g246929246970%_)
                                                         (let ((_%receiver246989%_
                                                                (let ((_%$e246986%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (gxc#apply-extract-receiver
                                (cons (let ()
                                        (declare (not safe))
                                        (gx#datum->syntax__0 '#f '%#begin))
                                      _%$%g246927246968%_))))
                          (if _%$e246986%_ _%$e246986%_ _%$%g246929246970%_))))
                   (for-each
                    (lambda (_%$%g246990246992%_)
                      (gxc#apply-collect-object-refs__%
                       '#f
                       _%receiver246989%_
                       _%method-calls246308%_
                       _%slot-refs246309%_
                       _%$%g246990246992%_))
                    _%$%g246927246968%_))))
              (_%__kont249219249220%_ (lambda () '#!void)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair?
                                                         _%__stx249215249216%_))
                                                      (let ((_%$%e246930246952%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-e _%__stx249215249216%_))))
                (let ((_%$%tl246932246957%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%e246930246952%_)))
                      (_%$%hd246931246955%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%e246930246952%_))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%hd246931246955%_))
                      (let ((_%$%e246933246960%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%hd246931246955%_))))
                        (let ((_%$%tl246935246965%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e246933246960%_)))
                              (_%$%hd246934246963%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e246933246960%_))))
                          (_%__kont249217249218%_
                           _%$%tl246932246957%_
                           _%$%tl246935246965%_
                           _%$%hd246934246963%_)))
                      '#!void)))
              '#!void))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                            (let ((__tmp250429
                                                   (lambda (_%$%g246997247000%_
                                                            _%$%g246998247002%_)
                                                     (cons _%$%g246997247000%_
                                                           _%$%g246998247002%_))))
                                              (declare (not safe))
                                              (foldr__0
                                               __tmp250429
                                               '()
                                               _%$%clause246868246906%_)))
                                           (if (_%no-specializer?246312%_)
                                               _%stx246216%_
                                               (let* ((_%specializer-id247011%_
                                                       (let* ((_%id247005%_
                                                               (let ((__tmp250430
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%g246227246289%_))))
                         (declare (not safe))
                         (make-symbol__1 __tmp250430 '"::specialize")))
                      (_%specializer-id247008%_
                       (let ((__tmp250431
                              (let ()
                                (declare (not safe))
                                (gx#stx-source _%stx246216%_))))
                         (declare (not safe))
                         (gx#core-quote-syntax__1 _%id247005%_ __tmp250431))))
                 (let ()
                   (declare (not safe))
                   (gx#core-bind-runtime!__0 _%specializer-id247008%_))
                 _%specializer-id247008%_))
              (_%$klass247013%_
               (let ((__tmp250432
                      (let () (declare (not safe)) (##gensym '__klass))))
                 (declare (not safe))
                 (make-symbol__0 __tmp250432)))
              (_%$method-table247015%_
               (let ((__tmp250433
                      (let ()
                        (declare (not safe))
                        (##gensym '__method-table))))
                 (declare (not safe))
                 (make-symbol__0 __tmp250433)))
              (_%methods247017%_
               (let ()
                 (declare (not safe))
                 (__hash-keys _%method-calls246308%_)))
              (_%$methods247021%_
               (let ((__tmp250434
                      (lambda (_%id247019%_)
                        (let ((__tmp250435 (gensym _%id247019%_)))
                          (declare (not safe))
                          (make-symbol__1 '"__" __tmp250435)))))
                 (declare (not safe))
                 (##map __tmp250434 _%methods247017%_)))
              (_%_247030%_
               (let ((__tmp250436
                      (lambda (_%$%g247022247025%_ _%$%g247023247027%_)
                        (let ()
                          (declare (not safe))
                          (__hash-put!
                           _%method-calls246308%_
                           _%$%g247022247025%_
                           _%$%g247023247027%_)))))
                 (declare (not safe))
                 (##for-each
                  __tmp250436
                  _%methods247017%_
                  _%$methods247021%_)))
              (_%methods-bind247040%_
               (let ((__tmp250437
                      (lambda (_%$%g247032247035%_ _%$%g247033247037%_)
                        (_%generate-method-bind246218%_
                         _%$klass247013%_
                         _%$method-table247015%_
                         _%$%g247032247035%_
                         _%$%g247033247037%_))))
                 (declare (not safe))
                 (##map __tmp250437 _%methods247017%_ _%$methods247021%_)))
              (_%slots247042%_
               (let () (declare (not safe)) (__hash-keys _%slot-refs246309%_)))
              (_%$slots247046%_
               (let ((__tmp250438
                      (lambda (_%id247044%_)
                        (let ((__tmp250439 (gensym _%id247044%_)))
                          (declare (not safe))
                          (make-symbol__1 '"__" __tmp250439)))))
                 (declare (not safe))
                 (##map __tmp250438 _%slots247042%_)))
              (_%_247055%_
               (let ((__tmp250440
                      (lambda (_%$%g247047247050%_ _%$%g247048247052%_)
                        (let ()
                          (declare (not safe))
                          (__hash-put!
                           _%slot-refs246309%_
                           _%$%g247047247050%_
                           _%$%g247048247052%_)))))
                 (declare (not safe))
                 (##for-each __tmp250440 _%slots247042%_ _%$slots247046%_)))
              (_%slots-bind247064%_
               (let ((__tmp250441
                      (lambda (_%$%g247056247059%_ _%$%g247057247061%_)
                        (_%generate-slot-bind246219%_
                         _%$klass247013%_
                         _%$%g247056247059%_
                         _%$%g247057247061%_))))
                 (declare (not safe))
                 (##map __tmp250441 _%slots247042%_ _%$slots247046%_)))
              (_%specializer-clauses247162%_
               (map (lambda (_%clause247066%_)
                      (let* ((_%__stx249235249236%_ _%clause247066%_)
                             (_%$%g247069247084%_
                              (lambda ()
                                (let ()
                                  (declare (not safe))
                                  (gx#raise-syntax-error
                                   '#f
                                   '"Bad syntax; invalid match target"
                                   _%__stx249235249236%_)))))
                        (let ((_%__kont249237249238%_
                               (lambda (_%$%g247071247112%_
                                        _%$%g247072247113%_
                                        _%$%g247073247114%_)
                                 (let* ((_%receiver247143%_
                                         (let ((_%$e247140%_
                                                (gxc#apply-extract-receiver
                                                 (cons (let ()
                                                         (declare (not safe))
                                                         (gx#datum->syntax__0
                                                          '#f
                                                          '%#begin))
                                                       _%$%g247071247112%_))))
                                           (if _%$e247140%_
                                               _%$e247140%_
                                               _%$%g247073247114%_)))
                                        (_%body247149%_
                                         (map (lambda (_%$%g247144247146%_)
                                                (gxc#apply-subst-object-refs__%
                                                 '#f
                                                 _%receiver247143%_
                                                 _%$klass247013%_
                                                 _%method-calls246308%_
                                                 _%slot-refs246309%_
                                                 _%$%g247144247146%_))
                                              _%$%g247071247112%_)))
                                   (cons (cons _%$%g247073247114%_
                                               _%$%g247072247113%_)
                                         _%body247149%_))))
                              (_%__kont249239249240%_
                               (lambda () _%clause247066%_)))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%__stx249235249236%_))
                              (let ((_%$%e247074247096%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%__stx249235249236%_))))
                                (let ((_%$%tl247076247101%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e247074247096%_)))
                                      (_%$%hd247075247099%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e247074247096%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd247075247099%_))
                                      (let ((_%$%e247077247104%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd247075247099%_))))
                                        (let ((_%$%tl247079247109%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e247077247104%_)))
                                              (_%$%hd247078247107%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e247077247104%_))))
                                          (_%__kont249237249238%_
                                           _%$%tl247076247101%_
                                           _%$%tl247079247109%_
                                           _%$%hd247078247107%_)))
                                      (_%__kont249239249240%_))))
                              (_%__kont249239249240%_)))))
                    (let ((__tmp250442
                           (lambda (_%$%g247154247157%_ _%$%g247155247159%_)
                             (cons _%$%g247154247157%_ _%$%g247155247159%_))))
                      (declare (not safe))
                      (foldr__0 __tmp250442 '() _%$%clause246868246906%_))))
              (_%specializer-impl247164%_
               (let ((__tmp250443
                      (cons '%#case-lambda _%specializer-clauses247162%_)))
                 (declare (not safe))
                 (gxc#xform-wrap-source __tmp250443 _%stx246216%_)))
              (_%specializer-impl247166%_
               (_%generate-specializer-impl246220%_
                _%$klass247013%_
                _%$method-table247015%_
                _%methods-bind247040%_
                _%slots-bind247064%_
                _%specializer-impl247164%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (let ((__tmp250445
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%$%g246227246289%_)))
                                                       (__tmp250444
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%specializer-id247011%_))))
                                                   (declare (not safe))
                                                   (gxc#verbose
                                                    '"generate method specializer "
                                                    __tmp250445
                                                    '" => "
                                                    __tmp250444))
                                                 (_%generate-specializer-def246221%_
                                                  _%$%g246227246289%_
                                                  _%specializer-id247011%_
                                                  _%specializer-impl247166%_))))))))
                           (_%$%loop246863246891%_
                            _%$%target246860246886%_
                            '()))
                         (_%$%g246854246873%_ _%$%g246855246876%_)))))
               (_%$%g246854246873%_ _%$%g246855246876%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%g246854246873%_
                                                _%$%g246855246876%_)))))
                                   (_%$%g246853247169%_ _%$%g246226246288%_))
                                 (if (let ()
                                       (declare (not safe))
                                       (gxc#opt-lambda-expr?
                                        _%$%g246226246288%_))
                                     (let* ((_%$%g247173247203%_
                                             (lambda (_%$%g247174247200%_)
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#raise-syntax-error
                                                  '#f
                                                  '"Bad syntax; invalid match target"
                                                  _%$%g247174247200%_))))
                                            (_%$%g247172247830%_
                                             (lambda (_%$%g247174247206%_)
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-pair?
                                                      _%$%g247174247206%_))
                                                   (let ((_%$%e247178247208%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%g247174247206%_))))
                                                     (let ((_%$%hd247179247211%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e247178247208%_)))
                                                           (_%$%tl247180247213%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e247178247208%_))))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-pair?
                                                              _%$%tl247180247213%_))
                                                           (let ((_%$%e247181247216%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%tl247180247213%_))))
                     (let ((_%$%hd247182247219%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%e247181247216%_)))
                           (_%$%tl247183247221%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%e247181247216%_))))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-pair? _%$%hd247182247219%_))
                           (let ((_%$%e247184247224%_
                                  (let ()
                                    (declare (not safe))
                                    (gx#stx-e _%$%hd247182247219%_))))
                             (let ((_%$%hd247185247227%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%e247184247224%_)))
                                   (_%$%tl247186247229%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%e247184247224%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%hd247185247227%_))
                                   (let ((_%$%e247187247232%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#stx-e _%$%hd247185247227%_))))
                                     (let ((_%$%hd247188247235%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e247187247232%_)))
                                           (_%$%tl247189247237%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e247187247232%_))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-pair?
                                              _%$%hd247188247235%_))
                                           (let ((_%$%e247190247240%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#stx-e
                                                     _%$%hd247188247235%_))))
                                             (let ((_%$%hd247191247243%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e247190247240%_)))
                                                   (_%$%tl247192247245%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e247190247240%_))))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-null?
                                                      _%$%tl247192247245%_))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%tl247189247237%_))
                                                       (let ((_%$%e247193247248%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%tl247189247237%_))))
                 (let ((_%$%hd247194247251%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e247193247248%_)))
                       (_%$%tl247195247253%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e247193247248%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-null? _%$%tl247195247253%_))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-null? _%$%tl247186247229%_))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-pair? _%$%tl247183247221%_))
                               (let ((_%$%e247196247256%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#stx-e _%$%tl247183247221%_))))
                                 (let ((_%$%hd247197247259%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%e247196247256%_)))
                                       (_%$%tl247198247261%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%e247196247256%_))))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-null? _%$%tl247198247261%_))
                                       (let ()
                                         (let* ((_%$%g247290247308%_
                                                 (lambda (_%$%g247291247305%_)
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#raise-syntax-error
                                                      '#f
                                                      '"Bad syntax; invalid match target"
                                                      _%$%g247291247305%_))))
                                                (_%$%g247289247364%_
                                                 (lambda (_%$%g247291247311%_)
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%g247291247311%_))
                                                       (let ((_%$%e247295247313%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%g247291247311%_))))
                 (let ((_%$%hd247296247316%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e247295247313%_)))
                       (_%$%tl247297247318%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e247295247313%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl247297247318%_))
                       (let ((_%$%e247298247321%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl247297247318%_))))
                         (let ((_%$%hd247299247324%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e247298247321%_)))
                               (_%$%tl247300247326%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e247298247321%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-pair? _%$%hd247299247324%_))
                               (let ((_%$%e247301247329%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#stx-e _%$%hd247299247324%_))))
                                 (let ((_%$%hd247302247332%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%e247301247329%_)))
                                       (_%$%tl247303247334%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%e247301247329%_))))
                                   (let ((_%receiver247358%_
                                          (let ((_%$e247355%_
                                                 (gxc#apply-extract-receiver
                                                  (cons (let ()
                                                          (declare (not safe))
                                                          (gx#datum->syntax__0
                                                           '#f
                                                           '%#begin))
                                                        _%$%tl247300247326%_))))
                                            (if _%$e247355%_
                                                _%$e247355%_
                                                _%$%hd247302247332%_))))
                                     (for-each
                                      (lambda (_%$%g247359247361%_)
                                        (gxc#apply-collect-object-refs__%
                                         '#f
                                         _%receiver247358%_
                                         _%method-calls246308%_
                                         _%slot-refs246309%_
                                         _%$%g247359247361%_))
                                      _%$%tl247300247326%_))))
                               (_%$%g247290247308%_ _%$%g247291247311%_))))
                       (_%$%g247290247308%_ _%$%g247291247311%_))))
               (_%$%g247290247308%_ _%$%g247291247311%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (_%$%g247289247364%_
                                            _%$%hd247194247251%_))
                                         (let* ((_%$%g247367247386%_
                                                 (lambda (_%$%g247368247383%_)
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#raise-syntax-error
                                                      '#f
                                                      '"Bad syntax; invalid match target"
                                                      _%$%g247368247383%_))))
                                                (_%$%g247366247508%_
                                                 (lambda (_%$%g247368247389%_)
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%g247368247389%_))
                                                       (let ((_%$%e247370247391%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%g247368247389%_))))
                 (let ((_%$%hd247371247394%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e247370247391%_)))
                       (_%$%tl247372247396%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e247370247391%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-pair/null? _%$%tl247372247396%_))
                       (let ((_g250446_
                              (let ()
                                (declare (not safe))
                                (gx#syntax-split-splice
                                 _%$%tl247372247396%_
                                 '0))))
                         (begin
                           (let ((_g250447_
                                  (let ()
                                    (declare (not safe))
                                    (if (##values? _g250446_)
                                        (##values-length _g250446_)
                                        1))))
                             (if (not (let ()
                                        (declare (not safe))
                                        (##fx= _g250447_ 2)))
                                 (error "Context expects 2 values" _g250447_)))
                           (let ((_%$%target247373247399%_
                                  (let ()
                                    (declare (not safe))
                                    (##values-ref _g250446_ 0)))
                                 (_%$%tl247375247401%_
                                  (let ()
                                    (declare (not safe))
                                    (##values-ref _g250446_ 1))))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-null? _%$%tl247375247401%_))
                                 (letrec ((_%$%loop247376247404%_
                                           (lambda (_%$%hd247374247407%_
                                                    _%$%clause247380247409%_)
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair?
                                                    _%$%hd247374247407%_))
                                                 (let ((_%$%e247377247411%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%$%hd247374247407%_))))
                                                   (let ((_%$%lp-hd247378247414%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e247377247411%_)))
                                                         (_%$%lp-tl247379247416%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e247377247411%_))))
                                                     (_%$%loop247376247404%_
                                                      _%$%lp-tl247379247416%_
                                                      (cons _%$%lp-hd247378247414%_
                                                            _%$%clause247380247409%_))))
                                                 (let ((_%$%clause247381247419%_
                                                        (reverse _%$%clause247380247409%_)))
                                                   (for-each
                                                    (lambda (_%clause247434%_)
                                                      (let* ((_%$%g247436247451%_
                                                              (lambda (_%$%g247437247448%_)
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#raise-syntax-error
                           '#f
                           '"Bad syntax; invalid match target"
                           _%$%g247437247448%_))))
                     (_%$%g247435247498%_
                      (lambda (_%$%g247437247454%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%g247437247454%_))
                            (let ((_%$%e247441247456%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%g247437247454%_))))
                              (let ((_%$%hd247442247459%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e247441247456%_)))
                                    (_%$%tl247443247461%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e247441247456%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%hd247442247459%_))
                                    (let ((_%$%e247444247464%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%hd247442247459%_))))
                                      (let ((_%$%hd247445247467%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e247444247464%_)))
                                            (_%$%tl247446247469%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e247444247464%_))))
                                        (let ((_%receiver247492%_
                                               (let ((_%$e247489%_
                                                      (gxc#apply-extract-receiver
                                                       (cons (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#datum->syntax__0 '#f '%#begin))
                     _%$%tl247443247461%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (if _%$e247489%_
                                                     _%$e247489%_
                                                     _%$%hd247445247467%_))))
                                          (for-each
                                           (lambda (_%$%g247493247495%_)
                                             (gxc#apply-collect-object-refs__%
                                              '#f
                                              _%receiver247492%_
                                              _%method-calls246308%_
                                              _%slot-refs246309%_
                                              _%$%g247493247495%_))
                                           _%$%tl247443247461%_))))
                                    (_%$%g247436247451%_
                                     _%$%g247437247454%_))))
                            (_%$%g247436247451%_ _%$%g247437247454%_)))))
                (_%$%g247435247498%_ _%clause247434%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ((__tmp250448
                                                           (lambda (_%$%g247500247503%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            _%$%g247501247505%_)
                     (cons _%$%g247500247503%_ _%$%g247501247505%_))))
              (declare (not safe))
              (foldr__0 __tmp250448 '() _%$%clause247381247419%_))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                   (_%$%loop247376247404%_
                                    _%$%target247373247399%_
                                    '()))
                                 (_%$%g247367247386%_ _%$%g247368247389%_)))))
                       (_%$%g247367247386%_ _%$%g247368247389%_))))
               (_%$%g247367247386%_ _%$%g247368247389%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (_%$%g247366247508%_
                                            _%$%hd247197247259%_))
                                         (if (_%no-specializer?246312%_)
                                             _%stx246216%_
                                             (let* ((_%specializer-id247517%_
                                                     (let* ((_%id247511%_
                                                             (let ((__tmp250449
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%g246227246289%_))))
                       (declare (not safe))
                       (make-symbol__1 __tmp250449 '"::specialize")))
                    (_%specializer-id247514%_
                     (let ((__tmp250450
                            (let ()
                              (declare (not safe))
                              (gx#stx-source _%stx246216%_))))
                       (declare (not safe))
                       (gx#core-quote-syntax__1 _%id247511%_ __tmp250450))))
               (let ()
                 (declare (not safe))
                 (gx#core-bind-runtime!__0 _%specializer-id247514%_))
               _%specializer-id247514%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%$klass247519%_
                                                     (let ((__tmp250451
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##gensym
                                                               '__klass))))
                                                       (declare (not safe))
                                                       (make-symbol__0
                                                        __tmp250451)))
                                                    (_%$method-table247521%_
                                                     (let ((__tmp250452
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##gensym
                                                               '__method-table))))
                                                       (declare (not safe))
                                                       (make-symbol__0
                                                        __tmp250452)))
                                                    (_%methods247523%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (__hash-keys
                                                        _%method-calls246308%_)))
                                                    (_%$methods247527%_
                                                     (let ((__tmp250453
                                                            (lambda (_%id247525%_)
                                                              (let ((__tmp250454
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gensym _%id247525%_)))
                        (declare (not safe))
                        (make-symbol__1 '"__" __tmp250454)))))
               (declare (not safe))
               (##map __tmp250453 _%methods247523%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%_247536%_
                                                     (let ((__tmp250455
                                                            (lambda (_%$%g247528247531%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%$%g247529247533%_)
                      (let ()
                        (declare (not safe))
                        (__hash-put!
                         _%method-calls246308%_
                         _%$%g247528247531%_
                         _%$%g247529247533%_)))))
               (declare (not safe))
               (##for-each __tmp250455 _%methods247523%_ _%$methods247527%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%methods-bind247546%_
                                                     (let ((__tmp250456
                                                            (lambda (_%$%g247538247541%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%$%g247539247543%_)
                      (_%generate-method-bind246218%_
                       _%$klass247519%_
                       _%$method-table247521%_
                       _%$%g247538247541%_
                       _%$%g247539247543%_))))
               (declare (not safe))
               (##map __tmp250456 _%methods247523%_ _%$methods247527%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%slots247548%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (__hash-keys
                                                        _%slot-refs246309%_)))
                                                    (_%$slots247552%_
                                                     (let ((__tmp250457
                                                            (lambda (_%id247550%_)
                                                              (let ((__tmp250458
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             (gensym _%id247550%_)))
                        (declare (not safe))
                        (make-symbol__1 '"__" __tmp250458)))))
               (declare (not safe))
               (##map __tmp250457 _%slots247548%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%_247561%_
                                                     (let ((__tmp250459
                                                            (lambda (_%$%g247553247556%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%$%g247554247558%_)
                      (let ()
                        (declare (not safe))
                        (__hash-put!
                         _%slot-refs246309%_
                         _%$%g247553247556%_
                         _%$%g247554247558%_)))))
               (declare (not safe))
               (##for-each __tmp250459 _%slots247548%_ _%$slots247552%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%slots-bind247570%_
                                                     (let ((__tmp250460
                                                            (lambda (_%$%g247562247565%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             _%$%g247563247567%_)
                      (_%generate-slot-bind246219%_
                       _%$klass247519%_
                       _%$%g247562247565%_
                       _%$%g247563247567%_))))
               (declare (not safe))
               (##map __tmp250460 _%slots247548%_ _%$slots247552%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%specializer-lambda-expr247662%_
                                                     (let* ((_%$%g247572247590%_
                                                             (lambda (_%$%g247573247587%_)
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#raise-syntax-error
                          '#f
                          '"Bad syntax; invalid match target"
                          _%$%g247573247587%_))))
                    (_%$%g247571247659%_
                     (lambda (_%$%g247573247593%_)
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-pair? _%$%g247573247593%_))
                           (let ((_%$%e247577247595%_
                                  (let ()
                                    (declare (not safe))
                                    (gx#stx-e _%$%g247573247593%_))))
                             (let ((_%$%hd247578247598%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%e247577247595%_)))
                                   (_%$%tl247579247600%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%e247577247595%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%tl247579247600%_))
                                   (let ((_%$%e247580247603%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#stx-e _%$%tl247579247600%_))))
                                     (let ((_%$%hd247581247606%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e247580247603%_)))
                                           (_%$%tl247582247608%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e247580247603%_))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-pair?
                                              _%$%hd247581247606%_))
                                           (let ((_%$%e247583247611%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#stx-e
                                                     _%$%hd247581247606%_))))
                                             (let ((_%$%hd247584247614%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e247583247611%_)))
                                                   (_%$%tl247585247616%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e247583247611%_))))
                                               (let* ((_%receiver247650%_
                                                       (let ((_%$e247647%_
                                                              (gxc#apply-extract-receiver
                                                               (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (declare (not safe))
                               (gx#datum->syntax__0 '#f '%#begin))
                             _%$%tl247582247608%_))))
                 (if _%$e247647%_ _%$e247647%_ _%$%hd247584247614%_)))
              (_%body247656%_
               (map (lambda (_%$%g247651247653%_)
                      (gxc#apply-subst-object-refs__%
                       '#f
                       _%receiver247650%_
                       _%$klass247519%_
                       _%method-calls246308%_
                       _%slot-refs246309%_
                       _%$%g247651247653%_))
                    _%$%tl247582247608%_))
              (__tmp250461
               (cons '%#lambda
                     (cons (cons _%$%hd247584247614%_ _%$%tl247585247616%_)
                           _%body247656%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (declare (not safe))
                                                 (gxc#xform-wrap-source
                                                  __tmp250461
                                                  _%$%hd247194247251%_))))
                                           (_%$%g247572247590%_
                                            _%$%g247573247593%_))))
                                   (_%$%g247572247590%_ _%$%g247573247593%_))))
                           (_%$%g247572247590%_ _%$%g247573247593%_)))))
               (_%$%g247571247659%_ _%$%hd247194247251%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%specializer-case-lambda-expr247823%_
                                                     (let* ((_%$%g247664247683%_
                                                             (lambda (_%$%g247665247680%_)
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#raise-syntax-error
                          '#f
                          '"Bad syntax; invalid match target"
                          _%$%g247665247680%_))))
                    (_%$%g247663247820%_
                     (lambda (_%$%g247665247686%_)
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-pair? _%$%g247665247686%_))
                           (let ((_%$%e247667247688%_
                                  (let ()
                                    (declare (not safe))
                                    (gx#stx-e _%$%g247665247686%_))))
                             (let ((_%$%hd247668247691%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%e247667247688%_)))
                                   (_%$%tl247669247693%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%e247667247688%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair/null? _%$%tl247669247693%_))
                                   (let ((_g250462_
                                          (let ()
                                            (declare (not safe))
                                            (gx#syntax-split-splice
                                             _%$%tl247669247693%_
                                             '0))))
                                     (begin
                                       (let ((_g250463_
                                              (let ()
                                                (declare (not safe))
                                                (if (##values? _g250462_)
                                                    (##values-length _g250462_)
                                                    1))))
                                         (if (not (let ()
                                                    (declare (not safe))
                                                    (##fx= _g250463_ 2)))
                                             (error "Context expects 2 values"
                                                    _g250463_)))
                                       (let ((_%$%target247670247696%_
                                              (let ()
                                                (declare (not safe))
                                                (##values-ref _g250462_ 0)))
                                             (_%$%tl247672247698%_
                                              (let ()
                                                (declare (not safe))
                                                (##values-ref _g250462_ 1))))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-null?
                                                _%$%tl247672247698%_))
                                             (letrec ((_%$%loop247673247701%_
                                                       (lambda (_%$%hd247671247704%_
                                                                _%$%clause247677247706%_)
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-pair? _%$%hd247671247704%_))
                     (let ((_%$%e247674247708%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%hd247671247704%_))))
                       (let ((_%$%lp-hd247675247711%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%e247674247708%_)))
                             (_%$%lp-tl247676247713%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%e247674247708%_))))
                         (_%$%loop247673247701%_
                          _%$%lp-tl247676247713%_
                          (cons _%$%lp-hd247675247711%_
                                _%$%clause247677247706%_))))
                     (let* ((_%$%clause247678247716%_
                             (reverse _%$%clause247677247706%_))
                            (_%clauses247818%_
                             (map (lambda (_%clause247732%_)
                                    (let* ((_%__stx249255249256%_
                                            _%clause247732%_)
                                           (_%$%g247735247750%_
                                            (lambda ()
                                              (let ()
                                                (declare (not safe))
                                                (gx#raise-syntax-error
                                                 '#f
                                                 '"Bad syntax; invalid match target"
                                                 _%__stx249255249256%_)))))
                                      (let ((_%__kont249257249258%_
                                             (lambda (_%$%g247737247778%_
                                                      _%$%g247738247779%_
                                                      _%$%g247739247780%_)
                                               (let* ((_%receiver247799%_
                                                       (let ((_%$e247796%_
                                                              (gxc#apply-extract-receiver
                                                               (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                               (declare (not safe))
                               (gx#datum->syntax__0 '#f '%#begin))
                             _%$%g247737247778%_))))
                 (if _%$e247796%_ _%$e247796%_ _%$%g247739247780%_)))
              (_%body247805%_
               (map (lambda (_%$%g247800247802%_)
                      (gxc#apply-subst-object-refs__%
                       '#f
                       _%receiver247799%_
                       _%$klass247519%_
                       _%method-calls246308%_
                       _%slot-refs246309%_
                       _%$%g247800247802%_))
                    _%$%g247737247778%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (cons (cons _%$%g247739247780%_
                                                             _%$%g247738247779%_)
                                                       _%body247805%_))))
                                            (_%__kont249259249260%_
                                             (lambda () _%clause247732%_)))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%__stx249255249256%_))
                                            (let ((_%$%e247740247762%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%__stx249255249256%_))))
                                              (let ((_%$%tl247742247767%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e247740247762%_)))
                                                    (_%$%hd247741247765%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e247740247762%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%hd247741247765%_))
                                                    (let ((_%$%e247743247770%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%hd247741247765%_))))
                                                      (let ((_%$%tl247745247775%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e247743247770%_)))
                    (_%$%hd247744247773%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e247743247770%_))))
                (_%__kont249257249258%_
                 _%$%tl247742247767%_
                 _%$%tl247745247775%_
                 _%$%hd247744247773%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont249259249260%_))))
                                            (_%__kont249259249260%_)))))
                                  (let ((__tmp250464
                                         (lambda (_%$%g247810247813%_
                                                  _%$%g247811247815%_)
                                           (cons _%$%g247810247813%_
                                                 _%$%g247811247815%_))))
                                    (declare (not safe))
                                    (foldr__0
                                     __tmp250464
                                     '()
                                     _%$%clause247678247716%_))))
                            (__tmp250465
                             (cons '%#case-lambda _%clauses247818%_)))
                       (declare (not safe))
                       (gxc#xform-wrap-source
                        __tmp250465
                        _%$%hd247197247259%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%loop247673247701%_
                                                _%$%target247670247696%_
                                                '()))
                                             (_%$%g247664247683%_
                                              _%$%g247665247686%_)))))
                                   (_%$%g247664247683%_ _%$%g247665247686%_))))
                           (_%$%g247664247683%_ _%$%g247665247686%_)))))
               (_%$%g247663247820%_ _%$%hd247197247259%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%specializer-impl247825%_
                                                     (let ((__tmp250466
                                                            (cons '%#let-values
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons (cons (cons (cons _%$%hd247191247243%_ '())
                                            (cons _%specializer-lambda-expr247662%_
                                                  '()))
                                      '())
                                (cons _%specializer-case-lambda-expr247823%_
                                      '())))))
               (declare (not safe))
               (gxc#xform-wrap-source __tmp250466 _%stx246216%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%specializer-impl247827%_
                                                     (_%generate-specializer-impl246220%_
                                                      _%$klass247519%_
                                                      _%$method-table247521%_
                                                      _%methods-bind247546%_
                                                      _%slots-bind247570%_
                                                      _%specializer-impl247825%_)))
                                               (let ((__tmp250468
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%g246227246289%_)))
                                                     (__tmp250467
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%specializer-id247517%_))))
                                                 (declare (not safe))
                                                 (gxc#verbose
                                                  '"generate method specializer "
                                                  __tmp250468
                                                  '" => "
                                                  __tmp250467))
                                               (_%generate-specializer-def246221%_
                                                _%$%g246227246289%_
                                                _%specializer-id247517%_
                                                _%specializer-impl247827%_))))
                                       (_%$%g247173247203%_
                                        _%$%g247174247206%_))))
                               (_%$%g247173247203%_ _%$%g247174247206%_))
                           (_%$%g247173247203%_ _%$%g247174247206%_))
                       (_%$%g247173247203%_ _%$%g247174247206%_))))
               (_%$%g247173247203%_ _%$%g247174247206%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%g247173247203%_
                                                    _%$%g247174247206%_))))
                                           (_%$%g247173247203%_
                                            _%$%g247174247206%_))))
                                   (_%$%g247173247203%_ _%$%g247174247206%_))))
                           (_%$%g247173247203%_ _%$%g247174247206%_))))
                   (_%$%g247173247203%_ _%$%g247174247206%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%g247173247203%_
                                                    _%$%g247174247206%_)))))
                                       (_%$%g247172247830%_
                                        _%$%g246226246288%_))
                                     (if (let ()
                                           (declare (not safe))
                                           (gxc#kw-lambda-expr?
                                            _%$%g246226246288%_))
                                         (let* ((_%$%g247834247887%_
                                                 (lambda (_%$%g247835247884%_)
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#raise-syntax-error
                                                      '#f
                                                      '"Bad syntax; invalid match target"
                                                      _%$%g247835247884%_))))
                                                (_%$%g247833249052%_
                                                 (lambda (_%$%g247835247890%_)
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%g247835247890%_))
                                                       (let ((_%$%e247841247892%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%g247835247890%_))))
                 (let ((_%$%hd247842247895%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e247841247892%_)))
                       (_%$%tl247843247897%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e247841247892%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#identifier? _%$%hd247842247895%_))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-eq? '%#let-values _%$%hd247842247895%_))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-pair? _%$%tl247843247897%_))
                               (let ((_%$%e247844247900%_
                                      (let ()
                                        (declare (not safe))
                                        (gx#stx-e _%$%tl247843247897%_))))
                                 (let ((_%$%hd247845247903%_
                                        (let ()
                                          (declare (not safe))
                                          (##car _%$%e247844247900%_)))
                                       (_%$%tl247846247905%_
                                        (let ()
                                          (declare (not safe))
                                          (##cdr _%$%e247844247900%_))))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-pair? _%$%hd247845247903%_))
                                       (let ((_%$%e247847247908%_
                                              (let ()
                                                (declare (not safe))
                                                (gx#stx-e
                                                 _%$%hd247845247903%_))))
                                         (let ((_%$%hd247848247911%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##car _%$%e247847247908%_)))
                                               (_%$%tl247849247913%_
                                                (let ()
                                                  (declare (not safe))
                                                  (##cdr _%$%e247847247908%_))))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-pair?
                                                  _%$%hd247848247911%_))
                                               (let ((_%$%e247850247916%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%hd247848247911%_))))
                                                 (let ((_%$%hd247851247919%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e247850247916%_)))
                                                       (_%$%tl247852247921%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e247850247916%_))))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-pair?
                                                          _%$%hd247851247919%_))
                                                       (let ((_%$%e247853247924%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-e _%$%hd247851247919%_))))
                 (let ((_%$%hd247854247927%_
                        (let ()
                          (declare (not safe))
                          (##car _%$%e247853247924%_)))
                       (_%$%tl247855247929%_
                        (let ()
                          (declare (not safe))
                          (##cdr _%$%e247853247924%_))))
                   (if (let ()
                         (declare (not safe))
                         (gx#stx-null? _%$%tl247855247929%_))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-pair? _%$%tl247852247921%_))
                           (let ((_%$%e247856247932%_
                                  (let ()
                                    (declare (not safe))
                                    (gx#stx-e _%$%tl247852247921%_))))
                             (let ((_%$%hd247857247935%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%e247856247932%_)))
                                   (_%$%tl247858247937%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%e247856247932%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%hd247857247935%_))
                                   (let ((_%$%e247859247940%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#stx-e _%$%hd247857247935%_))))
                                     (let ((_%$%hd247860247943%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e247859247940%_)))
                                           (_%$%tl247861247945%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e247859247940%_))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#identifier?
                                              _%$%hd247860247943%_))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-eq?
                                                  '%#let-values
                                                  _%$%hd247860247943%_))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-pair?
                                                      _%$%tl247861247945%_))
                                                   (let ((_%$%e247862247948%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-e
                                                             _%$%tl247861247945%_))))
                                                     (let ((_%$%hd247863247951%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##car _%$%e247862247948%_)))
                                                           (_%$%tl247864247953%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (##cdr _%$%e247862247948%_))))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-pair?
                                                              _%$%hd247863247951%_))
                                                           (let ((_%$%e247865247956%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%hd247863247951%_))))
                     (let ((_%$%hd247866247959%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%e247865247956%_)))
                           (_%$%tl247867247961%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%e247865247956%_))))
                       (if (let ()
                             (declare (not safe))
                             (gx#stx-pair? _%$%hd247866247959%_))
                           (let ((_%$%e247868247964%_
                                  (let ()
                                    (declare (not safe))
                                    (gx#stx-e _%$%hd247866247959%_))))
                             (let ((_%$%hd247869247967%_
                                    (let ()
                                      (declare (not safe))
                                      (##car _%$%e247868247964%_)))
                                   (_%$%tl247870247969%_
                                    (let ()
                                      (declare (not safe))
                                      (##cdr _%$%e247868247964%_))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%hd247869247967%_))
                                   (let ((_%$%e247871247972%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#stx-e _%$%hd247869247967%_))))
                                     (let ((_%$%hd247872247975%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e247871247972%_)))
                                           (_%$%tl247873247977%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e247871247972%_))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-null?
                                              _%$%tl247873247977%_))
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-pair?
                                                  _%$%tl247870247969%_))
                                               (let ((_%$%e247874247980%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%tl247870247969%_))))
                                                 (let ((_%$%hd247875247983%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e247874247980%_)))
                                                       (_%$%tl247876247985%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e247874247980%_))))
                                                   (if (let ()
                                                         (declare (not safe))
                                                         (gx#stx-null?
                                                          _%$%tl247876247985%_))
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-null?
                                                              _%$%tl247867247961%_))
                                                           (if (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#stx-pair? _%$%tl247864247953%_))
                       (let ((_%$%e247877247988%_
                              (let ()
                                (declare (not safe))
                                (gx#stx-e _%$%tl247864247953%_))))
                         (let ((_%$%hd247878247991%_
                                (let ()
                                  (declare (not safe))
                                  (##car _%$%e247877247988%_)))
                               (_%$%tl247879247993%_
                                (let ()
                                  (declare (not safe))
                                  (##cdr _%$%e247877247988%_))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-null? _%$%tl247879247993%_))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-null? _%$%tl247858247937%_))
                                   (if (let ()
                                         (declare (not safe))
                                         (gx#stx-null? _%$%tl247849247913%_))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-pair?
                                              _%$%tl247846247905%_))
                                           (let ((_%$%e247880247996%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (gx#stx-e
                                                     _%$%tl247846247905%_))))
                                             (let ((_%$%hd247881247999%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##car _%$%e247880247996%_)))
                                                   (_%$%tl247882248001%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (##cdr _%$%e247880247996%_))))
                                               (if (let ()
                                                     (declare (not safe))
                                                     (gx#stx-null?
                                                      _%$%tl247882248001%_))
                                                   (let* ((_%$%g248048248110%_
                                                           (lambda (_%$%g248049248107%_)
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#raise-syntax-error
                        '#f
                        '"Bad syntax; invalid match target"
                        _%$%g248049248107%_))))
                  (_%$%g248047249049%_
                   (lambda (_%$%g248049248113%_)
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-pair? _%$%g248049248113%_))
                         (let ((_%$%e248055248115%_
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%g248049248113%_))))
                           (let ((_%$%hd248056248118%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%e248055248115%_)))
                                 (_%$%tl248057248120%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%e248055248115%_))))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#identifier? _%$%hd248056248118%_))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-eq?
                                        '%#lambda
                                        _%$%hd248056248118%_))
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-pair? _%$%tl248057248120%_))
                                         (let ((_%$%e248058248123%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#stx-e
                                                   _%$%tl248057248120%_))))
                                           (let ((_%$%hd248059248126%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e248058248123%_)))
                                                 (_%$%tl248060248128%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e248058248123%_))))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair?
                                                    _%$%tl248060248128%_))
                                                 (let ((_%$%e248061248131%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%$%tl248060248128%_))))
                                                   (let ((_%$%hd248062248134%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e248061248131%_)))
                                                         (_%$%tl248063248136%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e248061248131%_))))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-pair?
                                                            _%$%hd248062248134%_))
                                                         (let ((_%$%e248064248139%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-e _%$%hd248062248134%_))))
                   (let ((_%$%hd248065248142%_
                          (let ()
                            (declare (not safe))
                            (##car _%$%e248064248139%_)))
                         (_%$%tl248066248144%_
                          (let ()
                            (declare (not safe))
                            (##cdr _%$%e248064248139%_))))
                     (if (let ()
                           (declare (not safe))
                           (gx#identifier? _%$%hd248065248142%_))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-eq? '%#call _%$%hd248065248142%_))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-pair? _%$%tl248066248144%_))
                                 (let ((_%$%e248067248147%_
                                        (let ()
                                          (declare (not safe))
                                          (gx#stx-e _%$%tl248066248144%_))))
                                   (let ((_%$%hd248068248150%_
                                          (let ()
                                            (declare (not safe))
                                            (##car _%$%e248067248147%_)))
                                         (_%$%tl248069248152%_
                                          (let ()
                                            (declare (not safe))
                                            (##cdr _%$%e248067248147%_))))
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-pair? _%$%hd248068248150%_))
                                         (let ((_%$%e248070248155%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#stx-e
                                                   _%$%hd248068248150%_))))
                                           (let ((_%$%hd248071248158%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e248070248155%_)))
                                                 (_%$%tl248072248160%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e248070248155%_))))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#identifier?
                                                    _%$%hd248071248158%_))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-eq?
                                                        '%#ref
                                                        _%$%hd248071248158%_))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-pair?
                                                            _%$%tl248072248160%_))
                                                         (let ((_%$%e248073248163%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-e _%$%tl248072248160%_))))
                   (let ((_%$%hd248074248166%_
                          (let ()
                            (declare (not safe))
                            (##car _%$%e248073248163%_)))
                         (_%$%tl248075248168%_
                          (let ()
                            (declare (not safe))
                            (##cdr _%$%e248073248163%_))))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-null? _%$%tl248075248168%_))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-pair? _%$%tl248069248152%_))
                             (let ((_%$%e248076248171%_
                                    (let ()
                                      (declare (not safe))
                                      (gx#stx-e _%$%tl248069248152%_))))
                               (let ((_%$%hd248077248174%_
                                      (let ()
                                        (declare (not safe))
                                        (##car _%$%e248076248171%_)))
                                     (_%$%tl248078248176%_
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%$%e248076248171%_))))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-pair? _%$%hd248077248174%_))
                                     (let ((_%$%e248079248179%_
                                            (let ()
                                              (declare (not safe))
                                              (gx#stx-e
                                               _%$%hd248077248174%_))))
                                       (let ((_%$%hd248080248182%_
                                              (let ()
                                                (declare (not safe))
                                                (##car _%$%e248079248179%_)))
                                             (_%$%tl248081248184%_
                                              (let ()
                                                (declare (not safe))
                                                (##cdr _%$%e248079248179%_))))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#identifier?
                                                _%$%hd248080248182%_))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-eq?
                                                    '%#ref
                                                    _%$%hd248080248182%_))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-pair?
                                                        _%$%tl248081248184%_))
                                                     (let ((_%$%e248082248187%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%$%tl248081248184%_))))
                                                       (let ((_%$%hd248083248190%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##car _%$%e248082248187%_)))
                     (_%$%tl248084248192%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%e248082248187%_))))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-null? _%$%tl248084248192%_))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-pair? _%$%tl248078248176%_))
                         (let ((_%$%e248085248195%_
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%tl248078248176%_))))
                           (let ((_%$%hd248086248198%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%e248085248195%_)))
                                 (_%$%tl248087248200%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%e248085248195%_))))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-pair? _%$%hd248086248198%_))
                                 (let ((_%$%e248088248203%_
                                        (let ()
                                          (declare (not safe))
                                          (gx#stx-e _%$%hd248086248198%_))))
                                   (let ((_%$%hd248089248206%_
                                          (let ()
                                            (declare (not safe))
                                            (##car _%$%e248088248203%_)))
                                         (_%$%tl248090248208%_
                                          (let ()
                                            (declare (not safe))
                                            (##cdr _%$%e248088248203%_))))
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#identifier?
                                            _%$%hd248089248206%_))
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-eq?
                                                '%#ref
                                                _%$%hd248089248206%_))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair?
                                                    _%$%tl248090248208%_))
                                                 (let ((_%$%e248091248211%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%$%tl248090248208%_))))
                                                   (let ((_%$%hd248092248214%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e248091248211%_)))
                                                         (_%$%tl248093248216%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e248091248211%_))))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-null?
                                                            _%$%tl248093248216%_))
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#stx-pair/null? _%$%tl248087248200%_))
                     (if (let ((__tmp250469
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-length _%$%tl248087248200%_))))
                           (declare (not safe))
                           (##fx>= __tmp250469 '1))
                         (let ((_g250470_
                                (let ()
                                  (declare (not safe))
                                  (gx#syntax-split-splice
                                   _%$%tl248087248200%_
                                   '1))))
                           (begin
                             (let ((_g250471_
                                    (let ()
                                      (declare (not safe))
                                      (if (##values? _g250470_)
                                          (##values-length _g250470_)
                                          1))))
                               (if (not (let ()
                                          (declare (not safe))
                                          (##fx= _g250471_ 2)))
                                   (error "Context expects 2 values"
                                          _g250471_)))
                             (let ((_%$%target248094248219%_
                                    (let ()
                                      (declare (not safe))
                                      (##values-ref _g250470_ 0)))
                                   (_%$%tl248096248221%_
                                    (let ()
                                      (declare (not safe))
                                      (##values-ref _g250470_ 1))))
                               (if (let ()
                                     (declare (not safe))
                                     (gx#stx-pair? _%$%tl248096248221%_))
                                   (let ((_%$%e248103248224%_
                                          (let ()
                                            (declare (not safe))
                                            (gx#stx-e _%$%tl248096248221%_))))
                                     (let ((_%$%hd248104248227%_
                                            (let ()
                                              (declare (not safe))
                                              (##car _%$%e248103248224%_)))
                                           (_%$%tl248105248229%_
                                            (let ()
                                              (declare (not safe))
                                              (##cdr _%$%e248103248224%_))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-null?
                                              _%$%tl248105248229%_))
                                           (letrec ((_%$%loop248097248232%_
                                                     (lambda (_%$%hd248095248235%_
                                                              _%$%kw-ref248101248237%_)
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-pair?
                                                              _%$%hd248095248235%_))
                                                           (let ((_%$%e248098248239%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%hd248095248235%_))))
                     (let ((_%$%lp-hd248099248242%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%e248098248239%_)))
                           (_%$%lp-tl248100248244%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%e248098248239%_))))
                       (_%$%loop248097248232%_
                        _%$%lp-tl248100248244%_
                        (cons _%$%lp-hd248099248242%_
                              _%$%kw-ref248101248237%_))))
                   (let ((_%$%kw-ref248102248247%_
                          (reverse _%$%kw-ref248101248237%_)))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-null? _%$%tl248063248136%_))
                         (let* ((_%kw-count248304%_
                                 (length (let ((__tmp250472
                                                (lambda (_%$%g248296248299%_
                                                         _%$%g248297248301%_)
                                                  (cons _%$%g248296248299%_
                                                        _%$%g248297248301%_))))
                                           (declare (not safe))
                                           (foldr__0
                                            __tmp250472
                                            '()
                                            _%$%kw-ref248102248247%_))))
                                (_%self-index248306%_
                                 (let ()
                                   (declare (not safe))
                                   (##fx+ _%kw-count248304%_ '1))))
                           (if (let ()
                                 (declare (not safe))
                                 (gxc#lambda-expr? _%$%hd247875247983%_))
                               (let* ((_%$%g248310248324%_
                                       (lambda (_%$%g248311248321%_)
                                         (let ()
                                           (declare (not safe))
                                           (gx#raise-syntax-error
                                            '#f
                                            '"Bad syntax; invalid match target"
                                            _%$%g248311248321%_))))
                                      (_%$%g248309248447%_
                                       (lambda (_%$%g248311248327%_)
                                         (if (let ()
                                               (declare (not safe))
                                               (gx#stx-pair?
                                                _%$%g248311248327%_))
                                             (let ((_%$%e248314248329%_
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%$%g248311248327%_))))
                                               (let ((_%$%hd248315248332%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##car _%$%e248314248329%_)))
                                                     (_%$%tl248316248334%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (##cdr _%$%e248314248329%_))))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-pair?
                                                        _%$%tl248316248334%_))
                                                     (let ((_%$%e248317248337%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%$%tl248316248334%_))))
                                                       (let ((_%$%hd248318248340%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##car _%$%e248317248337%_)))
                     (_%$%tl248319248342%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%e248317248337%_))))
                 (let* ((_%self248363%_
                         (list-ref _%$%hd248318248340%_ _%self-index248306%_))
                        (_%receiver248368%_
                         (let ((_%$e248365%_
                                (gxc#apply-extract-receiver
                                 (cons (let ()
                                         (declare (not safe))
                                         (gx#datum->syntax__0 '#f '%#begin))
                                       _%$%tl248319248342%_))))
                           (if _%$e248365%_ _%$e248365%_ _%self248363%_))))
                   (for-each
                    (lambda (_%$%g248370248372%_)
                      (gxc#apply-collect-object-refs__%
                       '#f
                       _%receiver248368%_
                       _%method-calls246308%_
                       _%slot-refs246309%_
                       _%$%g248370248372%_))
                    _%$%tl248319248342%_)
                   (if (_%no-specializer?246312%_)
                       _%stx246216%_
                       (let* ((_%specializer-id248381%_
                               (let* ((_%id248375%_
                                       (let ((__tmp250473
                                              (let ()
                                                (declare (not safe))
                                                (gx#stx-e
                                                 _%$%g246227246289%_))))
                                         (declare (not safe))
                                         (make-symbol__1
                                          __tmp250473
                                          '"::specialize")))
                                      (_%specializer-id248378%_
                                       (let ((__tmp250474
                                              (let ()
                                                (declare (not safe))
                                                (gx#stx-source
                                                 _%stx246216%_))))
                                         (declare (not safe))
                                         (gx#core-quote-syntax__1
                                          _%id248375%_
                                          __tmp250474))))
                                 (let ()
                                   (declare (not safe))
                                   (gx#core-bind-runtime!__0
                                    _%specializer-id248378%_))
                                 _%specializer-id248378%_))
                              (_%$klass248383%_
                               (let ((__tmp250475
                                      (let ()
                                        (declare (not safe))
                                        (##gensym '__klass))))
                                 (declare (not safe))
                                 (make-symbol__0 __tmp250475)))
                              (_%$method-table248385%_
                               (let ((__tmp250476
                                      (let ()
                                        (declare (not safe))
                                        (##gensym '__method-table))))
                                 (declare (not safe))
                                 (make-symbol__0 __tmp250476)))
                              (_%methods248387%_
                               (let ()
                                 (declare (not safe))
                                 (__hash-keys _%method-calls246308%_)))
                              (_%$methods248391%_
                               (let ((__tmp250477
                                      (lambda (_%id248389%_)
                                        (let ((__tmp250478
                                               (gensym _%id248389%_)))
                                          (declare (not safe))
                                          (make-symbol__1
                                           '"__"
                                           __tmp250478)))))
                                 (declare (not safe))
                                 (##map __tmp250477 _%methods248387%_)))
                              (_%_248400%_
                               (let ((__tmp250479
                                      (lambda (_%$%g248392248395%_
                                               _%$%g248393248397%_)
                                        (let ()
                                          (declare (not safe))
                                          (__hash-put!
                                           _%method-calls246308%_
                                           _%$%g248392248395%_
                                           _%$%g248393248397%_)))))
                                 (declare (not safe))
                                 (##for-each
                                  __tmp250479
                                  _%methods248387%_
                                  _%$methods248391%_)))
                              (_%methods-bind248410%_
                               (let ((__tmp250480
                                      (lambda (_%$%g248402248405%_
                                               _%$%g248403248407%_)
                                        (_%generate-method-bind246218%_
                                         _%$klass248383%_
                                         _%$method-table248385%_
                                         _%$%g248402248405%_
                                         _%$%g248403248407%_))))
                                 (declare (not safe))
                                 (##map __tmp250480
                                        _%methods248387%_
                                        _%$methods248391%_)))
                              (_%slots248412%_
                               (let ()
                                 (declare (not safe))
                                 (__hash-keys _%slot-refs246309%_)))
                              (_%$slots248416%_
                               (let ((__tmp250481
                                      (lambda (_%id248414%_)
                                        (let ((__tmp250482
                                               (gensym _%id248414%_)))
                                          (declare (not safe))
                                          (make-symbol__1
                                           '"__"
                                           __tmp250482)))))
                                 (declare (not safe))
                                 (##map __tmp250481 _%slots248412%_)))
                              (_%_248425%_
                               (let ((__tmp250483
                                      (lambda (_%$%g248417248420%_
                                               _%$%g248418248422%_)
                                        (let ()
                                          (declare (not safe))
                                          (__hash-put!
                                           _%slot-refs246309%_
                                           _%$%g248417248420%_
                                           _%$%g248418248422%_)))))
                                 (declare (not safe))
                                 (##for-each
                                  __tmp250483
                                  _%slots248412%_
                                  _%$slots248416%_)))
                              (_%slots-bind248434%_
                               (let ((__tmp250484
                                      (lambda (_%$%g248426248429%_
                                               _%$%g248427248431%_)
                                        (_%generate-slot-bind246219%_
                                         _%$klass248383%_
                                         _%$%g248426248429%_
                                         _%$%g248427248431%_))))
                                 (declare (not safe))
                                 (##map __tmp250484
                                        _%slots248412%_
                                        _%$slots248416%_)))
                              (_%specializer-impl248442%_
                               (let* ((_%specializer-body248440%_
                                       (map (lambda (_%$%g248435248437%_)
                                              (gxc#apply-subst-object-refs__%
                                               '#f
                                               _%receiver248368%_
                                               _%$klass248383%_
                                               _%method-calls246308%_
                                               _%slot-refs246309%_
                                               _%$%g248435248437%_))
                                            _%$%tl248319248342%_))
                                      (__tmp250485
                                       (cons '%#let-values
                                             (cons (cons (cons (cons _%$%hd247854247927%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                             '())
                       (cons (cons '%#let-values
                                   (cons (cons (cons (cons _%$%hd247872247975%_
                                                           '())
                                                     (cons (let ((__tmp250486
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (cons '%#lambda
                                (cons _%$%hd248318248340%_
                                      _%specializer-body248440%_))))
                     (declare (not safe))
                     (gxc#xform-wrap-source __tmp250486 _%$%hd247875247983%_))
                   '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               '())
                                         (cons _%$%hd247878247991%_ '())))
                             '()))
                 '())
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (cons _%$%hd247881247999%_
                                                         '())))))
                                 (declare (not safe))
                                 (gxc#xform-wrap-source
                                  __tmp250485
                                  _%stx246216%_)))
                              (_%specializer-impl248444%_
                               (_%generate-specializer-impl246220%_
                                _%$klass248383%_
                                _%$method-table248385%_
                                _%methods-bind248410%_
                                _%slots-bind248434%_
                                _%specializer-impl248442%_)))
                         (let ((__tmp250488
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%g246227246289%_)))
                               (__tmp250487
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%specializer-id248381%_))))
                           (declare (not safe))
                           (gxc#verbose
                            '"generate method specializer "
                            __tmp250488
                            '" => "
                            __tmp250487))
                         (_%generate-specializer-def246221%_
                          _%$%g246227246289%_
                          _%specializer-id248381%_
                          _%specializer-impl248444%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248310248324%_
                                                      _%$%g248311248327%_))))
                                             (_%$%g248310248324%_
                                              _%$%g248311248327%_)))))
                                 (_%$%g248309248447%_ _%$%hd247875247983%_))
                               (if (let ()
                                     (declare (not safe))
                                     (gxc#opt-lambda-expr?
                                      _%$%hd247875247983%_))
                                   (let* ((_%$%g248451248481%_
                                           (lambda (_%$%g248452248478%_)
                                             (let ()
                                               (declare (not safe))
                                               (gx#raise-syntax-error
                                                '#f
                                                '"Bad syntax; invalid match target"
                                                _%$%g248452248478%_))))
                                          (_%$%g248450249045%_
                                           (lambda (_%$%g248452248484%_)
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-pair?
                                                    _%$%g248452248484%_))
                                                 (let ((_%$%e248456248486%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (gx#stx-e
                                                           _%$%g248452248484%_))))
                                                   (let ((_%$%hd248457248489%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##car _%$%e248456248486%_)))
                                                         (_%$%tl248458248491%_
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##cdr _%$%e248456248486%_))))
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (gx#stx-pair?
                                                            _%$%tl248458248491%_))
                                                         (let ((_%$%e248459248494%_
                                                                (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (declare (not safe))
                          (gx#stx-e _%$%tl248458248491%_))))
                   (let ((_%$%hd248460248497%_
                          (let ()
                            (declare (not safe))
                            (##car _%$%e248459248494%_)))
                         (_%$%tl248461248499%_
                          (let ()
                            (declare (not safe))
                            (##cdr _%$%e248459248494%_))))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-pair? _%$%hd248460248497%_))
                         (let ((_%$%e248462248502%_
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%hd248460248497%_))))
                           (let ((_%$%hd248463248505%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%e248462248502%_)))
                                 (_%$%tl248464248507%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%e248462248502%_))))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-pair? _%$%hd248463248505%_))
                                 (let ((_%$%e248465248510%_
                                        (let ()
                                          (declare (not safe))
                                          (gx#stx-e _%$%hd248463248505%_))))
                                   (let ((_%$%hd248466248513%_
                                          (let ()
                                            (declare (not safe))
                                            (##car _%$%e248465248510%_)))
                                         (_%$%tl248467248515%_
                                          (let ()
                                            (declare (not safe))
                                            (##cdr _%$%e248465248510%_))))
                                     (if (let ()
                                           (declare (not safe))
                                           (gx#stx-pair? _%$%hd248466248513%_))
                                         (let ((_%$%e248468248518%_
                                                (let ()
                                                  (declare (not safe))
                                                  (gx#stx-e
                                                   _%$%hd248466248513%_))))
                                           (let ((_%$%hd248469248521%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##car _%$%e248468248518%_)))
                                                 (_%$%tl248470248523%_
                                                  (let ()
                                                    (declare (not safe))
                                                    (##cdr _%$%e248468248518%_))))
                                             (if (let ()
                                                   (declare (not safe))
                                                   (gx#stx-null?
                                                    _%$%tl248470248523%_))
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-pair?
                                                        _%$%tl248467248515%_))
                                                     (let ((_%$%e248471248526%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%$%tl248467248515%_))))
                                                       (let ((_%$%hd248472248529%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##car _%$%e248471248526%_)))
                     (_%$%tl248473248531%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%e248471248526%_))))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-null? _%$%tl248473248531%_))
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-null? _%$%tl248464248507%_))
                         (if (let ()
                               (declare (not safe))
                               (gx#stx-pair? _%$%tl248461248499%_))
                             (let ((_%$%e248474248534%_
                                    (let ()
                                      (declare (not safe))
                                      (gx#stx-e _%$%tl248461248499%_))))
                               (let ((_%$%hd248475248537%_
                                      (let ()
                                        (declare (not safe))
                                        (##car _%$%e248474248534%_)))
                                     (_%$%tl248476248539%_
                                      (let ()
                                        (declare (not safe))
                                        (##cdr _%$%e248474248534%_))))
                                 (if (let ()
                                       (declare (not safe))
                                       (gx#stx-null? _%$%tl248476248539%_))
                                     (let ()
                                       (let* ((_%$%g248568248582%_
                                               (lambda (_%$%g248569248579%_)
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#raise-syntax-error
                                                    '#f
                                                    '"Bad syntax; invalid match target"
                                                    _%$%g248569248579%_))))
                                              (_%$%g248567248629%_
                                               (lambda (_%$%g248569248585%_)
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-pair?
                                                        _%$%g248569248585%_))
                                                     (let ((_%$%e248572248587%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%$%g248569248585%_))))
                                                       (let ((_%$%hd248573248590%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##car _%$%e248572248587%_)))
                     (_%$%tl248574248592%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%e248572248587%_))))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-pair? _%$%tl248574248592%_))
                     (let ((_%$%e248575248595%_
                            (let ()
                              (declare (not safe))
                              (gx#stx-e _%$%tl248574248592%_))))
                       (let ((_%$%hd248576248598%_
                              (let ()
                                (declare (not safe))
                                (##car _%$%e248575248595%_)))
                             (_%$%tl248577248600%_
                              (let ()
                                (declare (not safe))
                                (##cdr _%$%e248575248595%_))))
                         (let* ((_%self248617%_
                                 (list-ref
                                  _%$%hd248576248598%_
                                  _%self-index248306%_))
                                (_%receiver248622%_
                                 (let ((_%$e248619%_
                                        (gxc#apply-extract-receiver
                                         (cons (let ()
                                                 (declare (not safe))
                                                 (gx#datum->syntax__0
                                                  '#f
                                                  '%#begin))
                                               _%$%tl248577248600%_))))
                                   (if _%$e248619%_
                                       _%$e248619%_
                                       _%self248617%_))))
                           (for-each
                            (lambda (_%$%g248624248626%_)
                              (gxc#apply-collect-object-refs__%
                               '#f
                               _%receiver248622%_
                               _%method-calls246308%_
                               _%slot-refs246309%_
                               _%$%g248624248626%_))
                            _%$%tl248577248600%_))))
                     (_%$%g248568248582%_ _%$%g248569248585%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248568248582%_
                                                      _%$%g248569248585%_)))))
                                         (_%$%g248567248629%_
                                          _%$%hd248472248529%_))
                                       (let* ((_%$%g248632248651%_
                                               (lambda (_%$%g248633248648%_)
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#raise-syntax-error
                                                    '#f
                                                    '"Bad syntax; invalid match target"
                                                    _%$%g248633248648%_))))
                                              (_%$%g248631248760%_
                                               (lambda (_%$%g248633248654%_)
                                                 (if (let ()
                                                       (declare (not safe))
                                                       (gx#stx-pair?
                                                        _%$%g248633248654%_))
                                                     (let ((_%$%e248635248656%_
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-e
                                                               _%$%g248633248654%_))))
                                                       (let ((_%$%hd248636248659%_
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (##car _%$%e248635248656%_)))
                     (_%$%tl248637248661%_
                      (let ()
                        (declare (not safe))
                        (##cdr _%$%e248635248656%_))))
                 (if (let ()
                       (declare (not safe))
                       (gx#stx-pair/null? _%$%tl248637248661%_))
                     (let ((_g250489_
                            (let ()
                              (declare (not safe))
                              (gx#syntax-split-splice
                               _%$%tl248637248661%_
                               '0))))
                       (begin
                         (let ((_g250490_
                                (let ()
                                  (declare (not safe))
                                  (if (##values? _g250489_)
                                      (##values-length _g250489_)
                                      1))))
                           (if (not (let ()
                                      (declare (not safe))
                                      (##fx= _g250490_ 2)))
                               (error "Context expects 2 values" _g250490_)))
                         (let ((_%$%target248638248664%_
                                (let ()
                                  (declare (not safe))
                                  (##values-ref _g250489_ 0)))
                               (_%$%tl248640248666%_
                                (let ()
                                  (declare (not safe))
                                  (##values-ref _g250489_ 1))))
                           (if (let ()
                                 (declare (not safe))
                                 (gx#stx-null? _%$%tl248640248666%_))
                               (letrec ((_%$%loop248641248669%_
                                         (lambda (_%$%hd248639248672%_
                                                  _%$%clause248645248674%_)
                                           (if (let ()
                                                 (declare (not safe))
                                                 (gx#stx-pair?
                                                  _%$%hd248639248672%_))
                                               (let ((_%$%e248642248676%_
                                                      (let ()
                                                        (declare (not safe))
                                                        (gx#stx-e
                                                         _%$%hd248639248672%_))))
                                                 (let ((_%$%lp-hd248643248679%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##car _%$%e248642248676%_)))
                                                       (_%$%lp-tl248644248681%_
                                                        (let ()
                                                          (declare (not safe))
                                                          (##cdr _%$%e248642248676%_))))
                                                   (_%$%loop248641248669%_
                                                    _%$%lp-tl248644248681%_
                                                    (cons _%$%lp-hd248643248679%_
                                                          _%$%clause248645248674%_))))
                                               (let ((_%$%clause248646248684%_
                                                      (reverse _%$%clause248645248674%_)))
                                                 (for-each
                                                  (lambda (_%clause248699%_)
                                                    (let* ((_%$%g248701248712%_
                                                            (lambda (_%$%g248702248709%_)
                                                              (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#raise-syntax-error
                         '#f
                         '"Bad syntax; invalid match target"
                         _%$%g248702248709%_))))
                   (_%$%g248700248750%_
                    (lambda (_%$%g248702248715%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%g248702248715%_))
                          (let ((_%$%e248705248717%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%g248702248715%_))))
                            (let ((_%$%hd248706248720%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e248705248717%_)))
                                  (_%$%tl248707248722%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e248705248717%_))))
                              (let* ((_%self248738%_
                                      (list-ref
                                       _%$%hd248706248720%_
                                       _%self-index248306%_))
                                     (_%receiver248743%_
                                      (let ((_%$e248740%_
                                             (gxc#apply-extract-receiver
                                              (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       '%#begin))
                                                    _%$%tl248707248722%_))))
                                        (if _%$e248740%_
                                            _%$e248740%_
                                            _%self248738%_))))
                                (for-each
                                 (lambda (_%$%g248745248747%_)
                                   (gxc#apply-collect-object-refs__%
                                    '#f
                                    _%receiver248743%_
                                    _%method-calls246308%_
                                    _%slot-refs246309%_
                                    _%$%g248745248747%_))
                                 _%$%tl248707248722%_))))
                          (_%$%g248701248712%_ _%$%g248702248715%_)))))
              (_%$%g248700248750%_ _%clause248699%_)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (let ((__tmp250491
                                                         (lambda (_%$%g248752248755%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          _%$%g248753248757%_)
                   (cons _%$%g248752248755%_ _%$%g248753248757%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (declare (not safe))
                                                    (foldr__0
                                                     __tmp250491
                                                     '()
                                                     _%$%clause248646248684%_))))))))
                                 (_%$%loop248641248669%_
                                  _%$%target248638248664%_
                                  '()))
                               (_%$%g248632248651%_ _%$%g248633248654%_)))))
                     (_%$%g248632248651%_ _%$%g248633248654%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248632248651%_
                                                      _%$%g248633248654%_)))))
                                         (_%$%g248631248760%_
                                          _%$%hd248475248537%_))
                                       (if (_%no-specializer?246312%_)
                                           _%stx246216%_
                                           (let* ((_%specializer-id248769%_
                                                   (let* ((_%id248763%_
                                                           (let ((__tmp250492
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%g246227246289%_))))
                     (declare (not safe))
                     (make-symbol__1 __tmp250492 '"::specialize")))
                  (_%specializer-id248766%_
                   (let ((__tmp250493
                          (let ()
                            (declare (not safe))
                            (gx#stx-source _%stx246216%_))))
                     (declare (not safe))
                     (gx#core-quote-syntax__1 _%id248763%_ __tmp250493))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#core-bind-runtime!__0
                                                        _%specializer-id248766%_))
                                                     _%specializer-id248766%_))
                                                  (_%$klass248771%_
                                                   (let ((__tmp250494
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##gensym
                                                             '__klass))))
                                                     (declare (not safe))
                                                     (make-symbol__0
                                                      __tmp250494)))
                                                  (_%$method-table248773%_
                                                   (let ((__tmp250495
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (##gensym
                                                             '__method-table))))
                                                     (declare (not safe))
                                                     (make-symbol__0
                                                      __tmp250495)))
                                                  (_%methods248775%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (__hash-keys
                                                      _%method-calls246308%_)))
                                                  (_%$methods248779%_
                                                   (let ((__tmp250496
                                                          (lambda (_%id248777%_)
                                                            (let ((__tmp250497
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gensym _%id248777%_)))
                      (declare (not safe))
                      (make-symbol__1 '"__" __tmp250497)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (##map __tmp250496
                                                            _%methods248775%_)))
                                                  (_%_248788%_
                                                   (let ((__tmp250498
                                                          (lambda (_%$%g248780248783%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%g248781248785%_)
                    (let ()
                      (declare (not safe))
                      (__hash-put!
                       _%method-calls246308%_
                       _%$%g248780248783%_
                       _%$%g248781248785%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (##for-each
                                                      __tmp250498
                                                      _%methods248775%_
                                                      _%$methods248779%_)))
                                                  (_%methods-bind248798%_
                                                   (let ((__tmp250499
                                                          (lambda (_%$%g248790248793%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%g248791248795%_)
                    (_%generate-method-bind246218%_
                     _%$klass248771%_
                     _%$method-table248773%_
                     _%$%g248790248793%_
                     _%$%g248791248795%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (##map __tmp250499
                                                            _%methods248775%_
                                                            _%$methods248779%_)))
                                                  (_%slots248800%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (__hash-keys
                                                      _%slot-refs246309%_)))
                                                  (_%$slots248804%_
                                                   (let ((__tmp250500
                                                          (lambda (_%id248802%_)
                                                            (let ((__tmp250501
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gensym _%id248802%_)))
                      (declare (not safe))
                      (make-symbol__1 '"__" __tmp250501)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (##map __tmp250500
                                                            _%slots248800%_)))
                                                  (_%_248813%_
                                                   (let ((__tmp250502
                                                          (lambda (_%$%g248805248808%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%g248806248810%_)
                    (let ()
                      (declare (not safe))
                      (__hash-put!
                       _%slot-refs246309%_
                       _%$%g248805248808%_
                       _%$%g248806248810%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (##for-each
                                                      __tmp250502
                                                      _%slots248800%_
                                                      _%$slots248804%_)))
                                                  (_%slots-bind248822%_
                                                   (let ((__tmp250503
                                                          (lambda (_%$%g248814248817%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           _%$%g248815248819%_)
                    (_%generate-slot-bind246219%_
                     _%$klass248771%_
                     _%$%g248814248817%_
                     _%$%g248815248819%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (##map __tmp250503
                                                            _%slots248800%_
                                                            _%$slots248804%_)))
                                                  (_%specializer-lambda-expr248900%_
                                                   (let* ((_%$%g248824248838%_
                                                           (lambda (_%$%g248825248835%_)
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#raise-syntax-error
                        '#f
                        '"Bad syntax; invalid match target"
                        _%$%g248825248835%_))))
                  (_%$%g248823248897%_
                   (lambda (_%$%g248825248841%_)
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-pair? _%$%g248825248841%_))
                         (let ((_%$%e248828248843%_
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%g248825248841%_))))
                           (let ((_%$%hd248829248846%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%e248828248843%_)))
                                 (_%$%tl248830248848%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%e248828248843%_))))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-pair? _%$%tl248830248848%_))
                                 (let ((_%$%e248831248851%_
                                        (let ()
                                          (declare (not safe))
                                          (gx#stx-e _%$%tl248830248848%_))))
                                   (let ((_%$%hd248832248854%_
                                          (let ()
                                            (declare (not safe))
                                            (##car _%$%e248831248851%_)))
                                         (_%$%tl248833248856%_
                                          (let ()
                                            (declare (not safe))
                                            (##cdr _%$%e248831248851%_))))
                                     (let* ((_%self248883%_
                                             (list-ref
                                              _%$%hd248832248854%_
                                              _%self-index248306%_))
                                            (_%receiver248888%_
                                             (let ((_%$e248885%_
                                                    (gxc#apply-extract-receiver
                                                     (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#datum->syntax__0
                                                              '#f
                                                              '%#begin))
                                                           _%$%tl248833248856%_))))
                                               (if _%$e248885%_
                                                   _%$e248885%_
                                                   _%self248883%_)))
                                            (_%body248894%_
                                             (map (lambda (_%$%g248889248891%_)
                                                    (gxc#apply-subst-object-refs__%
                                                     '#f
                                                     _%receiver248888%_
                                                     _%$klass248771%_
                                                     _%method-calls246308%_
                                                     _%slot-refs246309%_
                                                     _%$%g248889248891%_))
                                                  _%$%tl248833248856%_))
                                            (__tmp250504
                                             (cons '%#lambda
                                                   (cons _%$%hd248832248854%_
                                                         _%body248894%_))))
                                       (declare (not safe))
                                       (gxc#xform-wrap-source
                                        __tmp250504
                                        _%$%hd248472248529%_))))
                                 (_%$%g248824248838%_ _%$%g248825248841%_))))
                         (_%$%g248824248838%_ _%$%g248825248841%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248823248897%_
                                                      _%$%hd248472248529%_)))
                                                  (_%specializer-case-lambda-expr249038%_
                                                   (let* ((_%$%g248902248921%_
                                                           (lambda (_%$%g248903248918%_)
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#raise-syntax-error
                        '#f
                        '"Bad syntax; invalid match target"
                        _%$%g248903248918%_))))
                  (_%$%g248901249035%_
                   (lambda (_%$%g248903248924%_)
                     (if (let ()
                           (declare (not safe))
                           (gx#stx-pair? _%$%g248903248924%_))
                         (let ((_%$%e248905248926%_
                                (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%g248903248924%_))))
                           (let ((_%$%hd248906248929%_
                                  (let ()
                                    (declare (not safe))
                                    (##car _%$%e248905248926%_)))
                                 (_%$%tl248907248931%_
                                  (let ()
                                    (declare (not safe))
                                    (##cdr _%$%e248905248926%_))))
                             (if (let ()
                                   (declare (not safe))
                                   (gx#stx-pair/null? _%$%tl248907248931%_))
                                 (let ((_g250505_
                                        (let ()
                                          (declare (not safe))
                                          (gx#syntax-split-splice
                                           _%$%tl248907248931%_
                                           '0))))
                                   (begin
                                     (let ((_g250506_
                                            (let ()
                                              (declare (not safe))
                                              (if (##values? _g250505_)
                                                  (##values-length _g250505_)
                                                  1))))
                                       (if (not (let ()
                                                  (declare (not safe))
                                                  (##fx= _g250506_ 2)))
                                           (error "Context expects 2 values"
                                                  _g250506_)))
                                     (let ((_%$%target248908248934%_
                                            (let ()
                                              (declare (not safe))
                                              (##values-ref _g250505_ 0)))
                                           (_%$%tl248910248936%_
                                            (let ()
                                              (declare (not safe))
                                              (##values-ref _g250505_ 1))))
                                       (if (let ()
                                             (declare (not safe))
                                             (gx#stx-null?
                                              _%$%tl248910248936%_))
                                           (letrec ((_%$%loop248911248939%_
                                                     (lambda (_%$%hd248909248942%_
                                                              _%$%clause248915248944%_)
                                                       (if (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-pair?
                                                              _%$%hd248909248942%_))
                                                           (let ((_%$%e248912248946%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%hd248909248942%_))))
                     (let ((_%$%lp-hd248913248949%_
                            (let ()
                              (declare (not safe))
                              (##car _%$%e248912248946%_)))
                           (_%$%lp-tl248914248951%_
                            (let ()
                              (declare (not safe))
                              (##cdr _%$%e248912248946%_))))
                       (_%$%loop248911248939%_
                        _%$%lp-tl248914248951%_
                        (cons _%$%lp-hd248913248949%_
                              _%$%clause248915248944%_))))
                   (let* ((_%$%clause248916248954%_
                           (reverse _%$%clause248915248944%_))
                          (_%clauses249033%_
                           (map (lambda (_%clause248970%_)
                                  (let* ((_%$%g248972248983%_
                                          (lambda (_%$%g248973248980%_)
                                            (let ()
                                              (declare (not safe))
                                              (gx#raise-syntax-error
                                               '#f
                                               '"Bad syntax; invalid match target"
                                               _%$%g248973248980%_))))
                                         (_%$%g248971249023%_
                                          (lambda (_%$%g248973248986%_)
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%g248973248986%_))
                                                (let ((_%$%e248976248988%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%g248973248986%_))))
                                                  (let ((_%$%hd248977248991%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e248976248988%_)))
                                                        (_%$%tl248978248993%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e248976248988%_))))
                                                    (let* ((_%self249009%_
                                                            (list-ref
                                                             _%$%hd248977248991%_
                                                             _%self-index248306%_))
                                                           (_%receiver249014%_
                                                            (let ((_%$e249011%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (gxc#apply-extract-receiver
                            (cons (let ()
                                    (declare (not safe))
                                    (gx#datum->syntax__0 '#f '%#begin))
                                  _%$%tl248978248993%_))))
                      (if _%$e249011%_ _%$e249011%_ _%self249009%_)))
                   (_%body249020%_
                    (map (lambda (_%$%g249015249017%_)
                           (gxc#apply-subst-object-refs__%
                            '#f
                            _%receiver249014%_
                            _%$klass248771%_
                            _%method-calls246308%_
                            _%slot-refs246309%_
                            _%$%g249015249017%_))
                         _%$%tl248978248993%_)))
              (cons _%$%hd248977248991%_ _%body249020%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%$%g248972248983%_
                                                 _%$%g248973248986%_)))))
                                    (_%$%g248971249023%_ _%clause248970%_)))
                                (let ((__tmp250507
                                       (lambda (_%$%g249025249028%_
                                                _%$%g249026249030%_)
                                         (cons _%$%g249025249028%_
                                               _%$%g249026249030%_))))
                                  (declare (not safe))
                                  (foldr__0
                                   __tmp250507
                                   '()
                                   _%$%clause248916248954%_))))
                          (__tmp250508
                           (cons '%#case-lambda _%clauses249033%_)))
                     (declare (not safe))
                     (gxc#xform-wrap-source
                      __tmp250508
                      _%$%hd248475248537%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             (_%$%loop248911248939%_
                                              _%$%target248908248934%_
                                              '()))
                                           (_%$%g248902248921%_
                                            _%$%g248903248924%_)))))
                                 (_%$%g248902248921%_ _%$%g248903248924%_))))
                         (_%$%g248902248921%_ _%$%g248903248924%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248901249035%_
                                                      _%$%hd248475248537%_)))
                                                  (_%specializer-impl249040%_
                                                   (let ((__tmp250509
                                                          (cons '%#let-values
                                                                (cons (cons (cons (cons _%$%hd247854247927%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                                '())
                                          (cons (cons '%#let-values
                                                      (cons (cons (cons (cons _%$%hd247872247975%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                      '())
                                (cons (let ((__tmp250510
                                             (cons '%#let-values
                                                   (cons (cons (cons (cons _%$%hd248469248521%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                   '())
                             (cons _%specializer-lambda-expr248900%_ '()))
                       '())
                 (cons _%specializer-case-lambda-expr249038%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                        (declare (not safe))
                                        (gxc#xform-wrap-source
                                         __tmp250510
                                         _%stx246216%_))
                                      '()))
                          '())
                    (cons _%$%hd247878247991%_ '())))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                '()))
                                    '())
                              (cons _%$%hd247881247999%_ '())))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (declare (not safe))
                                                     (gxc#xform-wrap-source
                                                      __tmp250509
                                                      _%stx246216%_)))
                                                  (_%specializer-impl249042%_
                                                   (_%generate-specializer-impl246220%_
                                                    _%$klass248771%_
                                                    _%$method-table248773%_
                                                    _%methods-bind248798%_
                                                    _%slots-bind248822%_
                                                    _%specializer-impl249040%_)))
                                             (let ((__tmp250512
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%$%g246227246289%_)))
                                                   (__tmp250511
                                                    (let ()
                                                      (declare (not safe))
                                                      (gx#stx-e
                                                       _%specializer-id248769%_))))
                                               (declare (not safe))
                                               (gxc#verbose
                                                '"generate method specializer "
                                                __tmp250512
                                                '" => "
                                                __tmp250511))
                                             (_%generate-specializer-def246221%_
                                              _%$%g246227246289%_
                                              _%specializer-id248769%_
                                              _%specializer-impl249042%_))))
                                     (_%$%g248451248481%_
                                      _%$%g248452248484%_))))
                             (_%$%g248451248481%_ _%$%g248452248484%_))
                         (_%$%g248451248481%_ _%$%g248452248484%_))
                     (_%$%g248451248481%_ _%$%g248452248484%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248451248481%_
                                                      _%$%g248452248484%_))
                                                 (_%$%g248451248481%_
                                                  _%$%g248452248484%_))))
                                         (_%$%g248451248481%_
                                          _%$%g248452248484%_))))
                                 (_%$%g248451248481%_ _%$%g248452248484%_))))
                         (_%$%g248451248481%_ _%$%g248452248484%_))))
                 (_%$%g248451248481%_ _%$%g248452248484%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g248451248481%_
                                                  _%$%g248452248484%_)))))
                                     (_%$%g248450249045%_
                                      _%$%hd247875247983%_))
                                   _%stx246216%_)))
                         (_%$%g248048248110%_ _%$%g248049248113%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                             (_%$%loop248097248232%_
                                              _%$%target248094248219%_
                                              '()))
                                           (_%$%g248048248110%_
                                            _%$%g248049248113%_))))
                                   (_%$%g248048248110%_
                                    _%$%g248049248113%_)))))
                         (_%$%g248048248110%_ _%$%g248049248113%_))
                     (_%$%g248048248110%_ _%$%g248049248113%_))
                 (_%$%g248048248110%_ _%$%g248049248113%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g248048248110%_
                                                  _%$%g248049248113%_))
                                             (_%$%g248048248110%_
                                              _%$%g248049248113%_))
                                         (_%$%g248048248110%_
                                          _%$%g248049248113%_))))
                                 (_%$%g248048248110%_ _%$%g248049248113%_))))
                         (_%$%g248048248110%_ _%$%g248049248113%_))
                     (_%$%g248048248110%_ _%$%g248049248113%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248048248110%_
                                                      _%$%g248049248113%_))
                                                 (_%$%g248048248110%_
                                                  _%$%g248049248113%_))
                                             (_%$%g248048248110%_
                                              _%$%g248049248113%_))))
                                     (_%$%g248048248110%_
                                      _%$%g248049248113%_))))
                             (_%$%g248048248110%_ _%$%g248049248113%_))
                         (_%$%g248048248110%_ _%$%g248049248113%_))))
                 (_%$%g248048248110%_ _%$%g248049248113%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248048248110%_
                                                      _%$%g248049248113%_))
                                                 (_%$%g248048248110%_
                                                  _%$%g248049248113%_))))
                                         (_%$%g248048248110%_
                                          _%$%g248049248113%_))))
                                 (_%$%g248048248110%_ _%$%g248049248113%_))
                             (_%$%g248048248110%_ _%$%g248049248113%_))
                         (_%$%g248048248110%_ _%$%g248049248113%_))))
                 (_%$%g248048248110%_ _%$%g248049248113%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                 (_%$%g248048248110%_
                                                  _%$%g248049248113%_))))
                                         (_%$%g248048248110%_
                                          _%$%g248049248113%_))
                                     (_%$%g248048248110%_ _%$%g248049248113%_))
                                 (_%$%g248048248110%_ _%$%g248049248113%_))))
                         (_%$%g248048248110%_ _%$%g248049248113%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (_%$%g248047249049%_
                                                      _%$%hd247878247991%_))
                                                   (_%$%g247834247887%_
                                                    _%$%g247835247890%_))))
                                           (_%$%g247834247887%_
                                            _%$%g247835247890%_))
                                       (_%$%g247834247887%_
                                        _%$%g247835247890%_))
                                   (_%$%g247834247887%_ _%$%g247835247890%_))
                               (_%$%g247834247887%_ _%$%g247835247890%_))))
                       (_%$%g247834247887%_ _%$%g247835247890%_))
                   (_%$%g247834247887%_ _%$%g247835247890%_))
               (_%$%g247834247887%_ _%$%g247835247890%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%g247834247887%_
                                                _%$%g247835247890%_))
                                           (_%$%g247834247887%_
                                            _%$%g247835247890%_))))
                                   (_%$%g247834247887%_ _%$%g247835247890%_))))
                           (_%$%g247834247887%_ _%$%g247835247890%_))))
                   (_%$%g247834247887%_ _%$%g247835247890%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   (_%$%g247834247887%_
                                                    _%$%g247835247890%_))
                                               (_%$%g247834247887%_
                                                _%$%g247835247890%_))
                                           (_%$%g247834247887%_
                                            _%$%g247835247890%_))))
                                   (_%$%g247834247887%_ _%$%g247835247890%_))))
                           (_%$%g247834247887%_ _%$%g247835247890%_))
                       (_%$%g247834247887%_ _%$%g247835247890%_))))
               (_%$%g247834247887%_ _%$%g247835247890%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                               (_%$%g247834247887%_
                                                _%$%g247835247890%_))))
                                       (_%$%g247834247887%_
                                        _%$%g247835247890%_))))
                               (_%$%g247834247887%_ _%$%g247835247890%_))
                           (_%$%g247834247887%_ _%$%g247835247890%_))
                       (_%$%g247834247887%_ _%$%g247835247890%_))))
               (_%$%g247834247887%_ _%$%g247835247890%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                           (_%$%g247833249052%_
                                            _%$%g246226246288%_))
                                         _%stx246216%_))))))))
                  (_%__kont249279249280%_ (lambda () _%stx246216%_)))
              (let ((_%__match249308249309%_
                     (lambda (_%$%e246228246256%_
                              _%$%hd246229246259%_
                              _%$%tl246230246261%_
                              _%$%e246231246264%_
                              _%$%hd246232246267%_
                              _%$%tl246233246269%_
                              _%$%e246234246272%_
                              _%$%hd246235246275%_
                              _%$%tl246236246277%_
                              _%$%e246237246280%_
                              _%$%hd246238246283%_
                              _%$%tl246239246285%_)
                       (let ((_%$%g246226246288%_ _%$%hd246238246283%_)
                             (_%$%g246227246289%_ _%$%hd246235246275%_))
                         (if (let ((__tmp250513
                                    (let ()
                                      (declare (not safe))
                                      (gxc#identifier-symbol
                                       _%$%g246227246289%_))))
                               (declare (not safe))
                               (gxc#optimizer-top-level-method? __tmp250513))
                             (_%__kont249277249278%_
                              _%$%g246226246288%_
                              _%$%g246227246289%_)
                             (_%__kont249279249280%_))))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%__stx249275249276%_))
                    (let ((_%$%e246228246256%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%__stx249275249276%_))))
                      (let ((_%$%tl246230246261%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e246228246256%_)))
                            (_%$%hd246229246259%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e246228246256%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl246230246261%_))
                            (let ((_%$%e246231246264%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl246230246261%_))))
                              (let ((_%$%tl246233246269%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e246231246264%_)))
                                    (_%$%hd246232246267%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e246231246264%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%hd246232246267%_))
                                    (let ((_%$%e246234246272%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%hd246232246267%_))))
                                      (let ((_%$%tl246236246277%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e246234246272%_)))
                                            (_%$%hd246235246275%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e246234246272%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl246236246277%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl246233246269%_))
                                                (let ((_%$%e246237246280%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl246233246269%_))))
                                                  (let ((_%$%tl246239246285%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e246237246280%_)))
                                                        (_%$%hd246238246283%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e246237246280%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl246239246285%_))
                                                        (_%__match249308249309%_
                                                         _%$%e246228246256%_
                                                         _%$%hd246229246259%_
                                                         _%$%tl246230246261%_
                                                         _%$%e246231246264%_
                                                         _%$%hd246232246267%_
                                                         _%$%tl246233246269%_
                                                         _%$%e246234246272%_
                                                         _%$%hd246235246275%_
                                                         _%$%tl246236246277%_
                                                         _%$%e246237246280%_
                                                         _%$%hd246238246283%_
                                                         _%$%tl246239246285%_)
                                                        (_%__kont249279249280%_))))
                                                (_%__kont249279249280%_))
                                            (_%__kont249279249280%_))))
                                    (_%__kont249279249280%_))))
                            (_%__kont249279249280%_))))
                    (_%__kont249279249280%_))))))))
    (define gxc#extract-receiver-begin-annotation%
      (lambda (_%self246068%_ _%stx246069%_)
        (let* ((_%__stx249311249312%_ _%stx246069%_)
               (_%$%g246072246105%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx249311249312%_)))))
          (let ((_%__kont249313249314%_
                 (lambda (_%$%g246074246195%_) _%$%g246074246195%_))
                (_%__kont249315249316%_
                 (lambda (_%$%g246090246134%_ _%$%g246091246135%_)
                   (let ()
                     (declare (not safe))
                     (gxc#compile-e__1 _%self246068%_ _%$%g246090246134%_)))))
            (if (let ()
                  (declare (not safe))
                  (gx#stx-pair? _%__stx249311249312%_))
                (let ((_%$%e246075246155%_
                       (let ()
                         (declare (not safe))
                         (gx#stx-e _%__stx249311249312%_))))
                  (let ((_%$%tl246077246160%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%e246075246155%_)))
                        (_%$%hd246076246158%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%e246075246155%_))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl246077246160%_))
                        (let ((_%$%e246078246163%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl246077246160%_))))
                          (let ((_%$%tl246080246168%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e246078246163%_)))
                                (_%$%hd246079246166%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e246078246163%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%hd246079246166%_))
                                (let ((_%$%e246081246171%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%hd246079246166%_))))
                                  (let ((_%$%tl246083246176%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e246081246171%_)))
                                        (_%$%hd246082246174%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e246081246171%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#identifier?
                                           _%$%hd246082246174%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-eq?
                                               '@receiver
                                               _%$%hd246082246174%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl246083246176%_))
                                                (let ((_%$%e246084246179%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl246083246176%_))))
                                                  (let ((_%$%tl246086246184%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e246084246179%_)))
                                                        (_%$%hd246085246182%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e246084246179%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl246086246184%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%tl246080246168%_))
                                                            (let ((_%$%e246087246187%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl246080246168%_))))
                      (let ((_%$%tl246089246192%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e246087246187%_)))
                            (_%$%hd246088246190%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e246087246187%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl246089246192%_))
                            (_%__kont249313249314%_ _%$%hd246085246182%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g246072246105%_)))))
                    (let () (declare (not safe)) (_%$%g246072246105%_)))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%$%tl246080246168%_))
                    (let ((_%$%e246098246126%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl246080246168%_))))
                      (let ((_%$%tl246100246131%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e246098246126%_)))
                            (_%$%hd246099246129%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e246098246126%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl246100246131%_))
                            (_%__kont249315249316%_
                             _%$%hd246099246129%_
                             _%$%hd246079246166%_)
                            (let ()
                              (declare (not safe))
                              (_%$%g246072246105%_)))))
                    (let () (declare (not safe)) (_%$%g246072246105%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%tl246080246168%_))
                                                    (let ((_%$%e246098246126%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%tl246080246168%_))))
                                                      (let ((_%$%tl246100246131%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e246098246126%_)))
                    (_%$%hd246099246129%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e246098246126%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl246100246131%_))
                    (_%__kont249315249316%_
                     _%$%hd246099246129%_
                     _%$%hd246079246166%_)
                    (let () (declare (not safe)) (_%$%g246072246105%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g246072246105%_))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl246080246168%_))
                                                (let ((_%$%e246098246126%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl246080246168%_))))
                                                  (let ((_%$%tl246100246131%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e246098246126%_)))
                                                        (_%$%hd246099246129%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e246098246126%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl246100246131%_))
                                                        (_%__kont249315249316%_
                                                         _%$%hd246099246129%_
                                                         _%$%hd246079246166%_)
                                                        (let ()
                                                          (declare (not safe))
                                                          (_%$%g246072246105%_)))))
                                                (let ()
                                                  (declare (not safe))
                                                  (_%$%g246072246105%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl246080246168%_))
                                            (let ((_%$%e246098246126%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl246080246168%_))))
                                              (let ((_%$%tl246100246131%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e246098246126%_)))
                                                    (_%$%hd246099246129%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e246098246126%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl246100246131%_))
                                                    (_%__kont249315249316%_
                                                     _%$%hd246099246129%_
                                                     _%$%hd246079246166%_)
                                                    (let ()
                                                      (declare (not safe))
                                                      (_%$%g246072246105%_)))))
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g246072246105%_))))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%tl246080246168%_))
                                    (let ((_%$%e246098246126%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%tl246080246168%_))))
                                      (let ((_%$%tl246100246131%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e246098246126%_)))
                                            (_%$%hd246099246129%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e246098246126%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl246100246131%_))
                                            (_%__kont249315249316%_
                                             _%$%hd246099246129%_
                                             _%$%hd246079246166%_)
                                            (let ()
                                              (declare (not safe))
                                              (_%$%g246072246105%_)))))
                                    (let ()
                                      (declare (not safe))
                                      (_%$%g246072246105%_))))))
                        (let () (declare (not safe)) (_%$%g246072246105%_)))))
                (let () (declare (not safe)) (_%$%g246072246105%_)))))))
    (define gxc#extract-receiver-if%
      (lambda (_%self245984%_ _%stx245985%_)
        (let* ((_%$%g245987246008%_
                (lambda (_%$%g245988246005%_)
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%$%g245988246005%_))))
               (_%$%g245986246065%_
                (lambda (_%$%g245988246011%_)
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-pair? _%$%g245988246011%_))
                      (let ((_%$%e245992246013%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%g245988246011%_))))
                        (let ((_%$%hd245993246016%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e245992246013%_)))
                              (_%$%tl245994246018%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e245992246013%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl245994246018%_))
                              (let ((_%$%e245995246021%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl245994246018%_))))
                                (let ((_%$%hd245996246024%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e245995246021%_)))
                                      (_%$%tl245997246026%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e245995246021%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%tl245997246026%_))
                                      (let ((_%$%e245998246029%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%tl245997246026%_))))
                                        (let ((_%$%hd245999246032%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e245998246029%_)))
                                              (_%$%tl246000246034%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e245998246029%_))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl246000246034%_))
                                              (let ((_%$%e246001246037%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl246000246034%_))))
                                                (let ((_%$%hd246002246040%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e246001246037%_)))
                                                      (_%$%tl246003246042%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e246001246037%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl246003246042%_))
                                                      (let ()
                                                        (declare (not safe))
                                                        (gxc#compile-e__1
                                                         _%self245984%_
                                                         _%$%hd245999246032%_))
                                                      (_%$%g245987246008%_
                                                       _%$%g245988246011%_))))
                                              (_%$%g245987246008%_
                                               _%$%g245988246011%_))))
                                      (_%$%g245987246008%_
                                       _%$%g245988246011%_))))
                              (_%$%g245987246008%_ _%$%g245988246011%_))))
                      (_%$%g245987246008%_ _%$%g245988246011%_)))))
          (_%$%g245986246065%_ _%stx245985%_))))
    (define gxc#collect-object-refs-call%
      (lambda (_%self244949%_ _%stx244950%_)
        (let* ((_%__stx249377249378%_ _%stx244950%_)
               (_%$%g244958245180%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx249377249378%_)))))
          (let ((_%__kont249379249380%_
                 (lambda (_%$%g244960245933%_
                          _%$%g244961245934%_
                          _%$%g244962245935%_
                          _%$%g244963245936%_)
                   (let ((__tmp250515
                          (let ()
                            (declare (not safe))
                            (slot-ref__0 _%self244949%_ 'methods)))
                         (__tmp250514
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%g244961245934%_))))
                     (declare (not safe))
                     (hash-put! __tmp250515 __tmp250514 '#t))
                   (for-each
                    (lambda (_%$%g245969245971%_)
                      (let ()
                        (declare (not safe))
                        (gxc#compile-e__1 _%self244949%_ _%$%g245969245971%_)))
                    (let ((__tmp250516
                           (lambda (_%$%g245973245976%_ _%$%g245974245978%_)
                             (cons _%$%g245973245976%_ _%$%g245974245978%_))))
                      (declare (not safe))
                      (foldr__0 __tmp250516 '() _%$%g244960245933%_)))))
                (_%__kont249383249384%_
                 (lambda (_%$%g245003245770%_
                          _%$%g245004245771%_
                          _%$%g245005245772%_
                          _%$%g245006245773%_
                          _%$%g245007245774%_)
                   (let ((__tmp250518
                          (let ()
                            (declare (not safe))
                            (slot-ref__0 _%self244949%_ 'methods)))
                         (__tmp250517
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%g245004245771%_))))
                     (declare (not safe))
                     (hash-put! __tmp250518 __tmp250517 '#t))
                   (for-each
                    (lambda (_%$%g245814245816%_)
                      (let ()
                        (declare (not safe))
                        (gxc#compile-e__1 _%self244949%_ _%$%g245814245816%_)))
                    (let ((__tmp250519
                           (lambda (_%$%g245818245821%_ _%$%g245819245823%_)
                             (cons _%$%g245818245821%_ _%$%g245819245823%_))))
                      (declare (not safe))
                      (foldr__0 __tmp250519 '() _%$%g245003245770%_)))))
                (_%__kont249387249388%_
                 (lambda (_%$%g245056245605%_
                          _%$%g245057245606%_
                          _%$%g245058245607%_)
                   (let ((__tmp250521
                          (let ()
                            (declare (not safe))
                            (slot-ref__0 _%self244949%_ 'slots)))
                         (__tmp250520
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%g245056245605%_))))
                     (declare (not safe))
                     (hash-put! __tmp250521 __tmp250520 '#t))))
                (_%__kont249389249390%_
                 (lambda (_%$%g245089245482%_
                          _%$%g245090245483%_
                          _%$%g245091245484%_
                          _%$%g245092245485%_)
                   (let ((__tmp250523
                          (let ()
                            (declare (not safe))
                            (slot-ref__0 _%self244949%_ 'slots)))
                         (__tmp250522
                          (let ()
                            (declare (not safe))
                            (gx#stx-e _%$%g245090245483%_))))
                     (declare (not safe))
                     (hash-put! __tmp250523 __tmp250522 '#t))
                   (let ()
                     (declare (not safe))
                     (gxc#compile-e__1 _%self244949%_ _%$%g245089245482%_))))
                (_%__kont249391249392%_
                 (lambda (_%$%g245126245356%_ _%$%g245127245357%_)
                   (let* ((_%accessor245379%_
                           (let ((__tmp250524
                                  (let ()
                                    (declare (not safe))
                                    (gxc#identifier-symbol
                                     _%$%g245127245357%_))))
                             (declare (not safe))
                             (gxc#optimizer-resolve-type __tmp250524)))
                          (_%klass245381%_
                           (let ((__tmp250525
                                  (##structure-ref
                                   _%accessor245379%_
                                   '1
                                   gxc#!type::t
                                   '#f)))
                             (declare (not safe))
                             (gxc#optimizer-resolve-class
                              _%stx244950%_
                              __tmp250525)))
                          (_%slot245383%_
                           (##structure-ref
                            _%accessor245379%_
                            '3
                            gxc#!accessor::t
                            '#f)))
                     (if (if (##structure-ref
                              _%accessor245379%_
                              '4
                              gxc#!accessor::t
                              '#f)
                             '#f
                             (or (let ()
                                   (declare (not safe))
                                   (gxc#!class-struct-slot?
                                    _%klass245381%_
                                    _%slot245383%_))
                                 (let ()
                                   (declare (not safe))
                                   (##unchecked-structure-ref
                                    _%klass245381%_
                                    '8
                                    '#f
                                    '#f))))
                         '#!void
                         (let ((__tmp250527
                                (let ()
                                  (declare (not safe))
                                  (slot-ref__0 _%self244949%_ 'slots)))
                               (__tmp250526
                                (##structure-ref
                                 _%accessor245379%_
                                 '3
                                 gxc#!accessor::t
                                 '#f)))
                           (declare (not safe))
                           (hash-put! __tmp250527 __tmp250526 '#t))))))
                (_%__kont249393249394%_
                 (lambda (_%$%g245149245256%_
                          _%$%g245150245257%_
                          _%$%g245151245258%_)
                   (let* ((_%mutator245285%_
                           (let ((__tmp250528
                                  (let ()
                                    (declare (not safe))
                                    (gxc#identifier-symbol
                                     _%$%g245151245258%_))))
                             (declare (not safe))
                             (gxc#optimizer-resolve-type __tmp250528)))
                          (_%klass245287%_
                           (let ((__tmp250529
                                  (##structure-ref
                                   _%mutator245285%_
                                   '1
                                   gxc#!type::t
                                   '#f)))
                             (declare (not safe))
                             (gxc#optimizer-resolve-class
                              _%stx244950%_
                              __tmp250529)))
                          (_%slot245289%_
                           (##structure-ref
                            _%mutator245285%_
                            '3
                            gxc#!mutator::t
                            '#f)))
                     (if (if (##structure-ref
                              _%mutator245285%_
                              '4
                              gxc#!mutator::t
                              '#f)
                             '#f
                             (or (let ()
                                   (declare (not safe))
                                   (gxc#!class-struct-slot?
                                    _%klass245287%_
                                    _%slot245289%_))
                                 (let ()
                                   (declare (not safe))
                                   (##unchecked-structure-ref
                                    _%klass245287%_
                                    '8
                                    '#f
                                    '#f))))
                         '#!void
                         (let ((__tmp250530
                                (let ()
                                  (declare (not safe))
                                  (slot-ref__0 _%self244949%_ 'slots))))
                           (declare (not safe))
                           (hash-put! __tmp250530 _%slot245289%_ '#t)))
                     (let ()
                       (declare (not safe))
                       (gxc#compile-e__1
                        _%self244949%_
                        _%$%g245149245256%_)))))
                (_%__kont249395249396%_
                 (lambda ()
                   (let ()
                     (declare (not safe))
                     (gxc#apply-operands _%self244949%_ _%stx244950%_)))))
            (let* ((_%__match249876249877%_
                    (lambda (_%$%e245152245192%_
                             _%$%hd245153245195%_
                             _%$%tl245154245197%_
                             _%$%e245155245200%_
                             _%$%hd245156245203%_
                             _%$%tl245157245205%_
                             _%$%e245158245208%_
                             _%$%hd245159245211%_
                             _%$%tl245160245213%_
                             _%$%e245161245216%_
                             _%$%hd245162245219%_
                             _%$%tl245163245221%_
                             _%$%e245164245224%_
                             _%$%hd245165245227%_
                             _%$%tl245166245229%_
                             _%$%e245167245232%_
                             _%$%hd245168245235%_
                             _%$%tl245169245237%_
                             _%$%e245170245240%_
                             _%$%hd245171245243%_
                             _%$%tl245172245245%_
                             _%$%e245173245248%_
                             _%$%hd245174245251%_
                             _%$%tl245175245253%_)
                      (let ((_%$%g245149245256%_ _%$%hd245174245251%_)
                            (_%$%g245150245257%_ _%$%hd245171245243%_)
                            (_%$%g245151245258%_ _%$%hd245162245219%_))
                        (if (and (let ((__tmp250531
                                        (let ((__tmp250532
                                               (let ()
                                                 (declare (not safe))
                                                 (gxc#identifier-symbol
                                                  _%$%g245151245258%_))))
                                          (declare (not safe))
                                          (gxc#optimizer-resolve-type
                                           __tmp250532))))
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    __tmp250531
                                    'gxc#!mutator::t))
                                 (let ((__tmp250533
                                        (let ()
                                          (declare (not safe))
                                          (slot-ref__0
                                           _%self244949%_
                                           'receiver))))
                                   (declare (not safe))
                                   (gx#free-identifier=?
                                    _%$%g245150245257%_
                                    __tmp250533)))
                            (_%__kont249393249394%_
                             _%$%g245149245256%_
                             _%$%g245150245257%_
                             _%$%g245151245258%_)
                            (_%__kont249395249396%_)))))
                   (_%__match249874249875%_
                    (lambda (_%$%e245152245192%_
                             _%$%hd245153245195%_
                             _%$%tl245154245197%_
                             _%$%e245155245200%_
                             _%$%hd245156245203%_
                             _%$%tl245157245205%_
                             _%$%e245158245208%_
                             _%$%hd245159245211%_
                             _%$%tl245160245213%_
                             _%$%e245161245216%_
                             _%$%hd245162245219%_
                             _%$%tl245163245221%_
                             _%$%e245164245224%_
                             _%$%hd245165245227%_
                             _%$%tl245166245229%_
                             _%$%e245167245232%_
                             _%$%hd245168245235%_
                             _%$%tl245169245237%_
                             _%$%e245170245240%_
                             _%$%hd245171245243%_
                             _%$%tl245172245245%_
                             _%$%e245173245248%_
                             _%$%hd245174245251%_
                             _%$%tl245175245253%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl245175245253%_))
                          (_%__match249876249877%_
                           _%$%e245152245192%_
                           _%$%hd245153245195%_
                           _%$%tl245154245197%_
                           _%$%e245155245200%_
                           _%$%hd245156245203%_
                           _%$%tl245157245205%_
                           _%$%e245158245208%_
                           _%$%hd245159245211%_
                           _%$%tl245160245213%_
                           _%$%e245161245216%_
                           _%$%hd245162245219%_
                           _%$%tl245163245221%_
                           _%$%e245164245224%_
                           _%$%hd245165245227%_
                           _%$%tl245166245229%_
                           _%$%e245167245232%_
                           _%$%hd245168245235%_
                           _%$%tl245169245237%_
                           _%$%e245170245240%_
                           _%$%hd245171245243%_
                           _%$%tl245172245245%_
                           _%$%e245173245248%_
                           _%$%hd245174245251%_
                           _%$%tl245175245253%_)
                          (_%__kont249395249396%_))))
                   (_%__match249868249869%_
                    (lambda (_%$%e245152245192%_
                             _%$%hd245153245195%_
                             _%$%tl245154245197%_
                             _%$%e245155245200%_
                             _%$%hd245156245203%_
                             _%$%tl245157245205%_
                             _%$%e245158245208%_
                             _%$%hd245159245211%_
                             _%$%tl245160245213%_
                             _%$%e245161245216%_
                             _%$%hd245162245219%_
                             _%$%tl245163245221%_
                             _%$%e245164245224%_
                             _%$%hd245165245227%_
                             _%$%tl245166245229%_
                             _%$%e245167245232%_
                             _%$%hd245168245235%_
                             _%$%tl245169245237%_
                             _%$%e245170245240%_
                             _%$%hd245171245243%_
                             _%$%tl245172245245%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl245166245229%_))
                          (let ((_%$%e245173245248%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl245166245229%_))))
                            (let ((_%$%tl245175245253%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e245173245248%_)))
                                  (_%$%hd245174245251%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e245173245248%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl245175245253%_))
                                  (_%__match249876249877%_
                                   _%$%e245152245192%_
                                   _%$%hd245153245195%_
                                   _%$%tl245154245197%_
                                   _%$%e245155245200%_
                                   _%$%hd245156245203%_
                                   _%$%tl245157245205%_
                                   _%$%e245158245208%_
                                   _%$%hd245159245211%_
                                   _%$%tl245160245213%_
                                   _%$%e245161245216%_
                                   _%$%hd245162245219%_
                                   _%$%tl245163245221%_
                                   _%$%e245164245224%_
                                   _%$%hd245165245227%_
                                   _%$%tl245166245229%_
                                   _%$%e245167245232%_
                                   _%$%hd245168245235%_
                                   _%$%tl245169245237%_
                                   _%$%e245170245240%_
                                   _%$%hd245171245243%_
                                   _%$%tl245172245245%_
                                   _%$%e245173245248%_
                                   _%$%hd245174245251%_
                                   _%$%tl245175245253%_)
                                  (_%__kont249395249396%_))))
                          (_%__kont249395249396%_))))
                   (_%__match249814249815%_
                    (lambda (_%$%e245128245300%_
                             _%$%hd245129245303%_
                             _%$%tl245130245305%_
                             _%$%e245131245308%_
                             _%$%hd245132245311%_
                             _%$%tl245133245313%_
                             _%$%e245134245316%_
                             _%$%hd245135245319%_
                             _%$%tl245136245321%_
                             _%$%e245137245324%_
                             _%$%hd245138245327%_
                             _%$%tl245139245329%_
                             _%$%e245140245332%_
                             _%$%hd245141245335%_
                             _%$%tl245142245337%_
                             _%$%e245143245340%_
                             _%$%hd245144245343%_
                             _%$%tl245145245345%_
                             _%$%e245146245348%_
                             _%$%hd245147245351%_
                             _%$%tl245148245353%_)
                      (let ((_%$%g245126245356%_ _%$%hd245147245351%_)
                            (_%$%g245127245357%_ _%$%hd245138245327%_))
                        (if (and (let ((__tmp250534
                                        (let ((__tmp250535
                                               (let ()
                                                 (declare (not safe))
                                                 (gxc#identifier-symbol
                                                  _%$%g245127245357%_))))
                                          (declare (not safe))
                                          (gxc#optimizer-resolve-type
                                           __tmp250535))))
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    __tmp250534
                                    'gxc#!accessor::t))
                                 (let ((__tmp250536
                                        (let ()
                                          (declare (not safe))
                                          (slot-ref__0
                                           _%self244949%_
                                           'receiver))))
                                   (declare (not safe))
                                   (gx#free-identifier=?
                                    _%$%g245126245356%_
                                    __tmp250536)))
                            (_%__kont249391249392%_
                             _%$%g245126245356%_
                             _%$%g245127245357%_)
                            (_%__kont249395249396%_)))))
                   (_%__match249812249813%_
                    (lambda (_%$%e245128245300%_
                             _%$%hd245129245303%_
                             _%$%tl245130245305%_
                             _%$%e245131245308%_
                             _%$%hd245132245311%_
                             _%$%tl245133245313%_
                             _%$%e245134245316%_
                             _%$%hd245135245319%_
                             _%$%tl245136245321%_
                             _%$%e245137245324%_
                             _%$%hd245138245327%_
                             _%$%tl245139245329%_
                             _%$%e245140245332%_
                             _%$%hd245141245335%_
                             _%$%tl245142245337%_
                             _%$%e245143245340%_
                             _%$%hd245144245343%_
                             _%$%tl245145245345%_
                             _%$%e245146245348%_
                             _%$%hd245147245351%_
                             _%$%tl245148245353%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl245142245337%_))
                          (_%__match249814249815%_
                           _%$%e245128245300%_
                           _%$%hd245129245303%_
                           _%$%tl245130245305%_
                           _%$%e245131245308%_
                           _%$%hd245132245311%_
                           _%$%tl245133245313%_
                           _%$%e245134245316%_
                           _%$%hd245135245319%_
                           _%$%tl245136245321%_
                           _%$%e245137245324%_
                           _%$%hd245138245327%_
                           _%$%tl245139245329%_
                           _%$%e245140245332%_
                           _%$%hd245141245335%_
                           _%$%tl245142245337%_
                           _%$%e245143245340%_
                           _%$%hd245144245343%_
                           _%$%tl245145245345%_
                           _%$%e245146245348%_
                           _%$%hd245147245351%_
                           _%$%tl245148245353%_)
                          (_%__match249868249869%_
                           _%$%e245128245300%_
                           _%$%hd245129245303%_
                           _%$%tl245130245305%_
                           _%$%e245131245308%_
                           _%$%hd245132245311%_
                           _%$%tl245133245313%_
                           _%$%e245134245316%_
                           _%$%hd245135245319%_
                           _%$%tl245136245321%_
                           _%$%e245137245324%_
                           _%$%hd245138245327%_
                           _%$%tl245139245329%_
                           _%$%e245140245332%_
                           _%$%hd245141245335%_
                           _%$%tl245142245337%_
                           _%$%e245143245340%_
                           _%$%hd245144245343%_
                           _%$%tl245145245345%_
                           _%$%e245146245348%_
                           _%$%hd245147245351%_
                           _%$%tl245148245353%_))))
                   (_%__match249758249759%_
                    (lambda (_%$%e245093245394%_
                             _%$%hd245094245397%_
                             _%$%tl245095245399%_
                             _%$%e245096245402%_
                             _%$%hd245097245405%_
                             _%$%tl245098245407%_
                             _%$%e245099245410%_
                             _%$%hd245100245413%_
                             _%$%tl245101245415%_
                             _%$%e245102245418%_
                             _%$%hd245103245421%_
                             _%$%tl245104245423%_
                             _%$%e245105245426%_
                             _%$%hd245106245429%_
                             _%$%tl245107245431%_
                             _%$%e245108245434%_
                             _%$%hd245109245437%_
                             _%$%tl245110245439%_
                             _%$%e245111245442%_
                             _%$%hd245112245445%_
                             _%$%tl245113245447%_
                             _%$%e245114245450%_
                             _%$%hd245115245453%_
                             _%$%tl245116245455%_
                             _%$%e245117245458%_
                             _%$%hd245118245461%_
                             _%$%tl245119245463%_
                             _%$%e245120245466%_
                             _%$%hd245121245469%_
                             _%$%tl245122245471%_
                             _%$%e245123245474%_
                             _%$%hd245124245477%_
                             _%$%tl245125245479%_)
                      (let ((_%$%g245089245482%_ _%$%hd245124245477%_)
                            (_%$%g245090245483%_ _%$%hd245121245469%_)
                            (_%$%g245091245484%_ _%$%hd245112245445%_)
                            (_%$%g245092245485%_ _%$%hd245103245421%_))
                        (if (and (or (let ()
                                       (declare (not safe))
                                       (gxc#runtime-identifier=?
                                        _%$%g245092245485%_
                                        'slot-set!))
                                     (let ()
                                       (declare (not safe))
                                       (gxc#runtime-identifier=?
                                        _%$%g245092245485%_
                                        'unchecked-slot-set!)))
                                 (let ((__tmp250537
                                        (let ()
                                          (declare (not safe))
                                          (slot-ref__0
                                           _%self244949%_
                                           'receiver))))
                                   (declare (not safe))
                                   (gx#free-identifier=?
                                    _%$%g245091245484%_
                                    __tmp250537)))
                            (_%__kont249389249390%_
                             _%$%g245089245482%_
                             _%$%g245090245483%_
                             _%$%g245091245484%_
                             _%$%g245092245485%_)
                            (_%__kont249395249396%_)))))
                   (_%__match249750249751%_
                    (lambda (_%$%e245093245394%_
                             _%$%hd245094245397%_
                             _%$%tl245095245399%_
                             _%$%e245096245402%_
                             _%$%hd245097245405%_
                             _%$%tl245098245407%_
                             _%$%e245099245410%_
                             _%$%hd245100245413%_
                             _%$%tl245101245415%_
                             _%$%e245102245418%_
                             _%$%hd245103245421%_
                             _%$%tl245104245423%_
                             _%$%e245105245426%_
                             _%$%hd245106245429%_
                             _%$%tl245107245431%_
                             _%$%e245108245434%_
                             _%$%hd245109245437%_
                             _%$%tl245110245439%_
                             _%$%e245111245442%_
                             _%$%hd245112245445%_
                             _%$%tl245113245447%_
                             _%$%e245114245450%_
                             _%$%hd245115245453%_
                             _%$%tl245116245455%_
                             _%$%e245117245458%_
                             _%$%hd245118245461%_
                             _%$%tl245119245463%_
                             _%$%e245120245466%_
                             _%$%hd245121245469%_
                             _%$%tl245122245471%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl245116245455%_))
                          (let ((_%$%e245123245474%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl245116245455%_))))
                            (let ((_%$%tl245125245479%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e245123245474%_)))
                                  (_%$%hd245124245477%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e245123245474%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl245125245479%_))
                                  (_%__match249758249759%_
                                   _%$%e245093245394%_
                                   _%$%hd245094245397%_
                                   _%$%tl245095245399%_
                                   _%$%e245096245402%_
                                   _%$%hd245097245405%_
                                   _%$%tl245098245407%_
                                   _%$%e245099245410%_
                                   _%$%hd245100245413%_
                                   _%$%tl245101245415%_
                                   _%$%e245102245418%_
                                   _%$%hd245103245421%_
                                   _%$%tl245104245423%_
                                   _%$%e245105245426%_
                                   _%$%hd245106245429%_
                                   _%$%tl245107245431%_
                                   _%$%e245108245434%_
                                   _%$%hd245109245437%_
                                   _%$%tl245110245439%_
                                   _%$%e245111245442%_
                                   _%$%hd245112245445%_
                                   _%$%tl245113245447%_
                                   _%$%e245114245450%_
                                   _%$%hd245115245453%_
                                   _%$%tl245116245455%_
                                   _%$%e245117245458%_
                                   _%$%hd245118245461%_
                                   _%$%tl245119245463%_
                                   _%$%e245120245466%_
                                   _%$%hd245121245469%_
                                   _%$%tl245122245471%_
                                   _%$%e245123245474%_
                                   _%$%hd245124245477%_
                                   _%$%tl245125245479%_)
                                  (_%__kont249395249396%_))))
                          (_%__match249874249875%_
                           _%$%e245093245394%_
                           _%$%hd245094245397%_
                           _%$%tl245095245399%_
                           _%$%e245096245402%_
                           _%$%hd245097245405%_
                           _%$%tl245098245407%_
                           _%$%e245099245410%_
                           _%$%hd245100245413%_
                           _%$%tl245101245415%_
                           _%$%e245102245418%_
                           _%$%hd245103245421%_
                           _%$%tl245104245423%_
                           _%$%e245105245426%_
                           _%$%hd245106245429%_
                           _%$%tl245107245431%_
                           _%$%e245108245434%_
                           _%$%hd245109245437%_
                           _%$%tl245110245439%_
                           _%$%e245111245442%_
                           _%$%hd245112245445%_
                           _%$%tl245113245447%_
                           _%$%e245114245450%_
                           _%$%hd245115245453%_
                           _%$%tl245116245455%_))))
                   (_%__match249672249673%_
                    (lambda (_%$%e245059245525%_
                             _%$%hd245060245528%_
                             _%$%tl245061245530%_
                             _%$%e245062245533%_
                             _%$%hd245063245536%_
                             _%$%tl245064245538%_
                             _%$%e245065245541%_
                             _%$%hd245066245544%_
                             _%$%tl245067245546%_
                             _%$%e245068245549%_
                             _%$%hd245069245552%_
                             _%$%tl245070245554%_
                             _%$%e245071245557%_
                             _%$%hd245072245560%_
                             _%$%tl245073245562%_
                             _%$%e245074245565%_
                             _%$%hd245075245568%_
                             _%$%tl245076245570%_
                             _%$%e245077245573%_
                             _%$%hd245078245576%_
                             _%$%tl245079245578%_
                             _%$%e245080245581%_
                             _%$%hd245081245584%_
                             _%$%tl245082245586%_
                             _%$%e245083245589%_
                             _%$%hd245084245592%_
                             _%$%tl245085245594%_
                             _%$%e245086245597%_
                             _%$%hd245087245600%_
                             _%$%tl245088245602%_)
                      (let ((_%$%g245056245605%_ _%$%hd245087245600%_)
                            (_%$%g245057245606%_ _%$%hd245078245576%_)
                            (_%$%g245058245607%_ _%$%hd245069245552%_))
                        (if (and (or (let ()
                                       (declare (not safe))
                                       (gxc#runtime-identifier=?
                                        _%$%g245058245607%_
                                        'slot-ref))
                                     (let ()
                                       (declare (not safe))
                                       (gxc#runtime-identifier=?
                                        _%$%g245058245607%_
                                        'unchecked-slot-ref)))
                                 (let ((__tmp250538
                                        (let ()
                                          (declare (not safe))
                                          (slot-ref__0
                                           _%self244949%_
                                           'receiver))))
                                   (declare (not safe))
                                   (gx#free-identifier=?
                                    _%$%g245057245606%_
                                    __tmp250538)))
                            (_%__kont249387249388%_
                             _%$%g245056245605%_
                             _%$%g245057245606%_
                             _%$%g245058245607%_)
                            (_%__match249876249877%_
                             _%$%e245059245525%_
                             _%$%hd245060245528%_
                             _%$%tl245061245530%_
                             _%$%e245062245533%_
                             _%$%hd245063245536%_
                             _%$%tl245064245538%_
                             _%$%e245065245541%_
                             _%$%hd245066245544%_
                             _%$%tl245067245546%_
                             _%$%e245068245549%_
                             _%$%hd245069245552%_
                             _%$%tl245070245554%_
                             _%$%e245071245557%_
                             _%$%hd245072245560%_
                             _%$%tl245073245562%_
                             _%$%e245074245565%_
                             _%$%hd245075245568%_
                             _%$%tl245076245570%_
                             _%$%e245077245573%_
                             _%$%hd245078245576%_
                             _%$%tl245079245578%_
                             _%$%e245080245581%_
                             _%$%hd245081245584%_
                             _%$%tl245082245586%_)))))
                   (_%__match249670249671%_
                    (lambda (_%$%e245059245525%_
                             _%$%hd245060245528%_
                             _%$%tl245061245530%_
                             _%$%e245062245533%_
                             _%$%hd245063245536%_
                             _%$%tl245064245538%_
                             _%$%e245065245541%_
                             _%$%hd245066245544%_
                             _%$%tl245067245546%_
                             _%$%e245068245549%_
                             _%$%hd245069245552%_
                             _%$%tl245070245554%_
                             _%$%e245071245557%_
                             _%$%hd245072245560%_
                             _%$%tl245073245562%_
                             _%$%e245074245565%_
                             _%$%hd245075245568%_
                             _%$%tl245076245570%_
                             _%$%e245077245573%_
                             _%$%hd245078245576%_
                             _%$%tl245079245578%_
                             _%$%e245080245581%_
                             _%$%hd245081245584%_
                             _%$%tl245082245586%_
                             _%$%e245083245589%_
                             _%$%hd245084245592%_
                             _%$%tl245085245594%_
                             _%$%e245086245597%_
                             _%$%hd245087245600%_
                             _%$%tl245088245602%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%$%tl245082245586%_))
                          (_%__match249672249673%_
                           _%$%e245059245525%_
                           _%$%hd245060245528%_
                           _%$%tl245061245530%_
                           _%$%e245062245533%_
                           _%$%hd245063245536%_
                           _%$%tl245064245538%_
                           _%$%e245065245541%_
                           _%$%hd245066245544%_
                           _%$%tl245067245546%_
                           _%$%e245068245549%_
                           _%$%hd245069245552%_
                           _%$%tl245070245554%_
                           _%$%e245071245557%_
                           _%$%hd245072245560%_
                           _%$%tl245073245562%_
                           _%$%e245074245565%_
                           _%$%hd245075245568%_
                           _%$%tl245076245570%_
                           _%$%e245077245573%_
                           _%$%hd245078245576%_
                           _%$%tl245079245578%_
                           _%$%e245080245581%_
                           _%$%hd245081245584%_
                           _%$%tl245082245586%_
                           _%$%e245083245589%_
                           _%$%hd245084245592%_
                           _%$%tl245085245594%_
                           _%$%e245086245597%_
                           _%$%hd245087245600%_
                           _%$%tl245088245602%_)
                          (_%__match249750249751%_
                           _%$%e245059245525%_
                           _%$%hd245060245528%_
                           _%$%tl245061245530%_
                           _%$%e245062245533%_
                           _%$%hd245063245536%_
                           _%$%tl245064245538%_
                           _%$%e245065245541%_
                           _%$%hd245066245544%_
                           _%$%tl245067245546%_
                           _%$%e245068245549%_
                           _%$%hd245069245552%_
                           _%$%tl245070245554%_
                           _%$%e245071245557%_
                           _%$%hd245072245560%_
                           _%$%tl245073245562%_
                           _%$%e245074245565%_
                           _%$%hd245075245568%_
                           _%$%tl245076245570%_
                           _%$%e245077245573%_
                           _%$%hd245078245576%_
                           _%$%tl245079245578%_
                           _%$%e245080245581%_
                           _%$%hd245081245584%_
                           _%$%tl245082245586%_
                           _%$%e245083245589%_
                           _%$%hd245084245592%_
                           _%$%tl245085245594%_
                           _%$%e245086245597%_
                           _%$%hd245087245600%_
                           _%$%tl245088245602%_))))
                   (_%__match249660249661%_
                    (lambda (_%$%e245059245525%_
                             _%$%hd245060245528%_
                             _%$%tl245061245530%_
                             _%$%e245062245533%_
                             _%$%hd245063245536%_
                             _%$%tl245064245538%_
                             _%$%e245065245541%_
                             _%$%hd245066245544%_
                             _%$%tl245067245546%_
                             _%$%e245068245549%_
                             _%$%hd245069245552%_
                             _%$%tl245070245554%_
                             _%$%e245071245557%_
                             _%$%hd245072245560%_
                             _%$%tl245073245562%_
                             _%$%e245074245565%_
                             _%$%hd245075245568%_
                             _%$%tl245076245570%_
                             _%$%e245077245573%_
                             _%$%hd245078245576%_
                             _%$%tl245079245578%_
                             _%$%e245080245581%_
                             _%$%hd245081245584%_
                             _%$%tl245082245586%_
                             _%$%e245083245589%_
                             _%$%hd245084245592%_
                             _%$%tl245085245594%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-eq? '%#quote _%$%hd245084245592%_))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl245085245594%_))
                              (let ((_%$%e245086245597%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl245085245594%_))))
                                (let ((_%$%tl245088245602%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e245086245597%_)))
                                      (_%$%hd245087245600%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e245086245597%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl245088245602%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-null?
                                             _%$%tl245082245586%_))
                                          (_%__match249672249673%_
                                           _%$%e245059245525%_
                                           _%$%hd245060245528%_
                                           _%$%tl245061245530%_
                                           _%$%e245062245533%_
                                           _%$%hd245063245536%_
                                           _%$%tl245064245538%_
                                           _%$%e245065245541%_
                                           _%$%hd245066245544%_
                                           _%$%tl245067245546%_
                                           _%$%e245068245549%_
                                           _%$%hd245069245552%_
                                           _%$%tl245070245554%_
                                           _%$%e245071245557%_
                                           _%$%hd245072245560%_
                                           _%$%tl245073245562%_
                                           _%$%e245074245565%_
                                           _%$%hd245075245568%_
                                           _%$%tl245076245570%_
                                           _%$%e245077245573%_
                                           _%$%hd245078245576%_
                                           _%$%tl245079245578%_
                                           _%$%e245080245581%_
                                           _%$%hd245081245584%_
                                           _%$%tl245082245586%_
                                           _%$%e245083245589%_
                                           _%$%hd245084245592%_
                                           _%$%tl245085245594%_
                                           _%$%e245086245597%_
                                           _%$%hd245087245600%_
                                           _%$%tl245088245602%_)
                                          (_%__match249750249751%_
                                           _%$%e245059245525%_
                                           _%$%hd245060245528%_
                                           _%$%tl245061245530%_
                                           _%$%e245062245533%_
                                           _%$%hd245063245536%_
                                           _%$%tl245064245538%_
                                           _%$%e245065245541%_
                                           _%$%hd245066245544%_
                                           _%$%tl245067245546%_
                                           _%$%e245068245549%_
                                           _%$%hd245069245552%_
                                           _%$%tl245070245554%_
                                           _%$%e245071245557%_
                                           _%$%hd245072245560%_
                                           _%$%tl245073245562%_
                                           _%$%e245074245565%_
                                           _%$%hd245075245568%_
                                           _%$%tl245076245570%_
                                           _%$%e245077245573%_
                                           _%$%hd245078245576%_
                                           _%$%tl245079245578%_
                                           _%$%e245080245581%_
                                           _%$%hd245081245584%_
                                           _%$%tl245082245586%_
                                           _%$%e245083245589%_
                                           _%$%hd245084245592%_
                                           _%$%tl245085245594%_
                                           _%$%e245086245597%_
                                           _%$%hd245087245600%_
                                           _%$%tl245088245602%_))
                                      (_%__match249874249875%_
                                       _%$%e245059245525%_
                                       _%$%hd245060245528%_
                                       _%$%tl245061245530%_
                                       _%$%e245062245533%_
                                       _%$%hd245063245536%_
                                       _%$%tl245064245538%_
                                       _%$%e245065245541%_
                                       _%$%hd245066245544%_
                                       _%$%tl245067245546%_
                                       _%$%e245068245549%_
                                       _%$%hd245069245552%_
                                       _%$%tl245070245554%_
                                       _%$%e245071245557%_
                                       _%$%hd245072245560%_
                                       _%$%tl245073245562%_
                                       _%$%e245074245565%_
                                       _%$%hd245075245568%_
                                       _%$%tl245076245570%_
                                       _%$%e245077245573%_
                                       _%$%hd245078245576%_
                                       _%$%tl245079245578%_
                                       _%$%e245080245581%_
                                       _%$%hd245081245584%_
                                       _%$%tl245082245586%_))))
                              (_%__match249874249875%_
                               _%$%e245059245525%_
                               _%$%hd245060245528%_
                               _%$%tl245061245530%_
                               _%$%e245062245533%_
                               _%$%hd245063245536%_
                               _%$%tl245064245538%_
                               _%$%e245065245541%_
                               _%$%hd245066245544%_
                               _%$%tl245067245546%_
                               _%$%e245068245549%_
                               _%$%hd245069245552%_
                               _%$%tl245070245554%_
                               _%$%e245071245557%_
                               _%$%hd245072245560%_
                               _%$%tl245073245562%_
                               _%$%e245074245565%_
                               _%$%hd245075245568%_
                               _%$%tl245076245570%_
                               _%$%e245077245573%_
                               _%$%hd245078245576%_
                               _%$%tl245079245578%_
                               _%$%e245080245581%_
                               _%$%hd245081245584%_
                               _%$%tl245082245586%_))
                          (_%__match249874249875%_
                           _%$%e245059245525%_
                           _%$%hd245060245528%_
                           _%$%tl245061245530%_
                           _%$%e245062245533%_
                           _%$%hd245063245536%_
                           _%$%tl245064245538%_
                           _%$%e245065245541%_
                           _%$%hd245066245544%_
                           _%$%tl245067245546%_
                           _%$%e245068245549%_
                           _%$%hd245069245552%_
                           _%$%tl245070245554%_
                           _%$%e245071245557%_
                           _%$%hd245072245560%_
                           _%$%tl245073245562%_
                           _%$%e245074245565%_
                           _%$%hd245075245568%_
                           _%$%tl245076245570%_
                           _%$%e245077245573%_
                           _%$%hd245078245576%_
                           _%$%tl245079245578%_
                           _%$%e245080245581%_
                           _%$%hd245081245584%_
                           _%$%tl245082245586%_))))
                   (_%__match249592249593%_
                    (lambda (_%$%e245008245644%_
                             _%$%hd245009245647%_
                             _%$%tl245010245649%_
                             _%$%e245011245652%_
                             _%$%hd245012245655%_
                             _%$%tl245013245657%_
                             _%$%e245014245660%_
                             _%$%hd245015245663%_
                             _%$%tl245016245665%_
                             _%$%e245017245668%_
                             _%$%hd245018245671%_
                             _%$%tl245019245673%_
                             _%$%e245020245676%_
                             _%$%hd245021245679%_
                             _%$%tl245022245681%_
                             _%$%e245023245684%_
                             _%$%hd245024245687%_
                             _%$%tl245025245689%_
                             _%$%e245026245692%_
                             _%$%hd245027245695%_
                             _%$%tl245028245697%_
                             _%$%e245029245700%_
                             _%$%hd245030245703%_
                             _%$%tl245031245705%_
                             _%$%e245032245708%_
                             _%$%hd245033245711%_
                             _%$%tl245034245713%_
                             _%$%e245035245716%_
                             _%$%hd245036245719%_
                             _%$%tl245037245721%_
                             _%$%e245038245724%_
                             _%$%hd245039245727%_
                             _%$%tl245040245729%_
                             _%$%e245041245732%_
                             _%$%hd245042245735%_
                             _%$%tl245043245737%_
                             _%$%e245044245740%_
                             _%$%hd245045245743%_
                             _%$%tl245046245745%_
                             _%__splice249385249386%_
                             _%$%target245047245748%_
                             _%$%tl245049245750%_)
                      (letrec ((_%$%loop245050245753%_
                                (lambda (_%$%hd245048245756%_
                                         _%$%args245054245758%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd245048245756%_))
                                      (let ((_%$%e245051245760%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd245048245756%_))))
                                        (let ((_%$%lp-tl245053245765%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e245051245760%_)))
                                              (_%$%lp-hd245052245763%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e245051245760%_))))
                                          (_%$%loop245050245753%_
                                           _%$%lp-tl245053245765%_
                                           (cons _%$%lp-hd245052245763%_
                                                 _%$%args245054245758%_))))
                                      (let ((_%$%args245055245768%_
                                             (reverse _%$%args245054245758%_)))
                                        (let ((_%$%g245003245770%_
                                               _%$%args245055245768%_)
                                              (_%$%g245004245771%_
                                               _%$%hd245045245743%_)
                                              (_%$%g245005245772%_
                                               _%$%hd245036245719%_)
                                              (_%$%g245006245773%_
                                               _%$%hd245027245695%_)
                                              (_%$%g245007245774%_
                                               _%$%hd245018245671%_))
                                          (if (and (let ()
                                                     (declare (not safe))
                                                     (gxc#runtime-identifier=?
                                                      _%$%g245007245774%_
                                                      'apply))
                                                   (let ()
                                                     (declare (not safe))
                                                     (gxc#runtime-identifier=?
                                                      _%$%g245006245773%_
                                                      'call-method))
                                                   (let ((__tmp250539
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (slot-ref__0
                                                             _%self244949%_
                                                             'receiver))))
                                                     (declare (not safe))
                                                     (gx#free-identifier=?
                                                      _%$%g245005245772%_
                                                      __tmp250539)))
                                              (_%__kont249383249384%_
                                               _%$%g245003245770%_
                                               _%$%g245004245771%_
                                               _%$%g245005245772%_
                                               _%$%g245006245773%_
                                               _%$%g245007245774%_)
                                              (_%__kont249395249396%_))))))))
                        (_%$%loop245050245753%_
                         _%$%target245047245748%_
                         '()))))
                   (_%__match249550249551%_
                    (lambda (_%$%e245008245644%_
                             _%$%hd245009245647%_
                             _%$%tl245010245649%_
                             _%$%e245011245652%_
                             _%$%hd245012245655%_
                             _%$%tl245013245657%_
                             _%$%e245014245660%_
                             _%$%hd245015245663%_
                             _%$%tl245016245665%_
                             _%$%e245017245668%_
                             _%$%hd245018245671%_
                             _%$%tl245019245673%_
                             _%$%e245020245676%_
                             _%$%hd245021245679%_
                             _%$%tl245022245681%_
                             _%$%e245023245684%_
                             _%$%hd245024245687%_
                             _%$%tl245025245689%_
                             _%$%e245026245692%_
                             _%$%hd245027245695%_
                             _%$%tl245028245697%_
                             _%$%e245029245700%_
                             _%$%hd245030245703%_
                             _%$%tl245031245705%_
                             _%$%e245032245708%_
                             _%$%hd245033245711%_
                             _%$%tl245034245713%_)
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-eq? '%#ref _%$%hd245033245711%_))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%tl245034245713%_))
                              (let ((_%$%e245035245716%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%tl245034245713%_))))
                                (let ((_%$%tl245037245721%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e245035245716%_)))
                                      (_%$%hd245036245719%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e245035245716%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-null? _%$%tl245037245721%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl245031245705%_))
                                          (let ((_%$%e245038245724%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#stx-e
                                                    _%$%tl245031245705%_))))
                                            (let ((_%$%tl245040245729%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e245038245724%_)))
                                                  (_%$%hd245039245727%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e245038245724%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%hd245039245727%_))
                                                  (let ((_%$%e245041245732%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%hd245039245727%_))))
                                                    (let ((_%$%tl245043245737%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e245041245732%_)))
                                                          (_%$%hd245042245735%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e245041245732%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#identifier?
                                                             _%$%hd245042245735%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-eq? '%#quote _%$%hd245042245735%_))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl245043245737%_))
                          (let ((_%$%e245044245740%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl245043245737%_))))
                            (let ((_%$%tl245046245745%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e245044245740%_)))
                                  (_%$%hd245045245743%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e245044245740%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl245046245745%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair/null?
                                         _%$%tl245040245729%_))
                                      (let ((_%__splice249385249386%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#syntax-split-splice->vector
                                                _%$%tl245040245729%_
                                                '0))))
                                        (let ((_%$%tl245049245750%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice249385249386%_
                                                  '1)))
                                              (_%$%target245047245748%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##vector-ref
                                                  _%__splice249385249386%_
                                                  '0))))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-null?
                                                 _%$%tl245049245750%_))
                                              (_%__match249592249593%_
                                               _%$%e245008245644%_
                                               _%$%hd245009245647%_
                                               _%$%tl245010245649%_
                                               _%$%e245011245652%_
                                               _%$%hd245012245655%_
                                               _%$%tl245013245657%_
                                               _%$%e245014245660%_
                                               _%$%hd245015245663%_
                                               _%$%tl245016245665%_
                                               _%$%e245017245668%_
                                               _%$%hd245018245671%_
                                               _%$%tl245019245673%_
                                               _%$%e245020245676%_
                                               _%$%hd245021245679%_
                                               _%$%tl245022245681%_
                                               _%$%e245023245684%_
                                               _%$%hd245024245687%_
                                               _%$%tl245025245689%_
                                               _%$%e245026245692%_
                                               _%$%hd245027245695%_
                                               _%$%tl245028245697%_
                                               _%$%e245029245700%_
                                               _%$%hd245030245703%_
                                               _%$%tl245031245705%_
                                               _%$%e245032245708%_
                                               _%$%hd245033245711%_
                                               _%$%tl245034245713%_
                                               _%$%e245035245716%_
                                               _%$%hd245036245719%_
                                               _%$%tl245037245721%_
                                               _%$%e245038245724%_
                                               _%$%hd245039245727%_
                                               _%$%tl245040245729%_
                                               _%$%e245041245732%_
                                               _%$%hd245042245735%_
                                               _%$%tl245043245737%_
                                               _%$%e245044245740%_
                                               _%$%hd245045245743%_
                                               _%$%tl245046245745%_
                                               _%__splice249385249386%_
                                               _%$%target245047245748%_
                                               _%$%tl245049245750%_)
                                              (_%__kont249395249396%_))))
                                      (_%__kont249395249396%_))
                                  (_%__kont249395249396%_))))
                          (_%__kont249395249396%_))
                      (_%__kont249395249396%_))
                  (_%__kont249395249396%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont249395249396%_))))
                                          (_%__match249874249875%_
                                           _%$%e245008245644%_
                                           _%$%hd245009245647%_
                                           _%$%tl245010245649%_
                                           _%$%e245011245652%_
                                           _%$%hd245012245655%_
                                           _%$%tl245013245657%_
                                           _%$%e245014245660%_
                                           _%$%hd245015245663%_
                                           _%$%tl245016245665%_
                                           _%$%e245017245668%_
                                           _%$%hd245018245671%_
                                           _%$%tl245019245673%_
                                           _%$%e245020245676%_
                                           _%$%hd245021245679%_
                                           _%$%tl245022245681%_
                                           _%$%e245023245684%_
                                           _%$%hd245024245687%_
                                           _%$%tl245025245689%_
                                           _%$%e245026245692%_
                                           _%$%hd245027245695%_
                                           _%$%tl245028245697%_
                                           _%$%e245029245700%_
                                           _%$%hd245030245703%_
                                           _%$%tl245031245705%_))
                                      (_%__match249874249875%_
                                       _%$%e245008245644%_
                                       _%$%hd245009245647%_
                                       _%$%tl245010245649%_
                                       _%$%e245011245652%_
                                       _%$%hd245012245655%_
                                       _%$%tl245013245657%_
                                       _%$%e245014245660%_
                                       _%$%hd245015245663%_
                                       _%$%tl245016245665%_
                                       _%$%e245017245668%_
                                       _%$%hd245018245671%_
                                       _%$%tl245019245673%_
                                       _%$%e245020245676%_
                                       _%$%hd245021245679%_
                                       _%$%tl245022245681%_
                                       _%$%e245023245684%_
                                       _%$%hd245024245687%_
                                       _%$%tl245025245689%_
                                       _%$%e245026245692%_
                                       _%$%hd245027245695%_
                                       _%$%tl245028245697%_
                                       _%$%e245029245700%_
                                       _%$%hd245030245703%_
                                       _%$%tl245031245705%_))))
                              (_%__match249874249875%_
                               _%$%e245008245644%_
                               _%$%hd245009245647%_
                               _%$%tl245010245649%_
                               _%$%e245011245652%_
                               _%$%hd245012245655%_
                               _%$%tl245013245657%_
                               _%$%e245014245660%_
                               _%$%hd245015245663%_
                               _%$%tl245016245665%_
                               _%$%e245017245668%_
                               _%$%hd245018245671%_
                               _%$%tl245019245673%_
                               _%$%e245020245676%_
                               _%$%hd245021245679%_
                               _%$%tl245022245681%_
                               _%$%e245023245684%_
                               _%$%hd245024245687%_
                               _%$%tl245025245689%_
                               _%$%e245026245692%_
                               _%$%hd245027245695%_
                               _%$%tl245028245697%_
                               _%$%e245029245700%_
                               _%$%hd245030245703%_
                               _%$%tl245031245705%_))
                          (_%__match249660249661%_
                           _%$%e245008245644%_
                           _%$%hd245009245647%_
                           _%$%tl245010245649%_
                           _%$%e245011245652%_
                           _%$%hd245012245655%_
                           _%$%tl245013245657%_
                           _%$%e245014245660%_
                           _%$%hd245015245663%_
                           _%$%tl245016245665%_
                           _%$%e245017245668%_
                           _%$%hd245018245671%_
                           _%$%tl245019245673%_
                           _%$%e245020245676%_
                           _%$%hd245021245679%_
                           _%$%tl245022245681%_
                           _%$%e245023245684%_
                           _%$%hd245024245687%_
                           _%$%tl245025245689%_
                           _%$%e245026245692%_
                           _%$%hd245027245695%_
                           _%$%tl245028245697%_
                           _%$%e245029245700%_
                           _%$%hd245030245703%_
                           _%$%tl245031245705%_
                           _%$%e245032245708%_
                           _%$%hd245033245711%_
                           _%$%tl245034245713%_))))
                   (_%__match249482249483%_
                    (lambda (_%$%e244964245831%_
                             _%$%hd244965245834%_
                             _%$%tl244966245836%_
                             _%$%e244967245839%_
                             _%$%hd244968245842%_
                             _%$%tl244969245844%_
                             _%$%e244970245847%_
                             _%$%hd244971245850%_
                             _%$%tl244972245852%_
                             _%$%e244973245855%_
                             _%$%hd244974245858%_
                             _%$%tl244975245860%_
                             _%$%e244976245863%_
                             _%$%hd244977245866%_
                             _%$%tl244978245868%_
                             _%$%e244979245871%_
                             _%$%hd244980245874%_
                             _%$%tl244981245876%_
                             _%$%e244982245879%_
                             _%$%hd244983245882%_
                             _%$%tl244984245884%_
                             _%$%e244985245887%_
                             _%$%hd244986245890%_
                             _%$%tl244987245892%_
                             _%$%e244988245895%_
                             _%$%hd244989245898%_
                             _%$%tl244990245900%_
                             _%$%e244991245903%_
                             _%$%hd244992245906%_
                             _%$%tl244993245908%_
                             _%__splice249381249382%_
                             _%$%target244994245911%_
                             _%$%tl244996245913%_)
                      (letrec ((_%$%loop244997245916%_
                                (lambda (_%$%hd244995245919%_
                                         _%$%args245001245921%_)
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-pair? _%$%hd244995245919%_))
                                      (let ((_%$%e244998245923%_
                                             (let ()
                                               (declare (not safe))
                                               (gx#stx-e
                                                _%$%hd244995245919%_))))
                                        (let ((_%$%lp-tl245000245928%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##cdr _%$%e244998245923%_)))
                                              (_%$%lp-hd244999245926%_
                                               (let ()
                                                 (declare (not safe))
                                                 (##car _%$%e244998245923%_))))
                                          (_%$%loop244997245916%_
                                           _%$%lp-tl245000245928%_
                                           (cons _%$%lp-hd244999245926%_
                                                 _%$%args245001245921%_))))
                                      (let ((_%$%args245002245931%_
                                             (reverse _%$%args245001245921%_)))
                                        (let ((_%$%g244960245933%_
                                               _%$%args245002245931%_)
                                              (_%$%g244961245934%_
                                               _%$%hd244992245906%_)
                                              (_%$%g244962245935%_
                                               _%$%hd244983245882%_)
                                              (_%$%g244963245936%_
                                               _%$%hd244974245858%_))
                                          (if (and (let ()
                                                     (declare (not safe))
                                                     (gxc#runtime-identifier=?
                                                      _%$%g244963245936%_
                                                      'call-method))
                                                   (let ((__tmp250540
                                                          (let ()
                                                            (declare
                                                              (not safe))
                                                            (slot-ref__0
                                                             _%self244949%_
                                                             'receiver))))
                                                     (declare (not safe))
                                                     (gx#free-identifier=?
                                                      _%$%g244962245935%_
                                                      __tmp250540)))
                                              (_%__kont249379249380%_
                                               _%$%g244960245933%_
                                               _%$%g244961245934%_
                                               _%$%g244962245935%_
                                               _%$%g244963245936%_)
                                              (_%__match249670249671%_
                                               _%$%e244964245831%_
                                               _%$%hd244965245834%_
                                               _%$%tl244966245836%_
                                               _%$%e244967245839%_
                                               _%$%hd244968245842%_
                                               _%$%tl244969245844%_
                                               _%$%e244970245847%_
                                               _%$%hd244971245850%_
                                               _%$%tl244972245852%_
                                               _%$%e244973245855%_
                                               _%$%hd244974245858%_
                                               _%$%tl244975245860%_
                                               _%$%e244976245863%_
                                               _%$%hd244977245866%_
                                               _%$%tl244978245868%_
                                               _%$%e244979245871%_
                                               _%$%hd244980245874%_
                                               _%$%tl244981245876%_
                                               _%$%e244982245879%_
                                               _%$%hd244983245882%_
                                               _%$%tl244984245884%_
                                               _%$%e244985245887%_
                                               _%$%hd244986245890%_
                                               _%$%tl244987245892%_
                                               _%$%e244988245895%_
                                               _%$%hd244989245898%_
                                               _%$%tl244990245900%_
                                               _%$%e244991245903%_
                                               _%$%hd244992245906%_
                                               _%$%tl244993245908%_))))))))
                        (_%$%loop244997245916%_
                         _%$%target244994245911%_
                         '())))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx249377249378%_))
                  (let ((_%$%e244964245831%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx249377249378%_))))
                    (let ((_%$%tl244966245836%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e244964245831%_)))
                          (_%$%hd244965245834%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e244964245831%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl244966245836%_))
                          (let ((_%$%e244967245839%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl244966245836%_))))
                            (let ((_%$%tl244969245844%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e244967245839%_)))
                                  (_%$%hd244968245842%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e244967245839%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-pair? _%$%hd244968245842%_))
                                  (let ((_%$%e244970245847%_
                                         (let ()
                                           (declare (not safe))
                                           (gx#stx-e _%$%hd244968245842%_))))
                                    (let ((_%$%tl244972245852%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%e244970245847%_)))
                                          (_%$%hd244971245850%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%e244970245847%_))))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#identifier?
                                             _%$%hd244971245850%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-eq?
                                                 '%#ref
                                                 _%$%hd244971245850%_))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-pair?
                                                     _%$%tl244972245852%_))
                                                  (let ((_%$%e244973245855%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (gx#stx-e
                                                            _%$%tl244972245852%_))))
                                                    (let ((_%$%tl244975245860%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##cdr _%$%e244973245855%_)))
                                                          (_%$%hd244974245858%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (##car _%$%e244973245855%_))))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-null?
                                                             _%$%tl244975245860%_))
                                                          (if (let ()
                                                                (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (not safe))
                        (gx#stx-pair? _%$%tl244969245844%_))
                      (let ((_%$%e244976245863%_
                             (let ()
                               (declare (not safe))
                               (gx#stx-e _%$%tl244969245844%_))))
                        (let ((_%$%tl244978245868%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%e244976245863%_)))
                              (_%$%hd244977245866%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%e244976245863%_))))
                          (if (let ()
                                (declare (not safe))
                                (gx#stx-pair? _%$%hd244977245866%_))
                              (let ((_%$%e244979245871%_
                                     (let ()
                                       (declare (not safe))
                                       (gx#stx-e _%$%hd244977245866%_))))
                                (let ((_%$%tl244981245876%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%e244979245871%_)))
                                      (_%$%hd244980245874%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%e244979245871%_))))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#identifier? _%$%hd244980245874%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-eq?
                                             '%#ref
                                             _%$%hd244980245874%_))
                                          (if (let ()
                                                (declare (not safe))
                                                (gx#stx-pair?
                                                 _%$%tl244981245876%_))
                                              (let ((_%$%e244982245879%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (gx#stx-e
                                                        _%$%tl244981245876%_))))
                                                (let ((_%$%tl244984245884%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##cdr _%$%e244982245879%_)))
                                                      (_%$%hd244983245882%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (##car _%$%e244982245879%_))))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-null?
                                                         _%$%tl244984245884%_))
                                                      (if (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#stx-pair?
                                                             _%$%tl244978245868%_))
                                                          (let ((_%$%e244985245887%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%$%tl244978245868%_))))
                    (let ((_%$%tl244987245892%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e244985245887%_)))
                          (_%$%hd244986245890%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e244985245887%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%hd244986245890%_))
                          (let ((_%$%e244988245895%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%hd244986245890%_))))
                            (let ((_%$%tl244990245900%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e244988245895%_)))
                                  (_%$%hd244989245898%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e244988245895%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#identifier? _%$%hd244989245898%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (gx#stx-eq?
                                         '%#quote
                                         _%$%hd244989245898%_))
                                      (if (let ()
                                            (declare (not safe))
                                            (gx#stx-pair?
                                             _%$%tl244990245900%_))
                                          (let ((_%$%e244991245903%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (gx#stx-e
                                                    _%$%tl244990245900%_))))
                                            (let ((_%$%tl244993245908%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%e244991245903%_)))
                                                  (_%$%hd244992245906%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%e244991245903%_))))
                                              (if (let ()
                                                    (declare (not safe))
                                                    (gx#stx-null?
                                                     _%$%tl244993245908%_))
                                                  (if (let ()
                                                        (declare (not safe))
                                                        (gx#stx-pair/null?
                                                         _%$%tl244987245892%_))
                                                      (let ((_%__splice249381249382%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (gx#syntax-split-splice->vector
                        _%$%tl244987245892%_
                        '0))))
                (let ((_%$%tl244996245913%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice249381249382%_ '1)))
                      (_%$%target244994245911%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref _%__splice249381249382%_ '0))))
                  (if (let ()
                        (declare (not safe))
                        (gx#stx-null? _%$%tl244996245913%_))
                      (_%__match249482249483%_
                       _%$%e244964245831%_
                       _%$%hd244965245834%_
                       _%$%tl244966245836%_
                       _%$%e244967245839%_
                       _%$%hd244968245842%_
                       _%$%tl244969245844%_
                       _%$%e244970245847%_
                       _%$%hd244971245850%_
                       _%$%tl244972245852%_
                       _%$%e244973245855%_
                       _%$%hd244974245858%_
                       _%$%tl244975245860%_
                       _%$%e244976245863%_
                       _%$%hd244977245866%_
                       _%$%tl244978245868%_
                       _%$%e244979245871%_
                       _%$%hd244980245874%_
                       _%$%tl244981245876%_
                       _%$%e244982245879%_
                       _%$%hd244983245882%_
                       _%$%tl244984245884%_
                       _%$%e244985245887%_
                       _%$%hd244986245890%_
                       _%$%tl244987245892%_
                       _%$%e244988245895%_
                       _%$%hd244989245898%_
                       _%$%tl244990245900%_
                       _%$%e244991245903%_
                       _%$%hd244992245906%_
                       _%$%tl244993245908%_
                       _%__splice249381249382%_
                       _%$%target244994245911%_
                       _%$%tl244996245913%_)
                      (_%__match249670249671%_
                       _%$%e244964245831%_
                       _%$%hd244965245834%_
                       _%$%tl244966245836%_
                       _%$%e244967245839%_
                       _%$%hd244968245842%_
                       _%$%tl244969245844%_
                       _%$%e244970245847%_
                       _%$%hd244971245850%_
                       _%$%tl244972245852%_
                       _%$%e244973245855%_
                       _%$%hd244974245858%_
                       _%$%tl244975245860%_
                       _%$%e244976245863%_
                       _%$%hd244977245866%_
                       _%$%tl244978245868%_
                       _%$%e244979245871%_
                       _%$%hd244980245874%_
                       _%$%tl244981245876%_
                       _%$%e244982245879%_
                       _%$%hd244983245882%_
                       _%$%tl244984245884%_
                       _%$%e244985245887%_
                       _%$%hd244986245890%_
                       _%$%tl244987245892%_
                       _%$%e244988245895%_
                       _%$%hd244989245898%_
                       _%$%tl244990245900%_
                       _%$%e244991245903%_
                       _%$%hd244992245906%_
                       _%$%tl244993245908%_))))
              (_%__match249670249671%_
               _%$%e244964245831%_
               _%$%hd244965245834%_
               _%$%tl244966245836%_
               _%$%e244967245839%_
               _%$%hd244968245842%_
               _%$%tl244969245844%_
               _%$%e244970245847%_
               _%$%hd244971245850%_
               _%$%tl244972245852%_
               _%$%e244973245855%_
               _%$%hd244974245858%_
               _%$%tl244975245860%_
               _%$%e244976245863%_
               _%$%hd244977245866%_
               _%$%tl244978245868%_
               _%$%e244979245871%_
               _%$%hd244980245874%_
               _%$%tl244981245876%_
               _%$%e244982245879%_
               _%$%hd244983245882%_
               _%$%tl244984245884%_
               _%$%e244985245887%_
               _%$%hd244986245890%_
               _%$%tl244987245892%_
               _%$%e244988245895%_
               _%$%hd244989245898%_
               _%$%tl244990245900%_
               _%$%e244991245903%_
               _%$%hd244992245906%_
               _%$%tl244993245908%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__match249874249875%_
                                                   _%$%e244964245831%_
                                                   _%$%hd244965245834%_
                                                   _%$%tl244966245836%_
                                                   _%$%e244967245839%_
                                                   _%$%hd244968245842%_
                                                   _%$%tl244969245844%_
                                                   _%$%e244970245847%_
                                                   _%$%hd244971245850%_
                                                   _%$%tl244972245852%_
                                                   _%$%e244973245855%_
                                                   _%$%hd244974245858%_
                                                   _%$%tl244975245860%_
                                                   _%$%e244976245863%_
                                                   _%$%hd244977245866%_
                                                   _%$%tl244978245868%_
                                                   _%$%e244979245871%_
                                                   _%$%hd244980245874%_
                                                   _%$%tl244981245876%_
                                                   _%$%e244982245879%_
                                                   _%$%hd244983245882%_
                                                   _%$%tl244984245884%_
                                                   _%$%e244985245887%_
                                                   _%$%hd244986245890%_
                                                   _%$%tl244987245892%_))))
                                          (_%__match249874249875%_
                                           _%$%e244964245831%_
                                           _%$%hd244965245834%_
                                           _%$%tl244966245836%_
                                           _%$%e244967245839%_
                                           _%$%hd244968245842%_
                                           _%$%tl244969245844%_
                                           _%$%e244970245847%_
                                           _%$%hd244971245850%_
                                           _%$%tl244972245852%_
                                           _%$%e244973245855%_
                                           _%$%hd244974245858%_
                                           _%$%tl244975245860%_
                                           _%$%e244976245863%_
                                           _%$%hd244977245866%_
                                           _%$%tl244978245868%_
                                           _%$%e244979245871%_
                                           _%$%hd244980245874%_
                                           _%$%tl244981245876%_
                                           _%$%e244982245879%_
                                           _%$%hd244983245882%_
                                           _%$%tl244984245884%_
                                           _%$%e244985245887%_
                                           _%$%hd244986245890%_
                                           _%$%tl244987245892%_))
                                      (_%__match249550249551%_
                                       _%$%e244964245831%_
                                       _%$%hd244965245834%_
                                       _%$%tl244966245836%_
                                       _%$%e244967245839%_
                                       _%$%hd244968245842%_
                                       _%$%tl244969245844%_
                                       _%$%e244970245847%_
                                       _%$%hd244971245850%_
                                       _%$%tl244972245852%_
                                       _%$%e244973245855%_
                                       _%$%hd244974245858%_
                                       _%$%tl244975245860%_
                                       _%$%e244976245863%_
                                       _%$%hd244977245866%_
                                       _%$%tl244978245868%_
                                       _%$%e244979245871%_
                                       _%$%hd244980245874%_
                                       _%$%tl244981245876%_
                                       _%$%e244982245879%_
                                       _%$%hd244983245882%_
                                       _%$%tl244984245884%_
                                       _%$%e244985245887%_
                                       _%$%hd244986245890%_
                                       _%$%tl244987245892%_
                                       _%$%e244988245895%_
                                       _%$%hd244989245898%_
                                       _%$%tl244990245900%_))
                                  (_%__match249874249875%_
                                   _%$%e244964245831%_
                                   _%$%hd244965245834%_
                                   _%$%tl244966245836%_
                                   _%$%e244967245839%_
                                   _%$%hd244968245842%_
                                   _%$%tl244969245844%_
                                   _%$%e244970245847%_
                                   _%$%hd244971245850%_
                                   _%$%tl244972245852%_
                                   _%$%e244973245855%_
                                   _%$%hd244974245858%_
                                   _%$%tl244975245860%_
                                   _%$%e244976245863%_
                                   _%$%hd244977245866%_
                                   _%$%tl244978245868%_
                                   _%$%e244979245871%_
                                   _%$%hd244980245874%_
                                   _%$%tl244981245876%_
                                   _%$%e244982245879%_
                                   _%$%hd244983245882%_
                                   _%$%tl244984245884%_
                                   _%$%e244985245887%_
                                   _%$%hd244986245890%_
                                   _%$%tl244987245892%_))))
                          (_%__match249874249875%_
                           _%$%e244964245831%_
                           _%$%hd244965245834%_
                           _%$%tl244966245836%_
                           _%$%e244967245839%_
                           _%$%hd244968245842%_
                           _%$%tl244969245844%_
                           _%$%e244970245847%_
                           _%$%hd244971245850%_
                           _%$%tl244972245852%_
                           _%$%e244973245855%_
                           _%$%hd244974245858%_
                           _%$%tl244975245860%_
                           _%$%e244976245863%_
                           _%$%hd244977245866%_
                           _%$%tl244978245868%_
                           _%$%e244979245871%_
                           _%$%hd244980245874%_
                           _%$%tl244981245876%_
                           _%$%e244982245879%_
                           _%$%hd244983245882%_
                           _%$%tl244984245884%_
                           _%$%e244985245887%_
                           _%$%hd244986245890%_
                           _%$%tl244987245892%_))))
                  (_%__match249812249813%_
                   _%$%e244964245831%_
                   _%$%hd244965245834%_
                   _%$%tl244966245836%_
                   _%$%e244967245839%_
                   _%$%hd244968245842%_
                   _%$%tl244969245844%_
                   _%$%e244970245847%_
                   _%$%hd244971245850%_
                   _%$%tl244972245852%_
                   _%$%e244973245855%_
                   _%$%hd244974245858%_
                   _%$%tl244975245860%_
                   _%$%e244976245863%_
                   _%$%hd244977245866%_
                   _%$%tl244978245868%_
                   _%$%e244979245871%_
                   _%$%hd244980245874%_
                   _%$%tl244981245876%_
                   _%$%e244982245879%_
                   _%$%hd244983245882%_
                   _%$%tl244984245884%_))
              (_%__kont249395249396%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                              (_%__kont249395249396%_))
                                          (_%__kont249395249396%_))
                                      (_%__kont249395249396%_))))
                              (_%__kont249395249396%_))))
                      (_%__kont249395249396%_))
                  (_%__kont249395249396%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                  (_%__kont249395249396%_))
                                              (_%__kont249395249396%_))
                                          (_%__kont249395249396%_))))
                                  (_%__kont249395249396%_))))
                          (_%__kont249395249396%_))))
                  (_%__kont249395249396%_)))))))
    (define gxc#subst-object-refs-call%
      (lambda (_%self243892%_ _%stx243893%_)
        (letrec ((_%force-e243895%_
                  (lambda (_%target244947%_)
                    (cons '%#call
                          (cons (cons '%#ref (cons 'force '()))
                                (cons (cons '%#ref (cons _%target244947%_ '()))
                                      '()))))))
          (let* ((_%__stx249879249880%_ _%stx243893%_)
                 (_%$%g243903244125%_
                  (lambda ()
                    (let ()
                      (declare (not safe))
                      (gx#raise-syntax-error
                       '#f
                       '"Bad syntax; invalid match target"
                       _%__stx249879249880%_)))))
            (let ((_%__kont249881249882%_
                   (lambda (_%$%g243905244893%_
                            _%$%g243906244894%_
                            _%$%g243907244895%_
                            _%$%g243908244896%_)
                     (let ((_%$method244941%_
                            (let ((__tmp250542
                                   (let ()
                                     (declare (not safe))
                                     (slot-ref__0 _%self243892%_ 'methods)))
                                  (__tmp250541
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%g243906244894%_))))
                              (declare (not safe))
                              (hash-ref__0 __tmp250542 __tmp250541)))
                           (_%args244942%_
                            (map (lambda (_%$%g244929244931%_)
                                   (let ()
                                     (declare (not safe))
                                     (gxc#compile-e__1
                                      _%self243892%_
                                      _%$%g244929244931%_)))
                                 (let ((__tmp250543
                                        (lambda (_%$%g244933244936%_
                                                 _%$%g244934244938%_)
                                          (cons _%$%g244933244936%_
                                                _%$%g244934244938%_))))
                                   (declare (not safe))
                                   (foldr__0
                                    __tmp250543
                                    '()
                                    _%$%g243905244893%_)))))
                       (let ((__tmp250544
                              (cons '%#call
                                    (cons (_%force-e243895%_ _%$method244941%_)
                                          (cons (cons '%#ref
                                                      (cons (let ()
                                                              (declare
                                                                (not safe))
                                                              (slot-ref__0
                                                               _%self243892%_
                                                               'receiver))
                                                            '()))
                                                _%args244942%_)))))
                         (declare (not safe))
                         (gxc#xform-wrap-source __tmp250544 _%stx243893%_)))))
                  (_%__kont249885249886%_
                   (lambda (_%$%g243948244727%_
                            _%$%g243949244728%_
                            _%$%g243950244729%_
                            _%$%g243951244730%_
                            _%$%g243952244731%_)
                     (let ((_%$method244783%_
                            (let ((__tmp250546
                                   (let ()
                                     (declare (not safe))
                                     (slot-ref__0 _%self243892%_ 'methods)))
                                  (__tmp250545
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%g243949244728%_))))
                              (declare (not safe))
                              (hash-ref__0 __tmp250546 __tmp250545)))
                           (_%args244784%_
                            (map (lambda (_%$%g244771244773%_)
                                   (let ()
                                     (declare (not safe))
                                     (gxc#compile-e__1
                                      _%self243892%_
                                      _%$%g244771244773%_)))
                                 (let ((__tmp250547
                                        (lambda (_%$%g244775244778%_
                                                 _%$%g244776244780%_)
                                          (cons _%$%g244775244778%_
                                                _%$%g244776244780%_))))
                                   (declare (not safe))
                                   (foldr__0
                                    __tmp250547
                                    '()
                                    _%$%g243948244727%_)))))
                       (let ((__tmp250548
                              (cons '%#call
                                    (cons (cons '%#ref (cons 'apply '()))
                                          (cons (_%force-e243895%_
                                                 _%$method244783%_)
                                                (cons (cons '%#ref
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (slot-ref__0 _%self243892%_ 'receiver))
                          '()))
              _%args244784%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                         (declare (not safe))
                         (gxc#xform-wrap-source __tmp250548 _%stx243893%_)))))
                  (_%__kont249889249890%_
                   (lambda (_%$%g244001244560%_
                            _%$%g244002244561%_
                            _%$%g244003244562%_)
                     (let* ((_%$field244594%_
                             (let ((__tmp250550
                                    (let ()
                                      (declare (not safe))
                                      (slot-ref__0 _%self243892%_ 'slots)))
                                   (__tmp250549
                                    (let ()
                                      (declare (not safe))
                                      (gx#stx-e _%$%g244001244560%_))))
                               (declare (not safe))
                               (hash-ref__0 __tmp250550 __tmp250549)))
                            (__tmp250551
                             (cons '%#struct-unchecked-ref
                                   (cons (cons '%#ref
                                               (cons (let ()
                                                       (declare (not safe))
                                                       (slot-ref__0
                                                        _%self243892%_
                                                        'klass))
                                                     '()))
                                         (cons (cons '%#ref
                                                     (cons _%$field244594%_
                                                           '()))
                                               (cons (cons '%#ref
                                                           (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (declare (not safe))
                           (slot-ref__0 _%self243892%_ 'receiver))
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     '()))))))
                       (declare (not safe))
                       (gxc#xform-wrap-source __tmp250551 _%stx243893%_))))
                  (_%__kont249891249892%_
                   (lambda (_%$%g244034244434%_
                            _%$%g244035244435%_
                            _%$%g244036244436%_
                            _%$%g244037244437%_)
                     (let ((_%$field244472%_
                            (let ((__tmp250553
                                   (let ()
                                     (declare (not safe))
                                     (slot-ref__0 _%self243892%_ 'slots)))
                                  (__tmp250552
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%g244035244435%_))))
                              (declare (not safe))
                              (hash-ref__0 __tmp250553 __tmp250552)))
                           (_%expr244473%_
                            (let ()
                              (declare (not safe))
                              (gxc#compile-e__1
                               _%self243892%_
                               _%$%g244034244434%_))))
                       (let ((__tmp250554
                              (cons '%#struct-unchecked-set!
                                    (cons (cons '%#ref
                                                (cons (let ()
                                                        (declare (not safe))
                                                        (slot-ref__0
                                                         _%self243892%_
                                                         'klass))
                                                      '()))
                                          (cons (cons '%#ref
                                                      (cons _%$field244472%_
                                                            '()))
                                                (cons (cons '%#ref
                                                            (cons (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (declare (not safe))
                            (slot-ref__0 _%self243892%_ 'receiver))
                          '()))
              (cons _%expr244473%_ '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                         (declare (not safe))
                         (gxc#xform-wrap-source __tmp250554 _%stx243893%_)))))
                  (_%__kont249893249894%_
                   (lambda (_%$%g244071244306%_ _%$%g244072244307%_)
                     (let* ((_%accessor244329%_
                             (let ((__tmp250555
                                    (let ()
                                      (declare (not safe))
                                      (gxc#identifier-symbol
                                       _%$%g244072244307%_))))
                               (declare (not safe))
                               (gxc#optimizer-resolve-type __tmp250555)))
                            (_%klass244331%_
                             (let ((__tmp250556
                                    (##structure-ref
                                     _%accessor244329%_
                                     '1
                                     gxc#!type::t
                                     '#f)))
                               (declare (not safe))
                               (gxc#optimizer-resolve-class
                                _%stx243893%_
                                __tmp250556)))
                            (_%slot244333%_
                             (##structure-ref
                              _%accessor244329%_
                              '3
                              gxc#!accessor::t
                              '#f)))
                       (if (if (##structure-ref
                                _%accessor244329%_
                                '4
                                gxc#!accessor::t
                                '#f)
                               '#f
                               (or (let ()
                                     (declare (not safe))
                                     (gxc#!class-struct-slot?
                                      _%klass244331%_
                                      _%slot244333%_))
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%klass244331%_
                                      '8
                                      '#f
                                      '#f))))
                           _%stx243893%_
                           (let* ((_%$field244339%_
                                   (let ((__tmp250557
                                          (let ()
                                            (declare (not safe))
                                            (slot-ref__0
                                             _%self243892%_
                                             'slots))))
                                     (declare (not safe))
                                     (hash-ref__0 __tmp250557 _%slot244333%_)))
                                  (__tmp250558
                                   (cons '%#struct-unchecked-ref
                                         (cons (cons '%#ref
                                                     (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (slot-ref__0
                                                              _%self243892%_
                                                              'klass))
                                                           '()))
                                               (cons (cons '%#ref
                                                           (cons _%$field244339%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (let ()
                                 (declare (not safe))
                                 (slot-ref__0 _%self243892%_ 'receiver))
                               '()))
                   '()))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                             (declare (not safe))
                             (gxc#xform-wrap-source
                              __tmp250558
                              _%stx243893%_))))))
                  (_%__kont249895249896%_
                   (lambda (_%$%g244094244201%_
                            _%$%g244095244202%_
                            _%$%g244096244203%_)
                     (let* ((_%mutator244231%_
                             (let ((__tmp250559
                                    (let ()
                                      (declare (not safe))
                                      (gxc#identifier-symbol
                                       _%$%g244096244203%_))))
                               (declare (not safe))
                               (gxc#optimizer-resolve-type __tmp250559)))
                            (_%klass244233%_
                             (let ((__tmp250560
                                    (##structure-ref
                                     _%mutator244231%_
                                     '1
                                     gxc#!type::t
                                     '#f)))
                               (declare (not safe))
                               (gxc#optimizer-resolve-class
                                _%stx243893%_
                                __tmp250560)))
                            (_%slot244235%_
                             (##structure-ref
                              _%mutator244231%_
                              '3
                              gxc#!mutator::t
                              '#f))
                            (_%expr244237%_
                             (let ()
                               (declare (not safe))
                               (gxc#compile-e__1
                                _%self243892%_
                                _%$%g244094244201%_))))
                       (if (if (##structure-ref
                                _%mutator244231%_
                                '4
                                gxc#!mutator::t
                                '#f)
                               '#f
                               (or (let ()
                                     (declare (not safe))
                                     (gxc#!class-struct-slot?
                                      _%klass244233%_
                                      _%slot244235%_))
                                   (let ()
                                     (declare (not safe))
                                     (##unchecked-structure-ref
                                      _%klass244233%_
                                      '8
                                      '#f
                                      '#f))))
                           (let ((__tmp250561
                                  (cons '%#call
                                        (cons (cons (let ()
                                                      (declare (not safe))
                                                      (gx#datum->syntax__0
                                                       '#f
                                                       '%#ref))
                                                    (cons _%$%g244096244203%_
                                                          '()))
                                              (cons (cons (let ()
                                                            (declare
                                                              (not safe))
                                                            (gx#datum->syntax__0
                                                             '#f
                                                             '%#ref))
                                                          (cons _%$%g244095244202%_
                                                                '()))
                                                    (cons _%expr244237%_
                                                          '()))))))
                             (declare (not safe))
                             (gxc#xform-wrap-source __tmp250561 _%stx243893%_))
                           (let* ((_%$field244243%_
                                   (let ((__tmp250562
                                          (let ()
                                            (declare (not safe))
                                            (slot-ref__0
                                             _%self243892%_
                                             'slots))))
                                     (declare (not safe))
                                     (hash-ref__0 __tmp250562 _%slot244235%_)))
                                  (__tmp250563
                                   (cons '%#struct-unchecked-set!
                                         (cons (cons '%#ref
                                                     (cons (let ()
                                                             (declare
                                                               (not safe))
                                                             (slot-ref__0
                                                              _%self243892%_
                                                              'klass))
                                                           '()))
                                               (cons (cons '%#ref
                                                           (cons _%$field244243%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         '()))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                     (cons (cons '%#ref
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (cons (let ()
                                 (declare (not safe))
                                 (slot-ref__0 _%self243892%_ 'receiver))
                               '()))
                   (cons _%expr244237%_ '())))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                             (declare (not safe))
                             (gxc#xform-wrap-source
                              __tmp250563
                              _%stx243893%_))))))
                  (_%__kont249897249898%_
                   (lambda ()
                     (let ()
                       (declare (not safe))
                       (gxc#xform-operands _%self243892%_ _%stx243893%_)))))
              (let* ((_%__match250378250379%_
                      (lambda (_%$%e244097244137%_
                               _%$%hd244098244140%_
                               _%$%tl244099244142%_
                               _%$%e244100244145%_
                               _%$%hd244101244148%_
                               _%$%tl244102244150%_
                               _%$%e244103244153%_
                               _%$%hd244104244156%_
                               _%$%tl244105244158%_
                               _%$%e244106244161%_
                               _%$%hd244107244164%_
                               _%$%tl244108244166%_
                               _%$%e244109244169%_
                               _%$%hd244110244172%_
                               _%$%tl244111244174%_
                               _%$%e244112244177%_
                               _%$%hd244113244180%_
                               _%$%tl244114244182%_
                               _%$%e244115244185%_
                               _%$%hd244116244188%_
                               _%$%tl244117244190%_
                               _%$%e244118244193%_
                               _%$%hd244119244196%_
                               _%$%tl244120244198%_)
                        (let ((_%$%g244094244201%_ _%$%hd244119244196%_)
                              (_%$%g244095244202%_ _%$%hd244116244188%_)
                              (_%$%g244096244203%_ _%$%hd244107244164%_))
                          (if (and (let ((__tmp250564
                                          (let ()
                                            (declare (not safe))
                                            (slot-ref__0
                                             _%self243892%_
                                             'receiver))))
                                     (declare (not safe))
                                     (gx#free-identifier=?
                                      _%$%g244095244202%_
                                      __tmp250564))
                                   (let ((__tmp250565
                                          (let ((__tmp250566
                                                 (let ()
                                                   (declare (not safe))
                                                   (gxc#identifier-symbol
                                                    _%$%g244096244203%_))))
                                            (declare (not safe))
                                            (gxc#optimizer-resolve-type
                                             __tmp250566))))
                                     (declare (not safe))
                                     (##structure-instance-of?
                                      __tmp250565
                                      'gxc#!mutator::t)))
                              (_%__kont249895249896%_
                               _%$%g244094244201%_
                               _%$%g244095244202%_
                               _%$%g244096244203%_)
                              (_%__kont249897249898%_)))))
                     (_%__match250376250377%_
                      (lambda (_%$%e244097244137%_
                               _%$%hd244098244140%_
                               _%$%tl244099244142%_
                               _%$%e244100244145%_
                               _%$%hd244101244148%_
                               _%$%tl244102244150%_
                               _%$%e244103244153%_
                               _%$%hd244104244156%_
                               _%$%tl244105244158%_
                               _%$%e244106244161%_
                               _%$%hd244107244164%_
                               _%$%tl244108244166%_
                               _%$%e244109244169%_
                               _%$%hd244110244172%_
                               _%$%tl244111244174%_
                               _%$%e244112244177%_
                               _%$%hd244113244180%_
                               _%$%tl244114244182%_
                               _%$%e244115244185%_
                               _%$%hd244116244188%_
                               _%$%tl244117244190%_
                               _%$%e244118244193%_
                               _%$%hd244119244196%_
                               _%$%tl244120244198%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl244120244198%_))
                            (_%__match250378250379%_
                             _%$%e244097244137%_
                             _%$%hd244098244140%_
                             _%$%tl244099244142%_
                             _%$%e244100244145%_
                             _%$%hd244101244148%_
                             _%$%tl244102244150%_
                             _%$%e244103244153%_
                             _%$%hd244104244156%_
                             _%$%tl244105244158%_
                             _%$%e244106244161%_
                             _%$%hd244107244164%_
                             _%$%tl244108244166%_
                             _%$%e244109244169%_
                             _%$%hd244110244172%_
                             _%$%tl244111244174%_
                             _%$%e244112244177%_
                             _%$%hd244113244180%_
                             _%$%tl244114244182%_
                             _%$%e244115244185%_
                             _%$%hd244116244188%_
                             _%$%tl244117244190%_
                             _%$%e244118244193%_
                             _%$%hd244119244196%_
                             _%$%tl244120244198%_)
                            (_%__kont249897249898%_))))
                     (_%__match250370250371%_
                      (lambda (_%$%e244097244137%_
                               _%$%hd244098244140%_
                               _%$%tl244099244142%_
                               _%$%e244100244145%_
                               _%$%hd244101244148%_
                               _%$%tl244102244150%_
                               _%$%e244103244153%_
                               _%$%hd244104244156%_
                               _%$%tl244105244158%_
                               _%$%e244106244161%_
                               _%$%hd244107244164%_
                               _%$%tl244108244166%_
                               _%$%e244109244169%_
                               _%$%hd244110244172%_
                               _%$%tl244111244174%_
                               _%$%e244112244177%_
                               _%$%hd244113244180%_
                               _%$%tl244114244182%_
                               _%$%e244115244185%_
                               _%$%hd244116244188%_
                               _%$%tl244117244190%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl244111244174%_))
                            (let ((_%$%e244118244193%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl244111244174%_))))
                              (let ((_%$%tl244120244198%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e244118244193%_)))
                                    (_%$%hd244119244196%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e244118244193%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-null? _%$%tl244120244198%_))
                                    (_%__match250378250379%_
                                     _%$%e244097244137%_
                                     _%$%hd244098244140%_
                                     _%$%tl244099244142%_
                                     _%$%e244100244145%_
                                     _%$%hd244101244148%_
                                     _%$%tl244102244150%_
                                     _%$%e244103244153%_
                                     _%$%hd244104244156%_
                                     _%$%tl244105244158%_
                                     _%$%e244106244161%_
                                     _%$%hd244107244164%_
                                     _%$%tl244108244166%_
                                     _%$%e244109244169%_
                                     _%$%hd244110244172%_
                                     _%$%tl244111244174%_
                                     _%$%e244112244177%_
                                     _%$%hd244113244180%_
                                     _%$%tl244114244182%_
                                     _%$%e244115244185%_
                                     _%$%hd244116244188%_
                                     _%$%tl244117244190%_
                                     _%$%e244118244193%_
                                     _%$%hd244119244196%_
                                     _%$%tl244120244198%_)
                                    (_%__kont249897249898%_))))
                            (_%__kont249897249898%_))))
                     (_%__match250316250317%_
                      (lambda (_%$%e244073244250%_
                               _%$%hd244074244253%_
                               _%$%tl244075244255%_
                               _%$%e244076244258%_
                               _%$%hd244077244261%_
                               _%$%tl244078244263%_
                               _%$%e244079244266%_
                               _%$%hd244080244269%_
                               _%$%tl244081244271%_
                               _%$%e244082244274%_
                               _%$%hd244083244277%_
                               _%$%tl244084244279%_
                               _%$%e244085244282%_
                               _%$%hd244086244285%_
                               _%$%tl244087244287%_
                               _%$%e244088244290%_
                               _%$%hd244089244293%_
                               _%$%tl244090244295%_
                               _%$%e244091244298%_
                               _%$%hd244092244301%_
                               _%$%tl244093244303%_)
                        (let ((_%$%g244071244306%_ _%$%hd244092244301%_)
                              (_%$%g244072244307%_ _%$%hd244083244277%_))
                          (if (and (let ((__tmp250567
                                          (let ()
                                            (declare (not safe))
                                            (slot-ref__0
                                             _%self243892%_
                                             'receiver))))
                                     (declare (not safe))
                                     (gx#free-identifier=?
                                      _%$%g244071244306%_
                                      __tmp250567))
                                   (let ((__tmp250568
                                          (let ((__tmp250569
                                                 (let ()
                                                   (declare (not safe))
                                                   (gxc#identifier-symbol
                                                    _%$%g244072244307%_))))
                                            (declare (not safe))
                                            (gxc#optimizer-resolve-type
                                             __tmp250569))))
                                     (declare (not safe))
                                     (##structure-instance-of?
                                      __tmp250568
                                      'gxc#!accessor::t)))
                              (_%__kont249893249894%_
                               _%$%g244071244306%_
                               _%$%g244072244307%_)
                              (_%__kont249897249898%_)))))
                     (_%__match250314250315%_
                      (lambda (_%$%e244073244250%_
                               _%$%hd244074244253%_
                               _%$%tl244075244255%_
                               _%$%e244076244258%_
                               _%$%hd244077244261%_
                               _%$%tl244078244263%_
                               _%$%e244079244266%_
                               _%$%hd244080244269%_
                               _%$%tl244081244271%_
                               _%$%e244082244274%_
                               _%$%hd244083244277%_
                               _%$%tl244084244279%_
                               _%$%e244085244282%_
                               _%$%hd244086244285%_
                               _%$%tl244087244287%_
                               _%$%e244088244290%_
                               _%$%hd244089244293%_
                               _%$%tl244090244295%_
                               _%$%e244091244298%_
                               _%$%hd244092244301%_
                               _%$%tl244093244303%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl244087244287%_))
                            (_%__match250316250317%_
                             _%$%e244073244250%_
                             _%$%hd244074244253%_
                             _%$%tl244075244255%_
                             _%$%e244076244258%_
                             _%$%hd244077244261%_
                             _%$%tl244078244263%_
                             _%$%e244079244266%_
                             _%$%hd244080244269%_
                             _%$%tl244081244271%_
                             _%$%e244082244274%_
                             _%$%hd244083244277%_
                             _%$%tl244084244279%_
                             _%$%e244085244282%_
                             _%$%hd244086244285%_
                             _%$%tl244087244287%_
                             _%$%e244088244290%_
                             _%$%hd244089244293%_
                             _%$%tl244090244295%_
                             _%$%e244091244298%_
                             _%$%hd244092244301%_
                             _%$%tl244093244303%_)
                            (_%__match250370250371%_
                             _%$%e244073244250%_
                             _%$%hd244074244253%_
                             _%$%tl244075244255%_
                             _%$%e244076244258%_
                             _%$%hd244077244261%_
                             _%$%tl244078244263%_
                             _%$%e244079244266%_
                             _%$%hd244080244269%_
                             _%$%tl244081244271%_
                             _%$%e244082244274%_
                             _%$%hd244083244277%_
                             _%$%tl244084244279%_
                             _%$%e244085244282%_
                             _%$%hd244086244285%_
                             _%$%tl244087244287%_
                             _%$%e244088244290%_
                             _%$%hd244089244293%_
                             _%$%tl244090244295%_
                             _%$%e244091244298%_
                             _%$%hd244092244301%_
                             _%$%tl244093244303%_))))
                     (_%__match250260250261%_
                      (lambda (_%$%e244038244346%_
                               _%$%hd244039244349%_
                               _%$%tl244040244351%_
                               _%$%e244041244354%_
                               _%$%hd244042244357%_
                               _%$%tl244043244359%_
                               _%$%e244044244362%_
                               _%$%hd244045244365%_
                               _%$%tl244046244367%_
                               _%$%e244047244370%_
                               _%$%hd244048244373%_
                               _%$%tl244049244375%_
                               _%$%e244050244378%_
                               _%$%hd244051244381%_
                               _%$%tl244052244383%_
                               _%$%e244053244386%_
                               _%$%hd244054244389%_
                               _%$%tl244055244391%_
                               _%$%e244056244394%_
                               _%$%hd244057244397%_
                               _%$%tl244058244399%_
                               _%$%e244059244402%_
                               _%$%hd244060244405%_
                               _%$%tl244061244407%_
                               _%$%e244062244410%_
                               _%$%hd244063244413%_
                               _%$%tl244064244415%_
                               _%$%e244065244418%_
                               _%$%hd244066244421%_
                               _%$%tl244067244423%_
                               _%$%e244068244426%_
                               _%$%hd244069244429%_
                               _%$%tl244070244431%_)
                        (let ((_%$%g244034244434%_ _%$%hd244069244429%_)
                              (_%$%g244035244435%_ _%$%hd244066244421%_)
                              (_%$%g244036244436%_ _%$%hd244057244397%_)
                              (_%$%g244037244437%_ _%$%hd244048244373%_))
                          (if (and (or (let ()
                                         (declare (not safe))
                                         (gxc#runtime-identifier=?
                                          _%$%g244037244437%_
                                          'slot-set!))
                                       (let ()
                                         (declare (not safe))
                                         (gxc#runtime-identifier=?
                                          _%$%g244037244437%_
                                          'unchecked-slot-set!)))
                                   (let ((__tmp250570
                                          (let ()
                                            (declare (not safe))
                                            (slot-ref__0
                                             _%self243892%_
                                             'receiver))))
                                     (declare (not safe))
                                     (gx#free-identifier=?
                                      _%$%g244036244436%_
                                      __tmp250570)))
                              (_%__kont249891249892%_
                               _%$%g244034244434%_
                               _%$%g244035244435%_
                               _%$%g244036244436%_
                               _%$%g244037244437%_)
                              (_%__kont249897249898%_)))))
                     (_%__match250252250253%_
                      (lambda (_%$%e244038244346%_
                               _%$%hd244039244349%_
                               _%$%tl244040244351%_
                               _%$%e244041244354%_
                               _%$%hd244042244357%_
                               _%$%tl244043244359%_
                               _%$%e244044244362%_
                               _%$%hd244045244365%_
                               _%$%tl244046244367%_
                               _%$%e244047244370%_
                               _%$%hd244048244373%_
                               _%$%tl244049244375%_
                               _%$%e244050244378%_
                               _%$%hd244051244381%_
                               _%$%tl244052244383%_
                               _%$%e244053244386%_
                               _%$%hd244054244389%_
                               _%$%tl244055244391%_
                               _%$%e244056244394%_
                               _%$%hd244057244397%_
                               _%$%tl244058244399%_
                               _%$%e244059244402%_
                               _%$%hd244060244405%_
                               _%$%tl244061244407%_
                               _%$%e244062244410%_
                               _%$%hd244063244413%_
                               _%$%tl244064244415%_
                               _%$%e244065244418%_
                               _%$%hd244066244421%_
                               _%$%tl244067244423%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl244061244407%_))
                            (let ((_%$%e244068244426%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl244061244407%_))))
                              (let ((_%$%tl244070244431%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e244068244426%_)))
                                    (_%$%hd244069244429%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e244068244426%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-null? _%$%tl244070244431%_))
                                    (_%__match250260250261%_
                                     _%$%e244038244346%_
                                     _%$%hd244039244349%_
                                     _%$%tl244040244351%_
                                     _%$%e244041244354%_
                                     _%$%hd244042244357%_
                                     _%$%tl244043244359%_
                                     _%$%e244044244362%_
                                     _%$%hd244045244365%_
                                     _%$%tl244046244367%_
                                     _%$%e244047244370%_
                                     _%$%hd244048244373%_
                                     _%$%tl244049244375%_
                                     _%$%e244050244378%_
                                     _%$%hd244051244381%_
                                     _%$%tl244052244383%_
                                     _%$%e244053244386%_
                                     _%$%hd244054244389%_
                                     _%$%tl244055244391%_
                                     _%$%e244056244394%_
                                     _%$%hd244057244397%_
                                     _%$%tl244058244399%_
                                     _%$%e244059244402%_
                                     _%$%hd244060244405%_
                                     _%$%tl244061244407%_
                                     _%$%e244062244410%_
                                     _%$%hd244063244413%_
                                     _%$%tl244064244415%_
                                     _%$%e244065244418%_
                                     _%$%hd244066244421%_
                                     _%$%tl244067244423%_
                                     _%$%e244068244426%_
                                     _%$%hd244069244429%_
                                     _%$%tl244070244431%_)
                                    (_%__kont249897249898%_))))
                            (_%__match250376250377%_
                             _%$%e244038244346%_
                             _%$%hd244039244349%_
                             _%$%tl244040244351%_
                             _%$%e244041244354%_
                             _%$%hd244042244357%_
                             _%$%tl244043244359%_
                             _%$%e244044244362%_
                             _%$%hd244045244365%_
                             _%$%tl244046244367%_
                             _%$%e244047244370%_
                             _%$%hd244048244373%_
                             _%$%tl244049244375%_
                             _%$%e244050244378%_
                             _%$%hd244051244381%_
                             _%$%tl244052244383%_
                             _%$%e244053244386%_
                             _%$%hd244054244389%_
                             _%$%tl244055244391%_
                             _%$%e244056244394%_
                             _%$%hd244057244397%_
                             _%$%tl244058244399%_
                             _%$%e244059244402%_
                             _%$%hd244060244405%_
                             _%$%tl244061244407%_))))
                     (_%__match250174250175%_
                      (lambda (_%$%e244004244480%_
                               _%$%hd244005244483%_
                               _%$%tl244006244485%_
                               _%$%e244007244488%_
                               _%$%hd244008244491%_
                               _%$%tl244009244493%_
                               _%$%e244010244496%_
                               _%$%hd244011244499%_
                               _%$%tl244012244501%_
                               _%$%e244013244504%_
                               _%$%hd244014244507%_
                               _%$%tl244015244509%_
                               _%$%e244016244512%_
                               _%$%hd244017244515%_
                               _%$%tl244018244517%_
                               _%$%e244019244520%_
                               _%$%hd244020244523%_
                               _%$%tl244021244525%_
                               _%$%e244022244528%_
                               _%$%hd244023244531%_
                               _%$%tl244024244533%_
                               _%$%e244025244536%_
                               _%$%hd244026244539%_
                               _%$%tl244027244541%_
                               _%$%e244028244544%_
                               _%$%hd244029244547%_
                               _%$%tl244030244549%_
                               _%$%e244031244552%_
                               _%$%hd244032244555%_
                               _%$%tl244033244557%_)
                        (let ((_%$%g244001244560%_ _%$%hd244032244555%_)
                              (_%$%g244002244561%_ _%$%hd244023244531%_)
                              (_%$%g244003244562%_ _%$%hd244014244507%_))
                          (if (and (or (let ()
                                         (declare (not safe))
                                         (gxc#runtime-identifier=?
                                          _%$%g244003244562%_
                                          'slot-ref))
                                       (let ()
                                         (declare (not safe))
                                         (gxc#runtime-identifier=?
                                          _%$%g244003244562%_
                                          'unchecked-slot-ref)))
                                   (let ((__tmp250571
                                          (let ()
                                            (declare (not safe))
                                            (slot-ref__0
                                             _%self243892%_
                                             'receiver))))
                                     (declare (not safe))
                                     (gx#free-identifier=?
                                      _%$%g244002244561%_
                                      __tmp250571)))
                              (_%__kont249889249890%_
                               _%$%g244001244560%_
                               _%$%g244002244561%_
                               _%$%g244003244562%_)
                              (_%__match250378250379%_
                               _%$%e244004244480%_
                               _%$%hd244005244483%_
                               _%$%tl244006244485%_
                               _%$%e244007244488%_
                               _%$%hd244008244491%_
                               _%$%tl244009244493%_
                               _%$%e244010244496%_
                               _%$%hd244011244499%_
                               _%$%tl244012244501%_
                               _%$%e244013244504%_
                               _%$%hd244014244507%_
                               _%$%tl244015244509%_
                               _%$%e244016244512%_
                               _%$%hd244017244515%_
                               _%$%tl244018244517%_
                               _%$%e244019244520%_
                               _%$%hd244020244523%_
                               _%$%tl244021244525%_
                               _%$%e244022244528%_
                               _%$%hd244023244531%_
                               _%$%tl244024244533%_
                               _%$%e244025244536%_
                               _%$%hd244026244539%_
                               _%$%tl244027244541%_)))))
                     (_%__match250172250173%_
                      (lambda (_%$%e244004244480%_
                               _%$%hd244005244483%_
                               _%$%tl244006244485%_
                               _%$%e244007244488%_
                               _%$%hd244008244491%_
                               _%$%tl244009244493%_
                               _%$%e244010244496%_
                               _%$%hd244011244499%_
                               _%$%tl244012244501%_
                               _%$%e244013244504%_
                               _%$%hd244014244507%_
                               _%$%tl244015244509%_
                               _%$%e244016244512%_
                               _%$%hd244017244515%_
                               _%$%tl244018244517%_
                               _%$%e244019244520%_
                               _%$%hd244020244523%_
                               _%$%tl244021244525%_
                               _%$%e244022244528%_
                               _%$%hd244023244531%_
                               _%$%tl244024244533%_
                               _%$%e244025244536%_
                               _%$%hd244026244539%_
                               _%$%tl244027244541%_
                               _%$%e244028244544%_
                               _%$%hd244029244547%_
                               _%$%tl244030244549%_
                               _%$%e244031244552%_
                               _%$%hd244032244555%_
                               _%$%tl244033244557%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-null? _%$%tl244027244541%_))
                            (_%__match250174250175%_
                             _%$%e244004244480%_
                             _%$%hd244005244483%_
                             _%$%tl244006244485%_
                             _%$%e244007244488%_
                             _%$%hd244008244491%_
                             _%$%tl244009244493%_
                             _%$%e244010244496%_
                             _%$%hd244011244499%_
                             _%$%tl244012244501%_
                             _%$%e244013244504%_
                             _%$%hd244014244507%_
                             _%$%tl244015244509%_
                             _%$%e244016244512%_
                             _%$%hd244017244515%_
                             _%$%tl244018244517%_
                             _%$%e244019244520%_
                             _%$%hd244020244523%_
                             _%$%tl244021244525%_
                             _%$%e244022244528%_
                             _%$%hd244023244531%_
                             _%$%tl244024244533%_
                             _%$%e244025244536%_
                             _%$%hd244026244539%_
                             _%$%tl244027244541%_
                             _%$%e244028244544%_
                             _%$%hd244029244547%_
                             _%$%tl244030244549%_
                             _%$%e244031244552%_
                             _%$%hd244032244555%_
                             _%$%tl244033244557%_)
                            (_%__match250252250253%_
                             _%$%e244004244480%_
                             _%$%hd244005244483%_
                             _%$%tl244006244485%_
                             _%$%e244007244488%_
                             _%$%hd244008244491%_
                             _%$%tl244009244493%_
                             _%$%e244010244496%_
                             _%$%hd244011244499%_
                             _%$%tl244012244501%_
                             _%$%e244013244504%_
                             _%$%hd244014244507%_
                             _%$%tl244015244509%_
                             _%$%e244016244512%_
                             _%$%hd244017244515%_
                             _%$%tl244018244517%_
                             _%$%e244019244520%_
                             _%$%hd244020244523%_
                             _%$%tl244021244525%_
                             _%$%e244022244528%_
                             _%$%hd244023244531%_
                             _%$%tl244024244533%_
                             _%$%e244025244536%_
                             _%$%hd244026244539%_
                             _%$%tl244027244541%_
                             _%$%e244028244544%_
                             _%$%hd244029244547%_
                             _%$%tl244030244549%_
                             _%$%e244031244552%_
                             _%$%hd244032244555%_
                             _%$%tl244033244557%_))))
                     (_%__match250162250163%_
                      (lambda (_%$%e244004244480%_
                               _%$%hd244005244483%_
                               _%$%tl244006244485%_
                               _%$%e244007244488%_
                               _%$%hd244008244491%_
                               _%$%tl244009244493%_
                               _%$%e244010244496%_
                               _%$%hd244011244499%_
                               _%$%tl244012244501%_
                               _%$%e244013244504%_
                               _%$%hd244014244507%_
                               _%$%tl244015244509%_
                               _%$%e244016244512%_
                               _%$%hd244017244515%_
                               _%$%tl244018244517%_
                               _%$%e244019244520%_
                               _%$%hd244020244523%_
                               _%$%tl244021244525%_
                               _%$%e244022244528%_
                               _%$%hd244023244531%_
                               _%$%tl244024244533%_
                               _%$%e244025244536%_
                               _%$%hd244026244539%_
                               _%$%tl244027244541%_
                               _%$%e244028244544%_
                               _%$%hd244029244547%_
                               _%$%tl244030244549%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-eq? '%#quote _%$%hd244029244547%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl244030244549%_))
                                (let ((_%$%e244031244552%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl244030244549%_))))
                                  (let ((_%$%tl244033244557%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e244031244552%_)))
                                        (_%$%hd244032244555%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e244031244552%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl244033244557%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-null?
                                               _%$%tl244027244541%_))
                                            (_%__match250174250175%_
                                             _%$%e244004244480%_
                                             _%$%hd244005244483%_
                                             _%$%tl244006244485%_
                                             _%$%e244007244488%_
                                             _%$%hd244008244491%_
                                             _%$%tl244009244493%_
                                             _%$%e244010244496%_
                                             _%$%hd244011244499%_
                                             _%$%tl244012244501%_
                                             _%$%e244013244504%_
                                             _%$%hd244014244507%_
                                             _%$%tl244015244509%_
                                             _%$%e244016244512%_
                                             _%$%hd244017244515%_
                                             _%$%tl244018244517%_
                                             _%$%e244019244520%_
                                             _%$%hd244020244523%_
                                             _%$%tl244021244525%_
                                             _%$%e244022244528%_
                                             _%$%hd244023244531%_
                                             _%$%tl244024244533%_
                                             _%$%e244025244536%_
                                             _%$%hd244026244539%_
                                             _%$%tl244027244541%_
                                             _%$%e244028244544%_
                                             _%$%hd244029244547%_
                                             _%$%tl244030244549%_
                                             _%$%e244031244552%_
                                             _%$%hd244032244555%_
                                             _%$%tl244033244557%_)
                                            (_%__match250252250253%_
                                             _%$%e244004244480%_
                                             _%$%hd244005244483%_
                                             _%$%tl244006244485%_
                                             _%$%e244007244488%_
                                             _%$%hd244008244491%_
                                             _%$%tl244009244493%_
                                             _%$%e244010244496%_
                                             _%$%hd244011244499%_
                                             _%$%tl244012244501%_
                                             _%$%e244013244504%_
                                             _%$%hd244014244507%_
                                             _%$%tl244015244509%_
                                             _%$%e244016244512%_
                                             _%$%hd244017244515%_
                                             _%$%tl244018244517%_
                                             _%$%e244019244520%_
                                             _%$%hd244020244523%_
                                             _%$%tl244021244525%_
                                             _%$%e244022244528%_
                                             _%$%hd244023244531%_
                                             _%$%tl244024244533%_
                                             _%$%e244025244536%_
                                             _%$%hd244026244539%_
                                             _%$%tl244027244541%_
                                             _%$%e244028244544%_
                                             _%$%hd244029244547%_
                                             _%$%tl244030244549%_
                                             _%$%e244031244552%_
                                             _%$%hd244032244555%_
                                             _%$%tl244033244557%_))
                                        (_%__match250376250377%_
                                         _%$%e244004244480%_
                                         _%$%hd244005244483%_
                                         _%$%tl244006244485%_
                                         _%$%e244007244488%_
                                         _%$%hd244008244491%_
                                         _%$%tl244009244493%_
                                         _%$%e244010244496%_
                                         _%$%hd244011244499%_
                                         _%$%tl244012244501%_
                                         _%$%e244013244504%_
                                         _%$%hd244014244507%_
                                         _%$%tl244015244509%_
                                         _%$%e244016244512%_
                                         _%$%hd244017244515%_
                                         _%$%tl244018244517%_
                                         _%$%e244019244520%_
                                         _%$%hd244020244523%_
                                         _%$%tl244021244525%_
                                         _%$%e244022244528%_
                                         _%$%hd244023244531%_
                                         _%$%tl244024244533%_
                                         _%$%e244025244536%_
                                         _%$%hd244026244539%_
                                         _%$%tl244027244541%_))))
                                (_%__match250376250377%_
                                 _%$%e244004244480%_
                                 _%$%hd244005244483%_
                                 _%$%tl244006244485%_
                                 _%$%e244007244488%_
                                 _%$%hd244008244491%_
                                 _%$%tl244009244493%_
                                 _%$%e244010244496%_
                                 _%$%hd244011244499%_
                                 _%$%tl244012244501%_
                                 _%$%e244013244504%_
                                 _%$%hd244014244507%_
                                 _%$%tl244015244509%_
                                 _%$%e244016244512%_
                                 _%$%hd244017244515%_
                                 _%$%tl244018244517%_
                                 _%$%e244019244520%_
                                 _%$%hd244020244523%_
                                 _%$%tl244021244525%_
                                 _%$%e244022244528%_
                                 _%$%hd244023244531%_
                                 _%$%tl244024244533%_
                                 _%$%e244025244536%_
                                 _%$%hd244026244539%_
                                 _%$%tl244027244541%_))
                            (_%__match250376250377%_
                             _%$%e244004244480%_
                             _%$%hd244005244483%_
                             _%$%tl244006244485%_
                             _%$%e244007244488%_
                             _%$%hd244008244491%_
                             _%$%tl244009244493%_
                             _%$%e244010244496%_
                             _%$%hd244011244499%_
                             _%$%tl244012244501%_
                             _%$%e244013244504%_
                             _%$%hd244014244507%_
                             _%$%tl244015244509%_
                             _%$%e244016244512%_
                             _%$%hd244017244515%_
                             _%$%tl244018244517%_
                             _%$%e244019244520%_
                             _%$%hd244020244523%_
                             _%$%tl244021244525%_
                             _%$%e244022244528%_
                             _%$%hd244023244531%_
                             _%$%tl244024244533%_
                             _%$%e244025244536%_
                             _%$%hd244026244539%_
                             _%$%tl244027244541%_))))
                     (_%__match250094250095%_
                      (lambda (_%$%e243953244601%_
                               _%$%hd243954244604%_
                               _%$%tl243955244606%_
                               _%$%e243956244609%_
                               _%$%hd243957244612%_
                               _%$%tl243958244614%_
                               _%$%e243959244617%_
                               _%$%hd243960244620%_
                               _%$%tl243961244622%_
                               _%$%e243962244625%_
                               _%$%hd243963244628%_
                               _%$%tl243964244630%_
                               _%$%e243965244633%_
                               _%$%hd243966244636%_
                               _%$%tl243967244638%_
                               _%$%e243968244641%_
                               _%$%hd243969244644%_
                               _%$%tl243970244646%_
                               _%$%e243971244649%_
                               _%$%hd243972244652%_
                               _%$%tl243973244654%_
                               _%$%e243974244657%_
                               _%$%hd243975244660%_
                               _%$%tl243976244662%_
                               _%$%e243977244665%_
                               _%$%hd243978244668%_
                               _%$%tl243979244670%_
                               _%$%e243980244673%_
                               _%$%hd243981244676%_
                               _%$%tl243982244678%_
                               _%$%e243983244681%_
                               _%$%hd243984244684%_
                               _%$%tl243985244686%_
                               _%$%e243986244689%_
                               _%$%hd243987244692%_
                               _%$%tl243988244694%_
                               _%$%e243989244697%_
                               _%$%hd243990244700%_
                               _%$%tl243991244702%_
                               _%__splice249887249888%_
                               _%$%target243992244705%_
                               _%$%tl243994244707%_)
                        (letrec ((_%$%loop243995244710%_
                                  (lambda (_%$%hd243993244713%_
                                           _%$%args243999244715%_)
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%hd243993244713%_))
                                        (let ((_%$%e243996244717%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%hd243993244713%_))))
                                          (let ((_%$%lp-tl243998244722%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e243996244717%_)))
                                                (_%$%lp-hd243997244720%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e243996244717%_))))
                                            (_%$%loop243995244710%_
                                             _%$%lp-tl243998244722%_
                                             (cons _%$%lp-hd243997244720%_
                                                   _%$%args243999244715%_))))
                                        (let ((_%$%args244000244725%_
                                               (reverse _%$%args243999244715%_)))
                                          (let ((_%$%g243948244727%_
                                                 _%$%args244000244725%_)
                                                (_%$%g243949244728%_
                                                 _%$%hd243990244700%_)
                                                (_%$%g243950244729%_
                                                 _%$%hd243981244676%_)
                                                (_%$%g243951244730%_
                                                 _%$%hd243972244652%_)
                                                (_%$%g243952244731%_
                                                 _%$%hd243963244628%_))
                                            (if (and (let ()
                                                       (declare (not safe))
                                                       (gxc#runtime-identifier=?
                                                        _%$%g243952244731%_
                                                        'apply))
                                                     (let ()
                                                       (declare (not safe))
                                                       (gxc#runtime-identifier=?
                                                        _%$%g243951244730%_
                                                        'call-method))
                                                     (let ((__tmp250572
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (slot-ref__0
                                                               _%self243892%_
                                                               'receiver))))
                                                       (declare (not safe))
                                                       (gx#free-identifier=?
                                                        _%$%g243950244729%_
                                                        __tmp250572)))
                                                (_%__kont249885249886%_
                                                 _%$%g243948244727%_
                                                 _%$%g243949244728%_
                                                 _%$%g243950244729%_
                                                 _%$%g243951244730%_
                                                 _%$%g243952244731%_)
                                                (_%__kont249897249898%_))))))))
                          (_%$%loop243995244710%_
                           _%$%target243992244705%_
                           '()))))
                     (_%__match250052250053%_
                      (lambda (_%$%e243953244601%_
                               _%$%hd243954244604%_
                               _%$%tl243955244606%_
                               _%$%e243956244609%_
                               _%$%hd243957244612%_
                               _%$%tl243958244614%_
                               _%$%e243959244617%_
                               _%$%hd243960244620%_
                               _%$%tl243961244622%_
                               _%$%e243962244625%_
                               _%$%hd243963244628%_
                               _%$%tl243964244630%_
                               _%$%e243965244633%_
                               _%$%hd243966244636%_
                               _%$%tl243967244638%_
                               _%$%e243968244641%_
                               _%$%hd243969244644%_
                               _%$%tl243970244646%_
                               _%$%e243971244649%_
                               _%$%hd243972244652%_
                               _%$%tl243973244654%_
                               _%$%e243974244657%_
                               _%$%hd243975244660%_
                               _%$%tl243976244662%_
                               _%$%e243977244665%_
                               _%$%hd243978244668%_
                               _%$%tl243979244670%_)
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-eq? '%#ref _%$%hd243978244668%_))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%tl243979244670%_))
                                (let ((_%$%e243980244673%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%tl243979244670%_))))
                                  (let ((_%$%tl243982244678%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e243980244673%_)))
                                        (_%$%hd243981244676%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e243980244673%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-null? _%$%tl243982244678%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl243976244662%_))
                                            (let ((_%$%e243983244681%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl243976244662%_))))
                                              (let ((_%$%tl243985244686%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e243983244681%_)))
                                                    (_%$%hd243984244684%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e243983244681%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%hd243984244684%_))
                                                    (let ((_%$%e243986244689%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%hd243984244684%_))))
                                                      (let ((_%$%tl243988244694%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e243986244689%_)))
                    (_%$%hd243987244692%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e243986244689%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#identifier? _%$%hd243987244692%_))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-eq? '%#quote _%$%hd243987244692%_))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl243988244694%_))
                            (let ((_%$%e243989244697%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl243988244694%_))))
                              (let ((_%$%tl243991244702%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e243989244697%_)))
                                    (_%$%hd243990244700%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e243989244697%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-null? _%$%tl243991244702%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair/null?
                                           _%$%tl243985244686%_))
                                        (let ((_%__splice249887249888%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#syntax-split-splice->vector
                                                  _%$%tl243985244686%_
                                                  '0))))
                                          (let ((_%$%tl243994244707%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice249887249888%_
                                                    '1)))
                                                (_%$%target243992244705%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##vector-ref
                                                    _%__splice249887249888%_
                                                    '0))))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-null?
                                                   _%$%tl243994244707%_))
                                                (_%__match250094250095%_
                                                 _%$%e243953244601%_
                                                 _%$%hd243954244604%_
                                                 _%$%tl243955244606%_
                                                 _%$%e243956244609%_
                                                 _%$%hd243957244612%_
                                                 _%$%tl243958244614%_
                                                 _%$%e243959244617%_
                                                 _%$%hd243960244620%_
                                                 _%$%tl243961244622%_
                                                 _%$%e243962244625%_
                                                 _%$%hd243963244628%_
                                                 _%$%tl243964244630%_
                                                 _%$%e243965244633%_
                                                 _%$%hd243966244636%_
                                                 _%$%tl243967244638%_
                                                 _%$%e243968244641%_
                                                 _%$%hd243969244644%_
                                                 _%$%tl243970244646%_
                                                 _%$%e243971244649%_
                                                 _%$%hd243972244652%_
                                                 _%$%tl243973244654%_
                                                 _%$%e243974244657%_
                                                 _%$%hd243975244660%_
                                                 _%$%tl243976244662%_
                                                 _%$%e243977244665%_
                                                 _%$%hd243978244668%_
                                                 _%$%tl243979244670%_
                                                 _%$%e243980244673%_
                                                 _%$%hd243981244676%_
                                                 _%$%tl243982244678%_
                                                 _%$%e243983244681%_
                                                 _%$%hd243984244684%_
                                                 _%$%tl243985244686%_
                                                 _%$%e243986244689%_
                                                 _%$%hd243987244692%_
                                                 _%$%tl243988244694%_
                                                 _%$%e243989244697%_
                                                 _%$%hd243990244700%_
                                                 _%$%tl243991244702%_
                                                 _%__splice249887249888%_
                                                 _%$%target243992244705%_
                                                 _%$%tl243994244707%_)
                                                (_%__kont249897249898%_))))
                                        (_%__kont249897249898%_))
                                    (_%__kont249897249898%_))))
                            (_%__kont249897249898%_))
                        (_%__kont249897249898%_))
                    (_%__kont249897249898%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont249897249898%_))))
                                            (_%__match250376250377%_
                                             _%$%e243953244601%_
                                             _%$%hd243954244604%_
                                             _%$%tl243955244606%_
                                             _%$%e243956244609%_
                                             _%$%hd243957244612%_
                                             _%$%tl243958244614%_
                                             _%$%e243959244617%_
                                             _%$%hd243960244620%_
                                             _%$%tl243961244622%_
                                             _%$%e243962244625%_
                                             _%$%hd243963244628%_
                                             _%$%tl243964244630%_
                                             _%$%e243965244633%_
                                             _%$%hd243966244636%_
                                             _%$%tl243967244638%_
                                             _%$%e243968244641%_
                                             _%$%hd243969244644%_
                                             _%$%tl243970244646%_
                                             _%$%e243971244649%_
                                             _%$%hd243972244652%_
                                             _%$%tl243973244654%_
                                             _%$%e243974244657%_
                                             _%$%hd243975244660%_
                                             _%$%tl243976244662%_))
                                        (_%__match250376250377%_
                                         _%$%e243953244601%_
                                         _%$%hd243954244604%_
                                         _%$%tl243955244606%_
                                         _%$%e243956244609%_
                                         _%$%hd243957244612%_
                                         _%$%tl243958244614%_
                                         _%$%e243959244617%_
                                         _%$%hd243960244620%_
                                         _%$%tl243961244622%_
                                         _%$%e243962244625%_
                                         _%$%hd243963244628%_
                                         _%$%tl243964244630%_
                                         _%$%e243965244633%_
                                         _%$%hd243966244636%_
                                         _%$%tl243967244638%_
                                         _%$%e243968244641%_
                                         _%$%hd243969244644%_
                                         _%$%tl243970244646%_
                                         _%$%e243971244649%_
                                         _%$%hd243972244652%_
                                         _%$%tl243973244654%_
                                         _%$%e243974244657%_
                                         _%$%hd243975244660%_
                                         _%$%tl243976244662%_))))
                                (_%__match250376250377%_
                                 _%$%e243953244601%_
                                 _%$%hd243954244604%_
                                 _%$%tl243955244606%_
                                 _%$%e243956244609%_
                                 _%$%hd243957244612%_
                                 _%$%tl243958244614%_
                                 _%$%e243959244617%_
                                 _%$%hd243960244620%_
                                 _%$%tl243961244622%_
                                 _%$%e243962244625%_
                                 _%$%hd243963244628%_
                                 _%$%tl243964244630%_
                                 _%$%e243965244633%_
                                 _%$%hd243966244636%_
                                 _%$%tl243967244638%_
                                 _%$%e243968244641%_
                                 _%$%hd243969244644%_
                                 _%$%tl243970244646%_
                                 _%$%e243971244649%_
                                 _%$%hd243972244652%_
                                 _%$%tl243973244654%_
                                 _%$%e243974244657%_
                                 _%$%hd243975244660%_
                                 _%$%tl243976244662%_))
                            (_%__match250162250163%_
                             _%$%e243953244601%_
                             _%$%hd243954244604%_
                             _%$%tl243955244606%_
                             _%$%e243956244609%_
                             _%$%hd243957244612%_
                             _%$%tl243958244614%_
                             _%$%e243959244617%_
                             _%$%hd243960244620%_
                             _%$%tl243961244622%_
                             _%$%e243962244625%_
                             _%$%hd243963244628%_
                             _%$%tl243964244630%_
                             _%$%e243965244633%_
                             _%$%hd243966244636%_
                             _%$%tl243967244638%_
                             _%$%e243968244641%_
                             _%$%hd243969244644%_
                             _%$%tl243970244646%_
                             _%$%e243971244649%_
                             _%$%hd243972244652%_
                             _%$%tl243973244654%_
                             _%$%e243974244657%_
                             _%$%hd243975244660%_
                             _%$%tl243976244662%_
                             _%$%e243977244665%_
                             _%$%hd243978244668%_
                             _%$%tl243979244670%_))))
                     (_%__match249984249985%_
                      (lambda (_%$%e243909244791%_
                               _%$%hd243910244794%_
                               _%$%tl243911244796%_
                               _%$%e243912244799%_
                               _%$%hd243913244802%_
                               _%$%tl243914244804%_
                               _%$%e243915244807%_
                               _%$%hd243916244810%_
                               _%$%tl243917244812%_
                               _%$%e243918244815%_
                               _%$%hd243919244818%_
                               _%$%tl243920244820%_
                               _%$%e243921244823%_
                               _%$%hd243922244826%_
                               _%$%tl243923244828%_
                               _%$%e243924244831%_
                               _%$%hd243925244834%_
                               _%$%tl243926244836%_
                               _%$%e243927244839%_
                               _%$%hd243928244842%_
                               _%$%tl243929244844%_
                               _%$%e243930244847%_
                               _%$%hd243931244850%_
                               _%$%tl243932244852%_
                               _%$%e243933244855%_
                               _%$%hd243934244858%_
                               _%$%tl243935244860%_
                               _%$%e243936244863%_
                               _%$%hd243937244866%_
                               _%$%tl243938244868%_
                               _%__splice249883249884%_
                               _%$%target243939244871%_
                               _%$%tl243941244873%_)
                        (letrec ((_%$%loop243942244876%_
                                  (lambda (_%$%hd243940244879%_
                                           _%$%args243946244881%_)
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-pair? _%$%hd243940244879%_))
                                        (let ((_%$%e243943244883%_
                                               (let ()
                                                 (declare (not safe))
                                                 (gx#stx-e
                                                  _%$%hd243940244879%_))))
                                          (let ((_%$%lp-tl243945244888%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%e243943244883%_)))
                                                (_%$%lp-hd243944244886%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%e243943244883%_))))
                                            (_%$%loop243942244876%_
                                             _%$%lp-tl243945244888%_
                                             (cons _%$%lp-hd243944244886%_
                                                   _%$%args243946244881%_))))
                                        (let ((_%$%args243947244891%_
                                               (reverse _%$%args243946244881%_)))
                                          (let ((_%$%g243905244893%_
                                                 _%$%args243947244891%_)
                                                (_%$%g243906244894%_
                                                 _%$%hd243937244866%_)
                                                (_%$%g243907244895%_
                                                 _%$%hd243928244842%_)
                                                (_%$%g243908244896%_
                                                 _%$%hd243919244818%_))
                                            (if (and (let ()
                                                       (declare (not safe))
                                                       (gxc#runtime-identifier=?
                                                        _%$%g243908244896%_
                                                        'call-method))
                                                     (let ((__tmp250573
                                                            (let ()
                                                              (declare
                                                                (not safe))
                                                              (slot-ref__0
                                                               _%self243892%_
                                                               'receiver))))
                                                       (declare (not safe))
                                                       (gx#free-identifier=?
                                                        _%$%g243907244895%_
                                                        __tmp250573)))
                                                (_%__kont249881249882%_
                                                 _%$%g243905244893%_
                                                 _%$%g243906244894%_
                                                 _%$%g243907244895%_
                                                 _%$%g243908244896%_)
                                                (_%__match250172250173%_
                                                 _%$%e243909244791%_
                                                 _%$%hd243910244794%_
                                                 _%$%tl243911244796%_
                                                 _%$%e243912244799%_
                                                 _%$%hd243913244802%_
                                                 _%$%tl243914244804%_
                                                 _%$%e243915244807%_
                                                 _%$%hd243916244810%_
                                                 _%$%tl243917244812%_
                                                 _%$%e243918244815%_
                                                 _%$%hd243919244818%_
                                                 _%$%tl243920244820%_
                                                 _%$%e243921244823%_
                                                 _%$%hd243922244826%_
                                                 _%$%tl243923244828%_
                                                 _%$%e243924244831%_
                                                 _%$%hd243925244834%_
                                                 _%$%tl243926244836%_
                                                 _%$%e243927244839%_
                                                 _%$%hd243928244842%_
                                                 _%$%tl243929244844%_
                                                 _%$%e243930244847%_
                                                 _%$%hd243931244850%_
                                                 _%$%tl243932244852%_
                                                 _%$%e243933244855%_
                                                 _%$%hd243934244858%_
                                                 _%$%tl243935244860%_
                                                 _%$%e243936244863%_
                                                 _%$%hd243937244866%_
                                                 _%$%tl243938244868%_))))))))
                          (_%$%loop243942244876%_
                           _%$%target243939244871%_
                           '())))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-pair? _%__stx249879249880%_))
                    (let ((_%$%e243909244791%_
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%__stx249879249880%_))))
                      (let ((_%$%tl243911244796%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e243909244791%_)))
                            (_%$%hd243910244794%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e243909244791%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%tl243911244796%_))
                            (let ((_%$%e243912244799%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%tl243911244796%_))))
                              (let ((_%$%tl243914244804%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e243912244799%_)))
                                    (_%$%hd243913244802%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e243912244799%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#stx-pair? _%$%hd243913244802%_))
                                    (let ((_%$%e243915244807%_
                                           (let ()
                                             (declare (not safe))
                                             (gx#stx-e _%$%hd243913244802%_))))
                                      (let ((_%$%tl243917244812%_
                                             (let ()
                                               (declare (not safe))
                                               (##cdr _%$%e243915244807%_)))
                                            (_%$%hd243916244810%_
                                             (let ()
                                               (declare (not safe))
                                               (##car _%$%e243915244807%_))))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#identifier?
                                               _%$%hd243916244810%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-eq?
                                                   '%#ref
                                                   _%$%hd243916244810%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-pair?
                                                       _%$%tl243917244812%_))
                                                    (let ((_%$%e243918244815%_
                                                           (let ()
                                                             (declare
                                                               (not safe))
                                                             (gx#stx-e
                                                              _%$%tl243917244812%_))))
                                                      (let ((_%$%tl243920244820%_
                                                             (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##cdr _%$%e243918244815%_)))
                    (_%$%hd243919244818%_
                     (let ()
                       (declare (not safe))
                       (##car _%$%e243918244815%_))))
                (if (let ()
                      (declare (not safe))
                      (gx#stx-null? _%$%tl243920244820%_))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-pair? _%$%tl243914244804%_))
                        (let ((_%$%e243921244823%_
                               (let ()
                                 (declare (not safe))
                                 (gx#stx-e _%$%tl243914244804%_))))
                          (let ((_%$%tl243923244828%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%e243921244823%_)))
                                (_%$%hd243922244826%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%e243921244823%_))))
                            (if (let ()
                                  (declare (not safe))
                                  (gx#stx-pair? _%$%hd243922244826%_))
                                (let ((_%$%e243924244831%_
                                       (let ()
                                         (declare (not safe))
                                         (gx#stx-e _%$%hd243922244826%_))))
                                  (let ((_%$%tl243926244836%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%e243924244831%_)))
                                        (_%$%hd243925244834%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%e243924244831%_))))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#identifier?
                                           _%$%hd243925244834%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-eq?
                                               '%#ref
                                               _%$%hd243925244834%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (gx#stx-pair?
                                                   _%$%tl243926244836%_))
                                                (let ((_%$%e243927244839%_
                                                       (let ()
                                                         (declare (not safe))
                                                         (gx#stx-e
                                                          _%$%tl243926244836%_))))
                                                  (let ((_%$%tl243929244844%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##cdr _%$%e243927244839%_)))
                                                        (_%$%hd243928244842%_
                                                         (let ()
                                                           (declare (not safe))
                                                           (##car _%$%e243927244839%_))))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-null?
                                                           _%$%tl243929244844%_))
                                                        (if (let ()
                                                              (declare
                                                                (not safe))
                                                              (gx#stx-pair?
                                                               _%$%tl243923244828%_))
                                                            (let ((_%$%e243930244847%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                           (let ()
                             (declare (not safe))
                             (gx#stx-e _%$%tl243923244828%_))))
                      (let ((_%$%tl243932244852%_
                             (let ()
                               (declare (not safe))
                               (##cdr _%$%e243930244847%_)))
                            (_%$%hd243931244850%_
                             (let ()
                               (declare (not safe))
                               (##car _%$%e243930244847%_))))
                        (if (let ()
                              (declare (not safe))
                              (gx#stx-pair? _%$%hd243931244850%_))
                            (let ((_%$%e243933244855%_
                                   (let ()
                                     (declare (not safe))
                                     (gx#stx-e _%$%hd243931244850%_))))
                              (let ((_%$%tl243935244860%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%e243933244855%_)))
                                    (_%$%hd243934244858%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%e243933244855%_))))
                                (if (let ()
                                      (declare (not safe))
                                      (gx#identifier? _%$%hd243934244858%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (gx#stx-eq?
                                           '%#quote
                                           _%$%hd243934244858%_))
                                        (if (let ()
                                              (declare (not safe))
                                              (gx#stx-pair?
                                               _%$%tl243935244860%_))
                                            (let ((_%$%e243936244863%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (gx#stx-e
                                                      _%$%tl243935244860%_))))
                                              (let ((_%$%tl243938244868%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##cdr _%$%e243936244863%_)))
                                                    (_%$%hd243937244866%_
                                                     (let ()
                                                       (declare (not safe))
                                                       (##car _%$%e243936244863%_))))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (gx#stx-null?
                                                       _%$%tl243938244868%_))
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (gx#stx-pair/null?
                                                           _%$%tl243932244852%_))
                                                        (let ((_%__splice249883249884%_
                                                               (let ()
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (declare (not safe))
                         (gx#syntax-split-splice->vector
                          _%$%tl243932244852%_
                          '0))))
                  (let ((_%$%tl243941244873%_
                         (let ()
                           (declare (not safe))
                           (##vector-ref _%__splice249883249884%_ '1)))
                        (_%$%target243939244871%_
                         (let ()
                           (declare (not safe))
                           (##vector-ref _%__splice249883249884%_ '0))))
                    (if (let ()
                          (declare (not safe))
                          (gx#stx-null? _%$%tl243941244873%_))
                        (_%__match249984249985%_
                         _%$%e243909244791%_
                         _%$%hd243910244794%_
                         _%$%tl243911244796%_
                         _%$%e243912244799%_
                         _%$%hd243913244802%_
                         _%$%tl243914244804%_
                         _%$%e243915244807%_
                         _%$%hd243916244810%_
                         _%$%tl243917244812%_
                         _%$%e243918244815%_
                         _%$%hd243919244818%_
                         _%$%tl243920244820%_
                         _%$%e243921244823%_
                         _%$%hd243922244826%_
                         _%$%tl243923244828%_
                         _%$%e243924244831%_
                         _%$%hd243925244834%_
                         _%$%tl243926244836%_
                         _%$%e243927244839%_
                         _%$%hd243928244842%_
                         _%$%tl243929244844%_
                         _%$%e243930244847%_
                         _%$%hd243931244850%_
                         _%$%tl243932244852%_
                         _%$%e243933244855%_
                         _%$%hd243934244858%_
                         _%$%tl243935244860%_
                         _%$%e243936244863%_
                         _%$%hd243937244866%_
                         _%$%tl243938244868%_
                         _%__splice249883249884%_
                         _%$%target243939244871%_
                         _%$%tl243941244873%_)
                        (_%__match250172250173%_
                         _%$%e243909244791%_
                         _%$%hd243910244794%_
                         _%$%tl243911244796%_
                         _%$%e243912244799%_
                         _%$%hd243913244802%_
                         _%$%tl243914244804%_
                         _%$%e243915244807%_
                         _%$%hd243916244810%_
                         _%$%tl243917244812%_
                         _%$%e243918244815%_
                         _%$%hd243919244818%_
                         _%$%tl243920244820%_
                         _%$%e243921244823%_
                         _%$%hd243922244826%_
                         _%$%tl243923244828%_
                         _%$%e243924244831%_
                         _%$%hd243925244834%_
                         _%$%tl243926244836%_
                         _%$%e243927244839%_
                         _%$%hd243928244842%_
                         _%$%tl243929244844%_
                         _%$%e243930244847%_
                         _%$%hd243931244850%_
                         _%$%tl243932244852%_
                         _%$%e243933244855%_
                         _%$%hd243934244858%_
                         _%$%tl243935244860%_
                         _%$%e243936244863%_
                         _%$%hd243937244866%_
                         _%$%tl243938244868%_))))
                (_%__match250172250173%_
                 _%$%e243909244791%_
                 _%$%hd243910244794%_
                 _%$%tl243911244796%_
                 _%$%e243912244799%_
                 _%$%hd243913244802%_
                 _%$%tl243914244804%_
                 _%$%e243915244807%_
                 _%$%hd243916244810%_
                 _%$%tl243917244812%_
                 _%$%e243918244815%_
                 _%$%hd243919244818%_
                 _%$%tl243920244820%_
                 _%$%e243921244823%_
                 _%$%hd243922244826%_
                 _%$%tl243923244828%_
                 _%$%e243924244831%_
                 _%$%hd243925244834%_
                 _%$%tl243926244836%_
                 _%$%e243927244839%_
                 _%$%hd243928244842%_
                 _%$%tl243929244844%_
                 _%$%e243930244847%_
                 _%$%hd243931244850%_
                 _%$%tl243932244852%_
                 _%$%e243933244855%_
                 _%$%hd243934244858%_
                 _%$%tl243935244860%_
                 _%$%e243936244863%_
                 _%$%hd243937244866%_
                 _%$%tl243938244868%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__match250376250377%_
                                                     _%$%e243909244791%_
                                                     _%$%hd243910244794%_
                                                     _%$%tl243911244796%_
                                                     _%$%e243912244799%_
                                                     _%$%hd243913244802%_
                                                     _%$%tl243914244804%_
                                                     _%$%e243915244807%_
                                                     _%$%hd243916244810%_
                                                     _%$%tl243917244812%_
                                                     _%$%e243918244815%_
                                                     _%$%hd243919244818%_
                                                     _%$%tl243920244820%_
                                                     _%$%e243921244823%_
                                                     _%$%hd243922244826%_
                                                     _%$%tl243923244828%_
                                                     _%$%e243924244831%_
                                                     _%$%hd243925244834%_
                                                     _%$%tl243926244836%_
                                                     _%$%e243927244839%_
                                                     _%$%hd243928244842%_
                                                     _%$%tl243929244844%_
                                                     _%$%e243930244847%_
                                                     _%$%hd243931244850%_
                                                     _%$%tl243932244852%_))))
                                            (_%__match250376250377%_
                                             _%$%e243909244791%_
                                             _%$%hd243910244794%_
                                             _%$%tl243911244796%_
                                             _%$%e243912244799%_
                                             _%$%hd243913244802%_
                                             _%$%tl243914244804%_
                                             _%$%e243915244807%_
                                             _%$%hd243916244810%_
                                             _%$%tl243917244812%_
                                             _%$%e243918244815%_
                                             _%$%hd243919244818%_
                                             _%$%tl243920244820%_
                                             _%$%e243921244823%_
                                             _%$%hd243922244826%_
                                             _%$%tl243923244828%_
                                             _%$%e243924244831%_
                                             _%$%hd243925244834%_
                                             _%$%tl243926244836%_
                                             _%$%e243927244839%_
                                             _%$%hd243928244842%_
                                             _%$%tl243929244844%_
                                             _%$%e243930244847%_
                                             _%$%hd243931244850%_
                                             _%$%tl243932244852%_))
                                        (_%__match250052250053%_
                                         _%$%e243909244791%_
                                         _%$%hd243910244794%_
                                         _%$%tl243911244796%_
                                         _%$%e243912244799%_
                                         _%$%hd243913244802%_
                                         _%$%tl243914244804%_
                                         _%$%e243915244807%_
                                         _%$%hd243916244810%_
                                         _%$%tl243917244812%_
                                         _%$%e243918244815%_
                                         _%$%hd243919244818%_
                                         _%$%tl243920244820%_
                                         _%$%e243921244823%_
                                         _%$%hd243922244826%_
                                         _%$%tl243923244828%_
                                         _%$%e243924244831%_
                                         _%$%hd243925244834%_
                                         _%$%tl243926244836%_
                                         _%$%e243927244839%_
                                         _%$%hd243928244842%_
                                         _%$%tl243929244844%_
                                         _%$%e243930244847%_
                                         _%$%hd243931244850%_
                                         _%$%tl243932244852%_
                                         _%$%e243933244855%_
                                         _%$%hd243934244858%_
                                         _%$%tl243935244860%_))
                                    (_%__match250376250377%_
                                     _%$%e243909244791%_
                                     _%$%hd243910244794%_
                                     _%$%tl243911244796%_
                                     _%$%e243912244799%_
                                     _%$%hd243913244802%_
                                     _%$%tl243914244804%_
                                     _%$%e243915244807%_
                                     _%$%hd243916244810%_
                                     _%$%tl243917244812%_
                                     _%$%e243918244815%_
                                     _%$%hd243919244818%_
                                     _%$%tl243920244820%_
                                     _%$%e243921244823%_
                                     _%$%hd243922244826%_
                                     _%$%tl243923244828%_
                                     _%$%e243924244831%_
                                     _%$%hd243925244834%_
                                     _%$%tl243926244836%_
                                     _%$%e243927244839%_
                                     _%$%hd243928244842%_
                                     _%$%tl243929244844%_
                                     _%$%e243930244847%_
                                     _%$%hd243931244850%_
                                     _%$%tl243932244852%_))))
                            (_%__match250376250377%_
                             _%$%e243909244791%_
                             _%$%hd243910244794%_
                             _%$%tl243911244796%_
                             _%$%e243912244799%_
                             _%$%hd243913244802%_
                             _%$%tl243914244804%_
                             _%$%e243915244807%_
                             _%$%hd243916244810%_
                             _%$%tl243917244812%_
                             _%$%e243918244815%_
                             _%$%hd243919244818%_
                             _%$%tl243920244820%_
                             _%$%e243921244823%_
                             _%$%hd243922244826%_
                             _%$%tl243923244828%_
                             _%$%e243924244831%_
                             _%$%hd243925244834%_
                             _%$%tl243926244836%_
                             _%$%e243927244839%_
                             _%$%hd243928244842%_
                             _%$%tl243929244844%_
                             _%$%e243930244847%_
                             _%$%hd243931244850%_
                             _%$%tl243932244852%_))))
                    (_%__match250314250315%_
                     _%$%e243909244791%_
                     _%$%hd243910244794%_
                     _%$%tl243911244796%_
                     _%$%e243912244799%_
                     _%$%hd243913244802%_
                     _%$%tl243914244804%_
                     _%$%e243915244807%_
                     _%$%hd243916244810%_
                     _%$%tl243917244812%_
                     _%$%e243918244815%_
                     _%$%hd243919244818%_
                     _%$%tl243920244820%_
                     _%$%e243921244823%_
                     _%$%hd243922244826%_
                     _%$%tl243923244828%_
                     _%$%e243924244831%_
                     _%$%hd243925244834%_
                     _%$%tl243926244836%_
                     _%$%e243927244839%_
                     _%$%hd243928244842%_
                     _%$%tl243929244844%_))
                (_%__kont249897249898%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (_%__kont249897249898%_))
                                            (_%__kont249897249898%_))
                                        (_%__kont249897249898%_))))
                                (_%__kont249897249898%_))))
                        (_%__kont249897249898%_))
                    (_%__kont249897249898%_))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%__kont249897249898%_))
                                                (_%__kont249897249898%_))
                                            (_%__kont249897249898%_))))
                                    (_%__kont249897249898%_))))
                            (_%__kont249897249898%_))))
                    (_%__kont249897249898%_))))))))))
