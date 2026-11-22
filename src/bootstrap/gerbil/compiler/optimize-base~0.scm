(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/compiler/optimize-base::timestamp 1795039818)
  (begin
    (define gxc#current-compile-optimizer-info (make-parameter '#f))
    (define gxc#current-compile-mutators (make-parameter '#f))
    (define gxc#current-compile-local-type (make-parameter '#f))
    (define gxc#current-compile-path-type (make-parameter '()))
    (define gxc#optimizer-info::t
      (let ((__tmp224958 (list)) (__tmp224957 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#optimizer-info::t
         'optimizer-info
         __tmp224958
         '(type classes ssxi methods)
         __tmp224957
         ':init!)))
    (define gxc#optimizer-info?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#optimizer-info::t)))
    (define gxc#make-optimizer-info
      (lambda _%$args224519%_
        (apply make-instance gxc#optimizer-info::t _%$args224519%_)))
    (define gxc#optimizer-info-type
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#optimizer-info::t 'type)))
    (define gxc#optimizer-info-classes
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#optimizer-info::t 'classes)))
    (define gxc#optimizer-info-ssxi
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#optimizer-info::t 'ssxi)))
    (define gxc#optimizer-info-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#optimizer-info::t 'methods)))
    (define gxc#optimizer-info-type-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#optimizer-info::t 'type)))
    (define gxc#optimizer-info-classes-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#optimizer-info::t 'classes)))
    (define gxc#optimizer-info-ssxi-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#optimizer-info::t 'ssxi)))
    (define gxc#optimizer-info-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#optimizer-info::t 'methods)))
    (define gxc#&optimizer-info-type
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#optimizer-info::t 'type)))
    (define gxc#&optimizer-info-classes
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#optimizer-info::t 'classes)))
    (define gxc#&optimizer-info-ssxi
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#optimizer-info::t 'ssxi)))
    (define gxc#&optimizer-info-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#optimizer-info::t 'methods)))
    (define gxc#&optimizer-info-type-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#optimizer-info::t 'type)))
    (define gxc#&optimizer-info-classes-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#optimizer-info::t 'classes)))
    (define gxc#&optimizer-info-ssxi-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#optimizer-info::t 'ssxi)))
    (define gxc#&optimizer-info-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#optimizer-info::t 'methods)))
    (define gxc#optimizer-info:::init!
      (lambda (_%self224506%_)
        (let ((_%self224509%_ _%self224506%_))
          (if (let ((__tmp224959
                     (let ()
                       (declare (not safe))
                       (##structure-length _%self224509%_))))
                (declare (not safe))
                (##fx< '4 __tmp224959))
              (begin
                (let ((__tmp224960
                       (let () (declare (not safe)) (make-hash-table-eq))))
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%self224509%_
                   __tmp224960
                   '1
                   '#f
                   '#f))
                (let ((__tmp224961
                       (let () (declare (not safe)) (make-hash-table-eq))))
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%self224509%_
                   __tmp224961
                   '2
                   '#f
                   '#f))
                (let ((__tmp224962
                       (let () (declare (not safe)) (make-hash-table-eq))))
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%self224509%_
                   __tmp224962
                   '3
                   '#f
                   '#f))
                (let ((__tmp224963
                       (let () (declare (not safe)) (make-hash-table-eq))))
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%self224509%_
                   __tmp224963
                   '4
                   '#f
                   '#f))
                '#!void)
              (let ((__tmp224964
                     (let ()
                       (declare (not safe))
                       (##structure-length _%self224509%_))))
                (declare (not safe))
                (error '"struct-instance-init!: too many arguments for struct"
                       _%self224509%_
                       '4
                       __tmp224964))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#optimizer-info::t
       ':init!
       gxc#optimizer-info:::init!
       '#f))
    (define gxc#!type::t
      (let ((__tmp224966 (list))
            (__tmp224965
             (cons (cons 'struct: '#t) '((equal: . #t) (print: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!type::t
         '!type
         __tmp224966
         '(id)
         __tmp224965
         '#f)))
    (define gxc#!type?
      (let () (declare (not safe)) (__make-class-predicate gxc#!type::t)))
    (define gxc#make-!type
      (lambda _%$args224381%_
        (apply make-instance gxc#!type::t _%$args224381%_)))
    (define gxc#!type-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!type::t 'id)))
    (define gxc#!type-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!type::t 'id)))
    (define gxc#&!type-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!type::t 'id)))
    (define gxc#&!type-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!type::t 'id)))
    (define gxc#!abort::t
      (let ((__tmp224968 (list gxc#!type::t))
            (__tmp224967 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!abort::t
         '!abort
         __tmp224968
         '()
         __tmp224967
         ':init!)))
    (define gxc#!abort?
      (let () (declare (not safe)) (__make-class-predicate gxc#!abort::t)))
    (define gxc#make-!abort
      (lambda _%$args224378%_
        (apply make-instance gxc#!abort::t _%$args224378%_)))
    (define gxc#!abort-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!abort::t 'id)))
    (define gxc#!abort-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!abort::t 'id)))
    (define gxc#&!abort-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!abort::t 'id)))
    (define gxc#&!abort-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!abort::t 'id)))
    (define gxc#!alias::t
      (let ((__tmp224970 (list gxc#!type::t))
            (__tmp224969 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!alias::t
         '!alias
         __tmp224970
         '()
         __tmp224969
         '#f)))
    (define gxc#!alias?
      (let () (declare (not safe)) (__make-class-predicate gxc#!alias::t)))
    (define gxc#make-!alias
      (lambda _%$args224375%_
        (apply make-instance gxc#!alias::t _%$args224375%_)))
    (define gxc#!alias-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!alias::t 'id)))
    (define gxc#!alias-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!alias::t 'id)))
    (define gxc#&!alias-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!alias::t 'id)))
    (define gxc#&!alias-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!alias::t 'id)))
    (define gxc#!nullable-type::t
      (let ((__tmp224972 (list gxc#!type::t))
            (__tmp224971 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!nullable-type::t
         '!nullable-type
         __tmp224972
         '(base)
         __tmp224971
         '#f)))
    (define gxc#!nullable-type?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#!nullable-type::t)))
    (define gxc#make-!nullable-type
      (lambda _%$args224372%_
        (apply make-instance gxc#!nullable-type::t _%$args224372%_)))
    (define gxc#!nullable-type-base
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!nullable-type::t 'base)))
    (define gxc#!nullable-type-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!nullable-type::t 'id)))
    (define gxc#!nullable-type-base-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!nullable-type::t 'base)))
    (define gxc#!nullable-type-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!nullable-type::t 'id)))
    (define gxc#&!nullable-type-base
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!nullable-type::t 'base)))
    (define gxc#&!nullable-type-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!nullable-type::t 'id)))
    (define gxc#&!nullable-type-base-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!nullable-type::t 'base)))
    (define gxc#&!nullable-type-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!nullable-type::t 'id)))
    (define gxc#nullable-type
      (lambda (_%type224366%_)
        (if _%type224366%_
            (if (let ()
                  (declare (not safe))
                  (##structure-instance-of?
                   _%type224366%_
                   'gxc#!nullable-type::t))
                _%type224366%_
                (if (let ((__tmp224973
                           (##structure-ref
                            _%type224366%_
                            '1
                            gxc#!type::t
                            '#f)))
                      (declare (not safe))
                      (##memq __tmp224973 '(t false)))
                    _%type224366%_
                    (let ()
                      (declare (not safe))
                      (##structure
                       gxc#!nullable-type::t
                       'nullable
                       _%type224366%_))))
            '#f)))
    (define gxc#!signature::t
      (let ((__tmp224975 (list))
            (__tmp224974
             (cons (cons 'final: '#t) '((equal: . #t) (print: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!signature::t
         '!signature
         __tmp224975
         '(return effect arguments unchecked origin)
         __tmp224974
         '#f)))
    (define gxc#!signature?
      (let () (declare (not safe)) (__make-class-predicate gxc#!signature::t)))
    (define gxc#make-!signature
      (lambda _%$args224363%_
        (apply make-instance gxc#!signature::t _%$args224363%_)))
    (define gxc#!signature-return
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!signature::t 'return)))
    (define gxc#!signature-effect
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!signature::t 'effect)))
    (define gxc#!signature-arguments
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!signature::t 'arguments)))
    (define gxc#!signature-unchecked
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!signature::t 'unchecked)))
    (define gxc#!signature-origin
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!signature::t 'origin)))
    (define gxc#!signature-return-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!signature::t 'return)))
    (define gxc#!signature-effect-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!signature::t 'effect)))
    (define gxc#!signature-arguments-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!signature::t 'arguments)))
    (define gxc#!signature-unchecked-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!signature::t 'unchecked)))
    (define gxc#!signature-origin-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!signature::t 'origin)))
    (define gxc#&!signature-return
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!signature::t 'return)))
    (define gxc#&!signature-effect
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!signature::t 'effect)))
    (define gxc#&!signature-arguments
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!signature::t 'arguments)))
    (define gxc#&!signature-unchecked
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!signature::t 'unchecked)))
    (define gxc#&!signature-origin
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!signature::t 'origin)))
    (define gxc#&!signature-return-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!signature::t 'return)))
    (define gxc#&!signature-effect-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!signature::t 'effect)))
    (define gxc#&!signature-arguments-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!signature::t 'arguments)))
    (define gxc#&!signature-unchecked-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!signature::t 'unchecked)))
    (define gxc#&!signature-origin-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!signature::t 'origin)))
    (define gxc#!procedure::t
      (let ((__tmp224977 (list gxc#!type::t))
            (__tmp224976
             (cons (cons 'struct: '#t) '((equal: . #t) (print: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!procedure::t
         '!procedure
         __tmp224977
         '(signature)
         __tmp224976
         '#f)))
    (define gxc#!procedure?
      (let () (declare (not safe)) (__make-class-predicate gxc#!procedure::t)))
    (define gxc#!procedure-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!procedure::t 'signature)))
    (define gxc#!procedure-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!procedure::t 'id)))
    (define gxc#!procedure-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!procedure::t 'signature)))
    (define gxc#!procedure-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!procedure::t 'id)))
    (define gxc#&!procedure-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!procedure::t 'signature)))
    (define gxc#&!procedure-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!procedure::t 'id)))
    (define gxc#&!procedure-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!procedure::t 'signature)))
    (define gxc#&!procedure-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!procedure::t 'id)))
    (define gxc#__make-!procedure
      (lambda (_%id224350%_ _%signature224351%_)
        (let ((_%signature224354%_ _%signature224351%_))
          (declare (not safe))
          (##structure gxc#!procedure::t _%id224350%_ _%signature224354%_))))
    (define gxc#make-!procedure
      (lambda (_%id224328%_ _%signature224330%_)
        (if (or (not _%signature224330%_)
                (let ()
                  (declare (not safe))
                  (##structure-direct-instance-of?
                   _%signature224330%_
                   'gxc#!signature::t)))
            (let ((_%signature224340%_ _%signature224330%_))
              (gxc#__make-!procedure _%id224328%_ _%signature224340%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '(? (or not !signature?))
               'value:
               _%signature224330%_)
              '#!void))))
    (define gxc#__!procedure-signature-set!
      (lambda (_%$obj224307%_ _%signature224308%_)
        (let* ((_%$obj224311%_ _%$obj224307%_)
               (_%signature224319%_ _%signature224308%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj224311%_
           _%signature224319%_
           '2
           '#f
           '#f))))
    (define gxc#!procedure-signature-set!
      (lambda (_%$obj224274%_ _%signature224276%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%$obj224274%_ 'gxc#!procedure::t))
            (let ((_%$obj224281%_ _%$obj224274%_))
              (if (or (not _%signature224276%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature224276%_
                         'gxc#!signature::t)))
                  (let ((_%signature224297%_ _%signature224276%_))
                    (gxc#__!procedure-signature-set!
                     _%$obj224281%_
                     _%signature224297%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature224276%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!procedure?
               'value:
               _%$obj224274%_)
              '#!void))))
    (define gxc#!class-meta::t
      (let ((__tmp224979 (list gxc#!type::t))
            (__tmp224978 (cons (cons 'struct: '#t) '())))
        (declare (not safe))
        (make-class-type
         'gxc#!class-meta::t
         '!class-meta
         __tmp224979
         '(class)
         __tmp224978
         ':init!)))
    (define gxc#!class-meta?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#!class-meta::t)))
    (define gxc#make-!class-meta
      (lambda _%$args224271%_
        (apply make-instance gxc#!class-meta::t _%$args224271%_)))
    (define gxc#!class-meta-class
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class-meta::t 'class)))
    (define gxc#!class-meta-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class-meta::t 'id)))
    (define gxc#!class-meta-class-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class-meta::t 'class)))
    (define gxc#!class-meta-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class-meta::t 'id)))
    (define gxc#&!class-meta-class
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class-meta::t 'class)))
    (define gxc#&!class-meta-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class-meta::t 'id)))
    (define gxc#&!class-meta-class-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class-meta::t 'class)))
    (define gxc#&!class-meta-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class-meta::t 'id)))
    (define gxc#!class::t
      (let ((__tmp224981 (list gxc#!type::t))
            (__tmp224980
             (cons (cons 'struct: '#t)
                   '((equal: . #t) (print: super precedence-list)))))
        (declare (not safe))
        (make-class-type
         'gxc#!class::t
         '!class
         __tmp224981
         '(super precedence-list
                 slots
                 fields
                 constructor
                 struct?
                 final?
                 system?
                 metaclass
                 methods)
         __tmp224980
         ':init!)))
    (define gxc#!class?
      (let () (declare (not safe)) (__make-class-predicate gxc#!class::t)))
    (define gxc#make-!class
      (lambda _%$args224268%_
        (apply make-instance gxc#!class::t _%$args224268%_)))
    (define gxc#!class-super
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'super)))
    (define gxc#!class-precedence-list
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'precedence-list)))
    (define gxc#!class-slots
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'slots)))
    (define gxc#!class-fields
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'fields)))
    (define gxc#!class-constructor
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'constructor)))
    (define gxc#!class-struct?
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'struct?)))
    (define gxc#!class-final?
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'final?)))
    (define gxc#!class-system?
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'system?)))
    (define gxc#!class-metaclass
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'metaclass)))
    (define gxc#!class-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'methods)))
    (define gxc#!class-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!class::t 'id)))
    (define gxc#!class-super-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'super)))
    (define gxc#!class-precedence-list-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'precedence-list)))
    (define gxc#!class-slots-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'slots)))
    (define gxc#!class-fields-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'fields)))
    (define gxc#!class-constructor-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'constructor)))
    (define gxc#!class-struct?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'struct?)))
    (define gxc#!class-final?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'final?)))
    (define gxc#!class-system?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'system?)))
    (define gxc#!class-metaclass-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'metaclass)))
    (define gxc#!class-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'methods)))
    (define gxc#!class-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!class::t 'id)))
    (define gxc#&!class-super
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'super)))
    (define gxc#&!class-precedence-list
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'precedence-list)))
    (define gxc#&!class-slots
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'slots)))
    (define gxc#&!class-fields
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'fields)))
    (define gxc#&!class-constructor
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'constructor)))
    (define gxc#&!class-struct?
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'struct?)))
    (define gxc#&!class-final?
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'final?)))
    (define gxc#&!class-system?
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'system?)))
    (define gxc#&!class-metaclass
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'metaclass)))
    (define gxc#&!class-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'methods)))
    (define gxc#&!class-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!class::t 'id)))
    (define gxc#&!class-super-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'super)))
    (define gxc#&!class-precedence-list-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'precedence-list)))
    (define gxc#&!class-slots-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'slots)))
    (define gxc#&!class-fields-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'fields)))
    (define gxc#&!class-constructor-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'constructor)))
    (define gxc#&!class-struct?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'struct?)))
    (define gxc#&!class-final?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'final?)))
    (define gxc#&!class-system?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'system?)))
    (define gxc#&!class-metaclass-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'metaclass)))
    (define gxc#&!class-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'methods)))
    (define gxc#&!class-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!class::t 'id)))
    (define gxc#!predicate::t
      (let ((__tmp224983 (list gxc#!procedure::t))
            (__tmp224982 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!predicate::t
         '!predicate
         __tmp224983
         '()
         __tmp224982
         ':init!)))
    (define gxc#!predicate?
      (let () (declare (not safe)) (__make-class-predicate gxc#!predicate::t)))
    (define gxc#make-!predicate
      (lambda _%$args224265%_
        (apply make-instance gxc#!predicate::t _%$args224265%_)))
    (define gxc#!predicate-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!predicate::t 'signature)))
    (define gxc#!predicate-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!predicate::t 'id)))
    (define gxc#!predicate-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!predicate::t 'signature)))
    (define gxc#!predicate-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!predicate::t 'id)))
    (define gxc#&!predicate-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!predicate::t 'signature)))
    (define gxc#&!predicate-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!predicate::t 'id)))
    (define gxc#&!predicate-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!predicate::t 'signature)))
    (define gxc#&!predicate-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!predicate::t 'id)))
    (define gxc#__!predicate-signature-set!
      (lambda (_%$obj224244%_ _%signature224245%_)
        (let* ((_%$obj224248%_ _%$obj224244%_)
               (_%signature224256%_ _%signature224245%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj224248%_
           _%signature224256%_
           '2
           '#f
           '#f))))
    (define gxc#!predicate-signature-set!
      (lambda (_%$obj224211%_ _%signature224213%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%$obj224211%_ 'gxc#!predicate::t))
            (let ((_%$obj224218%_ _%$obj224211%_))
              (if (or (not _%signature224213%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature224213%_
                         'gxc#!signature::t)))
                  (let ((_%signature224234%_ _%signature224213%_))
                    (gxc#__!predicate-signature-set!
                     _%$obj224218%_
                     _%signature224234%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature224213%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!predicate?
               'value:
               _%$obj224211%_)
              '#!void))))
    (define gxc#!constructor::t
      (let ((__tmp224985 (list gxc#!procedure::t))
            (__tmp224984 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!constructor::t
         '!constructor
         __tmp224985
         '()
         __tmp224984
         ':init!)))
    (define gxc#!constructor?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#!constructor::t)))
    (define gxc#make-!constructor
      (lambda _%$args224208%_
        (apply make-instance gxc#!constructor::t _%$args224208%_)))
    (define gxc#!constructor-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!constructor::t 'signature)))
    (define gxc#!constructor-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!constructor::t 'id)))
    (define gxc#!constructor-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!constructor::t 'signature)))
    (define gxc#!constructor-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!constructor::t 'id)))
    (define gxc#&!constructor-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!constructor::t 'signature)))
    (define gxc#&!constructor-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!constructor::t 'id)))
    (define gxc#&!constructor-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!constructor::t 'signature)))
    (define gxc#&!constructor-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!constructor::t 'id)))
    (define gxc#__!constructor-signature-set!
      (lambda (_%$obj224187%_ _%signature224188%_)
        (let* ((_%$obj224191%_ _%$obj224187%_)
               (_%signature224199%_ _%signature224188%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj224191%_
           _%signature224199%_
           '2
           '#f
           '#f))))
    (define gxc#!constructor-signature-set!
      (lambda (_%$obj224154%_ _%signature224156%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%$obj224154%_ 'gxc#!constructor::t))
            (let ((_%$obj224161%_ _%$obj224154%_))
              (if (or (not _%signature224156%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature224156%_
                         'gxc#!signature::t)))
                  (let ((_%signature224177%_ _%signature224156%_))
                    (gxc#__!constructor-signature-set!
                     _%$obj224161%_
                     _%signature224177%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature224156%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!constructor?
               'value:
               _%$obj224154%_)
              '#!void))))
    (define gxc#!accessor::t
      (let ((__tmp224987 (list gxc#!procedure::t))
            (__tmp224986 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!accessor::t
         '!accessor
         __tmp224987
         '(slot checked?)
         __tmp224986
         ':init!)))
    (define gxc#!accessor?
      (let () (declare (not safe)) (__make-class-predicate gxc#!accessor::t)))
    (define gxc#make-!accessor
      (lambda _%$args224151%_
        (apply make-instance gxc#!accessor::t _%$args224151%_)))
    (define gxc#!accessor-slot
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!accessor::t 'slot)))
    (define gxc#!accessor-checked?
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!accessor::t 'checked?)))
    (define gxc#!accessor-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!accessor::t 'signature)))
    (define gxc#!accessor-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!accessor::t 'id)))
    (define gxc#!accessor-slot-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!accessor::t 'slot)))
    (define gxc#!accessor-checked?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!accessor::t 'checked?)))
    (define gxc#!accessor-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!accessor::t 'signature)))
    (define gxc#!accessor-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!accessor::t 'id)))
    (define gxc#&!accessor-slot
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!accessor::t 'slot)))
    (define gxc#&!accessor-checked?
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!accessor::t 'checked?)))
    (define gxc#&!accessor-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!accessor::t 'signature)))
    (define gxc#&!accessor-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!accessor::t 'id)))
    (define gxc#&!accessor-slot-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!accessor::t 'slot)))
    (define gxc#&!accessor-checked?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!accessor::t 'checked?)))
    (define gxc#&!accessor-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!accessor::t 'signature)))
    (define gxc#&!accessor-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!accessor::t 'id)))
    (define gxc#__!accessor-signature-set!
      (lambda (_%$obj224130%_ _%signature224131%_)
        (let* ((_%$obj224134%_ _%$obj224130%_)
               (_%signature224142%_ _%signature224131%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj224134%_
           _%signature224142%_
           '2
           '#f
           '#f))))
    (define gxc#!accessor-signature-set!
      (lambda (_%$obj224097%_ _%signature224099%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%$obj224097%_ 'gxc#!accessor::t))
            (let ((_%$obj224104%_ _%$obj224097%_))
              (if (or (not _%signature224099%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature224099%_
                         'gxc#!signature::t)))
                  (let ((_%signature224120%_ _%signature224099%_))
                    (gxc#__!accessor-signature-set!
                     _%$obj224104%_
                     _%signature224120%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature224099%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!accessor?
               'value:
               _%$obj224097%_)
              '#!void))))
    (define gxc#!mutator::t
      (let ((__tmp224989 (list gxc#!procedure::t))
            (__tmp224988 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!mutator::t
         '!mutator
         __tmp224989
         '(slot checked?)
         __tmp224988
         ':init!)))
    (define gxc#!mutator?
      (let () (declare (not safe)) (__make-class-predicate gxc#!mutator::t)))
    (define gxc#make-!mutator
      (lambda _%$args224094%_
        (apply make-instance gxc#!mutator::t _%$args224094%_)))
    (define gxc#!mutator-slot
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!mutator::t 'slot)))
    (define gxc#!mutator-checked?
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!mutator::t 'checked?)))
    (define gxc#!mutator-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!mutator::t 'signature)))
    (define gxc#!mutator-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!mutator::t 'id)))
    (define gxc#!mutator-slot-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!mutator::t 'slot)))
    (define gxc#!mutator-checked?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!mutator::t 'checked?)))
    (define gxc#!mutator-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!mutator::t 'signature)))
    (define gxc#!mutator-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!mutator::t 'id)))
    (define gxc#&!mutator-slot
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!mutator::t 'slot)))
    (define gxc#&!mutator-checked?
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!mutator::t 'checked?)))
    (define gxc#&!mutator-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!mutator::t 'signature)))
    (define gxc#&!mutator-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!mutator::t 'id)))
    (define gxc#&!mutator-slot-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!mutator::t 'slot)))
    (define gxc#&!mutator-checked?-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!mutator::t 'checked?)))
    (define gxc#&!mutator-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!mutator::t 'signature)))
    (define gxc#&!mutator-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!mutator::t 'id)))
    (define gxc#__!mutator-signature-set!
      (lambda (_%$obj224073%_ _%signature224074%_)
        (let* ((_%$obj224077%_ _%$obj224073%_)
               (_%signature224085%_ _%signature224074%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj224077%_
           _%signature224085%_
           '2
           '#f
           '#f))))
    (define gxc#!mutator-signature-set!
      (lambda (_%$obj224040%_ _%signature224042%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%$obj224040%_ 'gxc#!mutator::t))
            (let ((_%$obj224047%_ _%$obj224040%_))
              (if (or (not _%signature224042%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature224042%_
                         'gxc#!signature::t)))
                  (let ((_%signature224063%_ _%signature224042%_))
                    (gxc#__!mutator-signature-set!
                     _%$obj224047%_
                     _%signature224063%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature224042%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!mutator?
               'value:
               _%$obj224040%_)
              '#!void))))
    (define gxc#!interface::t
      (let ((__tmp224991 (list gxc#!type::t))
            (__tmp224990 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!interface::t
         '!interface
         __tmp224991
         '(methods)
         __tmp224990
         '#f)))
    (define gxc#!interface?
      (let () (declare (not safe)) (__make-class-predicate gxc#!interface::t)))
    (define gxc#make-!interface
      (lambda _%$args224037%_
        (apply make-instance gxc#!interface::t _%$args224037%_)))
    (define gxc#!interface-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!interface::t 'methods)))
    (define gxc#!interface-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!interface::t 'id)))
    (define gxc#!interface-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!interface::t 'methods)))
    (define gxc#!interface-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!interface::t 'id)))
    (define gxc#&!interface-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!interface::t 'methods)))
    (define gxc#&!interface-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!interface::t 'id)))
    (define gxc#&!interface-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!interface::t 'methods)))
    (define gxc#&!interface-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!interface::t 'id)))
    (define gxc#!lambda::t
      (let ((__tmp224993 (list gxc#!procedure::t))
            (__tmp224992 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!lambda::t
         '!lambda
         __tmp224993
         '(arity dispatch inline inline-typedecl)
         __tmp224992
         ':init!)))
    (define gxc#!lambda?
      (let () (declare (not safe)) (__make-class-predicate gxc#!lambda::t)))
    (define gxc#make-!lambda
      (lambda _%$args224034%_
        (apply make-instance gxc#!lambda::t _%$args224034%_)))
    (define gxc#!lambda-arity
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!lambda::t 'arity)))
    (define gxc#!lambda-dispatch
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!lambda::t 'dispatch)))
    (define gxc#!lambda-inline
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!lambda::t 'inline)))
    (define gxc#!lambda-inline-typedecl
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!lambda::t 'inline-typedecl)))
    (define gxc#!lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!lambda::t 'signature)))
    (define gxc#!lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!lambda::t 'id)))
    (define gxc#!lambda-arity-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!lambda::t 'arity)))
    (define gxc#!lambda-dispatch-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!lambda::t 'dispatch)))
    (define gxc#!lambda-inline-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!lambda::t 'inline)))
    (define gxc#!lambda-inline-typedecl-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!lambda::t 'inline-typedecl)))
    (define gxc#!lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!lambda::t 'signature)))
    (define gxc#!lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!lambda::t 'id)))
    (define gxc#&!lambda-arity
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!lambda::t 'arity)))
    (define gxc#&!lambda-dispatch
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!lambda::t 'dispatch)))
    (define gxc#&!lambda-inline
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!lambda::t 'inline)))
    (define gxc#&!lambda-inline-typedecl
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!lambda::t
         'inline-typedecl)))
    (define gxc#&!lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!lambda::t 'signature)))
    (define gxc#&!lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!lambda::t 'id)))
    (define gxc#&!lambda-arity-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!lambda::t 'arity)))
    (define gxc#&!lambda-dispatch-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!lambda::t 'dispatch)))
    (define gxc#&!lambda-inline-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!lambda::t 'inline)))
    (define gxc#&!lambda-inline-typedecl-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!lambda::t 'inline-typedecl)))
    (define gxc#&!lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!lambda::t 'signature)))
    (define gxc#&!lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!lambda::t 'id)))
    (define gxc#__!lambda-signature-set!
      (lambda (_%$obj224013%_ _%signature224014%_)
        (let* ((_%$obj224017%_ _%$obj224013%_)
               (_%signature224025%_ _%signature224014%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj224017%_
           _%signature224025%_
           '2
           '#f
           '#f))))
    (define gxc#!lambda-signature-set!
      (lambda (_%$obj223980%_ _%signature223982%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%$obj223980%_ 'gxc#!lambda::t))
            (let ((_%$obj223987%_ _%$obj223980%_))
              (if (or (not _%signature223982%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature223982%_
                         'gxc#!signature::t)))
                  (let ((_%signature224003%_ _%signature223982%_))
                    (gxc#__!lambda-signature-set!
                     _%$obj223987%_
                     _%signature224003%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature223982%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!lambda?
               'value:
               _%$obj223980%_)
              '#!void))))
    (define gxc#!case-lambda::t
      (let ((__tmp224995 (list gxc#!procedure::t))
            (__tmp224994 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!case-lambda::t
         '!case-lambda
         __tmp224995
         '(clauses)
         __tmp224994
         ':init!)))
    (define gxc#!case-lambda?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#!case-lambda::t)))
    (define gxc#make-!case-lambda
      (lambda _%$args223977%_
        (apply make-instance gxc#!case-lambda::t _%$args223977%_)))
    (define gxc#!case-lambda-clauses
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!case-lambda::t 'clauses)))
    (define gxc#!case-lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!case-lambda::t 'signature)))
    (define gxc#!case-lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!case-lambda::t 'id)))
    (define gxc#!case-lambda-clauses-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!case-lambda::t 'clauses)))
    (define gxc#!case-lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!case-lambda::t 'signature)))
    (define gxc#!case-lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!case-lambda::t 'id)))
    (define gxc#&!case-lambda-clauses
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!case-lambda::t 'clauses)))
    (define gxc#&!case-lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!case-lambda::t 'signature)))
    (define gxc#&!case-lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!case-lambda::t 'id)))
    (define gxc#&!case-lambda-clauses-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!case-lambda::t 'clauses)))
    (define gxc#&!case-lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!case-lambda::t 'signature)))
    (define gxc#&!case-lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!case-lambda::t 'id)))
    (define gxc#__!case-lambda-signature-set!
      (lambda (_%$obj223956%_ _%signature223957%_)
        (let* ((_%$obj223960%_ _%$obj223956%_)
               (_%signature223968%_ _%signature223957%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj223960%_
           _%signature223968%_
           '2
           '#f
           '#f))))
    (define gxc#!case-lambda-signature-set!
      (lambda (_%$obj223923%_ _%signature223925%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%$obj223923%_ 'gxc#!case-lambda::t))
            (let ((_%$obj223930%_ _%$obj223923%_))
              (if (or (not _%signature223925%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature223925%_
                         'gxc#!signature::t)))
                  (let ((_%signature223946%_ _%signature223925%_))
                    (gxc#__!case-lambda-signature-set!
                     _%$obj223930%_
                     _%signature223946%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature223925%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!case-lambda?
               'value:
               _%$obj223923%_)
              '#!void))))
    (define gxc#!kw-lambda::t
      (let ((__tmp224997 (list gxc#!procedure::t))
            (__tmp224996 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!kw-lambda::t
         '!kw-lambda
         __tmp224997
         '(table dispatch)
         __tmp224996
         ':init!)))
    (define gxc#!kw-lambda?
      (let () (declare (not safe)) (__make-class-predicate gxc#!kw-lambda::t)))
    (define gxc#make-!kw-lambda
      (lambda _%$args223920%_
        (apply make-instance gxc#!kw-lambda::t _%$args223920%_)))
    (define gxc#!kw-lambda-table
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!kw-lambda::t 'table)))
    (define gxc#!kw-lambda-dispatch
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!kw-lambda::t 'dispatch)))
    (define gxc#!kw-lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!kw-lambda::t 'signature)))
    (define gxc#!kw-lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!kw-lambda::t 'id)))
    (define gxc#!kw-lambda-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!kw-lambda::t 'table)))
    (define gxc#!kw-lambda-dispatch-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!kw-lambda::t 'dispatch)))
    (define gxc#!kw-lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!kw-lambda::t 'signature)))
    (define gxc#!kw-lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!kw-lambda::t 'id)))
    (define gxc#&!kw-lambda-table
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!kw-lambda::t 'table)))
    (define gxc#&!kw-lambda-dispatch
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!kw-lambda::t 'dispatch)))
    (define gxc#&!kw-lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!kw-lambda::t 'signature)))
    (define gxc#&!kw-lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!kw-lambda::t 'id)))
    (define gxc#&!kw-lambda-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!kw-lambda::t 'table)))
    (define gxc#&!kw-lambda-dispatch-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!kw-lambda::t 'dispatch)))
    (define gxc#&!kw-lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!kw-lambda::t 'signature)))
    (define gxc#&!kw-lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!kw-lambda::t 'id)))
    (define gxc#__!kw-lambda-signature-set!
      (lambda (_%$obj223899%_ _%signature223900%_)
        (let* ((_%$obj223903%_ _%$obj223899%_)
               (_%signature223911%_ _%signature223900%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj223903%_
           _%signature223911%_
           '2
           '#f
           '#f))))
    (define gxc#!kw-lambda-signature-set!
      (lambda (_%$obj223866%_ _%signature223868%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%$obj223866%_ 'gxc#!kw-lambda::t))
            (let ((_%$obj223873%_ _%$obj223866%_))
              (if (or (not _%signature223868%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature223868%_
                         'gxc#!signature::t)))
                  (let ((_%signature223889%_ _%signature223868%_))
                    (gxc#__!kw-lambda-signature-set!
                     _%$obj223873%_
                     _%signature223889%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature223868%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!kw-lambda?
               'value:
               _%$obj223866%_)
              '#!void))))
    (define gxc#!kw-lambda-primary::t
      (let ((__tmp224999 (list gxc#!procedure::t))
            (__tmp224998 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!kw-lambda-primary::t
         '!kw-lambda-primary
         __tmp224999
         '(keys main)
         __tmp224998
         ':init!)))
    (define gxc#!kw-lambda-primary?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#!kw-lambda-primary::t)))
    (define gxc#make-!kw-lambda-primary
      (lambda _%$args223863%_
        (apply make-instance gxc#!kw-lambda-primary::t _%$args223863%_)))
    (define gxc#!kw-lambda-primary-keys
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!kw-lambda-primary::t 'keys)))
    (define gxc#!kw-lambda-primary-main
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!kw-lambda-primary::t 'main)))
    (define gxc#!kw-lambda-primary-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!kw-lambda-primary::t 'signature)))
    (define gxc#!kw-lambda-primary-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!kw-lambda-primary::t 'id)))
    (define gxc#!kw-lambda-primary-keys-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!kw-lambda-primary::t 'keys)))
    (define gxc#!kw-lambda-primary-main-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!kw-lambda-primary::t 'main)))
    (define gxc#!kw-lambda-primary-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!kw-lambda-primary::t 'signature)))
    (define gxc#!kw-lambda-primary-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!kw-lambda-primary::t 'id)))
    (define gxc#&!kw-lambda-primary-keys
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!kw-lambda-primary::t
         'keys)))
    (define gxc#&!kw-lambda-primary-main
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!kw-lambda-primary::t
         'main)))
    (define gxc#&!kw-lambda-primary-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!kw-lambda-primary::t
         'signature)))
    (define gxc#&!kw-lambda-primary-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!kw-lambda-primary::t 'id)))
    (define gxc#&!kw-lambda-primary-keys-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!kw-lambda-primary::t 'keys)))
    (define gxc#&!kw-lambda-primary-main-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!kw-lambda-primary::t 'main)))
    (define gxc#&!kw-lambda-primary-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!kw-lambda-primary::t
         'signature)))
    (define gxc#&!kw-lambda-primary-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!kw-lambda-primary::t 'id)))
    (define gxc#__!kw-lambda-primary-signature-set!
      (lambda (_%$obj223842%_ _%signature223843%_)
        (let* ((_%$obj223846%_ _%$obj223842%_)
               (_%signature223854%_ _%signature223843%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj223846%_
           _%signature223854%_
           '2
           '#f
           '#f))))
    (define gxc#!kw-lambda-primary-signature-set!
      (lambda (_%$obj223809%_ _%signature223811%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of?
               _%$obj223809%_
               'gxc#!kw-lambda-primary::t))
            (let ((_%$obj223816%_ _%$obj223809%_))
              (if (or (not _%signature223811%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature223811%_
                         'gxc#!signature::t)))
                  (let ((_%signature223832%_ _%signature223811%_))
                    (gxc#__!kw-lambda-primary-signature-set!
                     _%$obj223816%_
                     _%signature223832%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature223811%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!kw-lambda-primary?
               'value:
               _%$obj223809%_)
              '#!void))))
    (define gxc#!primitive::t
      (let ((__tmp225000 (list)))
        (declare (not safe))
        (make-class-type
         'gxc#!primitive::t
         '!primitive
         __tmp225000
         '()
         '((equal: . #t))
         '#f)))
    (define gxc#!primitive?
      (let () (declare (not safe)) (__make-class-predicate gxc#!primitive::t)))
    (define gxc#make-!primitive
      (lambda _%$args223806%_
        (apply make-instance gxc#!primitive::t _%$args223806%_)))
    (define gxc#!primitive-predicate::t
      (let ((__tmp225002 (list gxc#!primitive::t gxc#!procedure::t))
            (__tmp225001 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!primitive-predicate::t
         '!primitive-predicate
         __tmp225002
         '()
         __tmp225001
         ':init!)))
    (define gxc#!primitive-predicate?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#!primitive-predicate::t)))
    (define gxc#make-!primitive-predicate
      (lambda _%$args223803%_
        (apply make-instance gxc#!primitive-predicate::t _%$args223803%_)))
    (define gxc#!primitive-predicate-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-predicate::t 'signature)))
    (define gxc#!primitive-predicate-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-predicate::t 'id)))
    (define gxc#!primitive-predicate-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-predicate::t 'signature)))
    (define gxc#!primitive-predicate-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-predicate::t 'id)))
    (define gxc#&!primitive-predicate-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-predicate::t
         'signature)))
    (define gxc#&!primitive-predicate-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-predicate::t
         'id)))
    (define gxc#&!primitive-predicate-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!primitive-predicate::t
         'signature)))
    (define gxc#&!primitive-predicate-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!primitive-predicate::t 'id)))
    (define gxc#__!primitive-predicate-signature-set!
      (lambda (_%$obj223782%_ _%signature223783%_)
        (let* ((_%$obj223786%_ _%$obj223782%_)
               (_%signature223794%_ _%signature223783%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj223786%_
           _%signature223794%_
           '2
           '#f
           '#f))))
    (define gxc#!primitive-predicate-signature-set!
      (lambda (_%$obj223749%_ _%signature223751%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of?
               _%$obj223749%_
               'gxc#!primitive-predicate::t))
            (let ((_%$obj223756%_ _%$obj223749%_))
              (if (or (not _%signature223751%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature223751%_
                         'gxc#!signature::t)))
                  (let ((_%signature223772%_ _%signature223751%_))
                    (gxc#__!primitive-predicate-signature-set!
                     _%$obj223756%_
                     _%signature223772%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature223751%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!primitive-predicate?
               'value:
               _%$obj223749%_)
              '#!void))))
    (define gxc#!primitive-lambda::t
      (let ((__tmp225004 (list gxc#!primitive::t gxc#!lambda::t))
            (__tmp225003 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!primitive-lambda::t
         '!primitive-lambda
         __tmp225004
         '()
         __tmp225003
         ':init!)))
    (define gxc#!primitive-lambda?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#!primitive-lambda::t)))
    (define gxc#make-!primitive-lambda
      (lambda _%$args223746%_
        (apply make-instance gxc#!primitive-lambda::t _%$args223746%_)))
    (define gxc#!primitive-lambda-arity
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-lambda::t 'arity)))
    (define gxc#!primitive-lambda-dispatch
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-lambda::t 'dispatch)))
    (define gxc#!primitive-lambda-inline
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-lambda::t 'inline)))
    (define gxc#!primitive-lambda-inline-typedecl
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor
         gxc#!primitive-lambda::t
         'inline-typedecl)))
    (define gxc#!primitive-lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-lambda::t 'signature)))
    (define gxc#!primitive-lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-lambda::t 'id)))
    (define gxc#!primitive-lambda-arity-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-lambda::t 'arity)))
    (define gxc#!primitive-lambda-dispatch-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-lambda::t 'dispatch)))
    (define gxc#!primitive-lambda-inline-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-lambda::t 'inline)))
    (define gxc#!primitive-lambda-inline-typedecl-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-lambda::t 'inline-typedecl)))
    (define gxc#!primitive-lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-lambda::t 'signature)))
    (define gxc#!primitive-lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-lambda::t 'id)))
    (define gxc#&!primitive-lambda-arity
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-lambda::t
         'arity)))
    (define gxc#&!primitive-lambda-dispatch
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-lambda::t
         'dispatch)))
    (define gxc#&!primitive-lambda-inline
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-lambda::t
         'inline)))
    (define gxc#&!primitive-lambda-inline-typedecl
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-lambda::t
         'inline-typedecl)))
    (define gxc#&!primitive-lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-lambda::t
         'signature)))
    (define gxc#&!primitive-lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor gxc#!primitive-lambda::t 'id)))
    (define gxc#&!primitive-lambda-arity-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!primitive-lambda::t 'arity)))
    (define gxc#&!primitive-lambda-dispatch-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!primitive-lambda::t
         'dispatch)))
    (define gxc#&!primitive-lambda-inline-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!primitive-lambda::t
         'inline)))
    (define gxc#&!primitive-lambda-inline-typedecl-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!primitive-lambda::t
         'inline-typedecl)))
    (define gxc#&!primitive-lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!primitive-lambda::t
         'signature)))
    (define gxc#&!primitive-lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator gxc#!primitive-lambda::t 'id)))
    (define gxc#__!primitive-lambda-signature-set!
      (lambda (_%$obj223725%_ _%signature223726%_)
        (let* ((_%$obj223729%_ _%$obj223725%_)
               (_%signature223737%_ _%signature223726%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj223729%_
           _%signature223737%_
           '2
           '#f
           '#f))))
    (define gxc#!primitive-lambda-signature-set!
      (lambda (_%$obj223692%_ _%signature223694%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of?
               _%$obj223692%_
               'gxc#!primitive-lambda::t))
            (let ((_%$obj223699%_ _%$obj223692%_))
              (if (or (not _%signature223694%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature223694%_
                         'gxc#!signature::t)))
                  (let ((_%signature223715%_ _%signature223694%_))
                    (gxc#__!primitive-lambda-signature-set!
                     _%$obj223699%_
                     _%signature223715%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature223694%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!primitive-lambda?
               'value:
               _%$obj223692%_)
              '#!void))))
    (define gxc#!primitive-case-lambda::t
      (let ((__tmp225006 (list gxc#!primitive::t gxc#!case-lambda::t))
            (__tmp225005 (cons (cons 'struct: '#t) '((equal: . #t)))))
        (declare (not safe))
        (make-class-type
         'gxc#!primitive-case-lambda::t
         '!primitive-case-lambda
         __tmp225006
         '()
         __tmp225005
         ':init!)))
    (define gxc#!primitive-case-lambda?
      (let ()
        (declare (not safe))
        (__make-class-predicate gxc#!primitive-case-lambda::t)))
    (define gxc#make-!primitive-case-lambda
      (lambda _%$args223689%_
        (apply make-instance gxc#!primitive-case-lambda::t _%$args223689%_)))
    (define gxc#!primitive-case-lambda-clauses
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-case-lambda::t 'clauses)))
    (define gxc#!primitive-case-lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-case-lambda::t 'signature)))
    (define gxc#!primitive-case-lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor gxc#!primitive-case-lambda::t 'id)))
    (define gxc#!primitive-case-lambda-clauses-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-case-lambda::t 'clauses)))
    (define gxc#!primitive-case-lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-case-lambda::t 'signature)))
    (define gxc#!primitive-case-lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator gxc#!primitive-case-lambda::t 'id)))
    (define gxc#&!primitive-case-lambda-clauses
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-case-lambda::t
         'clauses)))
    (define gxc#&!primitive-case-lambda-signature
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-case-lambda::t
         'signature)))
    (define gxc#&!primitive-case-lambda-id
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         gxc#!primitive-case-lambda::t
         'id)))
    (define gxc#&!primitive-case-lambda-clauses-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!primitive-case-lambda::t
         'clauses)))
    (define gxc#&!primitive-case-lambda-unchecked-signature-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!primitive-case-lambda::t
         'signature)))
    (define gxc#&!primitive-case-lambda-id-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         gxc#!primitive-case-lambda::t
         'id)))
    (define gxc#__!primitive-case-lambda-signature-set!
      (lambda (_%$obj223668%_ _%signature223669%_)
        (let* ((_%$obj223672%_ _%$obj223668%_)
               (_%signature223680%_ _%signature223669%_))
          (declare (not safe))
          (##unchecked-structure-set!
           _%$obj223672%_
           _%signature223680%_
           '2
           '#f
           '#f))))
    (define gxc#!primitive-case-lambda-signature-set!
      (lambda (_%$obj223635%_ _%signature223637%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of?
               _%$obj223635%_
               'gxc#!primitive-case-lambda::t))
            (let ((_%$obj223642%_ _%$obj223635%_))
              (if (or (not _%signature223637%_)
                      (let ()
                        (declare (not safe))
                        (##structure-direct-instance-of?
                         _%signature223637%_
                         'gxc#!signature::t)))
                  (let ((_%signature223658%_ _%signature223637%_))
                    (gxc#__!primitive-case-lambda-signature-set!
                     _%$obj223642%_
                     _%signature223658%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     'gerbil/compiler/optimize-base
                     'contract:
                     '(? (or not !signature?))
                     'value:
                     _%signature223637%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               'gerbil/compiler/optimize-base
               'contract:
               '!primitive-case-lambda?
               'value:
               _%$obj223635%_)
              '#!void))))
    (define gxc#!abort:::init!
      (lambda (_%self223622%_)
        (let ((_%self223625%_ _%self223622%_))
          (declare (not safe))
          (##unchecked-structure-set! _%self223625%_ 'abort '1 '#f '#f))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!abort::t ':init! gxc#!abort:::init! '#f))
    (define gxc#!class-meta:::init!
      (lambda (_%self223485%_ _%klass223486%_)
        (let ((_%self223489%_ _%self223485%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set! _%self223489%_ 'class '1 '#f '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223489%_
             _%klass223486%_
             '2
             '#f
             '#f)))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!class-meta::t
       ':init!
       gxc#!class-meta:::init!
       '#f))
    (define gxc#!class:::init!__0
      (lambda (_%self223175%_
               _%id223176%_
               _%super223177%_
               _%slots223178%_
               _%ctor-method223179%_
               _%struct?223180%_
               _%final?223181%_
               _%system?223182%_
               _%metaclass223183%_)
        (let ((_%self223186%_ _%self223175%_))
          (let _%lp223197%_ ((_%rest223199%_ _%super223177%_))
            (let* ((_%$%rest223200223208%_ _%rest223199%_)
                   (_%$%else223202223216%_ (lambda () '#!void))
                   (_%$%K223204223222%_
                    (lambda (_%rest223219%_ _%super-id223220%_)
                      (if (let ((__tmp225007
                                 (gxc#optimizer-resolve-class
                                  (list '!class _%id223176%_)
                                  _%super-id223220%_)))
                            (declare (not safe))
                            (##unchecked-structure-ref __tmp225007 '8 '#f '#f))
                          (let ((__tmp225008 (list '!class _%id223176%_)))
                            (declare (not safe))
                            (gxc#raise-compile-error
                             '"cannot extend final class"
                             __tmp225008
                             _%super-id223220%_))
                          '#!void)
                      (_%lp223197%_ _%rest223219%_))))
              (if (pair? _%$%rest223200223208%_)
                  (let ((_%$%hd223205223225%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest223200223208%_)))
                        (_%$%tl223206223227%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest223200223208%_))))
                    (let* ((_%super-id223230%_ _%$%hd223205223225%_)
                           (_%rest223232%_ _%$%tl223206223227%_))
                      (_%$%K223204223222%_ _%rest223232%_ _%super-id223230%_)))
                  '#!void)))
          (let* ((_%ctor-method223283%_
                  (let ((_%$e223234%_ _%ctor-method223179%_))
                    (if _%$e223234%_
                        _%$e223234%_
                        (let _%lp223237%_ ((_%rest223239%_ _%super223177%_)
                                           (_%method223240%_ '#f))
                          (let* ((_%$%rest223241223249%_ _%rest223239%_)
                                 (_%$%else223243223257%_
                                  (lambda () _%method223240%_))
                                 (_%$%K223245223271%_
                                  (lambda (_%rest223260%_ _%super-id223261%_)
                                    (let* ((_%klass223263%_
                                            (gxc#optimizer-resolve-class
                                             (list '!class _%id223176%_)
                                             _%super-id223261%_))
                                           (_%$e223265%_
                                            (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-ref
                                               _%klass223263%_
                                               '6
                                               '#f
                                               '#f))))
                                      (if _%$e223265%_
                                          (if _%method223240%_
                                              (if (eq? _%$e223265%_
                                                       _%method223240%_)
                                                  (_%lp223237%_
                                                   _%rest223260%_
                                                   _%$e223265%_)
                                                  (let ((__tmp225009
                                                         (list '!class
                                                               _%id223176%_)))
                                                    (declare (not safe))
                                                    (gxc#raise-compile-error
                                                     '"conflicting implicit constructor methods"
                                                     __tmp225009
                                                     _%method223240%_
                                                     _%$e223265%_)))
                                              (_%lp223237%_
                                               _%rest223260%_
                                               _%$e223265%_))
                                          (_%lp223237%_
                                           _%rest223260%_
                                           _%method223240%_))))))
                            (if (pair? _%$%rest223241223249%_)
                                (let ((_%$%hd223246223274%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%rest223241223249%_)))
                                      (_%$%tl223247223276%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%rest223241223249%_))))
                                  (let* ((_%super-id223279%_
                                          _%$%hd223246223274%_)
                                         (_%rest223281%_ _%$%tl223247223276%_))
                                    (_%$%K223245223271%_
                                     _%rest223281%_
                                     _%super-id223279%_)))
                                (_%$%else223243223257%_)))))))
                 (_g225010_
                  (let ((__tmp225014
                         (lambda (_%klass-id223285%_)
                           (cons _%klass-id223285%_
                                 (let ((__tmp225015
                                        (gxc#optimizer-resolve-class
                                         (list '!class _%id223176%_)
                                         _%klass-id223285%_)))
                                   (declare (not safe))
                                   (##unchecked-structure-ref
                                    __tmp225015
                                    '3
                                    '#f
                                    '#f)))))
                        (__tmp225012
                         (lambda (_%klass-id223287%_)
                           (let ((__tmp225013
                                  (gxc#optimizer-resolve-class
                                   (list '!class _%id223176%_)
                                   _%klass-id223287%_)))
                             (declare (not safe))
                             (##unchecked-structure-ref
                              __tmp225013
                              '7
                              '#f
                              '#f)))))
                    (declare (not safe))
                    (c4-linearize__%
                     '#f
                     __tmp225014
                     __tmp225012
                     eq?
                     identity
                     '()
                     _%super223177%_))))
            (begin
              (let ((_g225011_
                     (let ()
                       (declare (not safe))
                       (if (##values? _g225010_)
                           (##values-length _g225010_)
                           1))))
                (if (not (let () (declare (not safe)) (##fx= _g225011_ 2)))
                    (error "Context expects 2 values" _g225011_)))
              (let ((_%precedence-list223289%_
                     (let () (declare (not safe)) (##values-ref _g225010_ 0)))
                    (_%base-struct223290%_
                     (let () (declare (not safe)) (##values-ref _g225010_ 1))))
                (let* ((_%precedence-list223334%_
                        (if (let ()
                              (declare (not safe))
                              (##memq _%id223176%_ '(t object class)))
                            _%precedence-list223289%_
                            (if (memq 'object::t _%precedence-list223289%_)
                                _%precedence-list223289%_
                                (if _%system?223182%_
                                    (if (memq 't::t _%precedence-list223289%_)
                                        _%precedence-list223289%_
                                        (let ()
                                          (declare (not safe))
                                          (##append
                                           _%precedence-list223289%_
                                           '(t::t))))
                                    (let _%loop223296%_ ((_%tail223298%_
                                                          _%precedence-list223289%_)
                                                         (_%head223299%_ '()))
                                      (let* ((_%$%tail223300223308%_
                                              _%tail223298%_)
                                             (_%$%else223302223316%_
                                              (lambda ()
                                                (let ()
                                                  (declare (not safe))
                                                  (foldl__0
                                                   cons
                                                   '(object::t t::t)
                                                   _%head223299%_))))
                                             (_%$%K223304223322%_
                                              (lambda (_%rest223319%_
                                                       _%hd223320%_)
                                                (if (eq? _%hd223320%_ 't::t)
                                                    (let ((__tmp225016
                                                           (cons 'object::t
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         _%tail223298%_)))
              (declare (not safe))
              (foldl__0 cons __tmp225016 _%head223299%_))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                    (_%loop223296%_
                                                     _%rest223319%_
                                                     (cons _%hd223320%_
                                                           _%head223299%_))))))
                                        (if (pair? _%$%tail223300223308%_)
                                            (let ((_%$%hd223305223325%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##car _%$%tail223300223308%_)))
                                                  (_%$%tl223306223327%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##cdr _%$%tail223300223308%_))))
                                              (let* ((_%hd223330%_
                                                      _%$%hd223305223325%_)
                                                     (_%rest223332%_
                                                      _%$%tl223306223327%_))
                                                (_%$%K223304223322%_
                                                 _%rest223332%_
                                                 _%hd223330%_)))
                                            (_%$%else223302223316%_))))))))
                       (_%fields223336%_
                        (gxc#compute-class-fields
                         (list '!class _%id223176%_)
                         _%precedence-list223334%_
                         _%slots223178%_)))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%id223176%_
                     '1
                     '#f
                     '#f))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%super223177%_
                     '2
                     '#f
                     '#f))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%precedence-list223334%_
                     '3
                     '#f
                     '#f))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%slots223178%_
                     '4
                     '#f
                     '#f))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%fields223336%_
                     '5
                     '#f
                     '#f))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%ctor-method223283%_
                     '6
                     '#f
                     '#f))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%struct?223180%_
                     '7
                     '#f
                     '#f))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%final?223181%_
                     '8
                     '#f
                     '#f))
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%self223186%_
                     _%metaclass223183%_
                     '10
                     '#f
                     '#f)))))))))
    (define gxc#!class:::init!__1
      (lambda (_%self223339%_
               _%id223340%_
               _%super223341%_
               _%precedence-list223342%_
               _%slots223343%_
               _%fields223344%_
               _%constructor223345%_
               _%struct?223346%_
               _%final?223347%_
               _%system?223348%_
               _%metaclass223349%_
               _%methods223350%_)
        (let ((_%self223353%_ _%self223339%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%id223340%_
             '1
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%super223341%_
             '2
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%precedence-list223342%_
             '3
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%slots223343%_
             '4
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%fields223344%_
             '5
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%constructor223345%_
             '6
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%struct?223346%_
             '7
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%final?223347%_
             '8
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self223353%_
             _%metaclass223349%_
             '10
             '#f
             '#f))
          (if _%methods223350%_
              (let ((__tmp225017
                     (let ()
                       (declare (not safe))
                       (list->hash-table-eq _%methods223350%_))))
                (declare (not safe))
                (##unchecked-structure-set!
                 _%self223353%_
                 __tmp225017
                 '11
                 '#f
                 '#f))
              '#!void))))
    (define gxc#!class:::init!
      (lambda _g225018_
        (let ((_g225019_ (let () (declare (not safe)) (##length _g225018_))))
          (cond ((let () (declare (not safe)) (##fx= _g225019_ 9))
                 (apply gxc#!class:::init!__0 _g225018_))
                ((let () (declare (not safe)) (##fx= _g225019_ 12))
                 (apply gxc#!class:::init!__1 _g225018_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#!class:::init!
                  _g225018_))))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!class::t ':init! gxc#!class:::init! '#f))
    (define gxc#compute-class-fields
      (lambda (_%where223044%_
               _%precedence-list223045%_
               _%direct-slots223046%_)
        (let ((__tmp225021
               (lambda (_%mixin223048%_)
                 (let ((__tmp225022
                        (gxc#optimizer-resolve-class
                         _%where223044%_
                         _%mixin223048%_)))
                   (declare (not safe))
                   (##unchecked-structure-ref __tmp225022 '5 '#f '#f))))
              (__tmp225020
               (lambda (_%slot-list223050%_ _%slot-table223051%_)
                 (cdr _%slot-list223050%_))))
          (declare (not safe))
          (c4-compute-class-slots
           _%precedence-list223045%_
           _%direct-slots223046%_
           __tmp225021
           __tmp225020))))
    (define gxc#!class-slot->field-offset
      (lambda (_%klass223003%_ _%slot223004%_)
        (let _%lp223006%_ ((_%rest223008%_
                            (##structure-ref
                             _%klass223003%_
                             '5
                             gxc#!class::t
                             '#f))
                           (_%offset223009%_ '1))
          (let* ((_%$%rest223010223018%_ _%rest223008%_)
                 (_%$%else223012223026%_
                  (lambda ()
                    (let ((__tmp225024
                           (##structure-ref
                            _%klass223003%_
                            '1
                            gxc#!type::t
                            '#f))
                          (__tmp225023
                           (##structure-ref
                            _%klass223003%_
                            '5
                            gxc#!class::t
                            '#f)))
                      (declare (not safe))
                      (gxc#raise-compile-error
                       '"unknown class slot"
                       __tmp225024
                       __tmp225023
                       _%slot223004%_))))
                 (_%$%K223014223032%_
                  (lambda (_%rest223029%_ _%s223030%_)
                    (if (eq? _%s223030%_ _%slot223004%_)
                        _%offset223009%_
                        (_%lp223006%_
                         _%rest223029%_
                         (let ()
                           (declare (not safe))
                           (##fx+ _%offset223009%_ '1)))))))
            (if (pair? _%$%rest223010223018%_)
                (let ((_%$%hd223015223035%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest223010223018%_)))
                      (_%$%tl223016223037%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest223010223018%_))))
                  (let* ((_%s223040%_ _%$%hd223015223035%_)
                         (_%rest223042%_ _%$%tl223016223037%_))
                    (_%$%K223014223032%_ _%rest223042%_ _%s223040%_)))
                (_%$%else223012223026%_))))))
    (define gxc#!class-slot-find-struct
      (lambda (_%klass222961%_ _%slot222962%_)
        (if (gxc#!class-struct-slot? _%klass222961%_ _%slot222962%_)
            _%klass222961%_
            (let _%lp222964%_ ((_%rest222966%_
                                (##structure-ref
                                 _%klass222961%_
                                 '3
                                 gxc#!class::t
                                 '#f)))
              (let* ((_%$%rest222967222975%_ _%rest222966%_)
                     (_%$%else222969222983%_ (lambda () '#f))
                     (_%$%K222971222991%_
                      (lambda (_%rest222986%_ _%super222987%_)
                        (let ((_%super-class222989%_
                               (gxc#optimizer-resolve-class
                                (list '!class-slot-find-struct
                                      (##structure-ref
                                       _%klass222961%_
                                       '1
                                       gxc#!type::t
                                       '#f)
                                      _%slot222962%_)
                                _%super222987%_)))
                          (if (gxc#!class-struct-slot?
                               _%super-class222989%_
                               _%slot222962%_)
                              _%super-class222989%_
                              (_%lp222964%_ _%rest222986%_))))))
                (if (pair? _%$%rest222967222975%_)
                    (let ((_%$%hd222972222994%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%rest222967222975%_)))
                          (_%$%tl222973222996%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%rest222967222975%_))))
                      (let* ((_%super222999%_ _%$%hd222972222994%_)
                             (_%rest223001%_ _%$%tl222973222996%_))
                        (_%$%K222971222991%_ _%rest223001%_ _%super222999%_)))
                    (_%$%else222969222983%_)))))))
    (define gxc#!class-struct-slot?
      (lambda (_%klass222958%_ _%slot222959%_)
        (if (##structure-ref _%klass222958%_ '7 gxc#!class::t '#f)
            (memq _%slot222959%_
                  (##structure-ref _%klass222958%_ '5 gxc#!class::t '#f))
            '#f)))
    (define gxc#!predicate:::init!
      (lambda (_%self222904%_ _%id222905%_)
        (let ((_%self222908%_ _%self222904%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222908%_
             _%id222905%_
             '1
             '#f
             '#f))
          (let* ((_%$obj222919%_ _%self222908%_)
                 (_%signature222922%_
                  (let ((__obj224952
                         (let ()
                           (declare (not safe))
                           (##structure
                            gxc#!signature::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224952
                       'boolean::t
                       '1
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224952
                       '(pure predicate)
                       '2
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224952
                       '(t::t)
                       '3
                       '#f
                       '#f))
                    __obj224952))
                 (_%$obj222927%_ _%$obj222919%_))
            (if (or (not _%signature222922%_) '#t)
                (let ((_%signature222948%_ _%signature222922%_))
                  (gxc#__!predicate-signature-set!
                   _%$obj222927%_
                   _%signature222948%_))
                (begin
                  (raise-contract-violation-error
                   '"contract violation"
                   'context:
                   'gerbil/compiler/optimize-base
                   'contract:
                   '(? (or not !signature?))
                   'value:
                   _%signature222922%_)
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!predicate::t ':init! gxc#!predicate:::init! '#f))
    (define gxc#!constructor:::init!
      (lambda (_%self222728%_ _%id222729%_)
        (let ((_%self222732%_ _%self222728%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222732%_
             _%id222729%_
             '1
             '#f
             '#f))
          (let* ((_%$obj222743%_ _%self222732%_)
                 (_%signature222746%_
                  (let ((__obj224953
                         (let ()
                           (declare (not safe))
                           (##structure
                            gxc#!signature::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224953
                       _%id222729%_
                       '1
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224953
                       '(alloc)
                       '2
                       '#f
                       '#f))
                    __obj224953))
                 (_%$obj222751%_ _%$obj222743%_))
            (if (or (not _%signature222746%_) '#t)
                (let ((_%signature222772%_ _%signature222746%_))
                  (gxc#__!constructor-signature-set!
                   _%$obj222751%_
                   _%signature222772%_))
                (begin
                  (raise-contract-violation-error
                   '"contract violation"
                   'context:
                   'gerbil/compiler/optimize-base
                   'contract:
                   '(? (or not !signature?))
                   'value:
                   _%signature222746%_)
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!constructor::t
       ':init!
       gxc#!constructor:::init!
       '#f))
    (define gxc#!accessor:::init!
      (lambda (_%self222550%_ _%id222551%_ _%slot222552%_ _%checked?222553%_)
        (let ((_%self222556%_ _%self222550%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222556%_
             _%id222551%_
             '1
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222556%_
             _%slot222552%_
             '3
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222556%_
             _%checked?222553%_
             '4
             '#f
             '#f))
          (let* ((_%$obj222567%_ _%self222556%_)
                 (_%signature222570%_
                  (let ((__obj224954
                         (let ()
                           (declare (not safe))
                           (##structure
                            gxc#!signature::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224954
                       't::t
                       '1
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224954
                       '(pure)
                       '2
                       '#f
                       '#f))
                    (let ((__tmp225025 (cons _%id222551%_ '())))
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224954
                       __tmp225025
                       '3
                       '#f
                       '#f))
                    __obj224954))
                 (_%$obj222575%_ _%$obj222567%_))
            (if (or (not _%signature222570%_) '#t)
                (let ((_%signature222596%_ _%signature222570%_))
                  (gxc#__!accessor-signature-set!
                   _%$obj222575%_
                   _%signature222596%_))
                (begin
                  (raise-contract-violation-error
                   '"contract violation"
                   'context:
                   'gerbil/compiler/optimize-base
                   'contract:
                   '(? (or not !signature?))
                   'value:
                   _%signature222570%_)
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!accessor::t ':init! gxc#!accessor:::init! '#f))
    (define gxc#!mutator:::init!
      (lambda (_%self222372%_ _%id222373%_ _%slot222374%_ _%checked?222375%_)
        (let ((_%self222378%_ _%self222372%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222378%_
             _%id222373%_
             '1
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222378%_
             _%slot222374%_
             '3
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222378%_
             _%checked?222375%_
             '4
             '#f
             '#f))
          (let* ((_%$obj222389%_ _%self222378%_)
                 (_%signature222392%_
                  (let ((__obj224955
                         (let ()
                           (declare (not safe))
                           (##structure
                            gxc#!signature::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224955
                       'void::t
                       '1
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224955
                       '(mut)
                       '2
                       '#f
                       '#f))
                    (let ((__tmp225026 (cons _%id222373%_ (cons 't::t '()))))
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224955
                       __tmp225026
                       '3
                       '#f
                       '#f))
                    __obj224955))
                 (_%$obj222397%_ _%$obj222389%_))
            (if (or (not _%signature222392%_) '#t)
                (let ((_%signature222418%_ _%signature222392%_))
                  (gxc#__!mutator-signature-set!
                   _%$obj222397%_
                   _%signature222418%_))
                (begin
                  (raise-contract-violation-error
                   '"contract violation"
                   'context:
                   'gerbil/compiler/optimize-base
                   'contract:
                   '(? (or not !signature?))
                   'value:
                   _%signature222392%_)
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!mutator::t ':init! gxc#!mutator:::init! '#f))
    (define gxc#!lambda:::init!__%
      (lambda (_%@@keywords222177%_
               _%$%signature222174222178%_
               _%self222179%_
               _%arity222180%_
               _%dispatch222181%_)
        (let* ((_%signature222183%_
                (if (eq? _%$%signature222174222178%_ absent-value)
                    '#f
                    _%$%signature222174222178%_))
               (_%self222186%_ _%self222179%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set! _%self222186%_ 'procedure '1 '#f '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222186%_
             _%arity222180%_
             '3
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self222186%_
             _%dispatch222181%_
             '4
             '#f
             '#f))
          (let* ((_%$obj222198%_ _%self222186%_)
                 (_%signature222201%_ _%signature222183%_)
                 (_%$obj222206%_ _%$obj222198%_))
            (if (or (not _%signature222201%_)
                    (let ()
                      (declare (not safe))
                      (##structure-direct-instance-of?
                       _%signature222201%_
                       'gxc#!signature::t)))
                (let ((_%signature222227%_ _%signature222201%_))
                  (gxc#__!lambda-signature-set!
                   _%$obj222206%_
                   _%signature222227%_))
                (begin
                  (raise-contract-violation-error
                   '"contract violation"
                   'context:
                   'gerbil/compiler/optimize-base
                   'contract:
                   '(? (or not !signature?))
                   'value:
                   _%signature222201%_)
                  '#!void))))))
    (define gxc#!lambda:::init!__@
      (lambda (_%@@keywords222240%_ . _%args222241%_)
        (apply gxc#!lambda:::init!__%
               _%@@keywords222240%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords222240%_
                  'signature:
                  absent-value))
               _%args222241%_)))
    (define gxc#!lambda:::init!
      (lambda _%$%args222175222247%_
        (apply keyword-dispatch
               '#(signature:)
               gxc#!lambda:::init!__@
               _%$%args222175222247%_)))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!lambda::t ':init! gxc#!lambda:::init! '#f))
    (define gxc#!case-lambda:::init!__%
      (lambda (_%@@keywords221979%_
               _%$%signature221976221980%_
               _%self221981%_
               _%clauses221982%_)
        (let* ((_%signature221984%_
                (if (eq? _%$%signature221976221980%_ absent-value)
                    '#f
                    _%$%signature221976221980%_))
               (_%self221987%_ _%self221981%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set! _%self221987%_ 'procedure '1 '#f '#f))
          (let* ((_%$obj221999%_ _%self221987%_)
                 (_%signature222002%_ _%signature221984%_)
                 (_%$obj222007%_ _%$obj221999%_))
            (if (or (not _%signature222002%_)
                    (let ()
                      (declare (not safe))
                      (##structure-direct-instance-of?
                       _%signature222002%_
                       'gxc#!signature::t)))
                (let ((_%signature222028%_ _%signature222002%_))
                  (gxc#__!case-lambda-signature-set!
                   _%$obj222007%_
                   _%signature222028%_))
                (begin
                  (raise-contract-violation-error
                   '"contract violation"
                   'context:
                   'gerbil/compiler/optimize-base
                   'contract:
                   '(? (or not !signature?))
                   'value:
                   _%signature222002%_)
                  '#!void)))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self221987%_
             _%clauses221982%_
             '3
             '#f
             '#f)))))
    (define gxc#!case-lambda:::init!__@
      (lambda (_%@@keywords222041%_ . _%args222042%_)
        (apply gxc#!case-lambda:::init!__%
               _%@@keywords222041%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%@@keywords222041%_
                  'signature:
                  absent-value))
               _%args222042%_)))
    (define gxc#!case-lambda:::init!
      (lambda _%$%args221977222048%_
        (apply keyword-dispatch
               '#(signature:)
               gxc#!case-lambda:::init!__@
               _%$%args221977222048%_)))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!case-lambda::t
       ':init!
       gxc#!case-lambda:::init!
       '#f))
    (define gxc#!kw-lambda:::init!
      (lambda (_%self221837%_ _%tab221838%_ _%dispatch221839%_)
        (let ((_%self221842%_ _%self221837%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set! _%self221842%_ 'procedure '1 '#f '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self221842%_
             _%tab221838%_
             '3
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self221842%_
             _%dispatch221839%_
             '4
             '#f
             '#f)))))
    (let ()
      (declare (not safe))
      (__bind-method!__% gxc#!kw-lambda::t ':init! gxc#!kw-lambda:::init! '#f))
    (define gxc#!kw-lambda-primary:::init!
      (lambda (_%self221699%_ _%keys221700%_ _%main221701%_)
        (let ((_%self221704%_ _%self221699%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set! _%self221704%_ 'procedure '1 '#f '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self221704%_
             _%keys221700%_
             '3
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self221704%_
             _%main221701%_
             '4
             '#f
             '#f)))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!kw-lambda-primary::t
       ':init!
       gxc#!kw-lambda-primary:::init!
       '#f))
    (define gxc#!primitive-lambda:::init! gxc#!lambda:::init!)
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!primitive-lambda::t
       ':init!
       gxc#!primitive-lambda:::init!
       '#f))
    (define gxc#!primitive-case-lambda:::init! gxc#!case-lambda:::init!)
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!primitive-case-lambda::t
       ':init!
       gxc#!primitive-case-lambda:::init!
       '#f))
    (define gxc#!primitive-predicate:::init!
      (lambda (_%self221279%_ _%id221280%_)
        (let ((_%self221283%_ _%self221279%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self221283%_
             _%id221280%_
             '1
             '#f
             '#f))
          (let* ((_%$obj221294%_ _%self221283%_)
                 (_%signature221297%_
                  (let ((__obj224956
                         (let ()
                           (declare (not safe))
                           (##structure
                            gxc#!signature::t
                            '#f
                            '#f
                            '#f
                            '#f
                            '#f))))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224956
                       'boolean::t
                       '1
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224956
                       '(pure)
                       '2
                       '#f
                       '#f))
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-set!
                       __obj224956
                       '(t::t)
                       '3
                       '#f
                       '#f))
                    __obj224956))
                 (_%$obj221302%_ _%$obj221294%_))
            (if (or (not _%signature221297%_) '#t)
                (let ((_%signature221323%_ _%signature221297%_))
                  (gxc#__!primitive-predicate-signature-set!
                   _%$obj221302%_
                   _%signature221323%_))
                (begin
                  (raise-contract-violation-error
                   '"contract violation"
                   'context:
                   'gerbil/compiler/optimize-base
                   'contract:
                   '(? (or not !signature?))
                   'value:
                   _%signature221297%_)
                  '#!void))))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       gxc#!primitive-predicate::t
       ':init!
       gxc#!primitive-predicate:::init!
       '#f))
    (define gxc#!class-method-table
      (lambda (_%klass221149%_)
        (let ((_%$e221151%_
               (##structure-ref _%klass221149%_ '11 gxc#!class::t '#f)))
          (if _%$e221151%_
              _%$e221151%_
              (let ((_%tab221155%_
                     (let () (declare (not safe)) (make-hash-table-eq))))
                (##structure-set!
                 _%klass221149%_
                 _%tab221155%_
                 '11
                 gxc#!class::t
                 '#f)
                _%tab221155%_)))))
    (define gxc#!class-lookup-method
      (lambda (_%klass221141%_ _%method221142%_)
        (let ((_%$%tab221143221145%_
               (##structure-ref _%klass221141%_ '11 gxc#!class::t '#f)))
          (if _%$%tab221143221145%_
              (let ((_%tab221147%_ _%$%tab221143221145%_))
                (declare (not safe))
                (hash-get _%tab221147%_ _%method221142%_))
              '#f))))
    (define gxc#!type-subtype?
      (lambda (_%type-a221117%_ _%type-b221118%_)
        (if _%type-a221117%_
            (if _%type-b221118%_
                (let ((_%$e221120%_ (eq? _%type-a221117%_ _%type-b221118%_)))
                  (if _%$e221120%_
                      _%$e221120%_
                      (let ((_%$e221123%_
                             (eq? (##structure-ref
                                   _%type-b221118%_
                                   '1
                                   gxc#!type::t
                                   '#f)
                                  't)))
                        (if _%$e221123%_
                            _%$e221123%_
                            (let ((_%$e221126%_
                                   (if (let ()
                                         (declare (not safe))
                                         (##structure-instance-of?
                                          _%type-a221117%_
                                          'gxc#!nullable-type::t))
                                       (if (let ()
                                             (declare (not safe))
                                             (##structure-instance-of?
                                              _%type-b221118%_
                                              'gxc#!nullable-type::t))
                                           '#f
                                           (if (gxc#!type-subtype?
                                                (let ()
                                                  (declare (not safe))
                                                  (##unchecked-structure-ref
                                                   _%type-a221117%_
                                                   '2
                                                   '#f
                                                   '#f))
                                                _%type-b221118%_)
                                               (gxc#!type-subtype?
                                                (gxc#optimizer-resolve-class
                                                 'subtype
                                                 'false::t)
                                                _%type-b221118%_)
                                               '#f))
                                       '#f)))
                              (if _%$e221126%_
                                  _%$e221126%_
                                  (let ((_%$e221132%_
                                         (if (let ()
                                               (declare (not safe))
                                               (##structure-instance-of?
                                                _%type-b221118%_
                                                'gxc#!nullable-type::t))
                                             (let ((_%$e221129%_
                                                    (eq? (##structure-ref
                                                          _%type-a221117%_
                                                          '1
                                                          gxc#!type::t
                                                          '#f)
                                                         'false)))
                                               (if _%$e221129%_
                                                   _%$e221129%_
                                                   (gxc#!type-subtype?
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (##structure-instance-of?
                                                           _%type-a221117%_
                                                           'gxc#!nullable-type::t))
                                                        (let ()
                                                          (declare (not safe))
                                                          (##unchecked-structure-ref
                                                           _%type-a221117%_
                                                           '2
                                                           '#f
                                                           '#f))
                                                        _%type-a221117%_)
                                                    (let ()
                                                      (declare (not safe))
                                                      (##unchecked-structure-ref
                                                       _%type-b221118%_
                                                       '2
                                                       '#f
                                                       '#f)))))
                                             '#f)))
                                    (if _%$e221132%_
                                        _%$e221132%_
                                        (let ((_%$e221135%_
                                               (if (let ()
                                                     (declare (not safe))
                                                     (##structure-instance-of?
                                                      _%type-a221117%_
                                                      'gxc#!procedure::t))
                                                   (eq? (##structure-ref
                                                         _%type-b221118%_
                                                         '1
                                                         gxc#!type::t
                                                         '#f)
                                                        'procedure)
                                                   '#f)))
                                          (if _%$e221135%_
                                              _%$e221135%_
                                              (let ((_%$e221138%_
                                                     (if (let ()
                                                           (declare (not safe))
                                                           (##structure-instance-of?
                                                            _%type-a221117%_
                                                            'gxc#!class::t))
                                                         (if (let ()
                                                               (declare
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                         (not safe))
                       (##structure-instance-of?
                        _%type-b221118%_
                        'gxc#!class::t))
                     (gxc#!class-subclass? _%type-a221117%_ _%type-b221118%_)
                     '#f)
                 '#f)))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                (if _%$e221138%_
                                                    _%$e221138%_
                                                    (if (let ()
                                                          (declare (not safe))
                                                          (##structure-instance-of?
                                                           _%type-a221117%_
                                                           'gxc#!interface::t))
                                                        (eq? (##structure-ref
                                                              _%type-b221118%_
                                                              '1
                                                              gxc#!type::t
                                                              '#f)
                                                             'interface-descriptor::t)
                                                        '#f)))))))))))))
                '#f)
            '#f)))
    (define gxc#!class-subclass?
      (lambda (_%klass-a221068%_ _%klass-b221069%_)
        (let ((_%$e221071%_
               (eq? (##structure-ref _%klass-a221068%_ '1 gxc#!type::t '#f)
                    (##structure-ref _%klass-b221069%_ '1 gxc#!type::t '#f))))
          (if _%$e221071%_
              _%$e221071%_
              (let ((_%klass-id-b221074%_
                     (##structure-ref _%klass-b221069%_ '1 gxc#!type::t '#f))
                    (_%precedence-list221075%_
                     (##structure-ref _%klass-a221068%_ '3 gxc#!class::t '#f)))
                (let _%loop221077%_ ((_%rest221079%_
                                      _%precedence-list221075%_))
                  (let* ((_%$%rest221080221088%_ _%rest221079%_)
                         (_%$%else221082221096%_ (lambda () '#f))
                         (_%$%K221084221105%_
                          (lambda (_%rest221099%_ _%klass-name221100%_)
                            (let ((_%$e221102%_
                                   (eq? (let ((__tmp225027
                                               (gxc#optimizer-resolve-class
                                                (list 'subclass?
                                                      _%klass-a221068%_
                                                      _%klass-b221069%_)
                                                _%klass-name221100%_)))
                                          (declare (not safe))
                                          (##unchecked-structure-ref
                                           __tmp225027
                                           '1
                                           '#f
                                           '#f))
                                        _%klass-id-b221074%_)))
                              (if _%$e221102%_
                                  _%$e221102%_
                                  (_%loop221077%_ _%rest221099%_))))))
                    (if (pair? _%$%rest221080221088%_)
                        (let ((_%$%hd221085221108%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%rest221080221088%_)))
                              (_%$%tl221086221110%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%rest221080221088%_))))
                          (let* ((_%klass-name221113%_ _%$%hd221085221108%_)
                                 (_%rest221115%_ _%$%tl221086221110%_))
                            (_%$%K221084221105%_
                             _%rest221115%_
                             _%klass-name221113%_)))
                        (_%$%else221082221096%_)))))))))
    (define gxc#!class-primitive-leaf?
      (lambda (_%klass221066%_)
        (let ((__tmp225028
               (##structure-ref _%klass221066%_ '1 gxc#!type::t '#f)))
          (declare (not safe))
          (##memq __tmp225028
                  '(char true
                         false
                         eof
                         void
                         null
                         fixnum
                         bignum
                         ratnum
                         cpxnum
                         stflonum
                         haflonum
                         symbol
                         keyword
                         pair
                         vector
                         string
                         u8vector
                         s8vector
                         u16vector
                         s16vector
                         u32vector
                         s32vector
                         u64vector
                         s64vector
                         f32vector
                         f64vector)))))
    (define gxc#!class-struct-base
      (lambda (_%klass221025%_)
        (if (##structure-ref _%klass221025%_ '7 gxc#!class::t '#f)
            _%klass221025%_
            (let _%loop221027%_ ((_%rest221029%_
                                  (##structure-ref
                                   _%klass221025%_
                                   '3
                                   gxc#!class::t
                                   '#f)))
              (let* ((_%$%rest221030221038%_ _%rest221029%_)
                     (_%$%else221032221046%_ (lambda () '#f))
                     (_%$%K221034221054%_
                      (lambda (_%rest221049%_ _%name221050%_)
                        (let ((_%super221052%_
                               (gxc#optimizer-resolve-class
                                'struct-base
                                _%name221050%_)))
                          (if (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 _%super221052%_
                                 '7
                                 '#f
                                 '#f))
                              _%super221052%_
                              (_%loop221027%_ _%rest221049%_))))))
                (if (pair? _%$%rest221030221038%_)
                    (let ((_%$%hd221035221057%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%rest221030221038%_)))
                          (_%$%tl221036221059%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%rest221030221038%_))))
                      (let* ((_%name221062%_ _%$%hd221035221057%_)
                             (_%rest221064%_ _%$%tl221036221059%_))
                        (_%$%K221034221054%_ _%rest221064%_ _%name221062%_)))
                    (_%$%else221032221046%_)))))))
    (define gxc#!type-disjoint?
      (lambda (_%type-a220984%_ _%type-b220985%_)
        (if (or (not _%type-a220984%_)
                (not _%type-b220985%_)
                (let ()
                  (declare (not safe))
                  (##structure-instance-of? _%type-a220984%_ 'gxc#!abort::t))
                (let ()
                  (declare (not safe))
                  (##structure-instance-of? _%type-b220985%_ 'gxc#!abort::t))
                (let ()
                  (declare (not safe))
                  (##structure-instance-of?
                   _%type-a220984%_
                   'gxc#!nullable-type::t))
                (let ()
                  (declare (not safe))
                  (##structure-instance-of?
                   _%type-b220985%_
                   'gxc#!nullable-type::t)))
            '#f
            (if (or (gxc#!type-subtype? _%type-a220984%_ _%type-b220985%_)
                    (gxc#!type-subtype? _%type-b220985%_ _%type-a220984%_))
                '#f
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of?
                       _%type-a220984%_
                       'gxc#!procedure::t))
                    (gxc#!type-disjoint?
                     (gxc#optimizer-resolve-class 'disjoint 'procedure::t)
                     _%type-b220985%_)
                    (if (let ()
                          (declare (not safe))
                          (##structure-instance-of?
                           _%type-b220985%_
                           'gxc#!procedure::t))
                        (gxc#!type-disjoint?
                         _%type-a220984%_
                         (gxc#optimizer-resolve-class 'disjoint 'procedure::t))
                        (if (and (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%type-a220984%_
                                    'gxc#!class::t))
                                 (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%type-b220985%_
                                    'gxc#!class::t)))
                            (if (or (##structure-ref
                                     _%type-a220984%_
                                     '8
                                     gxc#!class::t
                                     '#f)
                                    (##structure-ref
                                     _%type-b220985%_
                                     '8
                                     gxc#!class::t
                                     '#f)
                                    (gxc#!class-primitive-leaf?
                                     _%type-a220984%_)
                                    (gxc#!class-primitive-leaf?
                                     _%type-b220985%_))
                                '#t
                                (let ((_%base-a221021%_
                                       (gxc#!class-struct-base
                                        _%type-a220984%_))
                                      (_%base-b221022%_
                                       (gxc#!class-struct-base
                                        _%type-b220985%_)))
                                  (if _%base-a221021%_
                                      (if _%base-b221022%_
                                          (if (gxc#!class-subclass?
                                               _%base-a221021%_
                                               _%base-b221022%_)
                                              '#f
                                              (not (gxc#!class-subclass?
                                                    _%base-b221022%_
                                                    _%base-a221021%_)))
                                          '#f)
                                      '#f)))
                            '#f)))))))
    (define gxc#!interface-instance?
      (lambda (_%type220982%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%type220982%_ 'gxc#!class::t))
            (memq 'interface-instance::t
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-ref _%type220982%_ '3 '#f '#f)))
            '#f)))
    (define gxc#!procedure-origin
      (lambda (_%proc220971%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%proc220971%_ 'gxc#!procedure::t))
            (let ((_%proc220974%_ _%proc220971%_))
              (if (let ()
                    (declare (not safe))
                    (##unchecked-structure-ref _%proc220974%_ '2 '#f '#f))
                  (##direct-structure-ref
                   (let ()
                     (declare (not safe))
                     (##unchecked-structure-ref _%proc220974%_ '2 '#f '#f))
                   '5
                   gxc#!signature::t
                   '#f)
                  '#f))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/compiler/optimize-base.ss\"@433.11-433.15"
               'contract:
               '!procedure?
               'value:
               _%proc220971%_)
              '#!void))))
    (define gxc#optimizer-declare-type!__%
      (lambda (_%sym220953%_ _%type220954%_ _%local?220955%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%type220954%_ 'gxc#!type::t))
            '#!void
            (let ()
              (declare (not safe))
              (error '"bad declaration: expected !type"
                     _%sym220953%_
                     _%type220954%_)))
        (let ()
          (declare (not safe))
          (gxc#verbose '"declare-type " _%sym220953%_ '" " _%type220954%_))
        (let ((_%table220957%_
               (if _%local?220955%_
                   (let ()
                     (declare (not safe))
                     (gxc#current-compile-local-type))
                   (##structure-ref
                    (let ()
                      (declare (not safe))
                      (gxc#current-compile-optimizer-info))
                    '1
                    gxc#optimizer-info::t
                    '#f))))
          (declare (not safe))
          (hash-put! _%table220957%_ _%sym220953%_ _%type220954%_))))
    (define gxc#optimizer-declare-type!__0
      (lambda (_%sym220962%_ _%type220963%_)
        (let ((_%local?220965%_ '#f))
          (gxc#optimizer-declare-type!__%
           _%sym220962%_
           _%type220963%_
           _%local?220965%_))))
    (define gxc#optimizer-declare-type!
      (lambda _g225029_
        (let ((_g225030_ (let () (declare (not safe)) (##length _g225029_))))
          (cond ((let () (declare (not safe)) (##fx= _g225030_ 2))
                 (apply gxc#optimizer-declare-type!__0 _g225029_))
                ((let () (declare (not safe)) (##fx= _g225030_ 3))
                 (apply gxc#optimizer-declare-type!__% _g225029_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#optimizer-declare-type!
                  _g225029_))))))
    (define gxc#optimizer-declare-class!
      (lambda (_%sym220947%_ _%type220948%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%type220948%_ 'gxc#!class::t))
            '#!void
            (let ()
              (declare (not safe))
              (error '"bad declaration: expected !class"
                     _%sym220947%_
                     _%type220948%_)))
        (let ((_%table220950%_
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gxc#current-compile-optimizer-info))
                '2
                gxc#optimizer-info::t
                '#f)))
          (let ((__tmp225031
                 (let () (declare (not safe)) (struct->list _%type220948%_))))
            (declare (not safe))
            (gxc#verbose '"declare-class " _%sym220947%_ '" " __tmp225031))
          (let ()
            (declare (not safe))
            (hash-put! _%table220950%_ _%sym220947%_ _%type220948%_))
          (let ()
            (declare (not safe))
            (hash-put! _%table220950%_ _%type220948%_ _%sym220947%_)))))
    (define gxc#optimizer-declare-builtin-class!
      (lambda (_%sym220942%_ _%type220943%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%type220943%_ 'gxc#!class::t))
            '#!void
            (let ()
              (declare (not safe))
              (error '"bad declaration: expected !class"
                     _%sym220942%_
                     _%type220943%_)))
        (let ((_%table220945%_
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gxc#current-compile-optimizer-info))
                '2
                gxc#optimizer-info::t
                '#f)))
          (if (let ()
                (declare (not safe))
                (hash-get _%table220945%_ _%sym220942%_))
              '#!void
              (begin
                (let ((__tmp225032
                       (let ()
                         (declare (not safe))
                         (struct->list _%type220943%_))))
                  (declare (not safe))
                  (gxc#verbose
                   '"declare-builtin-class "
                   _%sym220942%_
                   '" "
                   __tmp225032))
                (let ()
                  (declare (not safe))
                  (hash-put! _%table220945%_ _%sym220942%_ _%type220943%_))
                (let ()
                  (declare (not safe))
                  (hash-put!
                   _%table220945%_
                   _%type220943%_
                   _%sym220942%_)))))))
    (define gxc#optimizer-clear-type!
      (lambda (_%sym220940%_)
        (let ()
          (declare (not safe))
          (gxc#verbose '"clear-type " _%sym220940%_))
        (let ((__tmp225033
               (let () (declare (not safe)) (gxc#current-compile-local-type))))
          (declare (not safe))
          (hash-remove! __tmp225033 _%sym220940%_))
        (let ((__tmp225034
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gxc#current-compile-optimizer-info))
                '1
                gxc#optimizer-info::t
                '#f)))
          (declare (not safe))
          (hash-remove! __tmp225034 _%sym220940%_))))
    (define gxc#optimizer-declare-method!__%
      (lambda (_%type-t220908%_
               _%method220909%_
               _%sym220910%_
               _%rebind?220911%_)
        (let ((__tmp225035
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gxc#current-compile-optimizer-info))
                '4
                gxc#optimizer-info::t
                '#f)))
          (declare (not safe))
          (hash-put! __tmp225035 _%sym220910%_ '#t))
        (let ((_%klass220913%_ (gxc#optimizer-lookup-class _%type-t220908%_)))
          (if _%klass220913%_
              (let* ((_%vtab220915%_ (gxc#!class-method-table _%klass220913%_))
                     (_%$e220917%_
                      (let ()
                        (declare (not safe))
                        (hash-get _%vtab220915%_ _%method220909%_))))
                (if _%$e220917%_
                    (if _%rebind?220911%_
                        (let ()
                          (let ()
                            (declare (not safe))
                            (gxc#verbose
                             '"declare-method: rebind existing method"
                             _%type-t220908%_
                             '" "
                             _%method220909%_))
                          (let ()
                            (declare (not safe))
                            (hash-put!
                             _%vtab220915%_
                             _%method220909%_
                             _%sym220910%_)))
                        (if (eq? _%$e220917%_ _%sym220910%_)
                            '#!void
                            (let ((__tmp225036
                                   (list 'bind-method!
                                         _%type-t220908%_
                                         _%method220909%_
                                         _%sym220910%_)))
                              (declare (not safe))
                              (gxc#raise-compile-error
                               '"declare-method: duplicate method declaration"
                               __tmp225036
                               _%method220909%_))))
                    (let ()
                      (let ()
                        (declare (not safe))
                        (gxc#verbose
                         '"declare-method "
                         _%type-t220908%_
                         '" "
                         _%method220909%_
                         '" => "
                         _%sym220910%_))
                      (let ()
                        (declare (not safe))
                        (hash-put!
                         _%vtab220915%_
                         _%method220909%_
                         _%sym220910%_)))))
              (let ()
                (declare (not safe))
                (gxc#verbose
                 '"declare-method: unknown class"
                 _%type-t220908%_))))))
    (define gxc#optimizer-declare-method!__0
      (lambda (_%type-t220929%_ _%method220930%_ _%sym220931%_)
        (let ((_%rebind?220933%_ '#f))
          (gxc#optimizer-declare-method!__%
           _%type-t220929%_
           _%method220930%_
           _%sym220931%_
           _%rebind?220933%_))))
    (define gxc#optimizer-declare-method!
      (lambda _g225037_
        (let ((_g225038_ (let () (declare (not safe)) (##length _g225037_))))
          (cond ((let () (declare (not safe)) (##fx= _g225038_ 3))
                 (apply gxc#optimizer-declare-method!__0 _g225037_))
                ((let () (declare (not safe)) (##fx= _g225038_ 4))
                 (apply gxc#optimizer-declare-method!__% _g225037_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  gxc#optimizer-declare-method!
                  _g225037_))))))
    (define gxc#optimizer-lookup-type
      (lambda (_%sym220894%_)
        (let ((_%$e220896%_
               (let ((__tmp225039
                      (let ()
                        (declare (not safe))
                        (gxc#current-compile-path-type))))
                 (declare (not safe))
                 (agetq__0 _%sym220894%_ __tmp225039))))
          (if _%$e220896%_
              _%$e220896%_
              (let ((_%$e220904%_
                     (let ((_%$%ht220898220900%_
                            (let ()
                              (declare (not safe))
                              (gxc#current-compile-local-type))))
                       (if _%$%ht220898220900%_
                           (let ((_%ht220902%_ _%$%ht220898220900%_))
                             (declare (not safe))
                             (hash-get _%ht220902%_ _%sym220894%_))
                           '#f))))
                (if _%$e220904%_
                    _%$e220904%_
                    (let ((__tmp225040
                           (##structure-ref
                            (let ()
                              (declare (not safe))
                              (gxc#current-compile-optimizer-info))
                            '1
                            gxc#optimizer-info::t
                            '#f)))
                      (declare (not safe))
                      (hash-get __tmp225040 _%sym220894%_))))))))
    (define gxc#optimizer-resolve-type
      (lambda (_%sym220887%_)
        (let ((_%$%type220888220890%_
               (gxc#optimizer-lookup-type _%sym220887%_)))
          (if _%$%type220888220890%_
              (let ((_%type220892%_ _%$%type220888220890%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%type220892%_ 'gxc#!alias::t))
                    (gxc#optimizer-resolve-type
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref _%type220892%_ '1 '#f '#f)))
                    _%type220892%_))
              '#f))))
    (define gxc#optimizer-lookup-class
      (lambda (_%sym220883%_)
        (let ((_%table220885%_
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gxc#current-compile-optimizer-info))
                '2
                gxc#optimizer-info::t
                '#f)))
          (declare (not safe))
          (hash-get _%table220885%_ _%sym220883%_))))
    (define gxc#optimizer-resolve-class
      (lambda (_%where220868%_ _%sym220869%_)
        (let ((_%$e220872%_ (gxc#optimizer-lookup-class _%sym220869%_)))
          (if _%$e220872%_
              (let ((_%val220879%_ _%$e220872%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%val220879%_ 'gxc#!class::t))
                    _%val220879%_
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/compiler/optimize-base
                       'contract:
                       '(!class? val)
                       'value:
                       _%val220879%_)
                      '#!void)))
              (let ()
                (let ()
                  (declare (not safe))
                  (gxc#raise-compile-error
                   '"unknown class"
                   _%where220868%_
                   _%sym220869%_))
                '#!void)))))
    (define gxc#optimizer-lookup-class-name
      (lambda (_%klass220866%_)
        (let ((__tmp225041
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gxc#current-compile-optimizer-info))
                '2
                gxc#optimizer-info::t
                '#f)))
          (declare (not safe))
          (hash-get __tmp225041 _%klass220866%_))))
    (define gxc#optimizer-resolve-type-expression
      (lambda (_%where220816%_ _%expr220817%_)
        (let* ((_%$%expr220818220830%_ _%expr220817%_)
               (_%$%else220821220838%_
                (lambda ()
                  (gxc#optimizer-resolve-class
                   _%where220816%_
                   _%expr220817%_))))
          (let ((_%$%K220824220851%_
                 (lambda (_%base220849%_)
                   (gxc#nullable-type
                    (gxc#optimizer-resolve-type-expression
                     _%where220816%_
                     _%base220849%_))))
                (_%$%K220823220843%_ (lambda () '#f)))
            (let ((_%$%try-match220820220846%_
                   (lambda ()
                     (if (let ()
                           (declare (not safe))
                           (##eq? _%$%expr220818220830%_ '#f))
                         (_%$%K220823220843%_)
                         (_%$%else220821220838%_)))))
              (if (pair? _%$%expr220818220830%_)
                  (let ((_%$%tl220826220856%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%expr220818220830%_)))
                        (_%$%hd220825220854%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%expr220818220830%_))))
                    (if (let ()
                          (declare (not safe))
                          (##eq? _%$%hd220825220854%_ 'nullable))
                        (if (pair? _%$%tl220826220856%_)
                            (let ((_%$%tl220828220861%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%tl220826220856%_)))
                                  (_%$%hd220827220859%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%tl220826220856%_))))
                              (if (null? _%$%tl220828220861%_)
                                  (let ((_%base220864%_ _%$%hd220827220859%_))
                                    (_%$%K220824220851%_ _%base220864%_))
                                  (_%$%try-match220820220846%_)))
                            (_%$%try-match220820220846%_))
                        (_%$%try-match220820220846%_)))
                  (_%$%try-match220820220846%_)))))))
    (define gxc#optimizer-type-expression
      (lambda (_%type220806%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%type220806%_ 'gxc#!nullable-type::t))
            (let ((_%$%base220808220810%_
                   (gxc#optimizer-type-expression
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-ref _%type220806%_ '2 '#f '#f)))))
              (if _%$%base220808220810%_
                  (let ((_%base220812%_ _%$%base220808220810%_))
                    (cons 'nullable (cons _%base220812%_ '())))
                  '#f))
            (if (let ()
                  (declare (not safe))
                  (##structure-instance-of? _%type220806%_ 'gxc#!procedure::t))
                'procedure::t
                (gxc#optimizer-lookup-class-name _%type220806%_)))))
    (define gxc#type-expression->datum
      (lambda (_%stx220743%_)
        (let* ((_%__stx224875224876%_ _%stx220743%_)
               (_%$%g220746220760%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx224875224876%_)))))
          (let ((_%__kont224877224878%_
                 (lambda (_%$%g220748220788%_ _%$%g220749220789%_)
                   (cons 'nullable
                         (cons (gxc#type-expression->datum _%$%g220748220788%_)
                               '()))))
                (_%__kont224879224880%_
                 (lambda ()
                   (let ()
                     (declare (not safe))
                     (gxc#identifier-symbol _%stx220743%_)))))
            (let ((_%__match224894224895%_
                   (lambda (_%$%e220750220772%_
                            _%$%hd220751220775%_
                            _%$%tl220752220777%_
                            _%$%e220753220780%_
                            _%$%hd220754220783%_
                            _%$%tl220755220785%_)
                     (let ((_%$%g220748220788%_ _%$%hd220754220783%_)
                           (_%$%g220749220789%_ _%$%hd220751220775%_))
                       (if (eq? (let ()
                                  (declare (not safe))
                                  (gx#stx-e _%$%g220749220789%_))
                                'nullable)
                           (_%__kont224877224878%_
                            _%$%g220748220788%_
                            _%$%g220749220789%_)
                           (_%__kont224879224880%_))))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx224875224876%_))
                  (let ((_%$%e220750220772%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx224875224876%_))))
                    (let ((_%$%tl220752220777%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e220750220772%_)))
                          (_%$%hd220751220775%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e220750220772%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl220752220777%_))
                          (let ((_%$%e220753220780%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl220752220777%_))))
                            (let ((_%$%tl220755220785%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e220753220780%_)))
                                  (_%$%hd220754220783%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e220753220780%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl220755220785%_))
                                  (_%__match224894224895%_
                                   _%$%e220750220772%_
                                   _%$%hd220751220775%_
                                   _%$%tl220752220777%_
                                   _%$%e220753220780%_
                                   _%$%hd220754220783%_
                                   _%$%tl220755220785%_)
                                  (_%__kont224879224880%_))))
                          (_%__kont224879224880%_))))
                  (_%__kont224879224880%_)))))))
    (define gxc#map-type-expressions
      (lambda (_%proc220640%_ _%types220641%_)
        (let* ((_%__stx224897224898%_ _%types220641%_)
               (_%$%g220646220665%_
                (lambda ()
                  (let ()
                    (declare (not safe))
                    (gx#raise-syntax-error
                     '#f
                     '"Bad syntax; invalid match target"
                     _%__stx224897224898%_)))))
          (let ((_%__kont224899224900%_
                 (lambda (_%$%g220648220727%_ _%$%g220649220728%_)
                   (_%proc220640%_ _%types220641%_)))
                (_%__kont224901224902%_
                 (lambda (_%$%g220656220692%_ _%$%g220657220693%_)
                   (cons (_%proc220640%_ _%$%g220657220693%_)
                         (gxc#map-type-expressions
                          _%proc220640%_
                          _%$%g220656220692%_))))
                (_%__kont224903224904%_ (lambda () '()))
                (_%__kont224905224906%_
                 (lambda () (_%proc220640%_ _%types220641%_))))
            (let* ((_%$%g220644220679%_
                    (lambda ()
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-null? _%__stx224897224898%_))
                          (_%__kont224903224904%_)
                          (_%__kont224905224906%_))))
                   (_%__match224920224921%_
                    (lambda (_%$%e220650220711%_
                             _%$%hd220651220714%_
                             _%$%tl220652220716%_
                             _%$%e220653220719%_
                             _%$%hd220654220722%_
                             _%$%tl220655220724%_)
                      (let ((_%$%g220648220727%_ _%$%hd220654220722%_)
                            (_%$%g220649220728%_ _%$%hd220651220714%_))
                        (if (eq? (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%g220649220728%_))
                                 'nullable)
                            (_%__kont224899224900%_
                             _%$%g220648220727%_
                             _%$%g220649220728%_)
                            (_%__kont224901224902%_
                             _%$%tl220652220716%_
                             _%$%hd220651220714%_))))))
              (if (let ()
                    (declare (not safe))
                    (gx#stx-pair? _%__stx224897224898%_))
                  (let ((_%$%e220650220711%_
                         (let ()
                           (declare (not safe))
                           (gx#stx-e _%__stx224897224898%_))))
                    (let ((_%$%tl220652220716%_
                           (let ()
                             (declare (not safe))
                             (##cdr _%$%e220650220711%_)))
                          (_%$%hd220651220714%_
                           (let ()
                             (declare (not safe))
                             (##car _%$%e220650220711%_))))
                      (if (let ()
                            (declare (not safe))
                            (gx#stx-pair? _%$%tl220652220716%_))
                          (let ((_%$%e220653220719%_
                                 (let ()
                                   (declare (not safe))
                                   (gx#stx-e _%$%tl220652220716%_))))
                            (let ((_%$%tl220655220724%_
                                   (let ()
                                     (declare (not safe))
                                     (##cdr _%$%e220653220719%_)))
                                  (_%$%hd220654220722%_
                                   (let ()
                                     (declare (not safe))
                                     (##car _%$%e220653220719%_))))
                              (if (let ()
                                    (declare (not safe))
                                    (gx#stx-null? _%$%tl220655220724%_))
                                  (_%__match224920224921%_
                                   _%$%e220650220711%_
                                   _%$%hd220651220714%_
                                   _%$%tl220652220716%_
                                   _%$%e220653220719%_
                                   _%$%hd220654220722%_
                                   _%$%tl220655220724%_)
                                  (_%__kont224901224902%_
                                   _%$%tl220652220716%_
                                   _%$%hd220651220714%_))))
                          (_%__kont224901224902%_
                           _%$%tl220652220716%_
                           _%$%hd220651220714%_))))
                  (let () (declare (not safe)) (_%$%g220644220679%_))))))))
    (define gxc#optimizer-lookup-method
      (lambda (_%type-t220637%_ _%method220638%_)
        (gxc#!class-lookup-method
         (gxc#optimizer-resolve-class 'lookup-method _%type-t220637%_)
         _%method220638%_)))
    (define gxc#optimizer-top-level-method?
      (lambda (_%sym220635%_)
        (let ((__tmp225042
               (##structure-ref
                (let ()
                  (declare (not safe))
                  (gxc#current-compile-optimizer-info))
                '4
                gxc#optimizer-info::t
                '#f)))
          (declare (not safe))
          (hash-get __tmp225042 _%sym220635%_))))
    (define gxc#optimizer-current-types
      (lambda ()
        (letrec ((_%type-e220109%_
                  (lambda (_%t220575%_)
                    (if (symbol? _%t220575%_)
                        (_%type-e220109%_
                         (gxc#optimizer-lookup-type _%t220575%_))
                        (if (let ()
                              (declare (not safe))
                              (##structure-instance-of?
                               _%t220575%_
                               'gxc#!lambda::t))
                            (let* ((_%t220579%_ _%t220575%_)
                                   (_%t220583%_ _%t220579%_))
                              (_%__lambda-type220235%_ _%t220583%_))
                            (if (let ()
                                  (declare (not safe))
                                  (##structure-instance-of?
                                   _%t220575%_
                                   'gxc#!kw-lambda::t))
                                (let* ((_%t220595%_ _%t220575%_)
                                       (_%t220599%_ _%t220595%_))
                                  (_%__kw-lambda-type220358%_ _%t220599%_))
                                (if (let ()
                                      (declare (not safe))
                                      (##structure-instance-of?
                                       _%t220575%_
                                       'gxc#!kw-lambda-primary::t))
                                    (let* ((_%t220610%_ _%t220575%_)
                                           (_%t220614%_ _%t220610%_))
                                      (_%__kw-lambda-primary-type220481%_
                                       _%t220614%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##structure-instance-of?
                                           _%t220575%_
                                           'gxc#!procedure::t))
                                        (cons 'procedure
                                              (let ((_%t220625%_ _%t220575%_))
                                                (if (let ()
                                                      (declare (not safe))
                                                      (##unchecked-structure-ref
                                                       _%t220625%_
                                                       '2
                                                       '#f
                                                       '#f))
                                                    (##direct-structure-ref
                                                     (let ()
                                                       (declare (not safe))
                                                       (##unchecked-structure-ref
                                                        _%t220625%_
                                                        '2
                                                        '#f
                                                        '#f))
                                                     '1
                                                     gxc#!signature::t
                                                     '#f)
                                                    '#f)))
                                        (if (let ()
                                              (declare (not safe))
                                              (##structure-instance-of?
                                               _%t220575%_
                                               'gxc#!nullable-type::t))
                                            (gxc#optimizer-type-expression
                                             _%t220575%_)
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##structure-instance-of?
                                                   _%t220575%_
                                                   'gxc#!type::t))
                                                (let ()
                                                  (declare (not safe))
                                                  (##unchecked-structure-ref
                                                   _%t220575%_
                                                   '1
                                                   '#f
                                                   '#f))
                                                '#f)))))))))
                 (_%__lambda-type220235%_
                  (lambda (_%t220563%_)
                    (let ((_%t220566%_ _%t220563%_))
                      (if (let ()
                            (declare (not safe))
                            (##unchecked-structure-ref _%t220566%_ '4 '#f '#f))
                          (_%type-e220109%_
                           (let ()
                             (declare (not safe))
                             (##unchecked-structure-ref
                              _%t220566%_
                              '4
                              '#f
                              '#f)))
                          (cons 'procedure
                                (if (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-ref
                                       _%t220566%_
                                       '2
                                       '#f
                                       '#f))
                                    (##direct-structure-ref
                                     (let ()
                                       (declare (not safe))
                                       (##unchecked-structure-ref
                                        _%t220566%_
                                        '2
                                        '#f
                                        '#f))
                                     '1
                                     gxc#!signature::t
                                     '#f)
                                    '#f))))))
                 (_%lambda-type220236%_
                  (lambda (_%t220551%_)
                    (let ((_%t220554%_ _%t220551%_))
                      (_%__lambda-type220235%_ _%t220554%_))))
                 (_%__kw-lambda-type220358%_
                  (lambda (_%t220539%_)
                    (let ((_%t220542%_ _%t220539%_))
                      (_%type-e220109%_
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%t220542%_
                          '4
                          '#f
                          '#f))))))
                 (_%kw-lambda-type220359%_
                  (lambda (_%t220527%_)
                    (let ((_%t220530%_ _%t220527%_))
                      (_%__kw-lambda-type220358%_ _%t220530%_))))
                 (_%__kw-lambda-primary-type220481%_
                  (lambda (_%t220515%_)
                    (let ((_%t220518%_ _%t220515%_))
                      (_%type-e220109%_
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%t220518%_
                          '4
                          '#f
                          '#f))))))
                 (_%kw-lambda-primary-type220482%_
                  (lambda (_%t220503%_)
                    (let ((_%t220506%_ _%t220503%_))
                      (_%__kw-lambda-primary-type220481%_ _%t220506%_)))))
          (let* ((_%ht1220484%_
                  (##structure-ref
                   (let ()
                     (declare (not safe))
                     (gxc#current-compile-optimizer-info))
                   '1
                   gxc#optimizer-info::t
                   '#f))
                 (_%ht2220486%_
                  (let ()
                    (declare (not safe))
                    (gxc#current-compile-local-type)))
                 (_%result220488%_
                  (if _%ht1220484%_
                      (let () (declare (not safe)) (hash->list _%ht1220484%_))
                      '()))
                 (_%result220490%_
                  (if _%ht2220486%_
                      (let ((__tmp225043
                             (let ()
                               (declare (not safe))
                               (hash->list _%ht2220486%_))))
                        (declare (not safe))
                        (foldl__0 cons _%result220488%_ __tmp225043))
                      _%result220488%_)))
            (for-each
             (lambda (_%p220493%_)
               (let* ((_%t220495%_ (cdr _%p220493%_))
                      (_%tr220497%_ (_%type-e220109%_ _%t220495%_)))
                 (set-cdr! _%p220493%_ _%tr220497%_)))
             _%result220490%_)
            (list-sort
             (lambda (_%a220500%_ _%b220501%_)
               (let ((__tmp225045 (symbol->string (car _%a220500%_)))
                     (__tmp225044 (symbol->string (car _%b220501%_))))
                 (declare (not safe))
                 (##string<? __tmp225045 __tmp225044)))
             _%result220490%_)))))))
