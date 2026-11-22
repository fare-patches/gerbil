(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/interface::timestamp 1795039814)
  (begin
    (define CastError::t
      (let ((__tmp154626 (list Error::t)))
        (declare (not safe))
        (make-class-type
         'CastError::t
         'CastError
         __tmp154626
         '()
         '()
         ':init!)))
    (define CastError?
      (let () (declare (not safe)) (__make-class-predicate CastError::t)))
    (define make-CastError
      (lambda _%$args154540%_
        (apply make-instance CastError::t _%$args154540%_)))
    (define CastError-message
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor CastError::t 'message)))
    (define CastError-irritants
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor CastError::t 'irritants)))
    (define CastError-where
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor CastError::t 'where)))
    (define CastError-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor CastError::t 'continuation)))
    (define CastError-message-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator CastError::t 'message)))
    (define CastError-irritants-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator CastError::t 'irritants)))
    (define CastError-where-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator CastError::t 'where)))
    (define CastError-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator CastError::t 'continuation)))
    (define &CastError-message
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor CastError::t 'message)))
    (define &CastError-irritants
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor CastError::t 'irritants)))
    (define &CastError-where
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor CastError::t 'where)))
    (define &CastError-continuation
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor CastError::t 'continuation)))
    (define &CastError-message-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator CastError::t 'message)))
    (define &CastError-irritants-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator CastError::t 'irritants)))
    (define &CastError-where-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator CastError::t 'where)))
    (define &CastError-continuation-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator CastError::t 'continuation)))
    (define CastError:::init! Error:::init!)
    (let ()
      (declare (not safe))
      (__bind-method!__% CastError::t ':init! CastError:::init! '#f))
    (define raise-cast-error
      (lambda (_%where154414%_ _%message154415%_ . _%irritants154416%_)
        (let ((__tmp154627
               (let ((__obj154621
                      (let ()
                        (declare (not safe))
                        (##structure CastError::t '#f '#f '#f '#f))))
                 (let ()
                   (declare (not safe))
                   (CastError:::init!
                    __obj154621
                    _%message154415%_
                    'where:
                    _%where154414%_
                    'irritants:
                    _%irritants154416%_))
                 __obj154621)))
          (declare (not safe))
          (raise __tmp154627))))
    (define interface-cast-error? CastError?)
    (define interface-instance::t
      (let ((__tmp154629 (list))
            (__tmp154628 (cons (cons 'struct: '#t) '((print: object)))))
        (declare (not safe))
        (make-class-type
         'interface-instance::t
         'interface-instance
         __tmp154629
         '(object)
         __tmp154628
         '#f)))
    (define interface-instance?
      (let ()
        (declare (not safe))
        (__make-class-predicate interface-instance::t)))
    (define make-interface-instance
      (lambda _%$args154411%_
        (apply make-instance interface-instance::t _%$args154411%_)))
    (define interface-instance-object
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor interface-instance::t 'object)))
    (define interface-instance-object-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator interface-instance::t 'object)))
    (define &interface-instance-object
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor interface-instance::t 'object)))
    (define &interface-instance-object-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator interface-instance::t 'object)))
    (define interface-descriptor::t
      (let ((__tmp154631 (list))
            (__tmp154630
             (cons (cons 'struct: '#t)
                   (cons (cons 'final: '#t) '((print: type index))))))
        (declare (not safe))
        (make-class-type
         'interface-descriptor::t
         'interface-descriptor
         __tmp154631
         '(type methods index)
         __tmp154630
         ':init!)))
    (define interface-descriptor?
      (let ()
        (declare (not safe))
        (__make-class-predicate interface-descriptor::t)))
    (define make-interface-descriptor
      (lambda _%$args154408%_
        (apply make-instance interface-descriptor::t _%$args154408%_)))
    (define interface-descriptor-type
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor interface-descriptor::t 'type)))
    (define interface-descriptor-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor interface-descriptor::t 'methods)))
    (define interface-descriptor-index
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor interface-descriptor::t 'index)))
    (define interface-descriptor-type-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator interface-descriptor::t 'type)))
    (define interface-descriptor-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator interface-descriptor::t 'methods)))
    (define interface-descriptor-index-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator interface-descriptor::t 'index)))
    (define &interface-descriptor-type
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor interface-descriptor::t 'type)))
    (define &interface-descriptor-methods
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor
         interface-descriptor::t
         'methods)))
    (define &interface-descriptor-index
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor interface-descriptor::t 'index)))
    (define &interface-descriptor-type-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator interface-descriptor::t 'type)))
    (define &interface-descriptor-methods-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator
         interface-descriptor::t
         'methods)))
    (define &interface-descriptor-index-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator interface-descriptor::t 'index)))
    (define __next-interface-index '0)
    (define __next-interface-index-lock (vector '0 '#f))
    (define __get-next-interface-index
      (lambda ()
        (let ()
          (declare (not interrupts-enabled))
          (let _%again154386%_ ((_%spin154389%_ '0))
            (if (let ((__tmp154632
                       (let ()
                         (declare (not safe))
                         (##vector-cas!
                          __next-interface-index-lock
                          '0
                          '1
                          '0))))
                  (declare (not safe))
                  (##fx= __tmp154632 '0))
                (let ((__tmp154633 (current-thread)))
                  (declare (not safe))
                  (##vector-set! __next-interface-index-lock '1 __tmp154633))
                (if (let () (declare (not safe)) (##fx< _%spin154389%_ '10))
                    (let ()
                      (let () (declare (not safe)) (##thread-yield!))
                      (_%again154386%_
                       (let ()
                         (declare (not safe))
                         (##fx+ _%spin154389%_ '1))))
                    (let ((_%owner154395%_
                           (let ()
                             (declare (not safe))
                             (##vector-ref __next-interface-index-lock '1))))
                      (if (eq? _%owner154395%_ (macro-current-thread))
                          (let ()
                            (declare (not safe))
                            (##thread-deadlock-action!))
                          (if (macro-thread-end-condvar _%owner154395%_)
                              (let ()
                                (let () (declare (not safe)) (##thread-yield!))
                                (_%again154386%_ '0))
                              (let ()
                                (declare (not safe))
                                (##thread-deadlock-action!)))))))))
        (let ((_%$r154403%_
               (let ((_%index154401%_ __next-interface-index))
                 (set! __next-interface-index
                       (let ()
                         (declare (not safe))
                         (##fx+ _%index154401%_ '1)))
                 _%index154401%_)))
          (let ()
            (declare (not interrupts-enabled))
            (begin
              (let ()
                (declare (not safe))
                (##vector-set! __next-interface-index-lock '1 '#f))
              (let ()
                (declare (not safe))
                (##vector-cas! __next-interface-index-lock '0 '0 '1))))
          _%$r154403%_)))
    (define interface-descriptor:::init!
      (lambda (_%self154367%_ _%type154368%_ _%methods154369%_)
        (let ((_%self154372%_ _%self154367%_))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self154372%_
             _%type154368%_
             '1
             '#f
             '#f))
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%self154372%_
             _%methods154369%_
             '2
             '#f
             '#f))
          (let ((__tmp154634 (__get-next-interface-index)))
            (declare (not safe))
            (##unchecked-structure-set!
             _%self154372%_
             __tmp154634
             '3
             '#f
             '#f)))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       interface-descriptor::t
       ':init!
       interface-descriptor:::init!
       '#f))
    (define prototype-table::t
      (let ((__tmp154636 (list))
            (__tmp154635
             (cons (cons 'struct: '#t) (cons (cons 'final: '#t) '()))))
        (declare (not safe))
        (make-class-type
         'prototype-table::t
         'prototype-table
         __tmp154636
         '(lock table)
         __tmp154635
         ':init!)))
    (define prototype-table?
      (let ()
        (declare (not safe))
        (__make-class-predicate prototype-table::t)))
    (define make-prototype-table
      (lambda _%$args154242%_
        (apply make-instance prototype-table::t _%$args154242%_)))
    (define prototype-table-lock
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor prototype-table::t 'lock)))
    (define prototype-table-table
      (let ()
        (declare (not safe))
        (__make-class-slot-accessor prototype-table::t 'table)))
    (define prototype-table-lock-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator prototype-table::t 'lock)))
    (define prototype-table-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-mutator prototype-table::t 'table)))
    (define &prototype-table-lock
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor prototype-table::t 'lock)))
    (define &prototype-table-table
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-accessor prototype-table::t 'table)))
    (define &prototype-table-lock-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator prototype-table::t 'lock)))
    (define &prototype-table-table-set!
      (let ()
        (declare (not safe))
        (__make-class-slot-unchecked-mutator prototype-table::t 'table)))
    (define prototype-table:::init!
      (lambda (_%self154228%_)
        (let ((_%self154231%_ _%self154228%_))
          (let ((__tmp154637 (vector '0 '#f)))
            (declare (not safe))
            (##unchecked-structure-set! _%self154231%_ __tmp154637 '1 '#f '#f))
          (let ((__tmp154638
                 (let ()
                   (declare (not safe))
                   (##make-vector __next-interface-index '#f))))
            (declare (not safe))
            (##unchecked-structure-set!
             _%self154231%_
             __tmp154638
             '2
             '#f
             '#f)))))
    (let ()
      (declare (not safe))
      (__bind-method!__%
       prototype-table::t
       ':init!
       prototype-table:::init!
       '#f))
    (define ____prototype-table-get
      (lambda (_%prototable154081%_ _%descriptor154082%_)
        (let* ((_%prototable154085%_ _%prototable154081%_)
               (_%descriptor154093%_ _%descriptor154082%_))
          (declare (not safe) (not interrupts-enabled))
          (let ((_%tab154103%_
                 (##unchecked-structure-ref _%prototable154085%_ '2 '#f '#f))
                (_%index154104%_
                 (##unchecked-structure-ref _%descriptor154093%_ '3 '#f '#f)))
            (if (##fx< _%index154104%_ (vector-length _%tab154103%_))
                (vector-ref _%tab154103%_ _%index154104%_)
                '#f)))))
    (define __prototype-table-get
      (lambda (_%prototable154060%_ _%descriptor154061%_)
        (let* ((_%prototable154064%_ _%prototable154060%_)
               (_%descriptor154072%_ _%descriptor154061%_))
          (____prototype-table-get
           _%prototable154064%_
           _%descriptor154072%_))))
    (define ____prototype-table-set!
      (lambda (_%prototable154006%_ _%descriptor154007%_ _%prototype154008%_)
        (let* ((_%prototable154011%_ _%prototable154006%_)
               (_%descriptor154019%_ _%descriptor154007%_))
          (declare (not safe))
          (let ((_%lock154029%_
                 (##unchecked-structure-ref _%prototable154011%_ '1 '#f '#f))
                (_%index154030%_
                 (##unchecked-structure-ref _%descriptor154019%_ '3 '#f '#f)))
            (let ()
              (declare (not interrupts-enabled))
              (let _%again154034%_ ((_%spin154037%_ '0))
                (if (##fx= (##vector-cas! _%lock154029%_ '0 '1 '0) '0)
                    (##vector-set! _%lock154029%_ '1 (current-thread))
                    (if (##fx< _%spin154037%_ '10)
                        (let ()
                          (##thread-yield!)
                          (_%again154034%_ (##fx+ _%spin154037%_ '1)))
                        (let ((_%owner154043%_
                               (##vector-ref _%lock154029%_ '1)))
                          (if (eq? _%owner154043%_ (macro-current-thread))
                              (##thread-deadlock-action!)
                              (if (macro-thread-end-condvar _%owner154043%_)
                                  (let ()
                                    (##thread-yield!)
                                    (_%again154034%_ '0))
                                  (##thread-deadlock-action!))))))))
            (let ((_%$r154055%_
                   (let ((_%tab154049%_
                          (##unchecked-structure-ref
                           _%prototable154011%_
                           '2
                           '#f
                           '#f)))
                     (if (##fx< _%index154030%_ (vector-length _%tab154049%_))
                         (vector-set!
                          _%tab154049%_
                          _%index154030%_
                          _%prototype154008%_)
                         (let ((_%new-size154051%_ __next-interface-index))
                           (if (##fx< _%index154030%_ _%new-size154051%_)
                               (let ((_%new-tab154053%_
                                      (##make-vector _%new-size154051%_ '#f)))
                                 (subvector-move!
                                  _%tab154049%_
                                  '0
                                  (vector-length _%tab154049%_)
                                  _%new-tab154053%_
                                  '0)
                                 (vector-set!
                                  _%new-tab154053%_
                                  _%index154030%_
                                  _%prototype154008%_)
                                 (##unchecked-structure-set!
                                  _%prototable154011%_
                                  _%new-tab154053%_
                                  '2
                                  '#f
                                  '#f))
                               (error '"interface index out of range"
                                      'interface:
                                      _%descriptor154019%_
                                      'index:
                                      _%index154030%_
                                      'max-index:
                                      _%new-size154051%_)))))))
              (let ()
                (declare (not interrupts-enabled))
                (begin
                  (##vector-set! _%lock154029%_ '1 '#f)
                  (##vector-cas! _%lock154029%_ '0 '0 '1)))
              _%$r154055%_)))))
    (define __prototype-table-set!
      (lambda (_%prototable153984%_ _%descriptor153985%_ _%prototype153986%_)
        (let* ((_%prototable153989%_ _%prototable153984%_)
               (_%descriptor153997%_ _%descriptor153985%_))
          (____prototype-table-set!
           _%prototable153989%_
           _%descriptor153997%_
           _%prototype153986%_))))
    (define interface-subclass?
      (lambda (_%klass153977%_)
        (let ((_%$%super153978153980%_
               (let () (declare (not safe)) (##type-super _%klass153977%_))))
          (if _%$%super153978153980%_
              (let ((_%super153982%_ _%$%super153978153980%_))
                (eq? (let () (declare (not safe)) (##type-id _%super153982%_))
                     (let ()
                       (declare (not safe))
                       (##type-id interface-instance::t))))
              '#f))))
    (define class-type-interface-table
      (lambda (_%klass153969%_)
        (let ((_%$e153971%_
               (let ()
                 (declare (not safe))
                 (##unchecked-structure-ref _%klass153969%_ '13 '#f '#f))))
          (if _%$e153971%_
              _%$e153971%_
              (let ((_%tab153975%_
                     (let ((__obj154625
                            (let ()
                              (declare (not safe))
                              (##structure prototype-table::t '#f '#f))))
                       (prototype-table:::init! __obj154625)
                       __obj154625)))
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%klass153969%_
                   _%tab153975%_
                   '13
                   '#f
                   '#f))
                _%tab153975%_)))))
    (define create-prototype
      (lambda (_%descriptor153652%_ _%klass153653%_ _%obj-klass153654%_)
        (let ((_%method-table153672%_
               (let ((_%klass153656%_ _%obj-klass153654%_))
                 (if (let ()
                       (declare (not safe))
                       (##structure-instance-of? _%klass153656%_ 'class))
                     (let ((_%klass153661%_ _%klass153656%_))
                       (declare (not safe))
                       (__specialize-class _%klass153661%_))
                     (begin
                       (raise-contract-violation-error
                        '"contract violation"
                        'context:
                        'gerbil/runtime/interface
                        'contract:
                        'class-type?
                        'value:
                        _%klass153656%_)
                       '#!void)))))
          (let _%loop153675%_ ((_%rest153678%_
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   _%descriptor153652%_
                                   '2
                                   '#f
                                   '#f)))
                               (_%count153680%_ '0)
                               (_%methods153682%_ '()))
            (let* ((_%$%rest153684153692%_ _%rest153678%_)
                   (_%$%else153686153819%_
                    (lambda ()
                      (let ((_%prototype153735%_
                             (let* ((_%klass153700%_ _%klass153653%_)
                                    (_%k153703%_
                                     (let ()
                                       (declare (not safe))
                                       (##fx+ _%count153680%_ '2))))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-instance-of?
                                      _%klass153700%_
                                      'class))
                                   (let* ((_%klass153708%_ _%klass153700%_)
                                          (_%k153725%_ _%k153703%_))
                                     (declare (not safe))
                                     (__make-object
                                      _%klass153708%_
                                      _%k153725%_))
                                   (begin
                                     (raise-contract-violation-error
                                      '"contract violation"
                                      'context:
                                      'gerbil/runtime/interface
                                      'contract:
                                      'class-type?
                                      'value:
                                      _%klass153700%_)
                                     '#!void)))))
                        (let _%loop153738%_ ((_%rest153740%_ _%methods153682%_)
                                             (_%off153741%_
                                              (let ()
                                                (declare (not safe))
                                                (##fx+ _%count153680%_ '1))))
                          (let* ((_%$%rest153743153751%_ _%rest153740%_)
                                 (_%$%else153745153800%_
                                  (lambda ()
                                    (let ((_%tab153759%_
                                           (class-type-interface-table
                                            _%obj-klass153654%_)))
                                      (let* ((_%prototable153762%_
                                              _%tab153759%_)
                                             (_%descriptor153765%_
                                              _%descriptor153652%_)
                                             (_%prototype153768%_
                                              _%prototype153735%_)
                                             (_%prototable153772%_
                                              _%prototable153762%_)
                                             (_%descriptor153789%_
                                              _%descriptor153765%_))
                                        (____prototype-table-set!
                                         _%prototable153772%_
                                         _%descriptor153789%_
                                         _%prototype153768%_))
                                      _%prototype153735%_)))
                                 (_%$%K153747153807%_
                                  (lambda (_%rest153803%_ _%method153804%_)
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-set!
                                       _%prototype153735%_
                                       _%method153804%_
                                       _%off153741%_
                                       _%klass153653%_
                                       '#f))
                                    (_%loop153738%_
                                     _%rest153803%_
                                     (let ()
                                       (declare (not safe))
                                       (##fx- _%off153741%_ '1))))))
                            (if (pair? _%$%rest153743153751%_)
                                (let ((_%$%hd153748153810%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%rest153743153751%_)))
                                      (_%$%tl153749153812%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%rest153743153751%_))))
                                  (let* ((_%method153815%_
                                          _%$%hd153748153810%_)
                                         (_%rest153817%_ _%$%tl153749153812%_))
                                    (_%$%K153747153807%_
                                     _%rest153817%_
                                     _%method153815%_)))
                                (_%$%else153745153800%_)))))))
                   (_%$%K153688153957%_
                    (lambda (_%rest153822%_ _%method-spec153823%_)
                      (if (pair? _%method-spec153823%_)
                          (let _%loop-inner153827%_ ((_%methods-rest153830%_
                                                      _%method-spec153823%_))
                            (let* ((_%$%methods-rest153832153840%_
                                    _%methods-rest153830%_)
                                   (_%$%else153834153890%_
                                    (lambda ()
                                      (let ((_%tab153848%_
                                             (class-type-interface-table
                                              _%obj-klass153654%_)))
                                        (let* ((_%prototable153850%_
                                                _%tab153848%_)
                                               (_%descriptor153853%_
                                                _%descriptor153652%_)
                                               (_%prototype153856%_ '#!void)
                                               (_%prototable153860%_
                                                _%prototable153850%_)
                                               (_%descriptor153879%_
                                                _%descriptor153853%_))
                                          (____prototype-table-set!
                                           _%prototable153860%_
                                           _%descriptor153879%_
                                           _%prototype153856%_))
                                        (let ()
                                          (raise-cast-error
                                           'create-prototype
                                           '"cannot create interface prototype; missing method"
                                           'interface:
                                           _%descriptor153652%_
                                           'class:
                                           _%obj-klass153654%_
                                           'method:
                                           _%method-spec153823%_)
                                          '#!void))))
                                   (_%$%K153836153903%_
                                    (lambda (_%methods-rest153893%_
                                             _%method-name153894%_)
                                      (let ((_%$e153897%_
                                             (let ()
                                               (declare (not safe))
                                               (symbolic-table-ref
                                                _%method-table153672%_
                                                _%method-name153894%_
                                                '#f))))
                                        (if _%$e153897%_
                                            (_%loop153675%_
                                             _%rest153822%_
                                             (let ()
                                               (declare (not safe))
                                               (##fx+ _%count153680%_ '1))
                                             (cons _%$e153897%_
                                                   _%methods153682%_))
                                            (_%loop-inner153827%_
                                             _%methods-rest153893%_))))))
                              (if (pair? _%$%methods-rest153832153840%_)
                                  (let ((_%$%hd153837153906%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%methods-rest153832153840%_)))
                                        (_%$%tl153838153908%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%methods-rest153832153840%_))))
                                    (let* ((_%method-name153911%_
                                            _%$%hd153837153906%_)
                                           (_%methods-rest153913%_
                                            _%$%tl153838153908%_))
                                      (_%$%K153836153903%_
                                       _%methods-rest153913%_
                                       _%method-name153911%_)))
                                  (_%$%else153834153890%_))))
                          (let ((_%$e153915%_
                                 (let ()
                                   (declare (not safe))
                                   (symbolic-table-ref
                                    _%method-table153672%_
                                    _%method-spec153823%_
                                    '#f))))
                            (if _%$e153915%_
                                (_%loop153675%_
                                 _%rest153822%_
                                 (let ()
                                   (declare (not safe))
                                   (##fx+ _%count153680%_ '1))
                                 (cons _%$e153915%_ _%methods153682%_))
                                (let ((_%tab153921%_
                                       (class-type-interface-table
                                        _%obj-klass153654%_)))
                                  (let* ((_%prototable153923%_ _%tab153921%_)
                                         (_%descriptor153926%_
                                          _%descriptor153652%_)
                                         (_%prototype153929%_ '#!void)
                                         (_%prototable153933%_
                                          _%prototable153923%_)
                                         (_%descriptor153946%_
                                          _%descriptor153926%_))
                                    (____prototype-table-set!
                                     _%prototable153933%_
                                     _%descriptor153946%_
                                     _%prototype153929%_))
                                  (let ()
                                    (raise-cast-error
                                     'create-prototype
                                     '"cannot create interface prototype; missing method"
                                     'interface:
                                     _%descriptor153652%_
                                     'class:
                                     _%obj-klass153654%_
                                     'method:
                                     _%method-spec153823%_)
                                    '#!void))))))))
              (if (pair? _%$%rest153684153692%_)
                  (let ((_%$%hd153689153960%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest153684153692%_)))
                        (_%$%tl153690153962%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest153684153692%_))))
                    (let* ((_%method-spec153965%_ _%$%hd153689153960%_)
                           (_%rest153967%_ _%$%tl153690153962%_))
                      (_%$%K153688153957%_
                       _%rest153967%_
                       _%method-spec153965%_)))
                  (_%$%else153686153819%_)))))))
    (define try-create-prototype
      (lambda (_%descriptor153335%_ _%klass153336%_ _%obj-klass153337%_)
        (let ((_%method-table153355%_
               (let ((_%klass153339%_ _%obj-klass153337%_))
                 (if (let ()
                       (declare (not safe))
                       (##structure-instance-of? _%klass153339%_ 'class))
                     (let ((_%klass153344%_ _%klass153339%_))
                       (declare (not safe))
                       (__specialize-class _%klass153344%_))
                     (begin
                       (raise-contract-violation-error
                        '"contract violation"
                        'context:
                        'gerbil/runtime/interface
                        'contract:
                        'class-type?
                        'value:
                        _%klass153339%_)
                       '#!void)))))
          (let _%loop153358%_ ((_%rest153361%_
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   _%descriptor153335%_
                                   '2
                                   '#f
                                   '#f)))
                               (_%count153363%_ '0)
                               (_%methods153365%_ '()))
            (let* ((_%$%rest153367153375%_ _%rest153361%_)
                   (_%$%else153369153502%_
                    (lambda ()
                      (let ((_%prototype153418%_
                             (let* ((_%klass153383%_ _%klass153336%_)
                                    (_%k153386%_
                                     (let ()
                                       (declare (not safe))
                                       (##fx+ _%count153363%_ '2))))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-instance-of?
                                      _%klass153383%_
                                      'class))
                                   (let* ((_%klass153391%_ _%klass153383%_)
                                          (_%k153408%_ _%k153386%_))
                                     (declare (not safe))
                                     (__make-object
                                      _%klass153391%_
                                      _%k153408%_))
                                   (begin
                                     (raise-contract-violation-error
                                      '"contract violation"
                                      'context:
                                      'gerbil/runtime/interface
                                      'contract:
                                      'class-type?
                                      'value:
                                      _%klass153383%_)
                                     '#!void)))))
                        (let _%loop153421%_ ((_%rest153423%_ _%methods153365%_)
                                             (_%off153424%_
                                              (let ()
                                                (declare (not safe))
                                                (##fx+ _%count153363%_ '1))))
                          (let* ((_%$%rest153426153434%_ _%rest153423%_)
                                 (_%$%else153428153483%_
                                  (lambda ()
                                    (let ((_%tab153442%_
                                           (class-type-interface-table
                                            _%obj-klass153337%_)))
                                      (let* ((_%prototable153445%_
                                              _%tab153442%_)
                                             (_%descriptor153448%_
                                              _%descriptor153335%_)
                                             (_%prototype153451%_
                                              _%prototype153418%_)
                                             (_%prototable153455%_
                                              _%prototable153445%_)
                                             (_%descriptor153472%_
                                              _%descriptor153448%_))
                                        (____prototype-table-set!
                                         _%prototable153455%_
                                         _%descriptor153472%_
                                         _%prototype153451%_))
                                      _%prototype153418%_)))
                                 (_%$%K153430153490%_
                                  (lambda (_%rest153486%_ _%method153487%_)
                                    (let ()
                                      (declare (not safe))
                                      (##unchecked-structure-set!
                                       _%prototype153418%_
                                       _%method153487%_
                                       _%off153424%_
                                       _%klass153336%_
                                       '#f))
                                    (_%loop153421%_
                                     _%rest153486%_
                                     (let ()
                                       (declare (not safe))
                                       (##fx- _%off153424%_ '1))))))
                            (if (pair? _%$%rest153426153434%_)
                                (let ((_%$%hd153431153493%_
                                       (let ()
                                         (declare (not safe))
                                         (##car _%$%rest153426153434%_)))
                                      (_%$%tl153432153495%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%rest153426153434%_))))
                                  (let* ((_%method153498%_
                                          _%$%hd153431153493%_)
                                         (_%rest153500%_ _%$%tl153432153495%_))
                                    (_%$%K153430153490%_
                                     _%rest153500%_
                                     _%method153498%_)))
                                (_%$%else153428153483%_)))))))
                   (_%$%K153371153640%_
                    (lambda (_%rest153505%_ _%method-spec153506%_)
                      (if (pair? _%method-spec153506%_)
                          (let _%loop-inner153510%_ ((_%methods-rest153513%_
                                                      _%method-spec153506%_))
                            (let* ((_%$%methods-rest153515153523%_
                                    _%methods-rest153513%_)
                                   (_%$%else153517153573%_
                                    (lambda ()
                                      (let ((_%tab153531%_
                                             (class-type-interface-table
                                              _%obj-klass153337%_)))
                                        (let* ((_%prototable153533%_
                                                _%tab153531%_)
                                               (_%descriptor153536%_
                                                _%descriptor153335%_)
                                               (_%prototype153539%_ '#!void)
                                               (_%prototable153543%_
                                                _%prototable153533%_)
                                               (_%descriptor153562%_
                                                _%descriptor153536%_))
                                          (____prototype-table-set!
                                           _%prototable153543%_
                                           _%descriptor153562%_
                                           _%prototype153539%_))
                                        '#f)))
                                   (_%$%K153519153586%_
                                    (lambda (_%methods-rest153576%_
                                             _%method-name153577%_)
                                      (let ((_%$e153580%_
                                             (let ()
                                               (declare (not safe))
                                               (symbolic-table-ref
                                                _%method-table153355%_
                                                _%method-name153577%_
                                                '#f))))
                                        (if _%$e153580%_
                                            (_%loop153358%_
                                             _%rest153505%_
                                             (let ()
                                               (declare (not safe))
                                               (##fx+ _%count153363%_ '1))
                                             (cons _%$e153580%_
                                                   _%methods153365%_))
                                            (_%loop-inner153510%_
                                             _%methods-rest153576%_))))))
                              (if (pair? _%$%methods-rest153515153523%_)
                                  (let ((_%$%hd153520153589%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%methods-rest153515153523%_)))
                                        (_%$%tl153521153591%_
                                         (let ()
                                           (declare (not safe))
                                           (##cdr _%$%methods-rest153515153523%_))))
                                    (let* ((_%method-name153594%_
                                            _%$%hd153520153589%_)
                                           (_%methods-rest153596%_
                                            _%$%tl153521153591%_))
                                      (_%$%K153519153586%_
                                       _%methods-rest153596%_
                                       _%method-name153594%_)))
                                  (_%$%else153517153573%_))))
                          (let ((_%$e153598%_
                                 (let ()
                                   (declare (not safe))
                                   (symbolic-table-ref
                                    _%method-table153355%_
                                    _%method-spec153506%_
                                    '#f))))
                            (if _%$e153598%_
                                (_%loop153358%_
                                 _%rest153505%_
                                 (let ()
                                   (declare (not safe))
                                   (##fx+ _%count153363%_ '1))
                                 (cons _%$e153598%_ _%methods153365%_))
                                (let ((_%tab153604%_
                                       (class-type-interface-table
                                        _%obj-klass153337%_)))
                                  (let* ((_%prototable153606%_ _%tab153604%_)
                                         (_%descriptor153609%_
                                          _%descriptor153335%_)
                                         (_%prototype153612%_ '#!void)
                                         (_%prototable153616%_
                                          _%prototable153606%_)
                                         (_%descriptor153629%_
                                          _%descriptor153609%_))
                                    (____prototype-table-set!
                                     _%prototable153616%_
                                     _%descriptor153629%_
                                     _%prototype153612%_))
                                  '#f)))))))
              (if (pair? _%$%rest153367153375%_)
                  (let ((_%$%hd153372153643%_
                         (let ()
                           (declare (not safe))
                           (##car _%$%rest153367153375%_)))
                        (_%$%tl153373153645%_
                         (let ()
                           (declare (not safe))
                           (##cdr _%$%rest153367153375%_))))
                    (let* ((_%method-spec153648%_ _%$%hd153372153643%_)
                           (_%rest153650%_ _%$%tl153373153645%_))
                      (_%$%K153371153640%_
                       _%rest153650%_
                       _%method-spec153648%_)))
                  (_%$%else153369153502%_)))))))
    (define cast
      (lambda (_%descriptor153169%_ _%obj153171%_)
        (let* ((_%klass153174%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%descriptor153169%_ '1 '#f '#f)))
               (_%klass-id153177%_
                (let () (declare (not safe)) (##type-id _%klass153174%_))))
          (let _%loop153181%_ ((_%obj153184%_ _%obj153171%_))
            (declare (not interrupts-enabled))
            (let* ((_%obj-klass153187%_
                    (let () (declare (not safe)) (class-of _%obj153184%_)))
                   (_%obj-klass-id153190%_
                    (let ()
                      (declare (not safe))
                      (##type-id _%obj-klass153187%_))))
              (if (let ()
                    (declare (not safe))
                    (##eq? _%klass-id153177%_ _%obj-klass-id153190%_))
                  _%obj153184%_
                  (if (interface-subclass? _%obj-klass153187%_)
                      (let _%loop-interface153198%_ ((_%iface-klass153201%_
                                                      _%obj-klass153187%_))
                        (if _%iface-klass153201%_
                            (let* ((_%tab153204%_
                                    (class-type-interface-table
                                     _%iface-klass153201%_))
                                   (_%$e153246%_
                                    (let* ((_%prototable153207%_ _%tab153204%_)
                                           (_%descriptor153210%_
                                            _%descriptor153169%_)
                                           (_%prototable153214%_
                                            _%prototable153207%_)
                                           (_%descriptor153237%_
                                            _%descriptor153210%_))
                                      (____prototype-table-get
                                       _%prototable153214%_
                                       _%descriptor153237%_))))
                              (if _%$e153246%_
                                  (if (eq? _%$e153246%_ '#!void)
                                      (_%loop-interface153198%_
                                       (let ()
                                         (declare (not safe))
                                         (##type-super _%iface-klass153201%_)))
                                      (if _%$e153246%_
                                          (let ((_%instance153256%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##structure-copy
                                                    _%$e153246%_))))
                                            (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-set!
                                               _%instance153256%_
                                               _%obj153184%_
                                               '1
                                               '#f
                                               'cast))
                                            _%instance153256%_)
                                          (begin
                                            (raise-cast-error
                                             'cast
                                             '"cannot create interface prototype"
                                             'interface:
                                             _%descriptor153169%_
                                             'class:
                                             (let ()
                                               (declare (not safe))
                                               (class-of _%obj153184%_)))
                                            '#!void)))
                                  (let ((_%$e153258%_
                                         (try-create-prototype
                                          _%descriptor153169%_
                                          _%klass153174%_
                                          _%iface-klass153201%_)))
                                    (if _%$e153258%_
                                        (if _%$e153258%_
                                            (let ((_%instance153267%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##structure-copy
                                                      _%$e153258%_))))
                                              (let ()
                                                (declare (not safe))
                                                (##unchecked-structure-set!
                                                 _%instance153267%_
                                                 _%obj153184%_
                                                 '1
                                                 '#f
                                                 'cast))
                                              _%instance153267%_)
                                            (begin
                                              (raise-cast-error
                                               'cast
                                               '"cannot create interface prototype"
                                               'interface:
                                               _%descriptor153169%_
                                               'class:
                                               (let ()
                                                 (declare (not safe))
                                                 (class-of _%obj153184%_)))
                                              '#!void))
                                        (_%loop-interface153198%_
                                         (let ()
                                           (declare (not safe))
                                           (##type-super
                                            _%iface-klass153201%_)))))))
                            (_%loop153181%_
                             (let ()
                               (declare (not safe))
                               (##unchecked-structure-ref
                                _%obj153184%_
                                '1
                                '#f
                                '#f)))))
                      (let* ((_%tab153271%_
                              (class-type-interface-table _%obj-klass153187%_))
                             (_%$e153300%_
                              (let* ((_%prototable153273%_ _%tab153271%_)
                                     (_%descriptor153276%_
                                      _%descriptor153169%_)
                                     (_%prototable153280%_
                                      _%prototable153273%_)
                                     (_%descriptor153291%_
                                      _%descriptor153276%_))
                                (____prototype-table-get
                                 _%prototable153280%_
                                 _%descriptor153291%_))))
                        (if _%$e153300%_
                            (if (eq? _%$e153300%_ '#!void)
                                (let ()
                                  (raise-cast-error
                                   'cast
                                   '"cannot create interface prototype"
                                   'interface:
                                   _%descriptor153169%_
                                   'class:
                                   (let ()
                                     (declare (not safe))
                                     (class-of _%obj153184%_)))
                                  '#!void)
                                (if _%$e153300%_
                                    (let ((_%instance153315%_
                                           (let ()
                                             (declare (not safe))
                                             (##structure-copy _%$e153300%_))))
                                      (let ()
                                        (declare (not safe))
                                        (##unchecked-structure-set!
                                         _%instance153315%_
                                         _%obj153184%_
                                         '1
                                         '#f
                                         'cast))
                                      _%instance153315%_)
                                    (begin
                                      (raise-cast-error
                                       'cast
                                       '"cannot create interface prototype"
                                       'interface:
                                       _%descriptor153169%_
                                       'class:
                                       (let ()
                                         (declare (not safe))
                                         (class-of _%obj153184%_)))
                                      '#!void)))
                            (let ((_%$e153317%_
                                   (create-prototype
                                    _%descriptor153169%_
                                    _%klass153174%_
                                    _%obj-klass153187%_)))
                              (if _%$e153317%_
                                  (if _%$e153317%_
                                      (let ((_%instance153326%_
                                             (let ()
                                               (declare (not safe))
                                               (##structure-copy
                                                _%$e153317%_))))
                                        (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-set!
                                           _%instance153326%_
                                           _%obj153184%_
                                           '1
                                           '#f
                                           'cast))
                                        _%instance153326%_)
                                      (begin
                                        (raise-cast-error
                                         'cast
                                         '"cannot create interface prototype"
                                         'interface:
                                         _%descriptor153169%_
                                         'class:
                                         (let ()
                                           (declare (not safe))
                                           (class-of _%obj153184%_)))
                                        '#!void))
                                  (let ()
                                    (raise-cast-error
                                     'cast
                                     '"cannot create interface prototype"
                                     'interface:
                                     _%descriptor153169%_
                                     'class:
                                     (let ()
                                       (declare (not safe))
                                       (class-of _%obj153184%_)))
                                    '#!void))))))))))))
    (define try-cast
      (lambda (_%descriptor153003%_ _%obj153005%_)
        (let* ((_%klass153008%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%descriptor153003%_ '1 '#f '#f)))
               (_%klass-id153011%_
                (let () (declare (not safe)) (##type-id _%klass153008%_))))
          (let _%loop153015%_ ((_%obj153018%_ _%obj153005%_))
            (declare (not interrupts-enabled))
            (let* ((_%obj-klass153021%_
                    (let () (declare (not safe)) (class-of _%obj153018%_)))
                   (_%obj-klass-id153024%_
                    (let ()
                      (declare (not safe))
                      (##type-id _%obj-klass153021%_))))
              (if (let ()
                    (declare (not safe))
                    (##eq? _%klass-id153011%_ _%obj-klass-id153024%_))
                  _%obj153018%_
                  (if (interface-subclass? _%obj-klass153021%_)
                      (let _%loop-interface153032%_ ((_%iface-klass153035%_
                                                      _%obj-klass153021%_))
                        (if _%iface-klass153035%_
                            (let* ((_%tab153038%_
                                    (class-type-interface-table
                                     _%iface-klass153035%_))
                                   (_%$e153080%_
                                    (let* ((_%prototable153041%_ _%tab153038%_)
                                           (_%descriptor153044%_
                                            _%descriptor153003%_)
                                           (_%prototable153048%_
                                            _%prototable153041%_)
                                           (_%descriptor153071%_
                                            _%descriptor153044%_))
                                      (____prototype-table-get
                                       _%prototable153048%_
                                       _%descriptor153071%_))))
                              (if _%$e153080%_
                                  (if (eq? _%$e153080%_ '#!void)
                                      (_%loop-interface153032%_
                                       (let ()
                                         (declare (not safe))
                                         (##type-super _%iface-klass153035%_)))
                                      (if _%$e153080%_
                                          (let ((_%instance153090%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##structure-copy
                                                    _%$e153080%_))))
                                            (let ()
                                              (declare (not safe))
                                              (##unchecked-structure-set!
                                               _%instance153090%_
                                               _%obj153018%_
                                               '1
                                               '#f
                                               'cast))
                                            _%instance153090%_)
                                          '#f))
                                  (let ((_%$e153092%_
                                         (try-create-prototype
                                          _%descriptor153003%_
                                          _%klass153008%_
                                          _%iface-klass153035%_)))
                                    (if _%$e153092%_
                                        (if _%$e153092%_
                                            (let ((_%instance153101%_
                                                   (let ()
                                                     (declare (not safe))
                                                     (##structure-copy
                                                      _%$e153092%_))))
                                              (let ()
                                                (declare (not safe))
                                                (##unchecked-structure-set!
                                                 _%instance153101%_
                                                 _%obj153018%_
                                                 '1
                                                 '#f
                                                 'cast))
                                              _%instance153101%_)
                                            '#f)
                                        (_%loop-interface153032%_
                                         (let ()
                                           (declare (not safe))
                                           (##type-super
                                            _%iface-klass153035%_)))))))
                            (_%loop153015%_
                             (let ()
                               (declare (not safe))
                               (##unchecked-structure-ref
                                _%obj153018%_
                                '1
                                '#f
                                '#f)))))
                      (let* ((_%tab153105%_
                              (class-type-interface-table _%obj-klass153021%_))
                             (_%$e153134%_
                              (let* ((_%prototable153107%_ _%tab153105%_)
                                     (_%descriptor153110%_
                                      _%descriptor153003%_)
                                     (_%prototable153114%_
                                      _%prototable153107%_)
                                     (_%descriptor153125%_
                                      _%descriptor153110%_))
                                (____prototype-table-get
                                 _%prototable153114%_
                                 _%descriptor153125%_))))
                        (if _%$e153134%_
                            (if (eq? _%$e153134%_ '#!void)
                                '#f
                                (if _%$e153134%_
                                    (let ((_%instance153149%_
                                           (let ()
                                             (declare (not safe))
                                             (##structure-copy _%$e153134%_))))
                                      (let ()
                                        (declare (not safe))
                                        (##unchecked-structure-set!
                                         _%instance153149%_
                                         _%obj153018%_
                                         '1
                                         '#f
                                         'cast))
                                      _%instance153149%_)
                                    '#f))
                            (let ((_%$e153151%_
                                   (try-create-prototype
                                    _%descriptor153003%_
                                    _%klass153008%_
                                    _%obj-klass153021%_)))
                              (if _%$e153151%_
                                  (if _%$e153151%_
                                      (let ((_%instance153160%_
                                             (let ()
                                               (declare (not safe))
                                               (##structure-copy
                                                _%$e153151%_))))
                                        (let ()
                                          (declare (not safe))
                                          (##unchecked-structure-set!
                                           _%instance153160%_
                                           _%obj153018%_
                                           '1
                                           '#f
                                           'cast))
                                        _%instance153160%_)
                                      '#f)
                                  '#f)))))))))))
    (define satisfies?
      (lambda (_%descriptor152849%_ _%obj152851%_)
        (let* ((_%klass152854%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%descriptor152849%_ '1 '#f '#f)))
               (_%klass-id152857%_
                (let () (declare (not safe)) (##type-id _%klass152854%_))))
          (let _%loop152861%_ ((_%obj152864%_ _%obj152851%_))
            (declare (not interrupts-enabled))
            (let* ((_%obj-klass152867%_
                    (let () (declare (not safe)) (class-of _%obj152864%_)))
                   (_%obj-klass-id152870%_
                    (let ()
                      (declare (not safe))
                      (##type-id _%obj-klass152867%_))))
              (if (let ()
                    (declare (not safe))
                    (##eq? _%klass-id152857%_ _%obj-klass-id152870%_))
                  '#t
                  (if (interface-subclass? _%obj-klass152867%_)
                      (let _%loop-interface152878%_ ((_%iface-klass152881%_
                                                      _%obj-klass152867%_))
                        (if _%iface-klass152881%_
                            (let* ((_%tab152884%_
                                    (class-type-interface-table
                                     _%iface-klass152881%_))
                                   (_%$e152926%_
                                    (let* ((_%prototable152887%_ _%tab152884%_)
                                           (_%descriptor152890%_
                                            _%descriptor152849%_)
                                           (_%prototable152894%_
                                            _%prototable152887%_)
                                           (_%descriptor152917%_
                                            _%descriptor152890%_))
                                      (____prototype-table-get
                                       _%prototable152894%_
                                       _%descriptor152917%_))))
                              (if _%$e152926%_
                                  (if (eq? _%$e152926%_ '#!void)
                                      (_%loop-interface152878%_
                                       (let ()
                                         (declare (not safe))
                                         (##type-super _%iface-klass152881%_)))
                                      (if _%$e152926%_ '#t '#f))
                                  (let ((_%$e152936%_
                                         (try-create-prototype
                                          _%descriptor152849%_
                                          _%klass152854%_
                                          _%iface-klass152881%_)))
                                    (if _%$e152936%_
                                        (if _%$e152936%_ '#t '#f)
                                        (_%loop-interface152878%_
                                         (let ()
                                           (declare (not safe))
                                           (##type-super
                                            _%iface-klass152881%_)))))))
                            (_%loop152861%_
                             (let ()
                               (declare (not safe))
                               (##unchecked-structure-ref
                                _%obj152864%_
                                '1
                                '#f
                                '#f)))))
                      (let* ((_%tab152947%_
                              (class-type-interface-table _%obj-klass152867%_))
                             (_%$e152976%_
                              (let* ((_%prototable152949%_ _%tab152947%_)
                                     (_%descriptor152952%_
                                      _%descriptor152849%_)
                                     (_%prototable152956%_
                                      _%prototable152949%_)
                                     (_%descriptor152967%_
                                      _%descriptor152952%_))
                                (____prototype-table-get
                                 _%prototable152956%_
                                 _%descriptor152967%_))))
                        (if _%$e152976%_
                            (if (eq? _%$e152976%_ '#!void)
                                '#f
                                (if _%$e152976%_ '#t '#f))
                            (let ((_%$e152989%_
                                   (try-create-prototype
                                    _%descriptor152849%_
                                    _%klass152854%_
                                    _%obj-klass152867%_)))
                              (if _%$e152989%_
                                  (if _%$e152989%_ '#t '#f)
                                  '#f)))))))))))
    (define __with-prototype
      (lambda (_%descriptor152693%_
               _%obj152694%_
               _%with-prototype+receiver152695%_
               _%with-receiver152696%_)
        (let* ((_%descriptor152699%_ _%descriptor152693%_)
               (_%with-prototype+receiver152707%_
                _%with-prototype+receiver152695%_)
               (_%with-receiver152715%_ _%with-receiver152696%_)
               (_%klass152724%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%descriptor152699%_ '1 '#f '#f)))
               (_%klass-id152727%_
                (let () (declare (not safe)) (##type-id _%klass152724%_))))
          (let _%loop152731%_ ((_%obj152734%_ _%obj152694%_))
            (declare (not interrupts-enabled))
            (let* ((_%obj-klass152737%_
                    (let () (declare (not safe)) (class-of _%obj152734%_)))
                   (_%obj-klass-id152740%_
                    (let ()
                      (declare (not safe))
                      (##type-id _%obj-klass152737%_))))
              (if (let ()
                    (declare (not safe))
                    (##eq? _%klass-id152727%_ _%obj-klass-id152740%_))
                  (let ()
                    (declare (not safe))
                    (_%with-receiver152715%_ _%obj152734%_))
                  (if (interface-subclass? _%obj-klass152737%_)
                      (let _%loop-interface152746%_ ((_%iface-klass152749%_
                                                      _%obj-klass152737%_))
                        (if _%iface-klass152749%_
                            (let* ((_%tab152752%_
                                    (class-type-interface-table
                                     _%iface-klass152749%_))
                                   (_%$e152796%_
                                    (let* ((_%prototable152755%_ _%tab152752%_)
                                           (_%descriptor152758%_
                                            _%descriptor152699%_)
                                           (_%prototable152762%_
                                            _%prototable152755%_)
                                           (_%descriptor152787%_
                                            _%descriptor152758%_))
                                      (____prototype-table-get
                                       _%prototable152762%_
                                       _%descriptor152787%_))))
                              (if _%$e152796%_
                                  (if (eq? _%$e152796%_ '#!void)
                                      (_%loop-interface152746%_
                                       (let ()
                                         (declare (not safe))
                                         (##type-super _%iface-klass152749%_)))
                                      (let ()
                                        (declare (not safe))
                                        (_%with-prototype+receiver152707%_
                                         _%descriptor152699%_
                                         _%$e152796%_
                                         _%obj152734%_)))
                                  (let ((_%$e152802%_
                                         (try-create-prototype
                                          _%descriptor152699%_
                                          _%klass152724%_
                                          _%iface-klass152749%_)))
                                    (if _%$e152802%_
                                        (let ()
                                          (declare (not safe))
                                          (_%with-prototype+receiver152707%_
                                           _%descriptor152699%_
                                           _%$e152802%_
                                           _%obj152734%_))
                                        (_%loop-interface152746%_
                                         (let ()
                                           (declare (not safe))
                                           (##type-super
                                            _%iface-klass152749%_)))))))
                            (_%loop152731%_
                             (let ()
                               (declare (not safe))
                               (##unchecked-structure-ref
                                _%obj152734%_
                                '1
                                '#f
                                '#f)))))
                      (let* ((_%tab152809%_
                              (class-type-interface-table _%obj-klass152737%_))
                             (_%$e152838%_
                              (let* ((_%prototable152811%_ _%tab152809%_)
                                     (_%descriptor152814%_
                                      _%descriptor152699%_)
                                     (_%prototable152818%_
                                      _%prototable152811%_)
                                     (_%descriptor152829%_
                                      _%descriptor152814%_))
                                (____prototype-table-get
                                 _%prototable152818%_
                                 _%descriptor152829%_))))
                        (if _%$e152838%_
                            (if (eq? _%$e152838%_ '#!void)
                                (let ()
                                  (declare (not safe))
                                  (_%with-prototype+receiver152707%_
                                   _%descriptor152699%_
                                   '#f
                                   _%obj152734%_))
                                (let ()
                                  (declare (not safe))
                                  (_%with-prototype+receiver152707%_
                                   _%descriptor152699%_
                                   _%$e152838%_
                                   _%obj152734%_)))
                            (let ((_%$e152843%_
                                   (create-prototype
                                    _%descriptor152699%_
                                    _%klass152724%_
                                    _%obj-klass152737%_)))
                              (if _%$e152843%_
                                  (let ()
                                    (declare (not safe))
                                    (_%with-prototype+receiver152707%_
                                     _%descriptor152699%_
                                     _%$e152843%_
                                     _%obj152734%_))
                                  (let ()
                                    (declare (not safe))
                                    (_%with-prototype+receiver152707%_
                                     _%descriptor152699%_
                                     '#f
                                     _%obj152734%_)))))))))))))
    (define with-prototype
      (lambda (_%descriptor152656%_
               _%obj152657%_
               _%with-prototype+receiver152658%_
               _%with-receiver152659%_)
        (if (let ()
              (declare (not safe))
              (##structure-direct-instance-of?
               _%descriptor152656%_
               'interface-descriptor::t))
            (let ((_%descriptor152663%_ _%descriptor152656%_))
              (if (procedure? _%with-prototype+receiver152658%_)
                  (let ((_%with-prototype+receiver152673%_
                         _%with-prototype+receiver152658%_))
                    (if (procedure? _%with-receiver152659%_)
                        (let ((_%with-receiver152683%_
                               _%with-receiver152659%_))
                          (__with-prototype
                           _%descriptor152663%_
                           _%obj152657%_
                           _%with-prototype+receiver152673%_
                           _%with-receiver152683%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/interface.ss\"@236.9-236.22"
                           'contract:
                           'procedure?
                           'value:
                           _%with-receiver152659%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/interface.ss\"@235.9-235.32"
                     'contract:
                     'procedure?
                     'value:
                     _%with-prototype+receiver152658%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/interface.ss\"@234.23-234.33"
               'contract:
               'interface-descriptor?
               'value:
               _%descriptor152656%_)
              '#!void))))))
