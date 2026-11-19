(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/mop::timestamp 1795039813)
  (begin
    (define type-flag-opaque '1)
    (define type-flag-extensible '2)
    (define type-flag-macros '4)
    (define type-flag-concrete '8)
    (define type-flag-id '16)
    (define class-type-flag-struct '1024)
    (define class-type-flag-sealed '2048)
    (define class-type-flag-metaclass '4096)
    (define class-type-flag-system '8192)
    (define class-type-flag-acyclic '16384)
    (define t::t
      (let ((_%flags145561%_
             (let ()
               (declare (not safe))
               (##fxior type-flag-extensible
                        type-flag-id
                        class-type-flag-system)))
            (_%properties145562%_ '((direct-slots:) (system: . #t)))
            (_%slot-table145563%_
             (let () (declare (not safe)) (make-symbolic-table__% '#f '0))))
        (let ()
          (declare (not safe))
          (##structure
           '#f
           't
           't
           _%flags145561%_
           '#f
           '#()
           '()
           '#(#f)
           _%slot-table145563%_
           _%properties145562%_
           '#f
           '#f
           '#f
           '#f))))
    (define class::t
      (let* ((_%slots145518%_
              '(id name
                   flags
                   super
                   fields
                   precedence-list
                   slot-vector
                   slot-table
                   properties
                   constructor
                   methods
                   specializer
                   interface))
             (_%slot-vector145520%_ (list->vector (cons '#f _%slots145518%_)))
             (_%slot-table145546%_
              (let ((_%slot-table145522%_
                     (let ()
                       (declare (not safe))
                       (make-symbolic-table__% '#f '0))))
                (let ((__tmp148519
                       (lambda (_%slot145524%_ _%field145525%_)
                         (let ()
                           (declare (not safe))
                           (symbolic-table-set!
                            _%slot-table145522%_
                            _%slot145524%_
                            _%field145525%_))
                         (let ((__tmp148520
                                (let ((_%sym145527%_ _%slot145524%_))
                                  (if (symbol? _%sym145527%_)
                                      (let ((_%sym145532%_ _%sym145527%_))
                                        (declare (not safe))
                                        (__symbol->keyword _%sym145532%_))
                                      (begin
                                        (raise-contract-violation-error
                                         '"contract violation"
                                         'context:
                                         'gerbil/runtime/mop
                                         'contract:
                                         'symbol?
                                         'value:
                                         _%sym145527%_)
                                        '#!void)))))
                           (declare (not safe))
                           (symbolic-table-set!
                            _%slot-table145522%_
                            __tmp148520
                            _%field145525%_))))
                      (__tmp148517
                       (let ((__tmp148518
                              (let ()
                                (declare (not safe))
                                (##length _%slots145518%_))))
                         (declare (not safe))
                         (##iota __tmp148518 '1))))
                  (declare (not safe))
                  (##for-each __tmp148519 _%slots145518%_ __tmp148517))
                _%slot-table145522%_))
             (_%flags145548%_
              (let ()
                (declare (not safe))
                (##fxior type-flag-extensible
                         type-flag-concrete
                         type-flag-id
                         class-type-flag-struct)))
             (_%fields145554%_
              (list->vector
               (let ((__tmp148521
                      (map (lambda (_%$%g145549145551%_)
                             (list _%$%g145549145551%_ '5 '#f))
                           (drop _%slots145518%_ '5))))
                 (declare (not safe))
                 (##apply append __tmp148521))))
             (_%properties145556%_
              (cons (cons 'direct-slots: _%slots145518%_) '((struct: . #t))))
             (_%t145558%_
              (let ((__tmp148522 (cons t::t '())))
                (declare (not safe))
                (##structure
                 '#f
                 'class
                 'class
                 _%flags145548%_
                 ##type-type
                 _%fields145554%_
                 __tmp148522
                 _%slot-vector145520%_
                 _%slot-table145546%_
                 _%properties145556%_
                 '#f
                 '#f
                 '#f
                 '#f))))
        (let ()
          (declare (not safe))
          (##structure-type-set! _%t145558%_ _%t145558%_))
        _%t145558%_))
    (let () (declare (not safe)) (##structure-type-set! t::t class::t))
    (define object::t
      (let ((_%flags145514%_
             (let ()
               (declare (not safe))
               (##fxior type-flag-extensible
                        type-flag-id
                        class-type-flag-system)))
            (_%properties145515%_ '((direct-slots:) (system: . #t)))
            (_%slot-table145516%_
             (let () (declare (not safe)) (make-symbolic-table__% '#f '0))))
        (let ((__tmp148523 (cons t::t '())))
          (declare (not safe))
          (##structure
           class::t
           'object
           'object
           _%flags145514%_
           '#f
           '#()
           __tmp148523
           '#(#f)
           _%slot-table145516%_
           _%properties145515%_
           '#f
           '#f
           '#f
           '#f))))
    (define __class-type
      (lambda (_%klass145502%_)
        (let ((_%klass145505%_ _%klass145502%_))
          (declare (not safe))
          (##structure-type _%klass145505%_))))
    (define class-type
      (lambda (_%klass145488%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass145488%_ 'class))
            (let ((_%klass145492%_ _%klass145488%_))
              (__class-type _%klass145492%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@166.19-166.24"
               'contract:
               'class-type?
               'value:
               _%klass145488%_)
              '#!void))))
    (define class-type?
      (lambda (_%obj145486%_)
        (let ()
          (declare (not safe))
          (##structure-instance-of? _%obj145486%_ 'class))))
    (define __class-type=?
      (lambda (_%x145465%_ _%y145466%_)
        (let* ((_%x145469%_ _%x145465%_) (_%y145477%_ _%y145466%_))
          (eq? (let ()
                 (declare (not safe))
                 (##unchecked-structure-ref _%x145469%_ '1 '#f '#f))
               (let ()
                 (declare (not safe))
                 (##unchecked-structure-ref _%y145477%_ '1 '#f '#f))))))
    (define class-type=?
      (lambda (_%x145440%_ _%y145441%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%x145440%_ 'class))
            (let ((_%x145445%_ _%x145440%_))
              (if (let ()
                    (declare (not safe))
                    (##structure-instance-of? _%y145441%_ 'class))
                  (let ((_%y145455%_ _%y145441%_))
                    (__class-type=? _%x145445%_ _%y145455%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@175.34-175.35"
                     'contract:
                     'class-type?
                     'value:
                     _%y145441%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@175.21-175.22"
               'contract:
               'class-type?
               'value:
               _%x145440%_)
              '#!void))))
    (define __type-opaque?
      (lambda (_%type145428%_)
        (let* ((_%type145431%_ _%type145428%_)
               (__tmp148524
                (let ((__tmp148525
                       (let ()
                         (declare (not safe))
                         (##type-flags _%type145431%_))))
                  (declare (not safe))
                  (##fxand __tmp148525 type-flag-opaque))))
          (declare (not safe))
          (##fx= __tmp148524 type-flag-opaque))))
    (define type-opaque?
      (lambda (_%type145414%_)
        (if (let () (declare (not safe)) (##type? _%type145414%_))
            (let ((_%type145418%_ _%type145414%_))
              (__type-opaque? _%type145418%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@189.21-189.25"
               'contract:
               '##type?
               'value:
               _%type145414%_)
              '#!void))))
    (define __class-type-opaque?
      (lambda (_%klass145402%_)
        (let* ((_%klass145405%_ _%klass145402%_)
               (__tmp148526
                (let ((__tmp148527
                       (let ()
                         (declare (not safe))
                         (##type-flags _%klass145405%_))))
                  (declare (not safe))
                  (##fxand __tmp148527 type-flag-opaque))))
          (declare (not safe))
          (##fx= __tmp148526 type-flag-opaque))))
    (define class-type-opaque?
      (lambda (_%klass145388%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass145388%_ 'class))
            (let ((_%klass145392%_ _%klass145388%_))
              (__class-type-opaque? _%klass145392%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@191.27-191.32"
               'contract:
               'class-type?
               'value:
               _%klass145388%_)
              '#!void))))
    (define __type-extensible?
      (lambda (_%type145376%_)
        (let* ((_%type145379%_ _%type145376%_)
               (__tmp148528
                (let ((__tmp148529
                       (let ()
                         (declare (not safe))
                         (##type-flags _%type145379%_))))
                  (declare (not safe))
                  (##fxand __tmp148529 type-flag-extensible))))
          (declare (not safe))
          (##fx= __tmp148528 type-flag-extensible))))
    (define type-extensible?
      (lambda (_%type145362%_)
        (if (let () (declare (not safe)) (##type? _%type145362%_))
            (let ((_%type145366%_ _%type145362%_))
              (__type-extensible? _%type145366%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@193.25-193.29"
               'contract:
               '##type?
               'value:
               _%type145362%_)
              '#!void))))
    (define __class-type-final?
      (lambda (_%type145350%_)
        (let* ((_%type145353%_ _%type145350%_)
               (__tmp148530
                (let ((__tmp148531
                       (let ()
                         (declare (not safe))
                         (##type-flags _%type145353%_))))
                  (declare (not safe))
                  (##fxand __tmp148531 type-flag-extensible))))
          (declare (not safe))
          (##fx= __tmp148530 '0))))
    (define class-type-final?
      (lambda (_%type145336%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%type145336%_ 'class))
            (let ((_%type145340%_ _%type145336%_))
              (__class-type-final? _%type145340%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@195.26-195.30"
               'contract:
               'class-type?
               'value:
               _%type145336%_)
              '#!void))))
    (define __class-type-struct?
      (lambda (_%klass145324%_)
        (let* ((_%klass145327%_ _%klass145324%_)
               (__tmp148532
                (let ((__tmp148533
                       (let ()
                         (declare (not safe))
                         (##type-flags _%klass145327%_))))
                  (declare (not safe))
                  (##fxand __tmp148533 class-type-flag-struct))))
          (declare (not safe))
          (##fx= __tmp148532 class-type-flag-struct))))
    (define class-type-struct?
      (lambda (_%klass145310%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass145310%_ 'class))
            (let ((_%klass145314%_ _%klass145310%_))
              (__class-type-struct? _%klass145314%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@197.27-197.32"
               'contract:
               'class-type?
               'value:
               _%klass145310%_)
              '#!void))))
    (define __class-type-sealed?
      (lambda (_%klass145298%_)
        (let* ((_%klass145301%_ _%klass145298%_)
               (__tmp148534
                (let ((__tmp148535
                       (let ()
                         (declare (not safe))
                         (##type-flags _%klass145301%_))))
                  (declare (not safe))
                  (##fxand __tmp148535 class-type-flag-sealed))))
          (declare (not safe))
          (##fx= __tmp148534 class-type-flag-sealed))))
    (define class-type-sealed?
      (lambda (_%klass145284%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass145284%_ 'class))
            (let ((_%klass145288%_ _%klass145284%_))
              (__class-type-sealed? _%klass145288%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@199.27-199.32"
               'contract:
               'class-type?
               'value:
               _%klass145284%_)
              '#!void))))
    (define __class-type-metaclass?
      (lambda (_%klass145272%_)
        (let* ((_%klass145275%_ _%klass145272%_)
               (__tmp148536
                (let ((__tmp148537
                       (let ()
                         (declare (not safe))
                         (##type-flags _%klass145275%_))))
                  (declare (not safe))
                  (##fxand __tmp148537 class-type-flag-metaclass))))
          (declare (not safe))
          (##fx= __tmp148536 class-type-flag-metaclass))))
    (define class-type-metaclass?
      (lambda (_%klass145258%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass145258%_ 'class))
            (let ((_%klass145262%_ _%klass145258%_))
              (__class-type-metaclass? _%klass145262%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@201.30-201.35"
               'contract:
               'class-type?
               'value:
               _%klass145258%_)
              '#!void))))
    (define __class-type-system?
      (lambda (_%klass145246%_)
        (let* ((_%klass145249%_ _%klass145246%_)
               (__tmp148538
                (let ((__tmp148539
                       (let ()
                         (declare (not safe))
                         (##type-flags _%klass145249%_))))
                  (declare (not safe))
                  (##fxand __tmp148539 class-type-flag-system))))
          (declare (not safe))
          (##fx= __tmp148538 class-type-flag-system))))
    (define class-type-system?
      (lambda (_%klass145232%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass145232%_ 'class))
            (let ((_%klass145236%_ _%klass145232%_))
              (__class-type-system? _%klass145236%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@203.27-203.32"
               'contract:
               'class-type?
               'value:
               _%klass145232%_)
              '#!void))))
    (define __class-type-acyclic?
      (lambda (_%klass145220%_)
        (let* ((_%klass145223%_ _%klass145220%_)
               (__tmp148540
                (let ((__tmp148541
                       (let ()
                         (declare (not safe))
                         (##type-flags _%klass145223%_))))
                  (declare (not safe))
                  (##fxand __tmp148541 class-type-flag-acyclic))))
          (declare (not safe))
          (##fx= __tmp148540 class-type-flag-acyclic))))
    (define class-type-acyclic?
      (lambda (_%klass145206%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass145206%_ 'class))
            (let ((_%klass145210%_ _%klass145206%_))
              (__class-type-acyclic? _%klass145210%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@205.28-205.33"
               'contract:
               'class-type?
               'value:
               _%klass145206%_)
              '#!void))))
    (define make-class-type-descriptor
      (lambda (_%type-id144972%_
               _%type-name144973%_
               _%type-super144974%_
               _%precedence-list144975%_
               _%slot-vector144976%_
               _%properties144977%_
               _%constructor144978%_
               _%slot-table144979%_
               _%methods144980%_)
        (letrec ((_%make-props!144983%_
                  (lambda (_%key145151%_ _%transparent?145152%_)
                    (letrec* ((_%ht145154%_
                               (let ()
                                 (declare (not safe))
                                 (make-symbolic-table__% '#f '0)))
                              (_%put-slots!145155%_
                               (lambda (_%ht145199%_ _%slots145200%_)
                                 (for-each
                                  (lambda (_%$%g145201145203%_)
                                    (let ()
                                      (declare (not safe))
                                      (symbolic-table-set!
                                       _%ht145199%_
                                       _%$%g145201145203%_
                                       '#t)))
                                  _%slots145200%_)))
                              (_%put-all-new-slots!145156%_
                               (lambda (_%ht145191%_)
                                 (let ((_%first145193%_
                                        (if (let ()
                                              (declare (not safe))
                                              (##structure-instance-of?
                                               _%type-super144974%_
                                               'class))
                                            (let ((__tmp148542
                                                   (let ()
                                                     (declare (not safe))
                                                     (##unchecked-structure-ref
                                                      _%type-super144974%_
                                                      '7
                                                      '#f
                                                      '#f))))
                                              (declare (not safe))
                                              (##vector-length __tmp148542))
                                            '1)))
                                   (let _%lp145195%_ ((_%i145197%_
                                                       _%first145193%_))
                                     (if (let ((__tmp148543
                                                (let ()
                                                  (declare (not safe))
                                                  (##vector-length
                                                   _%slot-vector144976%_))))
                                           (declare (not safe))
                                           (##fx< _%i145197%_ __tmp148543))
                                         (begin
                                           (let ((__tmp148544
                                                  (let ()
                                                    (declare (not safe))
                                                    (##vector-ref
                                                     _%slot-vector144976%_
                                                     _%i145197%_))))
                                             (declare (not safe))
                                             (symbolic-table-set!
                                              _%ht145191%_
                                              __tmp148544
                                              '#t))
                                           (_%lp145195%_
                                            (let ()
                                              (declare (not safe))
                                              (##fx+ _%i145197%_ '1))))
                                         '#!void)))))
                              (_%put-alist!145157%_
                               (lambda (_%ht145182%_
                                        _%key145183%_
                                        _%alist145184%_)
                                 (let ((_%$e145186%_
                                        (let ()
                                          (declare (not safe))
                                          (agetq__%
                                           _%key145183%_
                                           _%alist145184%_
                                           _%transparent?145152%_))))
                                   (if _%$e145186%_
                                       (if (eq? _%$e145186%_ '#t)
                                           (_%put-all-new-slots!145156%_
                                            _%ht145182%_)
                                           (_%put-slots!145155%_
                                            _%ht145182%_
                                            _%$e145186%_))
                                       '#!void)))))
                      (_%put-alist!145157%_
                       _%ht145154%_
                       _%key145151%_
                       _%properties144977%_)
                      (for-each
                       (lambda (_%mixin145159%_)
                         (let ((_%alist145161%_
                                (##structure-ref
                                 _%mixin145159%_
                                 '9
                                 class::t
                                 '#f)))
                           (if (eq? '#t
                                    (let ()
                                      (declare (not safe))
                                      (agetq__%
                                       _%key145151%_
                                       _%alist145161%_
                                       _%transparent?145152%_)))
                               (_%put-slots!145155%_
                                _%ht145154%_
                                (let ((_%klass145163%_ _%mixin145159%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (##structure-instance-of?
                                         _%klass145163%_
                                         'class))
                                      (let ((_%klass145168%_ _%klass145163%_))
                                        (__class-type-slot-list
                                         _%klass145168%_))
                                      (begin
                                        (raise-contract-violation-error
                                         '"contract violation"
                                         'context:
                                         'gerbil/runtime/mop
                                         'contract:
                                         'class-type?
                                         'value:
                                         _%klass145163%_)
                                        '#!void))))
                               (_%put-alist!145157%_
                                _%ht145154%_
                                _%key145151%_
                                _%alist145161%_))))
                       _%precedence-list144975%_)
                      _%ht145154%_)))
                 (_%all-slots-property?144984%_
                  (lambda (_%key145146%_ _%transparent?145147%_)
                    (let ((_%entry145149%_
                           (assq _%key145146%_ _%properties144977%_)))
                      (if _%entry145149%_
                          (eq? (cdr _%entry145149%_) '#t)
                          _%transparent?145147%_)))))
          (let* ((_%transparent?145004%_
                  (let ((__tmp148545
                         (if _%type-super144974%_
                             (not (let ((_%type144986%_ _%type-super144974%_))
                                    (if (let ()
                                          (declare (not safe))
                                          (##type? _%type144986%_))
                                        (let ((_%type144991%_ _%type144986%_))
                                          (__type-opaque? _%type144991%_))
                                        (begin
                                          (raise-contract-violation-error
                                           '"contract violation"
                                           'context:
                                           'gerbil/runtime/mop
                                           'contract:
                                           '##type?
                                           'value:
                                           _%type144986%_)
                                          '#!void))))
                             '#t)))
                    (declare (not safe))
                    (agetq__% 'transparent: _%properties144977%_ __tmp148545)))
                 (_%all-slots-printable?145006%_
                  (_%all-slots-property?144984%_
                   'print:
                   _%transparent?145004%_))
                 (_%printable145008%_
                  (if _%all-slots-printable?145006%_
                      '#f
                      (_%make-props!144983%_ 'print: _%transparent?145004%_)))
                 (_%all-slots-equalable?145010%_
                  (_%all-slots-property?144984%_
                   'equal:
                   _%transparent?145004%_))
                 (_%equalable145012%_
                  (if _%all-slots-equalable?145010%_
                      '#f
                      (_%make-props!144983%_ 'equal: _%transparent?145004%_)))
                 (_%first-new-field145014%_
                  (if (let ()
                        (declare (not safe))
                        (##structure-instance-of? _%type-super144974%_ 'class))
                      (let ((__tmp148546
                             (let ()
                               (declare (not safe))
                               (##unchecked-structure-ref
                                _%type-super144974%_
                                '7
                                '#f
                                '#f))))
                        (declare (not safe))
                        (##vector-length __tmp148546))
                      '1))
                 (_%field-info-length145016%_
                  (let ((__tmp148547
                         (let ((__tmp148548
                                (let ()
                                  (declare (not safe))
                                  (##vector-length _%slot-vector144976%_))))
                           (declare (not safe))
                           (##fx- __tmp148548 _%first-new-field145014%_))))
                    (declare (not safe))
                    (##fx* '3 __tmp148547)))
                 (_%field-info145018%_
                  (let ()
                    (declare (not safe))
                    (##make-vector _%field-info-length145016%_ '#f)))
                 (_%_145036%_
                  (let _%loop145020%_ ((_%i145022%_ _%first-new-field145014%_)
                                       (_%j145023%_ '0))
                    (if (let ()
                          (declare (not safe))
                          (##fx< _%j145023%_ _%field-info-length145016%_))
                        (let* ((_%slot145025%_
                                (let ()
                                  (declare (not safe))
                                  (##vector-ref
                                   _%slot-vector144976%_
                                   _%i145022%_)))
                               (_%flags145033%_
                                (let ((__tmp148550
                                       (if (or _%all-slots-printable?145006%_
                                               (let ()
                                                 (declare (not safe))
                                                 (symbolic-table-ref
                                                  _%printable145008%_
                                                  _%slot145025%_
                                                  '#f)))
                                           '0
                                           '1))
                                      (__tmp148549
                                       (if (or _%all-slots-equalable?145010%_
                                               (let ()
                                                 (declare (not safe))
                                                 (symbolic-table-ref
                                                  _%equalable145012%_
                                                  _%slot145025%_
                                                  '#f)))
                                           '0
                                           '4)))
                                  (declare (not safe))
                                  (##fxior __tmp148550 __tmp148549))))
                          (vector-set!
                           _%field-info145018%_
                           _%j145023%_
                           _%slot145025%_)
                          (vector-set!
                           _%field-info145018%_
                           (let () (declare (not safe)) (##fx+ _%j145023%_ '1))
                           _%flags145033%_)
                          (_%loop145020%_
                           (let () (declare (not safe)) (##fx+ _%i145022%_ '1))
                           (let ()
                             (declare (not safe))
                             (##fx+ _%j145023%_ '3))))
                        '#!void)))
                 (_%struct?145038%_
                  (let ()
                    (declare (not safe))
                    (agetq__0 'struct: _%properties144977%_)))
                 (_%final?145040%_
                  (let ()
                    (declare (not safe))
                    (agetq__0 'final: _%properties144977%_)))
                 (_%metaclass145047%_
                  (let ((_%$%metaclass145041145043%_
                         (let ()
                           (declare (not safe))
                           (agetq__0 'metaclass: _%properties144977%_))))
                    (if _%$%metaclass145041145043%_
                        (let ((_%metaclass145045%_
                               _%$%metaclass145041145043%_))
                          (if (let ()
                                (declare (not safe))
                                (##structure-instance-of?
                                 _%metaclass145045%_
                                 'class))
                              '#!void
                              (error '"metaclass is not a class type"
                                     'class:
                                     _%type-id144972%_
                                     'metaclass:
                                     _%metaclass145045%_))
                          _%metaclass145045%_)
                        '#f)))
                 (_%system?145049%_
                  (let ()
                    (declare (not safe))
                    (agetq__0 'system: _%properties144977%_)))
                 (_%opaque?145058%_
                  (let ((_%$e145055%_
                         (let ((_%eq-entry145051%_
                                (assq 'equal: _%properties144977%_)))
                           (if _%eq-entry145051%_
                               (not (cdr _%eq-entry145051%_))
                               (let ((_%tr-entry145053%_
                                      (assq 'transparent:
                                            _%properties144977%_)))
                                 (if _%tr-entry145053%_
                                     (not (cdr _%tr-entry145053%_))
                                     '#f))))))
                    (if _%$e145055%_
                        _%$e145055%_
                        (let ((__tmp148551
                               (let ()
                                 (declare (not safe))
                                 (agetq__%
                                  'direct-supers:
                                  _%properties144977%_
                                  '()))))
                          (declare (not safe))
                          (ormap__0 type-opaque? __tmp148551)))))
                 (_%acyclic?145060%_
                  (let ()
                    (declare (not safe))
                    (agetq__0 'acyclic: _%properties144977%_)))
                 (_%type-flags145062%_
                  (let ((__tmp148557
                         (if _%final?145040%_ '0 type-flag-extensible))
                        (__tmp148556
                         (if _%opaque?145058%_ type-flag-opaque '0))
                        (__tmp148555
                         (if _%struct?145038%_ class-type-flag-struct '0))
                        (__tmp148554
                         (if _%metaclass145047%_ class-type-flag-metaclass '0))
                        (__tmp148553
                         (if _%system?145049%_ class-type-flag-system '0))
                        (__tmp148552
                         (if _%acyclic?145060%_ class-type-flag-acyclic '0)))
                    (declare (not safe))
                    (##fxior type-flag-id
                             type-flag-concrete
                             __tmp148557
                             __tmp148556
                             __tmp148555
                             __tmp148554
                             __tmp148553
                             __tmp148552)))
                 (_%precedence-list145070%_
                  (let ((_%$e145064%_ (memq t::t _%precedence-list144975%_)))
                    (if _%$e145064%_
                        (if (null? (cdr _%$e145064%_))
                            _%precedence-list144975%_
                            (error '"BUG: t::t is not last in the precedence list"
                                   'precedence-list:
                                   _%precedence-list144975%_))
                        (let ((__tmp148558 (cons t::t '())))
                          (declare (not safe))
                          (##append _%precedence-list144975%_ __tmp148558)))))
                 (_%klass145111%_
                  (if _%metaclass145047%_
                      (let ((_%val145108%_
                             (let* ((_%klass145072%_ _%metaclass145047%_)
                                    (_%args145075%_
                                     (list _%type-id144972%_
                                           _%type-name144973%_
                                           _%type-flags145062%_
                                           _%type-super144974%_
                                           _%field-info145018%_
                                           _%precedence-list145070%_
                                           _%slot-vector144976%_
                                           _%slot-table144979%_
                                           _%properties144977%_
                                           _%constructor144978%_
                                           _%methods144980%_
                                           '#f
                                           '#f)))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-instance-of?
                                      _%klass145072%_
                                      'class))
                                   (let ((_%klass145080%_ _%klass145072%_))
                                     (declare (not safe))
                                     (##apply __make-instance
                                              _%klass145080%_
                                              _%args145075%_))
                                   (begin
                                     (raise-contract-violation-error
                                      '"contract violation"
                                      'context:
                                      'gerbil/runtime/mop
                                      'contract:
                                      'class-type?
                                      'value:
                                      _%klass145072%_)
                                     '#!void)))))
                        (if (let ()
                              (declare (not safe))
                              (##structure-instance-of? _%val145108%_ 'class))
                            _%val145108%_
                            (begin
                              (raise-contract-violation-error
                               '"contract violation"
                               'context:
                               '"\"gerbil/runtime/mop.ss\"@326.16-329.37"
                               'contract:
                               '(class-type? val)
                               'value:
                               _%val145108%_)
                              '#!void)))
                      (let ()
                        (declare (not safe))
                        (##structure
                         class::t
                         _%type-id144972%_
                         _%type-name144973%_
                         _%type-flags145062%_
                         _%type-super144974%_
                         _%field-info145018%_
                         _%precedence-list145070%_
                         _%slot-vector144976%_
                         _%slot-table144979%_
                         _%properties144977%_
                         _%constructor144978%_
                         _%methods144980%_
                         '#f
                         '#f)))))
            (for-each
             (lambda (_%super145114%_)
               (let ()
                 (declare (not interrupts-enabled))
                 (let _%again145118%_ ((_%spin145121%_ '0))
                   (if (let ((__tmp148559
                              (let ()
                                (declare (not safe))
                                (##vector-cas!
                                 __class-type-properties-lock
                                 '0
                                 '1
                                 '0))))
                         (declare (not safe))
                         (##fx= __tmp148559 '0))
                       (let ((__tmp148560 (current-thread)))
                         (declare (not safe))
                         (##vector-set!
                          __class-type-properties-lock
                          '1
                          __tmp148560))
                       (if (let ()
                             (declare (not safe))
                             (##fx< _%spin145121%_ '10))
                           (let ()
                             (let () (declare (not safe)) (##thread-yield!))
                             (_%again145118%_
                              (let ()
                                (declare (not safe))
                                (##fx+ _%spin145121%_ '1))))
                           (let ((_%owner145127%_
                                  (let ()
                                    (declare (not safe))
                                    (##vector-ref
                                     __class-type-properties-lock
                                     '1))))
                             (if (eq? _%owner145127%_ (macro-current-thread))
                                 (let ()
                                   (declare (not safe))
                                   (##thread-deadlock-action!))
                                 (if (macro-thread-end-condvar _%owner145127%_)
                                     (let ()
                                       (let ()
                                         (declare (not safe))
                                         (##thread-yield!))
                                       (_%again145118%_ '0))
                                     (let ()
                                       (declare (not safe))
                                       (##thread-deadlock-action!)))))))))
               (let ((_%$r145141%_
                      (let* ((_%props145133%_
                              (let ()
                                (declare (not safe))
                                (##unchecked-structure-ref
                                 _%super145114%_
                                 '9
                                 '#f
                                 '#f)))
                             (_%$e145135%_
                              (assq 'subclasses: _%props145133%_)))
                        (if _%$e145135%_
                            (set-cdr!
                             _%$e145135%_
                             (cons _%klass145111%_ (cdr _%$e145135%_)))
                            (let ((__tmp148561
                                   (cons (cons 'subclasses:
                                               (cons _%klass145111%_ '()))
                                         _%props145133%_)))
                              (declare (not safe))
                              (##unchecked-structure-set!
                               _%super145114%_
                               __tmp148561
                               '9
                               '#f
                               '#f))))))
                 (let ()
                   (declare (not interrupts-enabled))
                   (begin
                     (let ()
                       (declare (not safe))
                       (##vector-set! __class-type-properties-lock '1 '#f))
                     (let ()
                       (declare (not safe))
                       (##vector-cas! __class-type-properties-lock '0 '0 '1))))
                 _%$r145141%_))
             (let ()
               (declare (not safe))
               (agetq__% 'direct-supers: _%properties144977%_ '())))
            _%klass145111%_))))
    (define class-type-id
      (lambda (_%klass144970%_)
        (##structure-ref _%klass144970%_ '1 class::t 'id)))
    (define &class-type-id
      (lambda (_%klass144968%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref _%klass144968%_ '1 class::t 'id))))
    (define class-type-id-set!
      (lambda (_%klass144965%_ _%val144966%_)
        (##structure-set! _%klass144965%_ _%val144966%_ '1 class::t 'id)))
    (define &class-type-id-set!
      (lambda (_%klass144960%_ _%val144962%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144960%_
           _%val144962%_
           '1
           class::t
           'id))))
    (define class-type-name
      (lambda (_%klass144958%_)
        (##structure-ref _%klass144958%_ '2 class::t 'name)))
    (define &class-type-name
      (lambda (_%klass144956%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref _%klass144956%_ '2 class::t 'name))))
    (define class-type-name-set!
      (lambda (_%klass144953%_ _%val144954%_)
        (##structure-set! _%klass144953%_ _%val144954%_ '2 class::t 'name)))
    (define &class-type-name-set!
      (lambda (_%klass144948%_ _%val144950%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144948%_
           _%val144950%_
           '2
           class::t
           'name))))
    (define class-type-flags
      (lambda (_%klass144946%_)
        (##structure-ref _%klass144946%_ '3 class::t 'flags)))
    (define &class-type-flags
      (lambda (_%klass144944%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref _%klass144944%_ '3 class::t 'flags))))
    (define class-type-flags-set!
      (lambda (_%klass144941%_ _%val144942%_)
        (##structure-set! _%klass144941%_ _%val144942%_ '3 class::t 'flags)))
    (define &class-type-flags-set!
      (lambda (_%klass144936%_ _%val144938%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144936%_
           _%val144938%_
           '3
           class::t
           'flags))))
    (define class-type-super
      (lambda (_%klass144934%_)
        (##structure-ref _%klass144934%_ '4 class::t 'super)))
    (define &class-type-super
      (lambda (_%klass144932%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref _%klass144932%_ '4 class::t 'super))))
    (define class-type-super-set!
      (lambda (_%klass144929%_ _%val144930%_)
        (##structure-set! _%klass144929%_ _%val144930%_ '4 class::t 'super)))
    (define &class-type-super-set!
      (lambda (_%klass144924%_ _%val144926%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144924%_
           _%val144926%_
           '4
           class::t
           'super))))
    (define class-type-fields
      (lambda (_%klass144922%_)
        (##structure-ref _%klass144922%_ '5 class::t 'fields)))
    (define &class-type-fields
      (lambda (_%klass144920%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref _%klass144920%_ '5 class::t 'fields))))
    (define class-type-fields-set!
      (lambda (_%klass144917%_ _%val144918%_)
        (##structure-set! _%klass144917%_ _%val144918%_ '5 class::t 'fields)))
    (define &class-type-fields-set!
      (lambda (_%klass144912%_ _%val144914%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144912%_
           _%val144914%_
           '5
           class::t
           'fields))))
    (define class-type-precedence-list
      (lambda (_%klass144910%_)
        (##structure-ref _%klass144910%_ '6 class::t 'precedence-list)))
    (define &class-type-precedence-list
      (lambda (_%klass144908%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref
           _%klass144908%_
           '6
           class::t
           'precedence-list))))
    (define class-type-precedence-list-set!
      (lambda (_%klass144905%_ _%val144906%_)
        (##structure-set!
         _%klass144905%_
         _%val144906%_
         '6
         class::t
         'precedence-list)))
    (define &class-type-precedence-list-set!
      (lambda (_%klass144900%_ _%val144902%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144900%_
           _%val144902%_
           '6
           class::t
           'precedence-list))))
    (define class-type-slot-vector
      (lambda (_%klass144898%_)
        (##structure-ref _%klass144898%_ '7 class::t 'slot-vector)))
    (define &class-type-slot-vector
      (lambda (_%klass144896%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref
           _%klass144896%_
           '7
           class::t
           'slot-vector))))
    (define class-type-slot-vector-set!
      (lambda (_%klass144893%_ _%val144894%_)
        (##structure-set!
         _%klass144893%_
         _%val144894%_
         '7
         class::t
         'slot-vector)))
    (define &class-type-slot-vector-set!
      (lambda (_%klass144888%_ _%val144890%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144888%_
           _%val144890%_
           '7
           class::t
           'slot-vector))))
    (define class-type-slot-table
      (lambda (_%klass144886%_)
        (##structure-ref _%klass144886%_ '8 class::t 'slot-table)))
    (define &class-type-slot-table
      (lambda (_%klass144884%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref
           _%klass144884%_
           '8
           class::t
           'slot-table))))
    (define class-type-slot-table-set!
      (lambda (_%klass144881%_ _%val144882%_)
        (##structure-set!
         _%klass144881%_
         _%val144882%_
         '8
         class::t
         'slot-table)))
    (define &class-type-slot-table-set!
      (lambda (_%klass144876%_ _%val144878%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144876%_
           _%val144878%_
           '8
           class::t
           'slot-table))))
    (define class-type-properties
      (lambda (_%klass144874%_)
        (##structure-ref _%klass144874%_ '9 class::t 'properties)))
    (define &class-type-properties
      (lambda (_%klass144872%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref
           _%klass144872%_
           '9
           class::t
           'properties))))
    (define class-type-properties-set!
      (lambda (_%klass144869%_ _%val144870%_)
        (##structure-set!
         _%klass144869%_
         _%val144870%_
         '9
         class::t
         'properties)))
    (define &class-type-properties-set!
      (lambda (_%klass144864%_ _%val144866%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144864%_
           _%val144866%_
           '9
           class::t
           'properties))))
    (define class-type-constructor
      (lambda (_%klass144862%_)
        (##structure-ref _%klass144862%_ '10 class::t 'constructor)))
    (define &class-type-constructor
      (lambda (_%klass144860%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref
           _%klass144860%_
           '10
           class::t
           'constructor))))
    (define class-type-constructor-set!
      (lambda (_%klass144857%_ _%val144858%_)
        (##structure-set!
         _%klass144857%_
         _%val144858%_
         '10
         class::t
         'constructor)))
    (define &class-type-constructor-set!
      (lambda (_%klass144852%_ _%val144854%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144852%_
           _%val144854%_
           '10
           class::t
           'constructor))))
    (define class-type-methods
      (lambda (_%klass144850%_)
        (##structure-ref _%klass144850%_ '11 class::t 'methods)))
    (define &class-type-methods
      (lambda (_%klass144848%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref _%klass144848%_ '11 class::t 'methods))))
    (define class-type-methods-set!
      (lambda (_%klass144845%_ _%val144846%_)
        (##structure-set!
         _%klass144845%_
         _%val144846%_
         '11
         class::t
         'methods)))
    (define &class-type-methods-set!
      (lambda (_%klass144840%_ _%val144842%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144840%_
           _%val144842%_
           '11
           class::t
           'methods))))
    (define class-type-specializer
      (lambda (_%klass144838%_)
        (##structure-ref _%klass144838%_ '12 class::t 'specializer)))
    (define &class-type-specializer
      (lambda (_%klass144836%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref
           _%klass144836%_
           '12
           class::t
           'specializer))))
    (define class-type-specializer-set!
      (lambda (_%klass144833%_ _%val144834%_)
        (##structure-set!
         _%klass144833%_
         _%val144834%_
         '12
         class::t
         'specializer)))
    (define &class-type-specializer-set!
      (lambda (_%klass144828%_ _%val144830%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144828%_
           _%val144830%_
           '12
           class::t
           'specializer))))
    (define class-type-interface
      (lambda (_%klass144826%_)
        (##structure-ref _%klass144826%_ '13 class::t 'interface)))
    (define &class-type-interface
      (lambda (_%klass144824%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref
           _%klass144824%_
           '13
           class::t
           'interface))))
    (define class-type-interface-set!
      (lambda (_%klass144821%_ _%val144822%_)
        (##structure-set!
         _%klass144821%_
         _%val144822%_
         '13
         class::t
         'interface)))
    (define &class-type-interface-set!
      (lambda (_%klass144816%_ _%val144818%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%klass144816%_
           _%val144818%_
           '13
           class::t
           'interface))))
    (define type-field-list
      (lambda (_%type144580%_)
        (letrec ((_%__fields->list144710%_
                  (lambda (_%fields144774%_)
                    (let* ((_%fields144777%_ _%fields144774%_)
                           (_%fields-len144786%_
                            (let ()
                              (declare (not safe))
                              (##vector-length _%fields144777%_))))
                      (let _%loop144788%_ ((_%i144790%_ '0) (_%r144791%_ '()))
                        (let* ((_%i144794%_ _%i144790%_)
                               (_%r144807%_ _%r144791%_))
                          (if (let ()
                                (declare (not safe))
                                (##fx< _%i144794%_ _%fields-len144786%_))
                              (_%loop144788%_
                               (let ()
                                 (declare (not safe))
                                 (##fx+ _%i144794%_ '3))
                               (cons (vector-ref _%fields144777%_ _%i144794%_)
                                     _%r144807%_))
                              (reverse! _%r144807%_)))))))
                 (_%fields->list144711%_
                  (lambda (_%fields144762%_)
                    (let ((_%fields144765%_ _%fields144762%_))
                      (_%__fields->list144710%_ _%fields144765%_)))))
          (let _%loop144713%_ ((_%type144715%_ _%type144580%_))
            (if (let () (declare (not safe)) (##type? _%type144715%_))
                (if (eq? _%type144715%_ ##type-type)
                    '()
                    (let ((_%$e144720%_
                           (let ()
                             (declare (not safe))
                             (##type-super _%type144715%_))))
                      (if _%$e144720%_
                          (let ((__tmp148563 (_%loop144713%_ _%$e144720%_))
                                (__tmp148562
                                 (let* ((_%fields144726%_
                                         (let ()
                                           (declare (not safe))
                                           (##type-fields _%type144715%_)))
                                        (_%fields144730%_ _%fields144726%_))
                                   (_%__fields->list144710%_
                                    _%fields144730%_))))
                            (declare (not safe))
                            (##append __tmp148563 __tmp148562))
                          (let* ((_%fields144747%_
                                  (let ()
                                    (declare (not safe))
                                    (##type-fields _%type144715%_)))
                                 (_%fields144751%_ _%fields144747%_))
                            (_%__fields->list144710%_ _%fields144751%_)))))
                '())))))
    (define __class-type-field-list
      (lambda (_%klass144548%_)
        (let ((_%klass144551%_ _%klass144548%_))
          (letrec ((_%get-fields!144560%_
                    (lambda (_%klass144575%_ _%type144576%_)
                      (let ((_%fields144578%_
                             (type-field-list _%type144576%_)))
                        (##structure-set!
                         _%klass144575%_
                         (cons (cons 'fields: _%fields144578%_)
                               (##structure-ref
                                _%klass144575%_
                                '9
                                class::t
                                '#f))
                         '9
                         class::t
                         '#f)
                        _%fields144578%_))))
            (let* ((_%props144562%_
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-ref _%klass144551%_ '9 '#f '#f)))
                   (_%$e144564%_
                    (let ()
                      (declare (not safe))
                      (agetq__0 'fields: _%props144562%_))))
              (if _%$e144564%_
                  _%$e144564%_
                  (let ((_%$e144567%_
                         (let ()
                           (declare (not safe))
                           (agetq__0 'system-type: _%props144562%_))))
                    (if _%$e144567%_
                        (_%get-fields!144560%_ _%klass144551%_ _%$e144567%_)
                        (_%get-fields!144560%_
                         _%klass144551%_
                         _%klass144551%_)))))))))
    (define class-type-field-list
      (lambda (_%klass144534%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass144534%_ 'class))
            (let ((_%klass144538%_ _%klass144534%_))
              (__class-type-field-list _%klass144538%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@427.30-427.35"
               'contract:
               'class-type?
               'value:
               _%klass144534%_)
              '#!void))))
    (define __class-type-slot-list
      (lambda (_%klass144522%_)
        (let ((_%klass144525%_ _%klass144522%_))
          (vector->list
           (let ()
             (declare (not safe))
             (##unchecked-structure-ref _%klass144525%_ '7 '#f '#f))
           '1))))
    (define class-type-slot-list
      (lambda (_%klass144508%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass144508%_ 'class))
            (let ((_%klass144512%_ _%klass144508%_))
              (__class-type-slot-list _%klass144512%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@443.29-443.34"
               'contract:
               'class-type?
               'value:
               _%klass144508%_)
              '#!void))))
    (define __class-type-field-count
      (lambda (_%klass144496%_)
        (let* ((_%klass144499%_ _%klass144496%_)
               (__tmp148564
                (let ((__tmp148565
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%klass144499%_
                          '7
                          '#f
                          '#f))))
                  (declare (not safe))
                  (##vector-length __tmp148565))))
          (declare (not safe))
          (##fx- __tmp148564 '1))))
    (define class-type-field-count
      (lambda (_%klass144482%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass144482%_ 'class))
            (let ((_%klass144486%_ _%klass144482%_))
              (__class-type-field-count _%klass144486%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@445.31-445.36"
               'contract:
               'class-type?
               'value:
               _%klass144482%_)
              '#!void))))
    (define __class-type-seal!
      (lambda (_%klass144470%_)
        (let ((_%klass144473%_ _%klass144470%_))
          (let ((__tmp148566
                 (let ((__tmp148567
                        (let ()
                          (declare (not safe))
                          (##type-flags _%klass144473%_))))
                   (declare (not safe))
                   (##fxior class-type-flag-sealed __tmp148567))))
            (declare (not safe))
            (##unchecked-structure-set!
             _%klass144473%_
             __tmp148566
             '3
             class::t
             class-type-seal!))
          '#!void)))
    (define class-type-seal!
      (lambda (_%klass144456%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass144456%_ 'class))
            (let ((_%klass144460%_ _%klass144456%_))
              (__class-type-seal! _%klass144460%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@448.25-448.30"
               'contract:
               'class-type?
               'value:
               _%klass144456%_)
              '#!void))))
    (define __class-type-properties-lock (vector '0 '#f))
    (define __class-type-properties-put!
      (lambda (_%klass144410%_ _%key144411%_ _%val144412%_)
        (let* ((_%klass144415%_ _%klass144410%_) (_%key144423%_ _%key144411%_))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again144434%_ ((_%spin144437%_ '0))
              (if (let ((__tmp148568
                         (let ()
                           (declare (not safe))
                           (##vector-cas!
                            __class-type-properties-lock
                            '0
                            '1
                            '0))))
                    (declare (not safe))
                    (##fx= __tmp148568 '0))
                  (let ((__tmp148569 (current-thread)))
                    (declare (not safe))
                    (##vector-set!
                     __class-type-properties-lock
                     '1
                     __tmp148569))
                  (if (let () (declare (not safe)) (##fx< _%spin144437%_ '10))
                      (let ()
                        (let () (declare (not safe)) (##thread-yield!))
                        (_%again144434%_
                         (let ()
                           (declare (not safe))
                           (##fx+ _%spin144437%_ '1))))
                      (let ((_%owner144443%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref
                                __class-type-properties-lock
                                '1))))
                        (if (eq? _%owner144443%_ (macro-current-thread))
                            (let ()
                              (declare (not safe))
                              (##thread-deadlock-action!))
                            (if (macro-thread-end-condvar _%owner144443%_)
                                (let ()
                                  (let ()
                                    (declare (not safe))
                                    (##thread-yield!))
                                  (_%again144434%_ '0))
                                (let ()
                                  (declare (not safe))
                                  (##thread-deadlock-action!)))))))))
          (let ((_%$r144451%_
                 (let ((_%props144449%_
                        (let ()
                          (declare (not safe))
                          (##unchecked-structure-ref
                           _%klass144415%_
                           '9
                           '#f
                           '#f))))
                   (if (assq _%key144423%_ _%props144449%_)
                       '#!void
                       (let ((__tmp148570
                              (cons (cons _%key144423%_ _%val144412%_)
                                    _%props144449%_)))
                         (declare (not safe))
                         (##unchecked-structure-set!
                          _%klass144415%_
                          __tmp148570
                          '9
                          '#f
                          '#f))))))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (let ()
                  (declare (not safe))
                  (##vector-set! __class-type-properties-lock '1 '#f))
                (let ()
                  (declare (not safe))
                  (##vector-cas! __class-type-properties-lock '0 '0 '1))))
            _%$r144451%_))))
    (define class-type-properties-put!
      (lambda (_%klass144384%_ _%key144385%_ _%val144386%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass144384%_ 'class))
            (let ((_%klass144390%_ _%klass144384%_))
              (if (keyword? _%key144385%_)
                  (let ((_%key144400%_ _%key144385%_))
                    (__class-type-properties-put!
                     _%klass144390%_
                     _%key144400%_
                     _%val144386%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@456.52-456.55"
                     'contract:
                     'keyword?
                     'value:
                     _%key144385%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@456.35-456.40"
               'contract:
               'class-type?
               'value:
               _%klass144384%_)
              '#!void))))
    (define __class-type-printable-slots
      (lambda (_%klass144278%_)
        (let ((_%klass144281%_ _%klass144278%_))
          (letrec ((_%get-field-vector144290%_
                    (lambda (_%type144368%_)
                      (let _%loop144370%_ ((_%type144372%_ _%type144368%_))
                        (let* ((_%fields144374%_
                                (let ()
                                  (declare (not safe))
                                  (##type-fields _%type144372%_)))
                               (_%$e144376%_
                                (let ()
                                  (declare (not safe))
                                  (##type-super _%type144372%_))))
                          (if _%$e144376%_
                              (let ((_%super-fields144381%_
                                     (_%loop144370%_ _%$e144376%_)))
                                (vector-append
                                 _%super-fields144381%_
                                 _%fields144374%_))
                              _%fields144374%_)))))
                   (_%get-printable-slot-alist144291%_
                    (lambda (_%type144351%_)
                      (let* ((_%fields144353%_
                              (_%get-field-vector144290%_ _%type144351%_))
                             (_%count144355%_
                              (vector-length _%fields144353%_)))
                        (let _%loop144358%_ ((_%i144360%_ '0)
                                             (_%offset144361%_ '1)
                                             (_%r144362%_ '()))
                          (if (let ()
                                (declare (not safe))
                                (##fx< _%i144360%_ _%count144355%_))
                              (let ((_%slot-name144364%_
                                     (vector-ref _%fields144353%_ _%i144360%_))
                                    (_%slot-flags144365%_
                                     (vector-ref
                                      _%fields144353%_
                                      (let ()
                                        (declare (not safe))
                                        (##fx+ _%i144360%_ '1))))
                                    (_%next-i144366%_
                                     (let ()
                                       (declare (not safe))
                                       (##fx+ _%i144360%_ '3))))
                                (if (let ((__tmp148571
                                           (let ()
                                             (declare (not safe))
                                             (##fxand _%slot-flags144365%_
                                                      '1))))
                                      (declare (not safe))
                                      (##fx= __tmp148571 '0))
                                    (_%loop144358%_
                                     _%next-i144366%_
                                     (let ()
                                       (declare (not safe))
                                       (##fx+ _%offset144361%_ '1))
                                     (cons (cons _%slot-name144364%_
                                                 _%offset144361%_)
                                           _%r144362%_))
                                    (_%loop144358%_
                                     _%next-i144366%_
                                     (let ()
                                       (declare (not safe))
                                       (##fx+ _%offset144361%_ '1))
                                     _%r144362%_)))
                              (reverse! _%r144362%_))))))
                   (_%get-printable-slots!144292%_
                    (lambda (_%klass144307%_ _%type144308%_)
                      (let ((_%printable144310%_
                             (_%get-printable-slot-alist144291%_
                              _%type144308%_)))
                        (let* ((_%klass144312%_ _%klass144307%_)
                               (_%key144315%_ 'printable-slots:)
                               (_%val144318%_ _%printable144310%_))
                          (if (let ()
                                (declare (not safe))
                                (##structure-instance-of?
                                 _%klass144312%_
                                 'class))
                              (let* ((_%klass144323%_ _%klass144312%_)
                                     (_%key144341%_ _%key144315%_))
                                (__class-type-properties-put!
                                 _%klass144323%_
                                 _%key144341%_
                                 _%val144318%_))
                              (begin
                                (raise-contract-violation-error
                                 '"contract violation"
                                 'context:
                                 'gerbil/runtime/mop
                                 'contract:
                                 'class-type?
                                 'value:
                                 _%klass144312%_)
                                '#!void)))
                        _%printable144310%_))))
            (let* ((_%props144294%_
                    (let ()
                      (declare (not safe))
                      (##unchecked-structure-ref _%klass144281%_ '9 '#f '#f)))
                   (_%$e144296%_
                    (let ()
                      (declare (not safe))
                      (agetq__0 'printable-slots: _%props144294%_))))
              (if _%$e144296%_
                  _%$e144296%_
                  (let ((_%$e144299%_
                         (let ()
                           (declare (not safe))
                           (agetq__0 'system-type: _%props144294%_))))
                    (if _%$e144299%_
                        (_%get-printable-slots!144292%_
                         _%klass144281%_
                         _%$e144299%_)
                        (_%get-printable-slots!144292%_
                         _%klass144281%_
                         _%klass144281%_)))))))))
    (define class-type-printable-slots
      (lambda (_%klass144264%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass144264%_ 'class))
            (let ((_%klass144268%_ _%klass144264%_))
              (__class-type-printable-slots _%klass144268%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@465.35-465.40"
               'contract:
               'class-type?
               'value:
               _%klass144264%_)
              '#!void))))
    (define __substruct?
      (lambda (_%maybe-sub-struct144233%_ _%maybe-super-struct144234%_)
        (let* ((_%maybe-sub-struct144237%_ _%maybe-sub-struct144233%_)
               (_%maybe-super-struct144245%_ _%maybe-super-struct144234%_)
               (_%maybe-super-struct-id144254%_
                (let ()
                  (declare (not safe))
                  (##type-id _%maybe-super-struct144245%_))))
          (let _%lp144256%_ ((_%super-struct144258%_
                              _%maybe-sub-struct144237%_))
            (if _%super-struct144258%_
                (if (eq? _%maybe-super-struct-id144254%_
                         (let ()
                           (declare (not safe))
                           (##type-id _%super-struct144258%_)))
                    '#t
                    (_%lp144256%_
                     (let ()
                       (declare (not safe))
                       (##type-super _%super-struct144258%_))))
                '#f)))))
    (define substruct?
      (lambda (_%maybe-sub-struct144208%_ _%maybe-super-struct144209%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%maybe-sub-struct144208%_ 'class))
            (let ((_%maybe-sub-struct144213%_ _%maybe-sub-struct144208%_))
              (if (let ()
                    (declare (not safe))
                    (##structure-instance-of?
                     _%maybe-super-struct144209%_
                     'class))
                  (let ((_%maybe-super-struct144223%_
                         _%maybe-super-struct144209%_))
                    (__substruct?
                     _%maybe-sub-struct144213%_
                     _%maybe-super-struct144223%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@509.47-509.65"
                     'contract:
                     'class-type?
                     'value:
                     _%maybe-super-struct144209%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@509.19-509.35"
               'contract:
               'class-type?
               'value:
               _%maybe-sub-struct144208%_)
              '#!void))))
    (define base-struct/1
      (lambda (_%klass144186%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass144186%_ 'class))
            (if (let* ((_%klass144189%_ _%klass144186%_)
                       (_%klass144194%_ _%klass144189%_))
                  (__class-type-struct? _%klass144194%_))
                _%klass144186%_
                (let () (declare (not safe)) (##type-super _%klass144186%_)))
            (if _%klass144186%_
                (error '"not a class or false" _%klass144186%_)
                '#f))))
    (define base-struct/2
      (lambda (_%klass1144109%_ _%klass2144110%_)
        (let ((_%s1144112%_ (base-struct/1 _%klass1144109%_))
              (_%s2144113%_ (base-struct/1 _%klass2144110%_)))
          (if (or (not _%s1144112%_)
                  (and _%s2144113%_
                       (let* ((_%maybe-sub-struct144118%_ _%s1144112%_)
                              (_%maybe-super-struct144121%_ _%s2144113%_))
                         (if (let ()
                               (declare (not safe))
                               (##structure-instance-of?
                                _%maybe-sub-struct144118%_
                                'class))
                             (let ((_%maybe-sub-struct144126%_
                                    _%maybe-sub-struct144118%_))
                               (if (let ()
                                     (declare (not safe))
                                     (##structure-instance-of?
                                      _%maybe-super-struct144121%_
                                      'class))
                                   (let ((_%maybe-super-struct144140%_
                                          _%maybe-super-struct144121%_))
                                     (__substruct?
                                      _%maybe-sub-struct144126%_
                                      _%maybe-super-struct144140%_))
                                   (begin
                                     (raise-contract-violation-error
                                      '"contract violation"
                                      'context:
                                      'gerbil/runtime/mop
                                      'contract:
                                      'class-type?
                                      'value:
                                      _%maybe-super-struct144121%_)
                                     '#!void)))
                             (begin
                               (raise-contract-violation-error
                                '"contract violation"
                                'context:
                                'gerbil/runtime/mop
                                'contract:
                                'class-type?
                                'value:
                                _%maybe-sub-struct144118%_)
                               '#!void)))))
              _%s2144113%_
              (if (or (not _%s2144113%_)
                      (and _%s1144112%_
                           (let* ((_%maybe-sub-struct144154%_ _%s2144113%_)
                                  (_%maybe-super-struct144157%_ _%s1144112%_))
                             (if (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%maybe-sub-struct144154%_
                                    'class))
                                 (let ((_%maybe-sub-struct144162%_
                                        _%maybe-sub-struct144154%_))
                                   (if (let ()
                                         (declare (not safe))
                                         (##structure-instance-of?
                                          _%maybe-super-struct144157%_
                                          'class))
                                       (let ((_%maybe-super-struct144174%_
                                              _%maybe-super-struct144157%_))
                                         (__substruct?
                                          _%maybe-sub-struct144162%_
                                          _%maybe-super-struct144174%_))
                                       (begin
                                         (raise-contract-violation-error
                                          '"contract violation"
                                          'context:
                                          'gerbil/runtime/mop
                                          'contract:
                                          'class-type?
                                          'value:
                                          _%maybe-super-struct144157%_)
                                         '#!void)))
                                 (begin
                                   (raise-contract-violation-error
                                    '"contract violation"
                                    'context:
                                    'gerbil/runtime/mop
                                    'contract:
                                    'class-type?
                                    'value:
                                    _%maybe-sub-struct144154%_)
                                   '#!void)))))
                  _%s1144112%_
                  (error '"bad mixin: incompatible struct bases"
                         _%klass1144109%_
                         _%klass2144110%_
                         _%s1144112%_
                         _%s2144113%_))))))
    (define base-struct/list
      (lambda (_%all-supers143994%_)
        (let* ((_%$%all-supers143995144020%_ _%all-supers143994%_)
               (_%$%E144000144024%_
                (lambda ()
                  (error '"No clause matching"
                         _%$%all-supers143995144020%_
                         '([])
                         '([x])
                         '([x y])
                         '([x y ...]))
                  '#!void)))
          (let ((_%$%K144018144106%_ (lambda () '#f))
                (_%$%K144015144092%_
                 (lambda (_%x144090%_) (base-struct/1 _%x144090%_)))
                (_%$%K144010144069%_
                 (lambda (_%y144066%_ _%x144067%_)
                   (base-struct/2 _%x144067%_ _%y144066%_)))
                (_%$%K144001144031%_
                 (lambda (_%y144028%_ _%x144029%_)
                   (let ()
                     (declare (not safe))
                     (foldr__0 base-struct/2 _%x144029%_ _%y144028%_)))))
            (let* ((_%__match147331147332%_
                    (lambda (_%$%hd144002144034%_ _%$%tl144003144036%_)
                      (let ((_%x144039%_ _%$%hd144002144034%_))
                        (letrec ((_%$%splice-rest144005144041%_
                                  (lambda (_%$%rest144009144048%_ _%y144050%_)
                                    (if (null? _%$%rest144009144048%_)
                                        (_%$%K144001144031%_
                                         _%y144050%_
                                         _%x144039%_)
                                        (_%$%E144000144024%_))))
                                 (_%$%splice-try144007144043%_
                                  (lambda (_%$%hd144008144052%_
                                           _%$%rest144009144054%_
                                           _%$%y144004144055%_)
                                    (let ((_%y144057%_ _%$%hd144008144052%_))
                                      (_%$%splice-loop144006144045%_
                                       (let ()
                                         (declare (not safe))
                                         (##cdr _%$%rest144009144054%_))
                                       (cons _%y144057%_
                                             _%$%y144004144055%_)))))
                                 (_%$%splice-loop144006144045%_
                                  (lambda (_%$%rest144009144059%_
                                           _%$%y144004144060%_)
                                    (if (pair? _%$%rest144009144059%_)
                                        (_%$%splice-try144007144043%_
                                         (let ()
                                           (declare (not safe))
                                           (##car _%$%rest144009144059%_))
                                         _%$%rest144009144059%_
                                         _%$%y144004144060%_)
                                        (_%$%splice-rest144005144041%_
                                         _%$%rest144009144059%_
                                         (reverse _%$%y144004144060%_))))))
                          (_%$%splice-loop144006144045%_
                           _%$%tl144003144036%_
                           '())))))
                   (_%$%try-match143997144102%_
                    (lambda ()
                      (if (pair? _%$%all-supers143995144020%_)
                          (let ((_%$%tl144017144097%_
                                 (let ()
                                   (declare (not safe))
                                   (##cdr _%$%all-supers143995144020%_)))
                                (_%$%hd144016144095%_
                                 (let ()
                                   (declare (not safe))
                                   (##car _%$%all-supers143995144020%_))))
                            (if (null? _%$%tl144017144097%_)
                                (let ((_%x144100%_ _%$%hd144016144095%_))
                                  (base-struct/1 _%x144100%_))
                                (if (pair? _%$%tl144017144097%_)
                                    (let ((_%$%tl144014144081%_
                                           (let ()
                                             (declare (not safe))
                                             (##cdr _%$%tl144017144097%_)))
                                          (_%$%hd144013144079%_
                                           (let ()
                                             (declare (not safe))
                                             (##car _%$%tl144017144097%_))))
                                      (if (null? _%$%tl144014144081%_)
                                          (let ((_%x144077%_
                                                 _%$%hd144016144095%_)
                                                (_%y144084%_
                                                 _%$%hd144013144079%_))
                                            (_%$%K144010144069%_
                                             _%y144084%_
                                             _%x144077%_))
                                          (_%__match147331147332%_
                                           _%$%hd144016144095%_
                                           _%$%tl144017144097%_)))
                                    (_%__match147331147332%_
                                     _%$%hd144016144095%_
                                     _%$%tl144017144097%_))))
                          (_%$%E144000144024%_)))))
              (if (null? _%$%all-supers143995144020%_)
                  (_%$%K144018144106%_)
                  (_%$%try-match143997144102%_)))))))
    (define base-struct
      (lambda _%all-supers143992%_ (base-struct/list _%all-supers143992%_)))
    (define find-super-constructor
      (lambda (_%super143943%_)
        (let _%lp143945%_ ((_%rest143947%_ _%super143943%_)
                           (_%constructor143948%_ '#f))
          (let* ((_%$%rest143949143957%_ _%rest143947%_)
                 (_%$%else143951143965%_ (lambda () _%constructor143948%_))
                 (_%$%K143953143980%_
                  (lambda (_%rest143968%_ _%hd143969%_)
                    (let ((_%$e143971%_
                           (let ()
                             (declare (not safe))
                             (##unchecked-structure-ref
                              _%hd143969%_
                              '10
                              '#f
                              '#f))))
                      (if _%$e143971%_
                          (if (or (not _%constructor143948%_)
                                  (eq? _%constructor143948%_ _%$e143971%_))
                              (_%lp143945%_ _%rest143968%_ _%$e143971%_)
                              (error '"conflicting implicit constructors"
                                     _%constructor143948%_
                                     _%$e143971%_))
                          (_%lp143945%_
                           _%rest143968%_
                           _%constructor143948%_))))))
            (if (pair? _%$%rest143949143957%_)
                (let ((_%$%hd143954143983%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest143949143957%_)))
                      (_%$%tl143955143985%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest143949143957%_))))
                  (let* ((_%hd143988%_ _%$%hd143954143983%_)
                         (_%rest143990%_ _%$%tl143955143985%_))
                    (_%$%K143953143980%_ _%rest143990%_ _%hd143988%_)))
                (_%$%else143951143965%_))))))
    (define compute-class-slots
      (lambda (_%class-precedence-list143935%_ _%direct-slots143936%_)
        (let ((__tmp148573
               (lambda (_%mixin143938%_)
                 (let ((__tmp148574
                        (let ()
                          (declare (not safe))
                          (##unchecked-structure-ref
                           _%mixin143938%_
                           '9
                           '#f
                           '#f))))
                   (declare (not safe))
                   (agetq__% 'direct-slots: __tmp148574 '()))))
              (__tmp148572
               (lambda (_%slot-list143940%_ _%slot-table143941%_)
                 (values (list->vector _%slot-list143940%_)
                         _%slot-table143941%_))))
          (declare (not safe))
          (c4-compute-class-slots
           _%class-precedence-list143935%_
           _%direct-slots143936%_
           __tmp148573
           __tmp148572))))
    (define __make-class-type
      (lambda (_%id143762%_
               _%name143763%_
               _%direct-supers143764%_
               _%direct-slots143765%_
               _%properties143766%_
               _%constructor143767%_)
        (let* ((_%id143770%_ _%id143762%_)
               (_%name143778%_ _%name143763%_)
               (_%direct-supers143786%_ _%direct-supers143764%_)
               (_%direct-slots143794%_ _%direct-slots143765%_)
               (_%properties143802%_ _%properties143766%_)
               (_%constructor143810%_ _%constructor143767%_))
          (let ((_%$e143844%_
                 (let* ((_%pred143822%_
                         (lambda (_%$obj143819%_)
                           (not (let ()
                                  (declare (not safe))
                                  (##structure-instance-of?
                                   _%$obj143819%_
                                   'class)))))
                        (_%lst143825%_ _%direct-supers143786%_)
                        (_%pred143830%_ _%pred143822%_))
                   (declare (not safe))
                   (__find _%pred143830%_ _%lst143825%_))))
            (if _%$e143844%_
                (error '"Illegal super class; not a class descriptor"
                       _%$e143844%_)
                (let ((_%$e143871%_
                       (let* ((_%pred143851%_ __class-type-final?)
                              (_%lst143854%_ _%direct-supers143786%_)
                              (_%pred143859%_ _%pred143851%_))
                         (declare (not safe))
                         (__find _%pred143859%_ _%lst143854%_))))
                  (if _%$e143871%_
                      (error '"Cannot extend final class" _%$e143871%_)
                      '#!void))))
          (let ((_g148575_ (compute-precedence-list _%direct-supers143786%_)))
            (begin
              (let ((_g148576_
                     (let ()
                       (declare (not safe))
                       (if (##values? _g148575_)
                           (##values-length _g148575_)
                           1))))
                (if (not (let () (declare (not safe)) (##fx= _g148576_ 2)))
                    (error "Context expects 2 values" _g148576_)))
              (let ((_%precedence-list143878%_
                     (let () (declare (not safe)) (##values-ref _g148575_ 0)))
                    (_%struct-super143879%_
                     (let () (declare (not safe)) (##values-ref _g148575_ 1))))
                (let ((_g148577_
                       (compute-class-slots
                        _%precedence-list143878%_
                        _%direct-slots143794%_)))
                  (begin
                    (let ((_g148578_
                           (let ()
                             (declare (not safe))
                             (if (##values? _g148577_)
                                 (##values-length _g148577_)
                                 1))))
                      (if (not (let ()
                                 (declare (not safe))
                                 (##fx= _g148578_ 2)))
                          (error "Context expects 2 values" _g148578_)))
                    (let ((_%slot-vector143881%_
                           (let ()
                             (declare (not safe))
                             (##values-ref _g148577_ 0)))
                          (_%slot-table143882%_
                           (let ()
                             (declare (not safe))
                             (##values-ref _g148577_ 1))))
                      (let* ((_%properties143884%_
                              (cons (cons 'direct-slots:
                                          _%direct-slots143794%_)
                                    (cons (cons 'direct-supers:
                                                _%direct-supers143786%_)
                                          _%properties143802%_)))
                             (_%constructor*143889%_
                              (let ((_%$e143886%_ _%constructor143810%_))
                                (if _%$e143886%_
                                    _%$e143886%_
                                    (find-super-constructor
                                     _%direct-supers143786%_))))
                             (_%precedence-list143932%_
                              (if (or (let ()
                                        (declare (not safe))
                                        (agetq__0
                                         'system:
                                         _%properties143884%_))
                                      (memq object::t
                                            _%precedence-list143878%_))
                                  _%precedence-list143878%_
                                  (let _%loop143894%_ ((_%tail143896%_
                                                        _%precedence-list143878%_)
                                                       (_%head143897%_ '()))
                                    (let* ((_%$%tail143898143906%_
                                            _%tail143896%_)
                                           (_%$%else143900143914%_
                                            (lambda ()
                                              (let ((__tmp148579
                                                     (cons object::t
                                                           (cons t::t '()))))
                                                (declare (not safe))
                                                (foldl__0
                                                 cons
                                                 __tmp148579
                                                 _%head143897%_))))
                                           (_%$%K143902143920%_
                                            (lambda (_%rest143917%_
                                                     _%hd143918%_)
                                              (if (eq? _%hd143918%_ t::t)
                                                  (let ((__tmp148580
                                                         (cons object::t
                                                               _%tail143896%_)))
                                                    (declare (not safe))
                                                    (foldl__0
                                                     cons
                                                     __tmp148580
                                                     _%head143897%_))
                                                  (_%loop143894%_
                                                   _%rest143917%_
                                                   (cons _%hd143918%_
                                                         _%head143897%_))))))
                                      (if (pair? _%$%tail143898143906%_)
                                          (let ((_%$%hd143903143923%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##car _%$%tail143898143906%_)))
                                                (_%$%tl143904143925%_
                                                 (let ()
                                                   (declare (not safe))
                                                   (##cdr _%$%tail143898143906%_))))
                                            (let* ((_%hd143928%_
                                                    _%$%hd143903143923%_)
                                                   (_%rest143930%_
                                                    _%$%tl143904143925%_))
                                              (_%$%K143902143920%_
                                               _%rest143930%_
                                               _%hd143928%_)))
                                          (_%$%else143900143914%_)))))))
                        (make-class-type-descriptor
                         _%id143770%_
                         _%name143778%_
                         _%struct-super143879%_
                         _%precedence-list143932%_
                         _%slot-vector143881%_
                         _%properties143884%_
                         _%constructor*143889%_
                         _%slot-table143882%_
                         '#f)))))))))))
    (define make-class-type
      (lambda (_%id143687%_
               _%name143688%_
               _%direct-supers143689%_
               _%direct-slots143690%_
               _%properties143691%_
               _%constructor143692%_)
        (if (symbol? _%id143687%_)
            (let ((_%id143696%_ _%id143687%_))
              (if (symbol? _%name143688%_)
                  (let ((_%name143706%_ _%name143688%_))
                    (if (list? _%direct-supers143689%_)
                        (let ((_%direct-supers143716%_
                               _%direct-supers143689%_))
                          (if (list? _%direct-slots143690%_)
                              (let ((_%direct-slots143726%_
                                     _%direct-slots143690%_))
                                (if (list? _%properties143691%_)
                                    (let ((_%properties143736%_
                                           _%properties143691%_))
                                      (if (or (not _%constructor143692%_)
                                              (symbol? _%constructor143692%_))
                                          (let ((_%constructor143752%_
                                                 _%constructor143692%_))
                                            (__make-class-type
                                             _%id143696%_
                                             _%name143706%_
                                             _%direct-supers143716%_
                                             _%direct-slots143726%_
                                             _%properties143736%_
                                             _%constructor143752%_))
                                          (begin
                                            (raise-contract-violation-error
                                             '"contract violation"
                                             'context:
                                             '"\"gerbil/runtime/mop.ss\"@590.24-590.35"
                                             'contract:
                                             '(? (or not symbol?))
                                             'value:
                                             _%constructor143692%_)
                                            '#!void)))
                                    (begin
                                      (raise-contract-violation-error
                                       '"contract violation"
                                       'context:
                                       '"\"gerbil/runtime/mop.ss\"@589.24-589.34"
                                       'contract:
                                       'list?
                                       'value:
                                       _%properties143691%_)
                                      '#!void)))
                              (begin
                                (raise-contract-violation-error
                                 '"contract violation"
                                 'context:
                                 '"\"gerbil/runtime/mop.ss\"@588.24-588.36"
                                 'contract:
                                 'list?
                                 'value:
                                 _%direct-slots143690%_)
                                '#!void)))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/mop.ss\"@587.24-587.37"
                           'contract:
                           'list?
                           'value:
                           _%direct-supers143689%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@586.24-586.28"
                     'contract:
                     'symbol?
                     'value:
                     _%name143688%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@585.24-585.26"
               'contract:
               'symbol?
               'value:
               _%id143687%_)
              '#!void))))
    (define __class-precedence-list
      (lambda (_%klass143675%_)
        (let ((_%klass143678%_ _%klass143675%_))
          (cons _%klass143678%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%klass143678%_ '6 '#f '#f))))))
    (define class-precedence-list
      (lambda (_%klass143661%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass143661%_ 'class))
            (let ((_%klass143665%_ _%klass143661%_))
              (__class-precedence-list _%klass143665%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@623.30-623.35"
               'contract:
               'class-type?
               'value:
               _%klass143661%_)
              '#!void))))
    (define compute-precedence-list
      (lambda (_%direct-supers143658%_)
        (let ()
          (declare (not safe))
          (c4-linearize__%
           '#f
           class-precedence-list
           class-type-struct?
           eq?
           ##type-name
           '()
           _%direct-supers143658%_))))
    (define __make-class-predicate
      (lambda (_%klass143574%_)
        (let* ((_%klass143577%_ _%klass143574%_)
               (_%tid143586%_
                (let () (declare (not safe)) (##type-id _%klass143577%_))))
          (if (let* ((_%type143588%_ _%klass143577%_)
                     (_%type143593%_ _%type143588%_))
                (__class-type-final? _%type143593%_))
              (lambda (_%$%g143607143609%_)
                (let ()
                  (declare (not safe))
                  (##structure-direct-instance-of?
                   _%$%g143607143609%_
                   _%tid143586%_)))
              (if (let* ((_%klass143612%_ _%klass143577%_)
                         (_%klass143617%_ _%klass143612%_))
                    (__class-type-struct? _%klass143617%_))
                  (lambda (_%$%g143627143629%_)
                    (let ()
                      (declare (not safe))
                      (##structure-instance-of?
                       _%$%g143627143629%_
                       _%tid143586%_)))
                  (lambda (_%$%g143632143634%_)
                    (let* ((_%klass143637%_ _%klass143577%_)
                           (_%obj143640%_ _%$%g143632143634%_)
                           (_%klass143645%_ _%klass143637%_))
                      (__class-instance? _%klass143645%_ _%obj143640%_))))))))
    (define make-class-predicate
      (lambda (_%klass143560%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass143560%_ 'class))
            (let ((_%klass143564%_ _%klass143560%_))
              (__make-class-predicate _%klass143564%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@635.29-635.34"
               'contract:
               'class-type?
               'value:
               _%klass143560%_)
              '#!void))))
    (define __make-class-slot-accessor
      (lambda (_%klass143494%_ _%slot143495%_)
        (let* ((_%klass143498%_ _%klass143494%_)
               (_%slot143506%_ _%slot143495%_)
               (_%field143515%_
                (let ((__tmp148581
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%klass143498%_
                          '8
                          '#f
                          '#f))))
                  (declare (not safe))
                  (symbolic-table-ref __tmp148581 _%slot143506%_ '#f))))
          (if _%field143515%_
              (if (let* ((_%type143519%_ _%klass143498%_)
                         (_%type143524%_ _%type143519%_))
                    (__class-type-final? _%type143524%_))
                  (make-final-slot-accessor
                   _%klass143498%_
                   _%slot143506%_
                   _%field143515%_)
                  (if (let* ((_%klass143539%_ _%klass143498%_)
                             (_%klass143544%_ _%klass143539%_))
                        (__class-type-struct? _%klass143544%_))
                      (make-struct-slot-accessor
                       _%klass143498%_
                       _%slot143506%_
                       _%field143515%_)
                      (if (let ((_%strukt143555%_
                                 (base-struct/1 _%klass143498%_)))
                            (and (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%strukt143555%_
                                    'class))
                                 (let ((__tmp148582
                                        (let ((__tmp148583
                                               (let ()
                                                 (declare (not safe))
                                                 (##unchecked-structure-ref
                                                  _%strukt143555%_
                                                  '7
                                                  '#f
                                                  '#f))))
                                          (declare (not safe))
                                          (##vector-length __tmp148583))))
                                   (declare (not safe))
                                   (##fx< _%field143515%_ __tmp148582))))
                          (make-struct-subclass-slot-accessor
                           _%klass143498%_
                           _%slot143506%_
                           _%field143515%_)
                          (make-class-cached-slot-accessor
                           _%klass143498%_
                           _%slot143506%_
                           _%field143515%_))))
              (let ()
                (error '"unknown slot"
                       'class:
                       _%klass143498%_
                       'slot:
                       _%slot143506%_)
                '#!void)))))
    (define make-class-slot-accessor
      (lambda (_%klass143469%_ _%slot143470%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass143469%_ 'class))
            (let ((_%klass143474%_ _%klass143469%_))
              (if (symbol? _%slot143470%_)
                  (let ((_%slot143484%_ _%slot143470%_))
                    (__make-class-slot-accessor
                     _%klass143474%_
                     _%slot143484%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@666.50-666.54"
                     'contract:
                     'symbol?
                     'value:
                     _%slot143470%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@666.33-666.38"
               'contract:
               'class-type?
               'value:
               _%klass143469%_)
              '#!void))))
    (define __make-class-slot-mutator
      (lambda (_%klass143403%_ _%slot143404%_)
        (let* ((_%klass143407%_ _%klass143403%_)
               (_%slot143415%_ _%slot143404%_)
               (_%field143424%_
                (let ((__tmp148584
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%klass143407%_
                          '8
                          '#f
                          '#f))))
                  (declare (not safe))
                  (symbolic-table-ref __tmp148584 _%slot143415%_ '#f))))
          (if _%field143424%_
              (if (let* ((_%type143428%_ _%klass143407%_)
                         (_%type143433%_ _%type143428%_))
                    (__class-type-final? _%type143433%_))
                  (make-final-slot-mutator
                   _%klass143407%_
                   _%slot143415%_
                   _%field143424%_)
                  (if (let* ((_%klass143448%_ _%klass143407%_)
                             (_%klass143453%_ _%klass143448%_))
                        (__class-type-struct? _%klass143453%_))
                      (make-struct-slot-mutator
                       _%klass143407%_
                       _%slot143415%_
                       _%field143424%_)
                      (if (let ((_%strukt143464%_
                                 (base-struct/1 _%klass143407%_)))
                            (and (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%strukt143464%_
                                    'class))
                                 (let ((__tmp148585
                                        (let ((__tmp148586
                                               (let ()
                                                 (declare (not safe))
                                                 (##unchecked-structure-ref
                                                  _%strukt143464%_
                                                  '7
                                                  '#f
                                                  '#f))))
                                          (declare (not safe))
                                          (##vector-length __tmp148586))))
                                   (declare (not safe))
                                   (##fx< _%field143424%_ __tmp148585))))
                          (make-struct-subclass-slot-mutator
                           _%klass143407%_
                           _%slot143415%_
                           _%field143424%_)
                          (make-class-cached-slot-mutator
                           _%klass143407%_
                           _%slot143415%_
                           _%field143424%_))))
              (let ()
                (error '"unknown slot"
                       'class:
                       _%klass143407%_
                       'slot:
                       _%slot143415%_)
                '#!void)))))
    (define make-class-slot-mutator
      (lambda (_%klass143378%_ _%slot143379%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass143378%_ 'class))
            (let ((_%klass143383%_ _%klass143378%_))
              (if (symbol? _%slot143379%_)
                  (let ((_%slot143393%_ _%slot143379%_))
                    (__make-class-slot-mutator _%klass143383%_ _%slot143393%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@674.49-674.53"
                     'contract:
                     'symbol?
                     'value:
                     _%slot143379%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@674.32-674.37"
               'contract:
               'class-type?
               'value:
               _%klass143378%_)
              '#!void))))
    (define __make-class-slot-unchecked-accessor
      (lambda (_%klass143312%_ _%slot143313%_)
        (let* ((_%klass143316%_ _%klass143312%_)
               (_%slot143324%_ _%slot143313%_)
               (_%field143333%_
                (let ((__tmp148587
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%klass143316%_
                          '8
                          '#f
                          '#f))))
                  (declare (not safe))
                  (symbolic-table-ref __tmp148587 _%slot143324%_ '#f))))
          (if _%field143333%_
              (if (let* ((_%type143337%_ _%klass143316%_)
                         (_%type143342%_ _%type143337%_))
                    (__class-type-final? _%type143342%_))
                  (make-struct-slot-unchecked-accessor
                   _%klass143316%_
                   _%slot143324%_
                   _%field143333%_)
                  (if (let* ((_%klass143357%_ _%klass143316%_)
                             (_%klass143362%_ _%klass143357%_))
                        (__class-type-struct? _%klass143362%_))
                      (make-struct-slot-unchecked-accessor
                       _%klass143316%_
                       _%slot143324%_
                       _%field143333%_)
                      (if (let ((_%strukt143373%_
                                 (base-struct/1 _%klass143316%_)))
                            (and (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%strukt143373%_
                                    'class))
                                 (let ((__tmp148588
                                        (let ((__tmp148589
                                               (let ()
                                                 (declare (not safe))
                                                 (##unchecked-structure-ref
                                                  _%strukt143373%_
                                                  '7
                                                  '#f
                                                  '#f))))
                                          (declare (not safe))
                                          (##vector-length __tmp148589))))
                                   (declare (not safe))
                                   (##fx< _%field143333%_ __tmp148588))))
                          (make-struct-slot-unchecked-accessor
                           _%klass143316%_
                           _%slot143324%_
                           _%field143333%_)
                          (make-class-cached-slot-unchecked-accessor
                           _%klass143316%_
                           _%slot143324%_
                           _%field143333%_))))
              (let ()
                (error '"unknown slot"
                       'class:
                       _%klass143316%_
                       'slot:
                       _%slot143324%_)
                '#!void)))))
    (define make-class-slot-unchecked-accessor
      (lambda (_%klass143287%_ _%slot143288%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass143287%_ 'class))
            (let ((_%klass143292%_ _%klass143287%_))
              (if (symbol? _%slot143288%_)
                  (let ((_%slot143302%_ _%slot143288%_))
                    (__make-class-slot-unchecked-accessor
                     _%klass143292%_
                     _%slot143302%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@682.60-682.64"
                     'contract:
                     'symbol?
                     'value:
                     _%slot143288%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@682.43-682.48"
               'contract:
               'class-type?
               'value:
               _%klass143287%_)
              '#!void))))
    (define __make-class-slot-unchecked-mutator
      (lambda (_%klass143221%_ _%slot143222%_)
        (let* ((_%klass143225%_ _%klass143221%_)
               (_%slot143233%_ _%slot143222%_)
               (_%field143242%_
                (let ((__tmp148590
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%klass143225%_
                          '8
                          '#f
                          '#f))))
                  (declare (not safe))
                  (symbolic-table-ref __tmp148590 _%slot143233%_ '#f))))
          (if _%field143242%_
              (if (let* ((_%type143246%_ _%klass143225%_)
                         (_%type143251%_ _%type143246%_))
                    (__class-type-final? _%type143251%_))
                  (make-struct-slot-unchecked-mutator
                   _%klass143225%_
                   _%slot143233%_
                   _%field143242%_)
                  (if (let* ((_%klass143266%_ _%klass143225%_)
                             (_%klass143271%_ _%klass143266%_))
                        (__class-type-struct? _%klass143271%_))
                      (make-struct-slot-unchecked-mutator
                       _%klass143225%_
                       _%slot143233%_
                       _%field143242%_)
                      (if (let ((_%strukt143282%_
                                 (base-struct/1 _%klass143225%_)))
                            (and (let ()
                                   (declare (not safe))
                                   (##structure-instance-of?
                                    _%strukt143282%_
                                    'class))
                                 (let ((__tmp148591
                                        (let ((__tmp148592
                                               (let ()
                                                 (declare (not safe))
                                                 (##unchecked-structure-ref
                                                  _%strukt143282%_
                                                  '7
                                                  '#f
                                                  '#f))))
                                          (declare (not safe))
                                          (##vector-length __tmp148592))))
                                   (declare (not safe))
                                   (##fx< _%field143242%_ __tmp148591))))
                          (make-struct-slot-unchecked-mutator
                           _%klass143225%_
                           _%slot143233%_
                           _%field143242%_)
                          (make-class-cached-slot-unchecked-mutator
                           _%klass143225%_
                           _%slot143233%_
                           _%field143242%_))))
              (let ()
                (error '"unknown slot"
                       'class:
                       _%klass143225%_
                       'slot:
                       _%slot143233%_)
                '#!void)))))
    (define make-class-slot-unchecked-mutator
      (lambda (_%klass143196%_ _%slot143197%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass143196%_ 'class))
            (let ((_%klass143201%_ _%klass143196%_))
              (if (symbol? _%slot143197%_)
                  (let ((_%slot143211%_ _%slot143197%_))
                    (__make-class-slot-unchecked-mutator
                     _%klass143201%_
                     _%slot143211%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@690.59-690.63"
                     'contract:
                     'symbol?
                     'value:
                     _%slot143197%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@690.42-690.47"
               'contract:
               'class-type?
               'value:
               _%klass143196%_)
              '#!void))))
    (define not-an-instance__%
      (lambda (_%object143180%_ _%class143181%_ _%slot143182%_)
        (apply error
               '"not an instance"
               'object:
               _%object143180%_
               'class:
               _%class143181%_
               (if _%slot143182%_
                   (cons 'slot: (cons _%slot143182%_ '()))
                   '()))))
    (define not-an-instance__0
      (lambda (_%object143187%_ _%class143188%_)
        (let ((_%slot143190%_ '#f))
          (not-an-instance__%
           _%object143187%_
           _%class143188%_
           _%slot143190%_))))
    (define not-an-instance
      (lambda _g148593_
        (let ((_g148594_ (let () (declare (not safe)) (##length _g148593_))))
          (cond ((let () (declare (not safe)) (##fx= _g148594_ 2))
                 (apply not-an-instance__0 _g148593_))
                ((let () (declare (not safe)) (##fx= _g148594_ 3))
                 (apply not-an-instance__% _g148593_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  not-an-instance
                  _g148593_))))))
    (define make-final-slot-accessor
      (lambda (_%klass143173%_ _%slot143174%_ _%field143175%_)
        (lambda (_%obj143177%_)
          (##direct-structure-ref
           _%obj143177%_
           _%field143175%_
           _%klass143173%_
           _%slot143174%_))))
    (define make-final-slot-mutator
      (lambda (_%klass143166%_ _%slot143167%_ _%field143168%_)
        (lambda (_%obj143170%_ _%val143171%_)
          (##direct-structure-set!
           _%obj143170%_
           _%val143171%_
           _%field143168%_
           _%klass143166%_
           _%slot143167%_))))
    (define make-struct-slot-accessor
      (lambda (_%klass143160%_ _%slot143161%_ _%field143162%_)
        (lambda (_%obj143164%_)
          (##structure-ref
           _%obj143164%_
           _%field143162%_
           _%klass143160%_
           _%slot143161%_))))
    (define make-struct-slot-mutator
      (lambda (_%klass143153%_ _%slot143154%_ _%field143155%_)
        (lambda (_%obj143157%_ _%val143158%_)
          (##structure-set!
           _%obj143157%_
           _%val143158%_
           _%field143155%_
           _%klass143153%_
           _%slot143154%_))))
    (define make-struct-slot-unchecked-accessor
      (lambda (_%klass143147%_ _%slot143148%_ _%field143149%_)
        (lambda (_%obj143151%_)
          (let ()
            (declare (not safe))
            (##unchecked-structure-ref
             _%obj143151%_
             _%field143149%_
             _%klass143147%_
             _%slot143148%_)))))
    (define make-struct-slot-unchecked-mutator
      (lambda (_%klass143140%_ _%slot143141%_ _%field143142%_)
        (lambda (_%obj143144%_ _%val143145%_)
          (let ()
            (declare (not safe))
            (##unchecked-structure-set!
             _%obj143144%_
             _%val143145%_
             _%field143142%_
             _%klass143140%_
             _%slot143141%_)))))
    (define make-struct-subclass-slot-accessor
      (lambda (_%klass143113%_ _%slot143114%_ _%field143115%_)
        (lambda (_%obj143117%_)
          (if (let* ((_%klass143119%_ _%klass143113%_)
                     (_%obj143122%_ _%obj143117%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%klass143119%_ 'class))
                    (let ((_%klass143127%_ _%klass143119%_))
                      (__class-instance? _%klass143127%_ _%obj143122%_))
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/mop
                       'contract:
                       'class-type?
                       'value:
                       _%klass143119%_)
                      '#!void)))
              (unchecked-slot-ref _%obj143117%_ _%field143115%_)
              (not-an-instance__%
               _%obj143117%_
               _%klass143113%_
               _%slot143114%_)))))
    (define make-struct-subclass-slot-mutator
      (lambda (_%klass143085%_ _%slot143086%_ _%field143087%_)
        (lambda (_%obj143089%_ _%val143090%_)
          (if (let* ((_%klass143092%_ _%klass143085%_)
                     (_%obj143095%_ _%obj143089%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%klass143092%_ 'class))
                    (let ((_%klass143100%_ _%klass143092%_))
                      (__class-instance? _%klass143100%_ _%obj143095%_))
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/mop
                       'contract:
                       'class-type?
                       'value:
                       _%klass143092%_)
                      '#!void)))
              (unchecked-field-set!
               _%obj143089%_
               _%field143087%_
               _%val143090%_)
              (not-an-instance__%
               _%obj143089%_
               _%klass143085%_
               _%slot143086%_)))))
    (define make-class-cached-slot-accessor
      (lambda (_%klass143036%_ _%slot143037%_ _%field143038%_)
        (lambda (_%obj143040%_)
          (if (let* ((_%klass143042%_ _%klass143036%_)
                     (_%obj143045%_ _%obj143040%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%klass143042%_ 'class))
                    (let ((_%klass143050%_ _%klass143042%_))
                      (__direct-instance? _%klass143050%_ _%obj143045%_))
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/mop
                       'contract:
                       'class-type?
                       'value:
                       _%klass143042%_)
                      '#!void)))
              (unchecked-field-ref _%obj143040%_ _%field143038%_)
              (if (let* ((_%klass143064%_ _%klass143036%_)
                         (_%obj143067%_ _%obj143040%_))
                    (if (let ()
                          (declare (not safe))
                          (##structure-instance-of? _%klass143064%_ 'class))
                        (let ((_%klass143072%_ _%klass143064%_))
                          (__class-instance? _%klass143072%_ _%obj143067%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           'gerbil/runtime/mop
                           'contract:
                           'class-type?
                           'value:
                           _%klass143064%_)
                          '#!void)))
                  (unchecked-slot-ref _%obj143040%_ _%slot143037%_)
                  (not-an-instance__%
                   _%obj143040%_
                   _%klass143036%_
                   _%slot143037%_))))))
    (define make-class-cached-slot-mutator
      (lambda (_%klass142986%_ _%slot142987%_ _%field142988%_)
        (lambda (_%obj142990%_ _%val142991%_)
          (if (let* ((_%klass142993%_ _%klass142986%_)
                     (_%obj142996%_ _%obj142990%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%klass142993%_ 'class))
                    (let ((_%klass143001%_ _%klass142993%_))
                      (__direct-instance? _%klass143001%_ _%obj142996%_))
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/mop
                       'contract:
                       'class-type?
                       'value:
                       _%klass142993%_)
                      '#!void)))
              (unchecked-field-set!
               _%obj142990%_
               _%field142988%_
               _%val142991%_)
              (if (let* ((_%klass143015%_ _%klass142986%_)
                         (_%obj143018%_ _%obj142990%_))
                    (if (let ()
                          (declare (not safe))
                          (##structure-instance-of? _%klass143015%_ 'class))
                        (let ((_%klass143023%_ _%klass143015%_))
                          (__class-instance? _%klass143023%_ _%obj143018%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           'gerbil/runtime/mop
                           'contract:
                           'class-type?
                           'value:
                           _%klass143015%_)
                          '#!void)))
                  (unchecked-slot-set!
                   _%obj142990%_
                   _%slot142987%_
                   _%val142991%_)
                  (not-an-instance__%
                   _%obj142990%_
                   _%klass142986%_
                   _%slot142987%_))))))
    (define make-class-cached-slot-unchecked-accessor
      (lambda (_%klass142959%_ _%slot142960%_ _%field142961%_)
        (lambda (_%obj142963%_)
          (if (let* ((_%klass142965%_ _%klass142959%_)
                     (_%obj142968%_ _%obj142963%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%klass142965%_ 'class))
                    (let ((_%klass142973%_ _%klass142965%_))
                      (__direct-instance? _%klass142973%_ _%obj142968%_))
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/mop
                       'contract:
                       'class-type?
                       'value:
                       _%klass142965%_)
                      '#!void)))
              (unchecked-field-ref _%obj142963%_ _%field142961%_)
              (unchecked-slot-ref _%obj142963%_ _%slot142960%_)))))
    (define make-class-cached-slot-unchecked-mutator
      (lambda (_%klass142931%_ _%slot142932%_ _%field142933%_)
        (lambda (_%obj142935%_ _%val142936%_)
          (if (let* ((_%klass142938%_ _%klass142931%_)
                     (_%obj142941%_ _%obj142935%_))
                (if (let ()
                      (declare (not safe))
                      (##structure-instance-of? _%klass142938%_ 'class))
                    (let ((_%klass142946%_ _%klass142938%_))
                      (__direct-instance? _%klass142946%_ _%obj142941%_))
                    (begin
                      (raise-contract-violation-error
                       '"contract violation"
                       'context:
                       'gerbil/runtime/mop
                       'contract:
                       'class-type?
                       'value:
                       _%klass142938%_)
                      '#!void)))
              (unchecked-field-set!
               _%obj142935%_
               _%field142933%_
               _%val142936%_)
              (unchecked-slot-set!
               _%obj142935%_
               _%slot142932%_
               _%val142936%_)))))
    (define __class-slot-offset
      (lambda (_%klass142910%_ _%slot142911%_)
        (let* ((_%klass142914%_ _%klass142910%_)
               (_%slot142922%_ _%slot142911%_)
               (__tmp148595
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%klass142914%_ '8 '#f '#f))))
          (declare (not safe))
          (symbolic-table-ref __tmp148595 _%slot142922%_ '#f))))
    (define class-slot-offset
      (lambda (_%klass142885%_ _%slot142886%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass142885%_ 'class))
            (let ((_%klass142890%_ _%klass142885%_))
              (if (let () (declare (not safe)) (symbolic? _%slot142886%_))
                  (let ((_%slot142900%_ _%slot142886%_))
                    (__class-slot-offset _%klass142890%_ _%slot142900%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@752.43-752.47"
                     'contract:
                     'symbolic?
                     'value:
                     _%slot142886%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@752.26-752.31"
               'contract:
               'class-type?
               'value:
               _%klass142885%_)
              '#!void))))
    (define __class-slot-ref
      (lambda (_%klass142810%_ _%obj142811%_ _%slot142812%_)
        (let* ((_%klass142815%_ _%klass142810%_)
               (_%slot142823%_ _%slot142812%_))
          (if (let* ((_%klass142832%_ _%klass142815%_)
                     (_%obj142835%_ _%obj142811%_)
                     (_%klass142840%_ _%klass142832%_))
                (__class-instance? _%klass142840%_ _%obj142835%_))
              (let ((_%off142883%_
                     (let* ((_%klass142854%_
                             (let ()
                               (declare (not safe))
                               (##structure-type _%obj142811%_)))
                            (_%slot142857%_ _%slot142823%_))
                       (if (let ()
                             (declare (not safe))
                             (##structure-instance-of? _%klass142854%_ 'class))
                           (let ((_%klass142862%_ _%klass142854%_))
                             (if (let ()
                                   (declare (not safe))
                                   (symbolic? _%slot142857%_))
                                 (let ((_%slot142873%_ _%slot142857%_))
                                   (__class-slot-offset
                                    _%klass142862%_
                                    _%slot142873%_))
                                 (begin
                                   (raise-contract-violation-error
                                    '"contract violation"
                                    'context:
                                    'gerbil/runtime/mop
                                    'contract:
                                    'symbolic?
                                    'value:
                                    _%slot142857%_)
                                   '#!void)))
                           (begin
                             (raise-contract-violation-error
                              '"contract violation"
                              'context:
                              'gerbil/runtime/mop
                              'contract:
                              'class-type?
                              'value:
                              _%klass142854%_)
                             '#!void)))))
                (declare (not safe))
                (##unchecked-structure-ref
                 _%obj142811%_
                 _%off142883%_
                 _%klass142815%_
                 _%slot142823%_))
              (not-an-instance__0 _%obj142811%_ _%klass142815%_)))))
    (define class-slot-ref
      (lambda (_%klass142784%_ _%obj142785%_ _%slot142786%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass142784%_ 'class))
            (let ((_%klass142790%_ _%klass142784%_))
              (if (let () (declare (not safe)) (symbolic? _%slot142786%_))
                  (let ((_%slot142800%_ _%slot142786%_))
                    (__class-slot-ref
                     _%klass142790%_
                     _%obj142785%_
                     _%slot142800%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@755.44-755.48"
                     'contract:
                     'symbolic?
                     'value:
                     _%slot142786%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@755.23-755.28"
               'contract:
               'class-type?
               'value:
               _%klass142784%_)
              '#!void))))
    (define __class-slot-set!
      (lambda (_%klass142708%_ _%obj142709%_ _%slot142710%_ _%val142711%_)
        (let* ((_%klass142714%_ _%klass142708%_)
               (_%slot142722%_ _%slot142710%_))
          (if (let* ((_%klass142731%_ _%klass142714%_)
                     (_%obj142734%_ _%obj142709%_)
                     (_%klass142739%_ _%klass142731%_))
                (__class-instance? _%klass142739%_ _%obj142734%_))
              (let ((_%off142782%_
                     (let* ((_%klass142753%_
                             (let ()
                               (declare (not safe))
                               (##structure-type _%obj142709%_)))
                            (_%slot142756%_ _%slot142722%_))
                       (if (let ()
                             (declare (not safe))
                             (##structure-instance-of? _%klass142753%_ 'class))
                           (let ((_%klass142761%_ _%klass142753%_))
                             (if (let ()
                                   (declare (not safe))
                                   (symbolic? _%slot142756%_))
                                 (let ((_%slot142772%_ _%slot142756%_))
                                   (__class-slot-offset
                                    _%klass142761%_
                                    _%slot142772%_))
                                 (begin
                                   (raise-contract-violation-error
                                    '"contract violation"
                                    'context:
                                    'gerbil/runtime/mop
                                    'contract:
                                    'symbolic?
                                    'value:
                                    _%slot142756%_)
                                   '#!void)))
                           (begin
                             (raise-contract-violation-error
                              '"contract violation"
                              'context:
                              'gerbil/runtime/mop
                              'contract:
                              'class-type?
                              'value:
                              _%klass142753%_)
                             '#!void)))))
                (declare (not safe))
                (##unchecked-structure-set!
                 _%obj142709%_
                 _%val142711%_
                 _%off142782%_
                 _%klass142714%_
                 _%slot142722%_))
              (not-an-instance__0 _%obj142709%_ _%klass142714%_)))))
    (define class-slot-set!
      (lambda (_%klass142681%_ _%obj142682%_ _%slot142683%_ _%val142684%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass142681%_ 'class))
            (let ((_%klass142688%_ _%klass142681%_))
              (if (let () (declare (not safe)) (symbolic? _%slot142683%_))
                  (let ((_%slot142698%_ _%slot142683%_))
                    (__class-slot-set!
                     _%klass142688%_
                     _%obj142682%_
                     _%slot142698%_
                     _%val142684%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@761.45-761.49"
                     'contract:
                     'symbolic?
                     'value:
                     _%slot142683%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@761.24-761.29"
               'contract:
               'class-type?
               'value:
               _%klass142681%_)
              '#!void))))
    (define unchecked-field-ref
      (lambda (_%obj142678%_ _%off142679%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-ref _%obj142678%_ _%off142679%_ '#f '#f))))
    (define unchecked-field-set!
      (lambda (_%obj142674%_ _%off142675%_ _%val142676%_)
        (let ()
          (declare (not safe))
          (##unchecked-structure-set!
           _%obj142674%_
           _%val142676%_
           _%off142675%_
           '#f
           '#f))))
    (define unchecked-slot-ref
      (lambda (_%obj142671%_ _%slot142672%_)
        (unchecked-field-ref
         _%obj142671%_
         (__class-slot-offset
          (let () (declare (not safe)) (##structure-type _%obj142671%_))
          _%slot142672%_))))
    (define unchecked-slot-set!
      (lambda (_%obj142667%_ _%slot142668%_ _%val142669%_)
        (unchecked-field-set!
         _%obj142667%_
         (__class-slot-offset
          (let () (declare (not safe)) (##structure-type _%obj142667%_))
          _%slot142668%_)
         _%val142669%_)))
    (define __slot-error
      (lambda (_%obj142664%_ _%slot142665%_)
        (error '"Cannot find slot"
               'object:
               _%obj142664%_
               'slot:
               _%slot142665%_)))
    (define __slot-ref__%
      (lambda (_%obj142588%_ _%slot142589%_ _%E142590%_)
        (let* ((_%slot142593%_ _%slot142589%_)
               (_%E142601%_ _%E142590%_)
               (_%klass142610%_ (class-of _%obj142588%_))
               (_%$e142646%_
                (let* ((_%klass142613%_ _%klass142610%_)
                       (_%slot142616%_ _%slot142593%_)
                       (_%klass142621%_ _%klass142613%_))
                  (if (let () (declare (not safe)) (symbolic? _%slot142616%_))
                      (let ((_%slot142636%_ _%slot142616%_))
                        (__class-slot-offset _%klass142621%_ _%slot142636%_))
                      (begin
                        (raise-contract-violation-error
                         '"contract violation"
                         'context:
                         'gerbil/runtime/mop
                         'contract:
                         'symbolic?
                         'value:
                         _%slot142616%_)
                        '#!void)))))
          (if _%$e142646%_
              (unchecked-field-ref _%obj142588%_ _%$e142646%_)
              (let ()
                (declare (not safe))
                (_%E142601%_ _%obj142588%_ _%slot142593%_))))))
    (define __slot-ref__0
      (lambda (_%obj142655%_ _%slot142656%_)
        (let ((_%E142658%_ __slot-error))
          (__slot-ref__% _%obj142655%_ _%slot142656%_ _%E142658%_))))
    (define __slot-ref
      (lambda _g148596_
        (let ((_g148597_ (let () (declare (not safe)) (##length _g148596_))))
          (cond ((let () (declare (not safe)) (##fx= _g148597_ 2))
                 (apply __slot-ref__0 _g148596_))
                ((let () (declare (not safe)) (##fx= _g148597_ 3))
                 (apply __slot-ref__% _g148596_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __slot-ref
                  _g148596_))))))
    (define slot-ref__%
      (lambda (_%obj142549%_ _%slot142550%_ _%E142551%_)
        (if (symbol? _%slot142550%_)
            (let ((_%slot142555%_ _%slot142550%_))
              (if (procedure? _%E142551%_)
                  (let ((_%E142565%_ _%E142551%_))
                    (__slot-ref__% _%obj142549%_ _%slot142555%_ _%E142565%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@787.38-787.39"
                     'contract:
                     'procedure?
                     'value:
                     _%E142551%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@787.21-787.25"
               'contract:
               'symbol?
               'value:
               _%slot142550%_)
              '#!void))))
    (define slot-ref__0
      (lambda (_%obj142578%_ _%slot142579%_)
        (let ((_%E142581%_ __slot-error))
          (slot-ref__% _%obj142578%_ _%slot142579%_ _%E142581%_))))
    (define slot-ref
      (lambda _g148598_
        (let ((_g148599_ (let () (declare (not safe)) (##length _g148598_))))
          (cond ((let () (declare (not safe)) (##fx= _g148599_ 2))
                 (apply slot-ref__0 _g148598_))
                ((let () (declare (not safe)) (##fx= _g148599_ 3))
                 (apply slot-ref__% _g148598_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  slot-ref
                  _g148598_))))))
    (define __slot-set!__%
      (lambda (_%obj142469%_ _%slot142470%_ _%val142471%_ _%E142472%_)
        (let* ((_%slot142475%_ _%slot142470%_)
               (_%E142483%_ _%E142472%_)
               (_%klass142492%_ (class-of _%obj142469%_))
               (_%$e142528%_
                (let* ((_%klass142495%_ _%klass142492%_)
                       (_%slot142498%_ _%slot142475%_)
                       (_%klass142503%_ _%klass142495%_))
                  (if (let () (declare (not safe)) (symbolic? _%slot142498%_))
                      (let ((_%slot142518%_ _%slot142498%_))
                        (__class-slot-offset _%klass142503%_ _%slot142518%_))
                      (begin
                        (raise-contract-violation-error
                         '"contract violation"
                         'context:
                         'gerbil/runtime/mop
                         'contract:
                         'symbolic?
                         'value:
                         _%slot142498%_)
                        '#!void)))))
          (if _%$e142528%_
              (unchecked-field-set! _%obj142469%_ _%$e142528%_ _%val142471%_)
              (let ()
                (declare (not safe))
                (_%E142483%_ _%obj142469%_ _%slot142475%_))))))
    (define __slot-set!__0
      (lambda (_%obj142537%_ _%slot142538%_ _%val142539%_)
        (let ((_%E142541%_ __slot-error))
          (__slot-set!__%
           _%obj142537%_
           _%slot142538%_
           _%val142539%_
           _%E142541%_))))
    (define __slot-set!
      (lambda _g148600_
        (let ((_g148601_ (let () (declare (not safe)) (##length _g148600_))))
          (cond ((let () (declare (not safe)) (##fx= _g148601_ 3))
                 (apply __slot-set!__0 _g148600_))
                ((let () (declare (not safe)) (##fx= _g148601_ 4))
                 (apply __slot-set!__% _g148600_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __slot-set!
                  _g148600_))))))
    (define slot-set!__%
      (lambda (_%obj142427%_ _%slot142428%_ _%val142429%_ _%E142430%_)
        (if (symbol? _%slot142428%_)
            (let ((_%slot142434%_ _%slot142428%_))
              (if (procedure? _%E142430%_)
                  (let ((_%E142444%_ _%E142430%_))
                    (__slot-set!__%
                     _%obj142427%_
                     _%slot142434%_
                     _%val142429%_
                     _%E142444%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@789.43-789.44"
                     'contract:
                     'procedure?
                     'value:
                     _%E142430%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@789.22-789.26"
               'contract:
               'symbol?
               'value:
               _%slot142428%_)
              '#!void))))
    (define slot-set!__0
      (lambda (_%obj142457%_ _%slot142458%_ _%val142459%_)
        (let ((_%E142461%_ __slot-error))
          (slot-set!__%
           _%obj142457%_
           _%slot142458%_
           _%val142459%_
           _%E142461%_))))
    (define slot-set!
      (lambda _g148602_
        (let ((_g148603_ (let () (declare (not safe)) (##length _g148602_))))
          (cond ((let () (declare (not safe)) (##fx= _g148603_ 3))
                 (apply slot-set!__0 _g148602_))
                ((let () (declare (not safe)) (##fx= _g148603_ 4))
                 (apply slot-set!__% _g148602_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  slot-set!
                  _g148602_))))))
    (define __subclass?
      (lambda (_%maybe-sub-class142398%_ _%maybe-super-class142399%_)
        (let* ((_%maybe-sub-class142402%_ _%maybe-sub-class142398%_)
               (_%maybe-super-class142410%_ _%maybe-super-class142399%_)
               (_%maybe-super-class-id142419%_
                (let ()
                  (declare (not safe))
                  (##type-id _%maybe-super-class142410%_)))
               (_%$e142421%_
                (eq? _%maybe-super-class-id142419%_
                     (let ()
                       (declare (not safe))
                       (##type-id _%maybe-sub-class142402%_)))))
          (if _%$e142421%_
              _%$e142421%_
              (let ((__tmp148605
                     (lambda (_%super-class142424%_)
                       (eq? (let ()
                              (declare (not safe))
                              (##type-id _%super-class142424%_))
                            _%maybe-super-class-id142419%_)))
                    (__tmp148604
                     (let ()
                       (declare (not safe))
                       (##unchecked-structure-ref
                        _%maybe-sub-class142402%_
                        '6
                        '#f
                        '#f))))
                (declare (not safe))
                (ormap__0 __tmp148605 __tmp148604))))))
    (define subclass?
      (lambda (_%maybe-sub-class142373%_ _%maybe-super-class142374%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%maybe-sub-class142373%_ 'class))
            (let ((_%maybe-sub-class142378%_ _%maybe-sub-class142373%_))
              (if (let ()
                    (declare (not safe))
                    (##structure-instance-of?
                     _%maybe-super-class142374%_
                     'class))
                  (let ((_%maybe-super-class142388%_
                         _%maybe-super-class142374%_))
                    (__subclass?
                     _%maybe-sub-class142378%_
                     _%maybe-super-class142388%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@795.45-795.62"
                     'contract:
                     'class-type?
                     'value:
                     _%maybe-super-class142374%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@795.18-795.33"
               'contract:
               'class-type?
               'value:
               _%maybe-sub-class142373%_)
              '#!void))))
    (define object?
      (lambda (_%o142370%_)
        (if (let () (declare (not safe)) (##structure? _%o142370%_))
            (let ((__tmp148606
                   (let ()
                     (declare (not safe))
                     (##structure-type _%o142370%_))))
              (declare (not safe))
              (##structure-instance-of? __tmp148606 'class))
            '#f)))
    (define __direct-instance?
      (lambda (_%klass142357%_ _%obj142358%_)
        (let* ((_%klass142361%_ _%klass142357%_)
               (__tmp148607
                (let () (declare (not safe)) (##type-id _%klass142361%_))))
          (declare (not safe))
          (##structure-direct-instance-of? _%obj142358%_ __tmp148607))))
    (define direct-instance?
      (lambda (_%klass142342%_ _%obj142343%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass142342%_ 'class))
            (let ((_%klass142347%_ _%klass142342%_))
              (__direct-instance? _%klass142347%_ _%obj142343%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@809.25-809.30"
               'contract:
               'class-type?
               'value:
               _%klass142342%_)
              '#!void))))
    (define __struct-instance?
      (lambda (_%klass142329%_ _%obj142330%_)
        (let* ((_%klass142333%_ _%klass142329%_)
               (__tmp148608
                (let () (declare (not safe)) (##type-id _%klass142333%_))))
          (declare (not safe))
          (##structure-instance-of? _%obj142330%_ __tmp148608))))
    (define struct-instance?
      (lambda (_%klass142314%_ _%obj142315%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass142314%_ 'class))
            (let ((_%klass142319%_ _%klass142314%_))
              (__struct-instance? _%klass142319%_ _%obj142315%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@821.25-821.30"
               'contract:
               'class-type?
               'value:
               _%klass142314%_)
              '#!void))))
    (define __class-instance?
      (lambda (_%klass142266%_ _%obj142267%_)
        (let* ((_%klass142270%_ _%klass142266%_)
               (_%type142279%_ (class-of _%obj142267%_))
               (_%maybe-sub-class142281%_ _%type142279%_)
               (_%maybe-super-class142284%_ _%klass142270%_)
               (_%maybe-sub-class142289%_ _%maybe-sub-class142281%_)
               (_%maybe-super-class142304%_ _%maybe-super-class142284%_))
          (__subclass?
           _%maybe-sub-class142289%_
           _%maybe-super-class142304%_))))
    (define class-instance?
      (lambda (_%klass142251%_ _%obj142252%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass142251%_ 'class))
            (let ((_%klass142256%_ _%klass142251%_))
              (__class-instance? _%klass142256%_ _%obj142252%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@833.24-833.29"
               'contract:
               'class-type?
               'value:
               _%klass142251%_)
              '#!void))))
    (define __make-object
      (lambda (_%klass142210%_ _%k142211%_)
        (let* ((_%klass142214%_ _%klass142210%_) (_%k142222%_ _%k142211%_))
          (if (let* ((_%klass142231%_ _%klass142214%_)
                     (_%klass142236%_ _%klass142231%_))
                (__class-type-system? _%klass142236%_))
              (begin
                (error '"cannot instantiate system class"
                       'class:
                       _%klass142214%_)
                '#!void)
              (let ((_%obj142249%_
                     (let ()
                       (declare (not safe))
                       (##make-structure _%klass142214%_ _%k142222%_))))
                (__object-fill! _%obj142249%_ '#f))))))
    (define make-object
      (lambda (_%klass142185%_ _%k142186%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass142185%_ 'class))
            (let ((_%klass142190%_ _%klass142185%_))
              (if (fixnum? _%k142186%_)
                  (let ((_%k142200%_ _%k142186%_))
                    (__make-object _%klass142190%_ _%k142200%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@838.37-838.38"
                     'contract:
                     'fixnum?
                     'value:
                     _%k142186%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@838.20-838.25"
               'contract:
               'class-type?
               'value:
               _%klass142185%_)
              '#!void))))
    (define __object-class
      (lambda (_%obj142173%_)
        (let ((_%obj142176%_ _%obj142173%_))
          (declare (not safe))
          (##structure-type _%obj142176%_))))
    (define object-class
      (lambda (_%obj142159%_)
        (if (object? _%obj142159%_)
            (let ((_%obj142163%_ _%obj142159%_))
              (__object-class _%obj142163%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@858.21-858.24"
               'contract:
               'object?
               'value:
               _%obj142159%_)
              '#!void))))
    (define __object-fill!
      (lambda (_%obj142141%_ _%fill142142%_)
        (let ((_%obj142145%_ _%obj142141%_))
          (let _%loop142154%_ ((_%i142156%_
                                (let ((__tmp148609
                                       (let ()
                                         (declare (not safe))
                                         (##structure-length _%obj142145%_))))
                                  (declare (not safe))
                                  (##fx- __tmp148609 '1))))
            (if (let () (declare (not safe)) (##fx> _%i142156%_ '0))
                (begin
                  (let ()
                    (declare (not safe))
                    (##unchecked-structure-set!
                     _%obj142145%_
                     _%fill142142%_
                     _%i142156%_
                     '#f
                     '#f))
                  (_%loop142154%_
                   (let () (declare (not safe)) (##fx- _%i142156%_ '1))))
                _%obj142145%_)))))
    (define object-fill!
      (lambda (_%obj142126%_ _%fill142127%_)
        (if (object? _%obj142126%_)
            (let ((_%obj142131%_ _%obj142126%_))
              (__object-fill! _%obj142131%_ _%fill142127%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@863.21-863.24"
               'contract:
               'object?
               'value:
               _%obj142126%_)
              '#!void))))
    (define __new-instance
      (lambda (_%klass142082%_)
        (let* ((_%klass142085%_ _%klass142082%_)
               (_%klass142094%_ _%klass142085%_)
               (_%k142097%_
                (let ((__tmp148610
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%klass142085%_
                          '7
                          '#f
                          '#f))))
                  (declare (not safe))
                  (##vector-length __tmp148610)))
               (_%klass142102%_ _%klass142094%_)
               (_%k142116%_ _%k142097%_))
          (__make-object _%klass142102%_ _%k142116%_))))
    (define new-instance
      (lambda (_%klass142068%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass142068%_ 'class))
            (let ((_%klass142072%_ _%klass142068%_))
              (__new-instance _%klass142072%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@874.21-874.26"
               'contract:
               'class-type?
               'value:
               _%klass142068%_)
              '#!void))))
    (define __make-instance
      (lambda (_%klass141927%_ . _%args141928%_)
        (let* ((_%klass141931%_ _%klass141927%_)
               (_%$e141940%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%klass141931%_ '10 '#f '#f))))
          (if _%$e141940%_
              (let ((_%obj141965%_
                     (let* ((_%klass141945%_ _%klass141931%_)
                            (_%klass141950%_ _%klass141945%_))
                       (__new-instance _%klass141950%_))))
                (___constructor-init!
                 _%klass141931%_
                 _%$e141940%_
                 _%obj141965%_
                 _%args141928%_)
                _%obj141965%_)
              (if (let* ((_%klass141967%_ _%klass141931%_)
                         (_%klass141972%_ _%klass141967%_))
                    (__class-type-metaclass? _%klass141972%_))
                  (let ((_%obj141999%_
                         (let* ((_%klass141983%_ _%klass141931%_)
                                (_%klass141988%_ _%klass141983%_))
                           (__new-instance _%klass141988%_))))
                    (__metaclass-instance-init!
                     _%klass141931%_
                     _%obj141999%_
                     _%args141928%_)
                    _%obj141999%_)
                  (if (let* ((_%klass142001%_ _%klass141931%_)
                             (_%klass142006%_ _%klass142001%_))
                        (__class-type-struct? _%klass142006%_))
                      (if (let ((__tmp148612
                                 (let* ((_%klass142035%_ _%klass141931%_)
                                        (_%klass142040%_ _%klass142035%_))
                                   (__class-type-field-count _%klass142040%_)))
                                (__tmp148611
                                 (let ()
                                   (declare (not safe))
                                   (##length _%args141928%_))))
                            (declare (not safe))
                            (##fx= __tmp148612 __tmp148611))
                          (apply ##structure _%klass141931%_ _%args141928%_)
                          (let ()
                            (error '"arguments don't match object size"
                                   'class:
                                   _%klass141931%_
                                   'slots:
                                   (let* ((_%klass142052%_ _%klass141931%_)
                                          (_%klass142057%_ _%klass142052%_))
                                     (__class-type-slot-list _%klass142057%_))
                                   'args:
                                   _%args141928%_)
                            '#!void))
                      (let ((_%obj142033%_
                             (let* ((_%klass142017%_ _%klass141931%_)
                                    (_%klass142022%_ _%klass142017%_))
                               (__new-instance _%klass142022%_))))
                        (___class-instance-init!
                         _%klass141931%_
                         _%obj142033%_
                         _%args141928%_)
                        _%obj142033%_)))))))
    (define make-instance
      (lambda (_%klass141912%_ . _%args141913%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass141912%_ 'class))
            (let ((_%klass141917%_ _%klass141912%_))
              (declare (not safe))
              (##apply __make-instance _%klass141917%_ _%args141913%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@877.22-877.27"
               'contract:
               'class-type?
               'value:
               _%klass141912%_)
              '#!void))))
    (define make-class-instance make-instance)
    (define __struct-instance-init!
      (lambda (_%obj141899%_ . _%args141900%_)
        (let ((_%obj141903%_ _%obj141899%_))
          (if (let ((__tmp148614
                     (let () (declare (not safe)) (##length _%args141900%_)))
                    (__tmp148613
                     (let ()
                       (declare (not safe))
                       (##structure-length _%obj141903%_))))
                (declare (not safe))
                (##fx< __tmp148614 __tmp148613))
              (___struct-instance-init! _%obj141903%_ _%args141900%_)
              (error '"too many arguments for struct"
                     'object:
                     _%obj141903%_
                     'args:
                     _%args141900%_))
          '#!void)))
    (define struct-instance-init!
      (lambda (_%obj141884%_ . _%args141885%_)
        (if (object? _%obj141884%_)
            (let ((_%obj141889%_ _%obj141884%_))
              (declare (not safe))
              (##apply __struct-instance-init! _%obj141889%_ _%args141885%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@902.30-902.33"
               'contract:
               'object?
               'value:
               _%obj141884%_)
              '#!void))))
    (define ___struct-instance-init!
      (lambda (_%obj141843%_ _%args141844%_)
        (let _%lp141846%_ ((_%k141848%_ '1) (_%rest141849%_ _%args141844%_))
          (let* ((_%$%rest141850141858%_ _%rest141849%_)
                 (_%$%else141852141866%_ (lambda () _%obj141843%_))
                 (_%$%K141854141872%_
                  (lambda (_%rest141869%_ _%hd141870%_)
                    (unchecked-field-set!
                     _%obj141843%_
                     _%k141848%_
                     _%hd141870%_)
                    (_%lp141846%_
                     (let () (declare (not safe)) (##fx+ _%k141848%_ '1))
                     _%rest141869%_))))
            (if (pair? _%$%rest141850141858%_)
                (let ((_%$%hd141855141875%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest141850141858%_)))
                      (_%$%tl141856141877%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest141850141858%_))))
                  (let* ((_%hd141880%_ _%$%hd141855141875%_)
                         (_%rest141882%_ _%$%tl141856141877%_))
                    (_%$%K141854141872%_ _%rest141882%_ _%hd141880%_)))
                (_%$%else141852141866%_))))))
    (define __class-instance-init!
      (lambda (_%obj141830%_ . _%args141831%_)
        (let ((_%obj141834%_ _%obj141830%_))
          (___class-instance-init!
           (let () (declare (not safe)) (##structure-type _%obj141834%_))
           _%obj141834%_
           _%args141831%_)
          '#!void)))
    (define class-instance-init!
      (lambda (_%obj141815%_ . _%args141816%_)
        (if (object? _%obj141815%_)
            (let ((_%obj141820%_ _%obj141815%_))
              (declare (not safe))
              (##apply __class-instance-init! _%obj141820%_ _%args141816%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@942.29-942.32"
               'contract:
               'object?
               'value:
               _%obj141815%_)
              '#!void))))
    (define ___class-instance-init!
      (lambda (_%klass141757%_ _%obj141758%_ _%args141759%_)
        (let _%lp141761%_ ((_%rest141763%_ _%args141759%_))
          (let* ((_%$%rest141764141774%_ _%rest141763%_)
                 (_%$%else141766141782%_
                  (lambda ()
                    (if (null? _%rest141763%_)
                        _%obj141758%_
                        (error '"unexpected class initializer arguments"
                               'class:
                               _%klass141757%_
                               'rest:
                               _%rest141763%_))))
                 (_%$%K141768141796%_
                  (lambda (_%rest141785%_ _%val141786%_ _%key141787%_)
                    (if (keyword? _%key141787%_)
                        (let ((_%$e141790%_
                               (__class-slot-offset
                                _%klass141757%_
                                _%key141787%_)))
                          (if _%$e141790%_
                              (let ()
                                (unchecked-field-set!
                                 _%obj141758%_
                                 _%$e141790%_
                                 _%val141786%_)
                                (_%lp141761%_ _%rest141785%_))
                              (error '"unknown slot"
                                     'class:
                                     _%klass141757%_
                                     'slot:
                                     _%key141787%_)))
                        (error '"non keyword slot initializer"
                               'slot:
                               _%key141787%_)))))
            (if (pair? _%$%rest141764141774%_)
                (let ((_%$%hd141769141799%_
                       (let ()
                         (declare (not safe))
                         (##car _%$%rest141764141774%_)))
                      (_%$%tl141770141801%_
                       (let ()
                         (declare (not safe))
                         (##cdr _%$%rest141764141774%_))))
                  (let ((_%key141804%_ _%$%hd141769141799%_))
                    (if (pair? _%$%tl141770141801%_)
                        (let ((_%$%hd141771141806%_
                               (let ()
                                 (declare (not safe))
                                 (##car _%$%tl141770141801%_)))
                              (_%$%tl141772141808%_
                               (let ()
                                 (declare (not safe))
                                 (##cdr _%$%tl141770141801%_))))
                          (let* ((_%val141811%_ _%$%hd141771141806%_)
                                 (_%rest141813%_ _%$%tl141772141808%_))
                            (_%$%K141768141796%_
                             _%rest141813%_
                             _%val141811%_
                             _%key141804%_)))
                        (_%$%else141766141782%_))))
                (_%$%else141766141782%_))))))
    (define __metaclass-instance-init!
      (lambda (_%klass141753%_ _%obj141754%_ _%args141755%_)
        (apply call-method
               _%klass141753%_
               'instance-init!
               _%obj141754%_
               _%args141755%_)))
    (define __constructor-init!
      (lambda (_%klass141722%_
               _%kons-id141723%_
               _%obj141724%_
               .
               _%args141725%_)
        (let* ((_%klass141728%_ _%klass141722%_)
               (_%kons-id141736%_ _%kons-id141723%_)
               (_%obj141744%_ _%obj141724%_))
          (___constructor-init!
           _%klass141728%_
           _%kons-id141736%_
           _%obj141744%_
           _%args141725%_)
          '#!void)))
    (define constructor-init!
      (lambda (_%klass141685%_
               _%kons-id141686%_
               _%obj141687%_
               .
               _%args141688%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass141685%_ 'class))
            (let ((_%klass141692%_ _%klass141685%_))
              (if (symbol? _%kons-id141686%_)
                  (let ((_%kons-id141702%_ _%kons-id141686%_))
                    (if (object? _%obj141687%_)
                        (let ((_%obj141712%_ _%obj141687%_))
                          (declare (not safe))
                          (##apply __constructor-init!
                                   _%klass141692%_
                                   _%kons-id141702%_
                                   _%obj141712%_
                                   _%args141688%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           '"\"gerbil/runtime/mop.ss\"@966.63-966.66"
                           'contract:
                           'object?
                           'value:
                           _%obj141687%_)
                          '#!void)))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@966.43-966.50"
                     'contract:
                     'symbol?
                     'value:
                     _%kons-id141686%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@966.26-966.31"
               'contract:
               'class-type?
               'value:
               _%klass141685%_)
              '#!void))))
    (define ___constructor-init!
      (lambda (_%klass141674%_ _%kons-id141675%_ _%obj141676%_ _%args141677%_)
        (let ((_%$e141679%_
               (__find-method
                _%klass141674%_
                _%obj141676%_
                _%kons-id141675%_)))
          (if _%$e141679%_
              (let ()
                (apply _%$e141679%_ _%obj141676%_ _%args141677%_)
                _%obj141676%_)
              (error '"missing constructor"
                     'class:
                     _%klass141674%_
                     'method:
                     _%kons-id141675%_)))))
    (define __struct-copy
      (lambda (_%struct141662%_)
        (let ((_%struct141665%_ _%struct141662%_))
          (declare (not safe))
          (##structure-copy _%struct141665%_))))
    (define struct-copy
      (lambda (_%struct141648%_)
        (if (object? _%struct141648%_)
            (let ((_%struct141652%_ _%struct141648%_))
              (__struct-copy _%struct141652%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@980.20-980.26"
               'contract:
               'object?
               'value:
               _%struct141648%_)
              '#!void))))
    (define __struct->list
      (lambda (_%obj141629%_)
        (let* ((_%obj141632%_ _%obj141629%_)
               (_%len141641%_
                (let ()
                  (declare (not safe))
                  (##structure-length _%obj141632%_))))
          (let _%recur141643%_ ((_%i141645%_ '0))
            (if (let () (declare (not safe)) (##fx< _%i141645%_ _%len141641%_))
                (cons (let ()
                        (declare (not safe))
                        (##unchecked-structure-ref
                         _%obj141632%_
                         _%i141645%_
                         '#f
                         '#f))
                      (_%recur141643%_
                       (let () (declare (not safe)) (##fx+ _%i141645%_ '1))))
                '())))))
    (define struct->list
      (lambda (_%obj141615%_)
        (if (object? _%obj141615%_)
            (let ((_%obj141619%_ _%obj141615%_))
              (__struct->list _%obj141619%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@983.21-983.24"
               'contract:
               'object?
               'value:
               _%obj141615%_)
              '#!void))))
    (define __class->list
      (lambda (_%obj141567%_)
        (let* ((_%obj141570%_ _%obj141567%_)
               (_%klass141579%_
                (let () (declare (not safe)) (##structure-type _%obj141570%_)))
               (_%slot-vector141581%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%klass141579%_ '7 '#f '#f))))
          (let _%loop141583%_ ((_%index141585%_
                                (let ((__tmp148615
                                       (let ()
                                         (declare (not safe))
                                         (##vector-length
                                          _%slot-vector141581%_))))
                                  (declare (not safe))
                                  (##fx- __tmp148615 '1)))
                               (_%plist141586%_ '()))
            (if (let () (declare (not safe)) (##fx< _%index141585%_ '1))
                (cons _%klass141579%_ _%plist141586%_)
                (let ((_%slot141589%_
                       (let ()
                         (declare (not safe))
                         (##vector-ref
                          _%slot-vector141581%_
                          _%index141585%_))))
                  (_%loop141583%_
                   (let () (declare (not safe)) (##fx- _%index141585%_ '1))
                   (cons (let ((_%sym141591%_ _%slot141589%_))
                           (if (symbol? _%sym141591%_)
                               (let ((_%sym141596%_ _%sym141591%_))
                                 (declare (not safe))
                                 (__symbol->keyword _%sym141596%_))
                               (begin
                                 (raise-contract-violation-error
                                  '"contract violation"
                                  'context:
                                  'gerbil/runtime/mop
                                  'contract:
                                  'symbol?
                                  'value:
                                  _%sym141591%_)
                                 '#!void)))
                         (cons (unchecked-field-ref
                                _%obj141570%_
                                _%index141585%_)
                               _%plist141586%_)))))))))
    (define class->list
      (lambda (_%obj141553%_)
        (if (object? _%obj141553%_)
            (let ((_%obj141557%_ _%obj141553%_)) (__class->list _%obj141557%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@991.20-991.23"
               'contract:
               'object?
               'value:
               _%obj141553%_)
              '#!void))))
    (define __call-method
      (lambda (_%obj141503%_ _%id141504%_ . _%args141505%_)
        (let* ((_%id141508%_ _%id141504%_)
               (_%$e141539%_
                (let* ((_%obj141517%_ _%obj141503%_)
                       (_%id141520%_ _%id141508%_)
                       (_%id141525%_ _%id141520%_))
                  (__method-ref _%obj141517%_ _%id141525%_))))
          (if _%$e141539%_
              (let ((_%method141544%_ _%$e141539%_))
                (apply _%method141544%_ _%obj141503%_ _%args141505%_))
              (error '"cannot find method"
                     'object:
                     _%obj141503%_
                     'method:
                     _%id141508%_)))))
    (define call-method
      (lambda (_%obj141487%_ _%id141488%_ . _%args141489%_)
        (if (symbol? _%id141488%_)
            (let ((_%id141493%_ _%id141488%_))
              (declare (not safe))
              (##apply __call-method
                       _%obj141487%_
                       _%id141493%_
                       _%args141489%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1006.24-1006.26"
               'contract:
               'symbol?
               'value:
               _%id141488%_)
              '#!void))))
    (define __method-ref
      (lambda (_%obj141438%_ _%id141439%_)
        (let* ((_%id141442%_ _%id141439%_)
               (_%klass141451%_ (class-of _%obj141438%_))
               (_%obj141454%_ _%obj141438%_)
               (_%id141457%_ _%id141442%_)
               (_%klass141462%_ _%klass141451%_)
               (_%id141477%_ _%id141457%_))
          (__find-method _%klass141462%_ _%obj141454%_ _%id141477%_))))
    (define method-ref
      (lambda (_%obj141423%_ _%id141424%_)
        (if (symbol? _%id141424%_)
            (let ((_%id141428%_ _%id141424%_))
              (__method-ref _%obj141423%_ _%id141428%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1033.23-1033.25"
               'contract:
               'symbol?
               'value:
               _%id141424%_)
              '#!void))))
    (define checked-method-ref
      (lambda (_%obj141395%_ _%id141396%_)
        (let ((_%$e141420%_
               (let* ((_%obj141399%_ _%obj141395%_)
                      (_%id141402%_ _%id141396%_))
                 (if (symbol? _%id141402%_)
                     (let ((_%id141407%_ _%id141402%_))
                       (__method-ref _%obj141399%_ _%id141407%_))
                     (begin
                       (raise-contract-violation-error
                        '"contract violation"
                        'context:
                        'gerbil/runtime/mop
                        'contract:
                        'symbol?
                        'value:
                        _%id141402%_)
                       '#!void)))))
          (if _%$e141420%_
              _%$e141420%_
              (begin
                (error '"missing method"
                       'object:
                       _%obj141395%_
                       'method:
                       _%id141396%_)
                '#!void)))))
    (define __bound-method-ref
      (lambda (_%obj141344%_ _%id141345%_)
        (let* ((_%id141348%_ _%id141345%_)
               (_%$e141379%_
                (let* ((_%obj141357%_ _%obj141344%_)
                       (_%id141360%_ _%id141348%_)
                       (_%id141365%_ _%id141360%_))
                  (__method-ref _%obj141357%_ _%id141365%_))))
          (if _%$e141379%_
              (let ((_%method141384%_ _%$e141379%_))
                (lambda _%args141392%_
                  (apply _%method141384%_ _%obj141344%_ _%args141392%_)))
              '#f))))
    (define bound-method-ref
      (lambda (_%obj141329%_ _%id141330%_)
        (if (symbol? _%id141330%_)
            (let ((_%id141334%_ _%id141330%_))
              (__bound-method-ref _%obj141329%_ _%id141334%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1041.29-1041.31"
               'contract:
               'symbol?
               'value:
               _%id141330%_)
              '#!void))))
    (define __checked-bound-method-ref
      (lambda (_%obj141312%_ _%id141313%_)
        (let* ((_%id141316%_ _%id141313%_)
               (_%method141325%_
                (checked-method-ref _%obj141312%_ _%id141316%_)))
          (lambda _%args141327%_
            (apply _%method141325%_ _%obj141312%_ _%args141327%_)))))
    (define checked-bound-method-ref
      (lambda (_%obj141297%_ _%id141298%_)
        (if (symbol? _%id141298%_)
            (let ((_%id141302%_ _%id141298%_))
              (__checked-bound-method-ref _%obj141297%_ _%id141302%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1050.37-1050.39"
               'contract:
               'symbol?
               'value:
               _%id141298%_)
              '#!void))))
    (define __find-method
      (lambda (_%klass141166%_ _%obj141167%_ _%id141168%_)
        (let* ((_%klass141171%_ _%klass141166%_) (_%id141179%_ _%id141168%_))
          (if (let* ((_%klass141188%_ _%klass141171%_)
                     (_%klass141193%_ _%klass141188%_))
                (__class-type-sealed? _%klass141193%_))
              (let ((_%tab141223%_
                     (let* ((_%klass141207%_ _%klass141171%_)
                            (_%klass141212%_ _%klass141207%_))
                       (__specialize-class _%klass141212%_))))
                (declare (not safe))
                (symbolic-table-ref _%tab141223%_ _%id141179%_ '#f))
              (let ((_%$e141258%_
                     (let* ((_%klass141225%_ _%klass141171%_)
                            (_%obj141228%_ _%obj141167%_)
                            (_%id141231%_ _%id141179%_)
                            (_%klass141236%_ _%klass141225%_)
                            (_%id141248%_ _%id141231%_))
                       (__direct-method-ref
                        _%klass141236%_
                        _%obj141228%_
                        _%id141248%_))))
                (if _%$e141258%_
                    _%$e141258%_
                    (let* ((_%klass141262%_ _%klass141171%_)
                           (_%obj141265%_ _%obj141167%_)
                           (_%id141268%_ _%id141179%_)
                           (_%klass141273%_ _%klass141262%_)
                           (_%id141287%_ _%id141268%_))
                      (__mixin-method-ref
                       _%klass141273%_
                       _%obj141265%_
                       _%id141287%_))))))))
    (define find-method
      (lambda (_%klass141140%_ _%obj141141%_ _%id141142%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass141140%_ 'class))
            (let ((_%klass141146%_ _%klass141140%_))
              (if (symbol? _%id141142%_)
                  (let ((_%id141156%_ _%id141142%_))
                    (__find-method _%klass141146%_ _%obj141141%_ _%id141156%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@1055.41-1055.43"
                     'contract:
                     'symbol?
                     'value:
                     _%id141142%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1055.20-1055.25"
               'contract:
               'class-type?
               'value:
               _%klass141140%_)
              '#!void))))
    (define __mixin-find-method
      (lambda (_%mixins141085%_ _%obj141086%_ _%id141087%_)
        (let* ((_%id141090%_ _%id141087%_)
               (__tmp148616
                (lambda (_%$%g141098141100%_)
                  (let* ((_%klass141103%_ _%$%g141098141100%_)
                         (_%obj141106%_ _%obj141086%_)
                         (_%id141109%_ _%id141090%_))
                    (if (let ()
                          (declare (not safe))
                          (##structure-instance-of? _%klass141103%_ 'class))
                        (let* ((_%klass141114%_ _%klass141103%_)
                               (_%id141130%_ _%id141109%_))
                          (__direct-method-ref
                           _%klass141114%_
                           _%obj141106%_
                           _%id141130%_))
                        (begin
                          (raise-contract-violation-error
                           '"contract violation"
                           'context:
                           'gerbil/runtime/mop
                           'contract:
                           'class-type?
                           'value:
                           _%klass141103%_)
                          '#!void))))))
          (declare (not safe))
          (ormap__0 __tmp148616 _%mixins141085%_))))
    (define mixin-find-method
      (lambda (_%mixins141069%_ _%obj141070%_ _%id141071%_)
        (if (symbol? _%id141071%_)
            (let ((_%id141075%_ _%id141071%_))
              (__mixin-find-method
               _%mixins141069%_
               _%obj141070%_
               _%id141075%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1064.37-1064.39"
               'contract:
               'symbol?
               'value:
               _%id141071%_)
              '#!void))))
    (define __direct-method-ref
      (lambda (_%klass140962%_ _%obj140963%_ _%id140964%_)
        (let* ((_%klass140967%_ _%klass140962%_) (_%id140975%_ _%id140964%_))
          (letrec ((_%metaclass-resolve-method140984%_
                    (lambda ()
                      (let* ((_%obj141045%_ _%klass140967%_)
                             (_%id141048%_ 'direct-method-ref)
                             (_%args141051%_ (list _%obj140963%_ _%id140975%_))
                             (_%id141056%_ _%id141048%_))
                        (declare (not safe))
                        (##apply __call-method
                                 _%obj141045%_
                                 _%id141056%_
                                 _%args141051%_))))
                   (_%metaclass-resolve-method!140985%_
                    (lambda ()
                      (let ((_%method141042%_
                             (_%metaclass-resolve-method140984%_)))
                        (let ((__tmp148618
                               (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%klass140967%_
                                  '11
                                  '#f
                                  '#f)))
                              (__tmp148617
                               (if _%method141042%_ 'resolved 'unknown)))
                          (declare (not safe))
                          (symbolic-table-set!
                           __tmp148618
                           _%id140975%_
                           __tmp148617))
                        _%method141042%_))))
            (let ((_%$e140987%_
                   (let ()
                     (declare (not safe))
                     (##unchecked-structure-ref _%klass140967%_ '11 '#f '#f))))
              (if _%$e140987%_
                  (let ((_%method140992%_
                         (let ()
                           (declare (not safe))
                           (symbolic-table-ref
                            _%$e140987%_
                            _%id140975%_
                            '#f))))
                    (if (procedure? _%method140992%_)
                        _%method140992%_
                        (if (let* ((_%klass140995%_ _%klass140967%_)
                                   (_%klass141000%_ _%klass140995%_))
                              (__class-type-metaclass? _%klass141000%_))
                            (let ((_%$e141018%_ _%method140992%_))
                              (if (eq? 'resolved _%$e141018%_)
                                  (_%metaclass-resolve-method140984%_)
                                  (if (eq? 'unknown _%$e141018%_)
                                      '#f
                                      (_%metaclass-resolve-method!140985%_))))
                            '#f)))
                  (if (let* ((_%klass141022%_ _%klass140967%_)
                             (_%klass141027%_ _%klass141022%_))
                        (__class-type-metaclass? _%klass141027%_))
                      (let ((_%tab141038%_
                             (let ()
                               (declare (not safe))
                               (make-symbolic-table__% '#f '0))))
                        (let ()
                          (declare (not safe))
                          (##unchecked-structure-set!
                           _%klass140967%_
                           _%tab141038%_
                           '11
                           '#f
                           '#f))
                        (_%metaclass-resolve-method!140985%_))
                      '#f)))))))
    (define direct-method-ref
      (lambda (_%klass140936%_ _%obj140937%_ _%id140938%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass140936%_ 'class))
            (let ((_%klass140942%_ _%klass140936%_))
              (if (symbol? _%id140938%_)
                  (let ((_%id140952%_ _%id140938%_))
                    (__direct-method-ref
                     _%klass140942%_
                     _%obj140937%_
                     _%id140952%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@1067.47-1067.49"
                     'contract:
                     'symbol?
                     'value:
                     _%id140938%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1067.26-1067.31"
               'contract:
               'class-type?
               'value:
               _%klass140936%_)
              '#!void))))
    (define __mixin-method-ref
      (lambda (_%klass140888%_ _%obj140889%_ _%id140890%_)
        (let* ((_%klass140893%_ _%klass140888%_)
               (_%id140901%_ _%id140890%_)
               (_%mixins140910%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%klass140893%_ '6 '#f '#f)))
               (_%obj140913%_ _%obj140889%_)
               (_%id140916%_ _%id140901%_)
               (_%id140921%_ _%id140916%_))
          (__mixin-find-method _%mixins140910%_ _%obj140913%_ _%id140921%_))))
    (define mixin-method-ref
      (lambda (_%klass140862%_ _%obj140863%_ _%id140864%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass140862%_ 'class))
            (let ((_%klass140868%_ _%klass140862%_))
              (if (symbol? _%id140864%_)
                  (let ((_%id140878%_ _%id140864%_))
                    (__mixin-method-ref
                     _%klass140868%_
                     _%obj140863%_
                     _%id140878%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@1097.46-1097.48"
                     'contract:
                     'symbol?
                     'value:
                     _%id140864%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1097.25-1097.30"
               'contract:
               'class-type?
               'value:
               _%klass140862%_)
              '#!void))))
    (define __bind-method!__%
      (lambda (_%klass140743%_ _%id140744%_ _%proc140745%_ _%rebind?140746%_)
        (let* ((_%id140749%_ _%id140744%_) (_%proc140757%_ _%proc140745%_))
          (letrec ((_%flush-caches!140766%_
                    (lambda (_%klass140820%_)
                      (if (let ()
                            (declare (not safe))
                            (##unchecked-structure-ref
                             _%klass140820%_
                             '12
                             '#f
                             '#f))
                          (begin
                            (let ()
                              (declare (not safe))
                              (##unchecked-structure-set!
                               _%klass140820%_
                               '#f
                               '12
                               '#f
                               '#f))
                            (if (let ((_%klass140822%_ _%klass140820%_))
                                  (if (let ()
                                        (declare (not safe))
                                        (##structure-instance-of?
                                         _%klass140822%_
                                         'class))
                                      (let ((_%klass140827%_ _%klass140822%_))
                                        (__class-type-sealed? _%klass140827%_))
                                      (begin
                                        (raise-contract-violation-error
                                         '"contract violation"
                                         'context:
                                         'gerbil/runtime/mop
                                         'contract:
                                         'class-type?
                                         'value:
                                         _%klass140822%_)
                                        '#!void)))
                                (let ((__tmp148619
                                       (let ((__tmp148621
                                              (let ()
                                                (declare (not safe))
                                                (##fxnot class-type-flag-sealed)))
                                             (__tmp148620
                                              (let ()
                                                (declare (not safe))
                                                (##type-flags
                                                 _%klass140820%_))))
                                         (declare (not safe))
                                         (##fxand __tmp148621 __tmp148620))))
                                  (declare (not safe))
                                  (##unchecked-structure-set!
                                   _%klass140820%_
                                   __tmp148619
                                   '3
                                   class::t
                                   bind-method!))
                                '#!void))
                          '#!void)
                      (if (and _%rebind?140746%_
                               (let ()
                                 (declare (not safe))
                                 (##unchecked-structure-ref
                                  _%klass140820%_
                                  '13
                                  '#f
                                  '#f)))
                          (let ()
                            (declare (not safe))
                            (##unchecked-structure-set!
                             _%klass140820%_
                             '#f
                             '13
                             '#f
                             '#f))
                          '#!void)
                      (let ((_%$e140838%_
                             (let ()
                               (declare (not safe))
                               (##unchecked-structure-ref
                                _%klass140820%_
                                '9
                                '#f
                                '#f))))
                        (if _%$e140838%_
                            (let ((_%$e140843%_
                                   (let ()
                                     (declare (not safe))
                                     (agetq__0 'subclasses: _%$e140838%_))))
                              (if _%$e140843%_
                                  (for-each
                                   _%flush-caches!140766%_
                                   _%$e140843%_)
                                  '#!void))
                            '#!void))))
                   (_%bind!140767%_
                    (lambda (_%ht140818%_)
                      (if (if _%rebind?140746%_
                              '#f
                              (let ()
                                (declare (not safe))
                                (symbolic-table-ref
                                 _%ht140818%_
                                 _%id140749%_
                                 '#f)))
                          (error '"method already bound"
                                 'class:
                                 _%klass140743%_
                                 'method:
                                 _%id140749%_)
                          (begin
                            (let ()
                              (declare (not safe))
                              (symbolic-table-set!
                               _%ht140818%_
                               _%id140749%_
                               _%proc140757%_))
                            (_%flush-caches!140766%_ _%klass140743%_)
                            '#!void)))))
            (if (let ()
                  (declare (not safe))
                  (##structure-instance-of? _%klass140743%_ 'class))
                (let ((_%ht140770%_
                       (let ()
                         (declare (not safe))
                         (##unchecked-structure-ref
                          _%klass140743%_
                          '11
                          '#f
                          '#f))))
                  (if _%ht140770%_
                      (_%bind!140767%_ _%ht140770%_)
                      (let ((_%ht140772%_
                             (let ()
                               (declare (not safe))
                               (make-symbolic-table__% '#f '0))))
                        (let ()
                          (declare (not safe))
                          (##unchecked-structure-set!
                           _%klass140743%_
                           _%ht140772%_
                           '11
                           '#f
                           '#f))
                        (_%bind!140767%_ _%ht140772%_))))
                (if (let () (declare (not safe)) (##type? _%klass140743%_))
                    (let* ((_%klass140775%_
                            (__shadow-class__0 _%klass140743%_))
                           (_%id140778%_ _%id140749%_)
                           (_%proc140781%_ _%proc140757%_)
                           (_%rebind?140784%_ _%rebind?140746%_)
                           (_%id140789%_ _%id140778%_)
                           (_%proc140807%_ _%proc140781%_))
                      (__bind-method!__%
                       _%klass140775%_
                       _%id140789%_
                       _%proc140807%_
                       _%rebind?140784%_))
                    (error '"bad class; expected class or builtin type"
                           _%klass140743%_)))))))
    (define __bind-method!__0
      (lambda (_%klass140851%_ _%id140852%_ _%proc140853%_)
        (let ((_%rebind?140855%_ '#f))
          (__bind-method!__%
           _%klass140851%_
           _%id140852%_
           _%proc140853%_
           _%rebind?140855%_))))
    (define __bind-method!
      (lambda _g148622_
        (let ((_g148623_ (let () (declare (not safe)) (##length _g148622_))))
          (cond ((let () (declare (not safe)) (##fx= _g148623_ 3))
                 (apply __bind-method!__0 _g148622_))
                ((let () (declare (not safe)) (##fx= _g148623_ 4))
                 (apply __bind-method!__% _g148622_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __bind-method!
                  _g148622_))))))
    (define bind-method!__%
      (lambda (_%klass140701%_ _%id140702%_ _%proc140703%_ _%rebind?140704%_)
        (if (symbol? _%id140702%_)
            (let ((_%id140708%_ _%id140702%_))
              (if (procedure? _%proc140703%_)
                  (let ((_%proc140718%_ _%proc140703%_))
                    (__bind-method!__%
                     _%klass140701%_
                     _%id140708%_
                     _%proc140718%_
                     _%rebind?140704%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@1100.42-1100.46"
                     'contract:
                     'procedure?
                     'value:
                     _%proc140703%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1100.27-1100.29"
               'contract:
               'symbol?
               'value:
               _%id140702%_)
              '#!void))))
    (define bind-method!__0
      (lambda (_%klass140731%_ _%id140732%_ _%proc140733%_)
        (let ((_%rebind?140735%_ '#f))
          (bind-method!__%
           _%klass140731%_
           _%id140732%_
           _%proc140733%_
           _%rebind?140735%_))))
    (define bind-method!
      (lambda _g148624_
        (let ((_g148625_ (let () (declare (not safe)) (##length _g148624_))))
          (cond ((let () (declare (not safe)) (##fx= _g148625_ 3))
                 (apply bind-method!__0 _g148624_))
                ((let () (declare (not safe)) (##fx= _g148625_ 4))
                 (apply bind-method!__% _g148624_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  bind-method!
                  _g148624_))))))
    (define make-method-specializer-table__%
      (lambda (_%size-hint140682%_ _%seed140683%_)
        (let ()
          (declare (not safe))
          (make-raw-table__1
           _%size-hint140682%_
           procedure-hash
           eq?
           _%seed140683%_))))
    (define make-method-specializer-table__0
      (lambda ()
        (let* ((_%size-hint140689%_ '#f) (_%seed140691%_ '0))
          (make-method-specializer-table__%
           _%size-hint140689%_
           _%seed140691%_))))
    (define make-method-specializer-table__1
      (lambda (_%size-hint140693%_)
        (let ((_%seed140695%_ '0))
          (make-method-specializer-table__%
           _%size-hint140693%_
           _%seed140695%_))))
    (define make-method-specializer-table
      (lambda _g148626_
        (let ((_g148627_ (let () (declare (not safe)) (##length _g148626_))))
          (cond ((let () (declare (not safe)) (##fx= _g148627_ 0))
                 (apply make-method-specializer-table__0 _g148626_))
                ((let () (declare (not safe)) (##fx= _g148627_ 1))
                 (apply make-method-specializer-table__1 _g148626_))
                ((let () (declare (not safe)) (##fx= _g148627_ 2))
                 (apply make-method-specializer-table__% _g148626_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-method-specializer-table
                  _g148626_))))))
    (define make-method-specializer-table/lock__%
      (lambda (_%size-hint140662%_ _%seed140664%_)
        (let ()
          (declare (not safe))
          (make-raw-table/lock__%
           _%size-hint140662%_
           procedure-hash
           eq?
           _%seed140664%_))))
    (define make-method-specializer-table/lock__0
      (lambda ()
        (let* ((_%size-hint140670%_ '#f) (_%seed140672%_ '0))
          (make-method-specializer-table/lock__%
           _%size-hint140670%_
           _%seed140672%_))))
    (define make-method-specializer-table/lock__1
      (lambda (_%size-hint140674%_)
        (let ((_%seed140676%_ '0))
          (make-method-specializer-table/lock__%
           _%size-hint140674%_
           _%seed140676%_))))
    (define make-method-specializer-table/lock
      (lambda _g148628_
        (let ((_g148629_ (let () (declare (not safe)) (##length _g148628_))))
          (cond ((let () (declare (not safe)) (##fx= _g148629_ 0))
                 (apply make-method-specializer-table/lock__0 _g148628_))
                ((let () (declare (not safe)) (##fx= _g148629_ 1))
                 (apply make-method-specializer-table/lock__1 _g148628_))
                ((let () (declare (not safe)) (##fx= _g148629_ 2))
                 (apply make-method-specializer-table/lock__% _g148628_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  make-method-specializer-table/lock
                  _g148628_))))))
    (define method-specializer-table-ref
      (lambda (_%tab140615%_ _%key140616%_ _%default140617%_)
        (let ((_%table140619%_
               (let () (declare (not safe)) (&raw-table-table _%tab140615%_)))
              (_%seed140620%_
               (let () (declare (not safe)) (&raw-table-seed _%tab140615%_))))
          (let* ((_%h140622%_
                  (fxxor (let ()
                           (declare (not safe))
                           (procedure-hash _%key140616%_))
                         _%seed140620%_))
                 (_%size140625%_ (vector-length _%table140619%_))
                 (_%entries140628%_
                  (let ()
                    (declare (not safe))
                    (##fxquotient _%size140625%_ '2)))
                 (_%start140631%_
                  (let ((__tmp148630
                         (let ()
                           (declare (not safe))
                           (##fxmodulo _%h140622%_ _%entries140628%_))))
                    (declare (not safe))
                    (##fxarithmetic-shift-left __tmp148630 '1))))
            (let _%loop140635%_ ((_%probe140638%_ _%start140631%_)
                                 (_%i140640%_ '1)
                                 (_%deleted140642%_ '#f))
              (let ((_%k140645%_ (vector-ref _%table140619%_ _%probe140638%_)))
                (if (eq? _%k140645%_ (macro-unused-obj))
                    _%default140617%_
                    (if (eq? _%k140645%_ (macro-deleted-obj))
                        (_%loop140635%_
                         (let ((_%next-probe140650%_
                                (fx+ _%start140631%_
                                     _%i140640%_
                                     (fx* _%i140640%_ _%i140640%_))))
                           (declare (not safe))
                           (##fxmodulo _%next-probe140650%_ _%size140625%_))
                         (let () (declare (not safe)) (##fx+ _%i140640%_ '1))
                         (let ((_%$e140653%_ _%deleted140642%_))
                           (if _%$e140653%_ _%$e140653%_ _%probe140638%_)))
                        (if (eq? _%key140616%_ _%k140645%_)
                            (vector-ref
                             _%table140619%_
                             (let ()
                               (declare (not safe))
                               (##fx+ _%probe140638%_ '1)))
                            (_%loop140635%_
                             (let ((_%next-probe140658%_
                                    (fx+ _%start140631%_
                                         _%i140640%_
                                         (fx* _%i140640%_ _%i140640%_))))
                               (declare (not safe))
                               (##fxmodulo
                                _%next-probe140658%_
                                _%size140625%_))
                             (let ()
                               (declare (not safe))
                               (##fx+ _%i140640%_ '1))
                             _%deleted140642%_))))))))))
    (define method-specializer-table-ref/lock
      (lambda (_%tab140586%_ _%key140587%_ _%default140588%_)
        (let ((_%lock140590%_
               (let () (declare (not safe)) (&raw-table-lock _%tab140586%_))))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again140595%_ ((_%spin140598%_ '0))
              (if (let ((__tmp148631
                         (let ()
                           (declare (not safe))
                           (##vector-cas! _%lock140590%_ '0 '1 '0))))
                    (declare (not safe))
                    (##fx= __tmp148631 '0))
                  (let ((__tmp148632 (current-thread)))
                    (declare (not safe))
                    (##vector-set! _%lock140590%_ '1 __tmp148632))
                  (if (let () (declare (not safe)) (##fx< _%spin140598%_ '10))
                      (let ()
                        (let () (declare (not safe)) (##thread-yield!))
                        (_%again140595%_
                         (let ()
                           (declare (not safe))
                           (##fx+ _%spin140598%_ '1))))
                      (let ((_%owner140604%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%lock140590%_ '1))))
                        (if (eq? _%owner140604%_ (macro-current-thread))
                            (let ()
                              (declare (not safe))
                              (##thread-deadlock-action!))
                            (if (macro-thread-end-condvar _%owner140604%_)
                                (let ()
                                  (let ()
                                    (declare (not safe))
                                    (##thread-yield!))
                                  (_%again140595%_ '0))
                                (let ()
                                  (declare (not safe))
                                  (##thread-deadlock-action!)))))))))
          (let ((_%$r140610%_
                 (method-specializer-table-ref
                  _%tab140586%_
                  _%key140587%_
                  _%default140588%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (let ()
                  (declare (not safe))
                  (##vector-set! _%lock140590%_ '1 '#f))
                (let ()
                  (declare (not safe))
                  (##vector-cas! _%lock140590%_ '0 '0 '1))))
            _%$r140610%_))))
    (define __method-specializer-table-set!
      (lambda (_%tab140538%_ _%key140539%_ _%value140540%_)
        (let ((_%table140542%_
               (let () (declare (not safe)) (&raw-table-table _%tab140538%_)))
              (_%seed140543%_
               (let () (declare (not safe)) (&raw-table-seed _%tab140538%_))))
          (let* ((_%h140545%_
                  (fxxor (let ()
                           (declare (not safe))
                           (procedure-hash _%key140539%_))
                         _%seed140543%_))
                 (_%size140548%_ (vector-length _%table140542%_))
                 (_%entries140551%_
                  (let ()
                    (declare (not safe))
                    (##fxquotient _%size140548%_ '2)))
                 (_%start140554%_
                  (let ((__tmp148633
                         (let ()
                           (declare (not safe))
                           (##fxmodulo _%h140545%_ _%entries140551%_))))
                    (declare (not safe))
                    (##fxarithmetic-shift-left __tmp148633 '1))))
            (let _%loop140558%_ ((_%probe140561%_ _%start140554%_)
                                 (_%i140563%_ '1)
                                 (_%deleted140565%_ '#f))
              (let ((_%k140568%_ (vector-ref _%table140542%_ _%probe140561%_)))
                (if (eq? _%k140568%_ (macro-unused-obj))
                    (if _%deleted140565%_
                        (begin
                          (vector-set!
                           _%table140542%_
                           _%deleted140565%_
                           _%key140539%_)
                          (vector-set!
                           _%table140542%_
                           (let ()
                             (declare (not safe))
                             (##fx+ _%deleted140565%_ '1))
                           _%value140540%_)
                          (let ((__tmp148634
                                 (let ((__tmp148635
                                        (let ()
                                          (declare (not safe))
                                          (&raw-table-count _%tab140538%_))))
                                   (declare (not safe))
                                   (##fx+ __tmp148635 '1))))
                            (declare (not safe))
                            (&raw-table-count-set! _%tab140538%_ __tmp148634)))
                        (begin
                          (vector-set!
                           _%table140542%_
                           _%probe140561%_
                           _%key140539%_)
                          (vector-set!
                           _%table140542%_
                           (let ()
                             (declare (not safe))
                             (##fx+ _%probe140561%_ '1))
                           _%value140540%_)
                          (let ()
                            (let ((__tmp148636
                                   (let ((__tmp148637
                                          (let ()
                                            (declare (not safe))
                                            (&raw-table-free _%tab140538%_))))
                                     (declare (not safe))
                                     (##fx- __tmp148637 '1))))
                              (declare (not safe))
                              (&raw-table-free-set! _%tab140538%_ __tmp148636))
                            (let ((__tmp148638
                                   (let ((__tmp148639
                                          (let ()
                                            (declare (not safe))
                                            (&raw-table-count _%tab140538%_))))
                                     (declare (not safe))
                                     (##fx+ __tmp148639 '1))))
                              (declare (not safe))
                              (&raw-table-count-set!
                               _%tab140538%_
                               __tmp148638)))))
                    (if (eq? _%k140568%_ (macro-deleted-obj))
                        (_%loop140558%_
                         (let ((_%next-probe140575%_
                                (fx+ _%start140554%_
                                     _%i140563%_
                                     (fx* _%i140563%_ _%i140563%_))))
                           (declare (not safe))
                           (##fxmodulo _%next-probe140575%_ _%size140548%_))
                         (let () (declare (not safe)) (##fx+ _%i140563%_ '1))
                         (let ((_%$e140578%_ _%deleted140565%_))
                           (if _%$e140578%_ _%$e140578%_ _%probe140561%_)))
                        (if (eq? _%key140539%_ _%k140568%_)
                            (let ()
                              (vector-set!
                               _%table140542%_
                               _%probe140561%_
                               _%key140539%_)
                              (vector-set!
                               _%table140542%_
                               (let ()
                                 (declare (not safe))
                                 (##fx+ _%probe140561%_ '1))
                               _%value140540%_))
                            (_%loop140558%_
                             (let ((_%next-probe140583%_
                                    (fx+ _%start140554%_
                                         _%i140563%_
                                         (fx* _%i140563%_ _%i140563%_))))
                               (declare (not safe))
                               (##fxmodulo
                                _%next-probe140583%_
                                _%size140548%_))
                             (let ()
                               (declare (not safe))
                               (##fx+ _%i140563%_ '1))
                             _%deleted140565%_))))))))))
    (define method-specializer-table-set!
      (lambda (_%tab140534%_ _%key140535%_ _%value140536%_)
        (if (let ((__tmp148642
                   (let ()
                     (declare (not safe))
                     (&raw-table-free _%tab140534%_)))
                  (__tmp148640
                   (let ((__tmp148641
                          (vector-length
                           (let ()
                             (declare (not safe))
                             (&raw-table-table _%tab140534%_)))))
                     (declare (not safe))
                     (##fxquotient __tmp148641 '4))))
              (declare (not safe))
              (##fx< __tmp148642 __tmp148640))
            (let () (declare (not safe)) (__raw-table-rehash! _%tab140534%_))
            '#!void)
        (__method-specializer-table-set!
         _%tab140534%_
         _%key140535%_
         _%value140536%_)))
    (define method-specializer-table-set!/lock
      (lambda (_%tab140504%_ _%key140505%_ _%value140506%_)
        (let ((_%lock140509%_
               (let () (declare (not safe)) (&raw-table-lock _%tab140504%_))))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again140514%_ ((_%spin140517%_ '0))
              (if (let ((__tmp148643
                         (let ()
                           (declare (not safe))
                           (##vector-cas! _%lock140509%_ '0 '1 '0))))
                    (declare (not safe))
                    (##fx= __tmp148643 '0))
                  (let ((__tmp148644 (current-thread)))
                    (declare (not safe))
                    (##vector-set! _%lock140509%_ '1 __tmp148644))
                  (if (let () (declare (not safe)) (##fx< _%spin140517%_ '10))
                      (let ()
                        (let () (declare (not safe)) (##thread-yield!))
                        (_%again140514%_
                         (let ()
                           (declare (not safe))
                           (##fx+ _%spin140517%_ '1))))
                      (let ((_%owner140523%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%lock140509%_ '1))))
                        (if (eq? _%owner140523%_ (macro-current-thread))
                            (let ()
                              (declare (not safe))
                              (##thread-deadlock-action!))
                            (if (macro-thread-end-condvar _%owner140523%_)
                                (let ()
                                  (let ()
                                    (declare (not safe))
                                    (##thread-yield!))
                                  (_%again140514%_ '0))
                                (let ()
                                  (declare (not safe))
                                  (##thread-deadlock-action!)))))))))
          (let ((_%$r140529%_
                 (method-specializer-table-set!
                  _%tab140504%_
                  _%key140505%_
                  _%value140506%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (let ()
                  (declare (not safe))
                  (##vector-set! _%lock140509%_ '1 '#f))
                (let ()
                  (declare (not safe))
                  (##vector-cas! _%lock140509%_ '0 '0 '1))))
            _%$r140529%_))))
    (define __method-specializer-table-update!
      (lambda (_%tab140455%_
               _%key140456%_
               _%method-specializer-table-update!140457%_
               _%default140458%_)
        (let ((_%table140460%_
               (let () (declare (not safe)) (&raw-table-table _%tab140455%_)))
              (_%seed140461%_
               (let () (declare (not safe)) (&raw-table-seed _%tab140455%_))))
          (let* ((_%h140463%_
                  (fxxor (let ()
                           (declare (not safe))
                           (procedure-hash _%key140456%_))
                         _%seed140461%_))
                 (_%size140466%_ (vector-length _%table140460%_))
                 (_%entries140469%_
                  (let ()
                    (declare (not safe))
                    (##fxquotient _%size140466%_ '2)))
                 (_%start140472%_
                  (let ((__tmp148645
                         (let ()
                           (declare (not safe))
                           (##fxmodulo _%h140463%_ _%entries140469%_))))
                    (declare (not safe))
                    (##fxarithmetic-shift-left __tmp148645 '1))))
            (let _%loop140476%_ ((_%probe140479%_ _%start140472%_)
                                 (_%i140481%_ '1)
                                 (_%deleted140483%_ '#f))
              (let ((_%k140486%_ (vector-ref _%table140460%_ _%probe140479%_)))
                (if (eq? _%k140486%_ (macro-unused-obj))
                    (if _%deleted140483%_
                        (begin
                          (vector-set!
                           _%table140460%_
                           _%deleted140483%_
                           _%key140456%_)
                          (vector-set!
                           _%table140460%_
                           (let ()
                             (declare (not safe))
                             (##fx+ _%deleted140483%_ '1))
                           (_%method-specializer-table-update!140457%_
                            _%default140458%_))
                          (let ((__tmp148646
                                 (let ((__tmp148647
                                        (let ()
                                          (declare (not safe))
                                          (&raw-table-count _%tab140455%_))))
                                   (declare (not safe))
                                   (##fx+ __tmp148647 '1))))
                            (declare (not safe))
                            (&raw-table-count-set! _%tab140455%_ __tmp148646)))
                        (begin
                          (vector-set!
                           _%table140460%_
                           _%probe140479%_
                           _%key140456%_)
                          (vector-set!
                           _%table140460%_
                           (let ()
                             (declare (not safe))
                             (##fx+ _%probe140479%_ '1))
                           (_%method-specializer-table-update!140457%_
                            _%default140458%_))
                          (let ()
                            (let ((__tmp148648
                                   (let ((__tmp148649
                                          (let ()
                                            (declare (not safe))
                                            (&raw-table-free _%tab140455%_))))
                                     (declare (not safe))
                                     (##fx- __tmp148649 '1))))
                              (declare (not safe))
                              (&raw-table-free-set! _%tab140455%_ __tmp148648))
                            (let ((__tmp148650
                                   (let ((__tmp148651
                                          (let ()
                                            (declare (not safe))
                                            (&raw-table-count _%tab140455%_))))
                                     (declare (not safe))
                                     (##fx+ __tmp148651 '1))))
                              (declare (not safe))
                              (&raw-table-count-set!
                               _%tab140455%_
                               __tmp148650)))))
                    (if (eq? _%k140486%_ (macro-deleted-obj))
                        (_%loop140476%_
                         (let ((_%next-probe140493%_
                                (fx+ _%start140472%_
                                     _%i140481%_
                                     (fx* _%i140481%_ _%i140481%_))))
                           (declare (not safe))
                           (##fxmodulo _%next-probe140493%_ _%size140466%_))
                         (let () (declare (not safe)) (##fx+ _%i140481%_ '1))
                         (let ((_%$e140496%_ _%deleted140483%_))
                           (if _%$e140496%_ _%$e140496%_ _%probe140479%_)))
                        (if (eq? _%key140456%_ _%k140486%_)
                            (let ()
                              (vector-set!
                               _%table140460%_
                               _%probe140479%_
                               _%key140456%_)
                              (vector-set!
                               _%table140460%_
                               (let ()
                                 (declare (not safe))
                                 (##fx+ _%probe140479%_ '1))
                               (_%method-specializer-table-update!140457%_
                                (vector-ref
                                 _%table140460%_
                                 (let ()
                                   (declare (not safe))
                                   (##fx+ _%probe140479%_ '1))))))
                            (_%loop140476%_
                             (let ((_%next-probe140501%_
                                    (fx+ _%start140472%_
                                         _%i140481%_
                                         (fx* _%i140481%_ _%i140481%_))))
                               (declare (not safe))
                               (##fxmodulo
                                _%next-probe140501%_
                                _%size140466%_))
                             (let ()
                               (declare (not safe))
                               (##fx+ _%i140481%_ '1))
                             _%deleted140483%_))))))))))
    (define method-specializer-table-update!
      (lambda (_%tab140450%_
               _%key140451%_
               _%method-specializer-table-update!140452%_
               _%default140453%_)
        (if (let ((__tmp148654
                   (let ()
                     (declare (not safe))
                     (&raw-table-free _%tab140450%_)))
                  (__tmp148652
                   (let ((__tmp148653
                          (vector-length
                           (let ()
                             (declare (not safe))
                             (&raw-table-table _%tab140450%_)))))
                     (declare (not safe))
                     (##fxquotient __tmp148653 '4))))
              (declare (not safe))
              (##fx< __tmp148654 __tmp148652))
            (let () (declare (not safe)) (__raw-table-rehash! _%tab140450%_))
            '#!void)
        (__method-specializer-table-update!
         _%tab140450%_
         _%key140451%_
         _%method-specializer-table-update!140452%_
         _%default140453%_)))
    (define method-specializer-table-update!/lock
      (lambda (_%tab140419%_
               _%key140420%_
               _%method-specializer-table-update!140421%_
               _%default140422%_)
        (let ((_%lock140425%_
               (let () (declare (not safe)) (&raw-table-lock _%tab140419%_))))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again140430%_ ((_%spin140433%_ '0))
              (if (let ((__tmp148655
                         (let ()
                           (declare (not safe))
                           (##vector-cas! _%lock140425%_ '0 '1 '0))))
                    (declare (not safe))
                    (##fx= __tmp148655 '0))
                  (let ((__tmp148656 (current-thread)))
                    (declare (not safe))
                    (##vector-set! _%lock140425%_ '1 __tmp148656))
                  (if (let () (declare (not safe)) (##fx< _%spin140433%_ '10))
                      (let ()
                        (let () (declare (not safe)) (##thread-yield!))
                        (_%again140430%_
                         (let ()
                           (declare (not safe))
                           (##fx+ _%spin140433%_ '1))))
                      (let ((_%owner140439%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%lock140425%_ '1))))
                        (if (eq? _%owner140439%_ (macro-current-thread))
                            (let ()
                              (declare (not safe))
                              (##thread-deadlock-action!))
                            (if (macro-thread-end-condvar _%owner140439%_)
                                (let ()
                                  (let ()
                                    (declare (not safe))
                                    (##thread-yield!))
                                  (_%again140430%_ '0))
                                (let ()
                                  (declare (not safe))
                                  (##thread-deadlock-action!)))))))))
          (let ((_%$r140445%_
                 (_%method-specializer-table-update!140421%_
                  _%tab140419%_
                  _%key140420%_
                  _%method-specializer-table-update!140421%_
                  _%default140422%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (let ()
                  (declare (not safe))
                  (##vector-set! _%lock140425%_ '1 '#f))
                (let ()
                  (declare (not safe))
                  (##vector-cas! _%lock140425%_ '0 '0 '1))))
            _%$r140445%_))))
    (define method-specializer-table-delete!
      (lambda (_%tab140376%_ _%key140377%_)
        (let ((_%table140379%_
               (let () (declare (not safe)) (&raw-table-table _%tab140376%_)))
              (_%seed140381%_
               (let () (declare (not safe)) (&raw-table-seed _%tab140376%_))))
          (let* ((_%h140384%_
                  (fxxor (let ()
                           (declare (not safe))
                           (procedure-hash _%key140377%_))
                         _%seed140381%_))
                 (_%size140387%_ (vector-length _%table140379%_))
                 (_%entries140390%_
                  (let ()
                    (declare (not safe))
                    (##fxquotient _%size140387%_ '2)))
                 (_%start140393%_
                  (let ((__tmp148657
                         (let ()
                           (declare (not safe))
                           (##fxmodulo _%h140384%_ _%entries140390%_))))
                    (declare (not safe))
                    (##fxarithmetic-shift-left __tmp148657 '1))))
            (let _%loop140397%_ ((_%probe140400%_ _%start140393%_)
                                 (_%i140402%_ '1))
              (let ((_%k140405%_ (vector-ref _%table140379%_ _%probe140400%_)))
                (if (eq? _%k140405%_ (macro-unused-obj))
                    '#!void
                    (if (eq? _%k140405%_ (macro-deleted-obj))
                        (_%loop140397%_
                         (let ((_%next-probe140410%_
                                (fx+ _%start140393%_
                                     _%i140402%_
                                     (fx* _%i140402%_ _%i140402%_))))
                           (declare (not safe))
                           (##fxmodulo _%next-probe140410%_ _%size140387%_))
                         (let () (declare (not safe)) (##fx+ _%i140402%_ '1)))
                        (if (eq? _%key140377%_ _%k140405%_)
                            (let ()
                              (vector-set!
                               _%table140379%_
                               _%probe140400%_
                               (macro-deleted-obj))
                              (vector-set!
                               _%table140379%_
                               (let ()
                                 (declare (not safe))
                                 (##fx+ _%probe140400%_ '1))
                               (macro-absent-obj))
                              (let ((__tmp148658
                                     (let ((__tmp148659
                                            (let ()
                                              (declare (not safe))
                                              (&raw-table-count
                                               _%tab140376%_))))
                                       (declare (not safe))
                                       (##fx- __tmp148659 '1))))
                                (declare (not safe))
                                (&raw-table-count-set!
                                 _%tab140376%_
                                 __tmp148658)))
                            (_%loop140397%_
                             (let ((_%next-probe140416%_
                                    (fx+ _%start140393%_
                                         _%i140402%_
                                         (fx* _%i140402%_ _%i140402%_))))
                               (declare (not safe))
                               (##fxmodulo
                                _%next-probe140416%_
                                _%size140387%_))
                             (let ()
                               (declare (not safe))
                               (##fx+ _%i140402%_ '1))))))))))))
    (define method-specializer-table-delete!/lock
      (lambda (_%tab140346%_ _%key140348%_)
        (let ((_%lock140351%_
               (let () (declare (not safe)) (&raw-table-lock _%tab140346%_))))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again140356%_ ((_%spin140359%_ '0))
              (if (let ((__tmp148660
                         (let ()
                           (declare (not safe))
                           (##vector-cas! _%lock140351%_ '0 '1 '0))))
                    (declare (not safe))
                    (##fx= __tmp148660 '0))
                  (let ((__tmp148661 (current-thread)))
                    (declare (not safe))
                    (##vector-set! _%lock140351%_ '1 __tmp148661))
                  (if (let () (declare (not safe)) (##fx< _%spin140359%_ '10))
                      (let ()
                        (let () (declare (not safe)) (##thread-yield!))
                        (_%again140356%_
                         (let ()
                           (declare (not safe))
                           (##fx+ _%spin140359%_ '1))))
                      (let ((_%owner140365%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref _%lock140351%_ '1))))
                        (if (eq? _%owner140365%_ (macro-current-thread))
                            (let ()
                              (declare (not safe))
                              (##thread-deadlock-action!))
                            (if (macro-thread-end-condvar _%owner140365%_)
                                (let ()
                                  (let ()
                                    (declare (not safe))
                                    (##thread-yield!))
                                  (_%again140356%_ '0))
                                (let ()
                                  (declare (not safe))
                                  (##thread-deadlock-action!)))))))))
          (let ((_%$r140371%_
                 (method-specializer-table-delete!
                  _%tab140346%_
                  _%key140348%_)))
            (let ()
              (declare (not interrupts-enabled))
              (begin
                (let ()
                  (declare (not safe))
                  (##vector-set! _%lock140351%_ '1 '#f))
                (let ()
                  (declare (not safe))
                  (##vector-cas! _%lock140351%_ '0 '0 '1))))
            _%$r140371%_))))
    (define __method-specializers
      (make-method-specializer-table/lock__% '#f '0))
    (define bind-specializer!
      (lambda (_%method-proc140343%_ _%specializer140344%_)
        (method-specializer-table-set!/lock
         __method-specializers
         _%method-proc140343%_
         _%specializer140344%_)))
    (define __lookup-method-specializer
      (lambda (_%proc140341%_)
        (method-specializer-table-ref/lock
         __method-specializers
         _%proc140341%_
         '#f)))
    (define __specialize-class
      (lambda (_%klass140323%_)
        (let* ((_%klass140326%_ _%klass140323%_)
               (_%$e140335%_
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-ref _%klass140326%_ '12 '#f '#f))))
          (if _%$e140335%_
              _%$e140335%_
              (let ((_%method-table140339%_
                     (___specialize-class _%klass140326%_)))
                (let ()
                  (declare (not safe))
                  (##unchecked-structure-set!
                   _%klass140326%_
                   _%method-table140339%_
                   '12
                   '#f
                   '#f))
                _%method-table140339%_)))))
    (define specialize-class
      (lambda (_%klass140309%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass140309%_ 'class))
            (let ((_%klass140313%_ _%klass140309%_))
              (__specialize-class _%klass140313%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1174.25-1174.30"
               'contract:
               'class-type?
               'value:
               _%klass140309%_)
              '#!void))))
    (define __specialize-method
      (lambda (_%klass140293%_
               _%method-table140294%_
               _%method140295%_
               _%proc140296%_)
        (let ((_%$e140298%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref
                  _%method-table140294%_
                  _%method140295%_
                  '#f))))
          (if _%$e140298%_
              _%$e140298%_
              (let ((_%$e140301%_
                     (__lookup-method-specializer _%proc140296%_)))
                (if _%$e140301%_
                    (let ((_%specialized-proc140306%_
                           (_%$e140301%_
                            _%klass140293%_
                            _%method-table140294%_)))
                      (declare (not safe))
                      (symbolic-table-set!
                       _%method-table140294%_
                       _%method140295%_
                       _%specialized-proc140306%_))
                    (let ()
                      (declare (not safe))
                      (symbolic-table-set!
                       _%method-table140294%_
                       _%method140295%_
                       _%proc140296%_))))))))
    (define ___specialize-class
      (lambda (_%klass140160%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass140160%_ 'class))
            (if (let* ((_%klass140163%_ _%klass140160%_)
                       (_%klass140168%_ _%klass140163%_))
                  (__class-type-metaclass? _%klass140168%_))
                (let* ((_%obj140180%_ _%klass140160%_)
                       (_%id140183%_ 'specialize-class)
                       (_%args140186%_ '())
                       (_%id140191%_ _%id140183%_))
                  (declare (not safe))
                  (##apply __call-method
                           _%obj140180%_
                           _%id140191%_
                           _%args140186%_))
                (if (let* ((_%pred140204%_ class-type-metaclass?)
                           (_%lst140207%_
                            (let ()
                              (declare (not safe))
                              (##unchecked-structure-ref
                               _%klass140160%_
                               '6
                               '#f
                               '#f)))
                           (_%pred140212%_ _%pred140204%_))
                      (declare (not safe))
                      (__find _%pred140212%_ _%lst140207%_))
                    (error '"cannot specialize class that extends metaclass without a metaclass"
                           _%klass140160%_)
                    (let ((_%method-table140225%_
                           (let ()
                             (declare (not safe))
                             (make-symbolic-table__% '#f '0))))
                      (let _%loop140227%_ ((_%rest140229%_
                                            (let* ((_%klass140276%_
                                                    _%klass140160%_)
                                                   (_%klass140281%_
                                                    _%klass140276%_))
                                              (__class-precedence-list
                                               _%klass140281%_))))
                        (let* ((_%$%rest140230140238%_ _%rest140229%_)
                               (_%$%else140232140246%_
                                (lambda () _%method-table140225%_))
                               (_%$%K140234140264%_
                                (lambda (_%rest140249%_ _%xklass140250%_)
                                  (let ((_%$%xmethod-table140251140253%_
                                         (let ()
                                           (declare (not safe))
                                           (##unchecked-structure-ref
                                            _%xklass140250%_
                                            '11
                                            '#f
                                            '#f))))
                                    (if _%$%xmethod-table140251140253%_
                                        (let* ((_%xmethod-table140255%_
                                                _%$%xmethod-table140251140253%_)
                                               (__tmp148662
                                                (lambda (_%$%g140256140259%_
                                                         _%$%g140257140261%_)
                                                  (__specialize-method
                                                   _%klass140160%_
                                                   _%method-table140225%_
                                                   _%$%g140256140259%_
                                                   _%$%g140257140261%_))))
                                          (declare (not safe))
                                          (raw-table-for-each
                                           _%xmethod-table140255%_
                                           __tmp148662))
                                        '#f))
                                  (_%loop140227%_ _%rest140249%_))))
                          (if (pair? _%$%rest140230140238%_)
                              (let ((_%$%hd140235140267%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest140230140238%_)))
                                    (_%$%tl140236140269%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest140230140238%_))))
                                (let* ((_%xklass140272%_ _%$%hd140235140267%_)
                                       (_%rest140274%_ _%$%tl140236140269%_))
                                  (_%$%K140234140264%_
                                   _%rest140274%_
                                   _%xklass140272%_)))
                              (_%$%else140232140246%_)))))))
            (if (let () (declare (not safe)) (##type? _%klass140160%_))
                (__specialize-class (__shadow-class__0 _%klass140160%_))
                (error '"bad class; cannot specialize" _%klass140160%_)))))
    (define __seal-class!
      (lambda (_%klass140023%_)
        (let ((_%klass140026%_ _%klass140023%_))
          (if (let* ((_%klass140035%_ _%klass140026%_)
                     (_%klass140040%_ _%klass140035%_))
                (__class-type-sealed? _%klass140040%_))
              '#!void
              (begin
                (if (let* ((_%klass140053%_ _%klass140026%_)
                           (_%klass140058%_ _%klass140053%_))
                      (__class-type-metaclass? _%klass140058%_))
                    (let ()
                      (let* ((_%obj140069%_ _%klass140026%_)
                             (_%id140072%_ 'seal-class!)
                             (_%args140075%_ '())
                             (_%id140080%_ _%id140072%_))
                        (declare (not safe))
                        (##apply __call-method
                                 _%obj140069%_
                                 _%id140080%_
                                 _%args140075%_))
                      (let* ((_%klass140093%_ _%klass140026%_)
                             (_%klass140098%_ _%klass140093%_))
                        (__specialize-class _%klass140098%_)))
                    (if (let* ((_%pred140108%_ class-type-metaclass?)
                               (_%lst140111%_
                                (let ()
                                  (declare (not safe))
                                  (##unchecked-structure-ref
                                   _%klass140026%_
                                   '6
                                   '#f
                                   '#f)))
                               (_%pred140116%_ _%pred140108%_))
                          (declare (not safe))
                          (__find _%pred140116%_ _%lst140111%_))
                        (error '"cannot seal class that extends metaclass without a metaclass"
                               _%klass140026%_)
                        (let* ((_%klass140129%_ _%klass140026%_)
                               (_%klass140134%_ _%klass140129%_))
                          (__specialize-class _%klass140134%_))))
                (let* ((_%klass140145%_ _%klass140026%_)
                       (_%klass140150%_ _%klass140145%_))
                  (__class-type-seal! _%klass140150%_)))))))
    (define seal-class!
      (lambda (_%klass140009%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%klass140009%_ 'class))
            (let ((_%klass140013%_ _%klass140009%_))
              (__seal-class! _%klass140013%_))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1220.20-1220.25"
               'contract:
               'class-type?
               'value:
               _%klass140009%_)
              '#!void))))
    (define __next-method
      (lambda (_%subklass139897%_ _%obj139898%_ _%id139899%_)
        (let* ((_%subklass139902%_ _%subklass139897%_)
               (_%id139910%_ _%id139899%_))
          (letrec ((_%find-next-method139919%_
                    (lambda (_%klass139921%_)
                      (let _%lp139923%_ ((_%rest139925%_
                                          (let ((_%klass139994%_
                                                 _%klass139921%_))
                                            (if (let ()
                                                  (declare (not safe))
                                                  (##structure-instance-of?
                                                   _%klass139994%_
                                                   'class))
                                                (let ((_%klass139999%_
                                                       _%klass139994%_))
                                                  (__class-precedence-list
                                                   _%klass139999%_))
                                                (begin
                                                  (raise-contract-violation-error
                                                   '"contract violation"
                                                   'context:
                                                   'gerbil/runtime/mop
                                                   'contract:
                                                   'class-type?
                                                   'value:
                                                   _%klass139994%_)
                                                  '#!void)))))
                        (let* ((_%$%rest139926139934%_ _%rest139925%_)
                               (_%$%else139928139942%_ (lambda () '#f))
                               (_%$%K139930139982%_
                                (lambda (_%rest139945%_ _%klass139946%_)
                                  (if (eq? (let ()
                                             (declare (not safe))
                                             (##type-id _%subklass139902%_))
                                           (let ()
                                             (declare (not safe))
                                             (##type-id _%klass139946%_)))
                                      (let* ((_%mixins139948%_ _%rest139945%_)
                                             (_%obj139951%_ _%obj139898%_)
                                             (_%id139954%_ _%id139910%_)
                                             (_%id139959%_ _%id139954%_))
                                        (__mixin-find-method
                                         _%mixins139948%_
                                         _%obj139951%_
                                         _%id139959%_))
                                      (_%lp139923%_ _%rest139945%_)))))
                          (if (pair? _%$%rest139926139934%_)
                              (let ((_%$%hd139931139985%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest139926139934%_)))
                                    (_%$%tl139932139987%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest139926139934%_))))
                                (let* ((_%klass139990%_ _%$%hd139931139985%_)
                                       (_%rest139992%_ _%$%tl139932139987%_))
                                  (_%$%K139930139982%_
                                   _%rest139992%_
                                   _%klass139990%_)))
                              (_%$%else139928139942%_)))))))
            (_%find-next-method139919%_ (class-of _%obj139898%_))))))
    (define next-method
      (lambda (_%subklass139871%_ _%obj139872%_ _%id139873%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%subklass139871%_ 'class))
            (let ((_%subklass139877%_ _%subklass139871%_))
              (if (symbol? _%id139873%_)
                  (let ((_%id139887%_ _%id139873%_))
                    (__next-method
                     _%subklass139877%_
                     _%obj139872%_
                     _%id139887%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@1242.44-1242.46"
                     'contract:
                     'symbol?
                     'value:
                     _%id139873%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1242.20-1242.28"
               'contract:
               'class-type?
               'value:
               _%subklass139871%_)
              '#!void))))
    (define __call-next-method
      (lambda (_%subklass139806%_ _%obj139807%_ _%id139808%_ . _%args139809%_)
        (let* ((_%subklass139812%_ _%subklass139806%_)
               (_%id139820%_ _%id139808%_)
               (_%$e139865%_
                (let* ((_%subklass139829%_ _%subklass139812%_)
                       (_%obj139832%_ _%obj139807%_)
                       (_%id139835%_ _%id139820%_)
                       (_%subklass139840%_ _%subklass139829%_)
                       (_%id139855%_ _%id139835%_))
                  (__next-method
                   _%subklass139840%_
                   _%obj139832%_
                   _%id139855%_))))
          (if _%$e139865%_
              (apply _%$e139865%_ _%obj139807%_ _%args139809%_)
              (error '"cannot find next method"
                     'object:
                     _%obj139807%_
                     'method:
                     _%id139820%_)))))
    (define call-next-method
      (lambda (_%subklass139779%_ _%obj139780%_ _%id139781%_ . _%args139782%_)
        (if (let ()
              (declare (not safe))
              (##structure-instance-of? _%subklass139779%_ 'class))
            (let ((_%subklass139786%_ _%subklass139779%_))
              (if (symbol? _%id139781%_)
                  (let ((_%id139796%_ _%id139781%_))
                    (declare (not safe))
                    (##apply __call-next-method
                             _%subklass139786%_
                             _%obj139780%_
                             _%id139796%_
                             _%args139782%_))
                  (begin
                    (raise-contract-violation-error
                     '"contract violation"
                     'context:
                     '"\"gerbil/runtime/mop.ss\"@1253.49-1253.51"
                     'contract:
                     'symbol?
                     'value:
                     _%id139781%_)
                    '#!void)))
            (begin
              (raise-contract-violation-error
               '"contract violation"
               'context:
               '"\"gerbil/runtime/mop.ss\"@1253.25-1253.33"
               'contract:
               'class-type?
               'value:
               _%subklass139779%_)
              '#!void))))
    (define __shadow-classes
      (let () (declare (not safe)) (make-symbolic-table__% '#f '0)))
    (define __shadow-classes-lock (vector '0 '#f))
    (define __shadow-class__%
      (lambda (_%type139558%_ _%properties139559%_)
        (letrec ((_%shadow-type-id139561%_
                  (lambda (_%type139767%_)
                    (let ((__tmp148663
                           (let ()
                             (declare (not safe))
                             (##type-name _%type139767%_))))
                      (declare (not safe))
                      (make-symbol__1 __tmp148663 '"::t"))))
                 (_%shadow-type-name139562%_
                  (lambda (_%type139765%_)
                    (let ()
                      (declare (not safe))
                      (##type-name _%type139765%_))))
                 (_%make-shadow-class139563%_
                  (lambda (_%type139647%_ _%precedence-list139648%_)
                    (let* ((_%super139650%_
                            (if (pair? _%precedence-list139648%_)
                                (cons (let ()
                                        (declare (not safe))
                                        (##car _%precedence-list139648%_))
                                      '())
                                '()))
                           (_%klass139762%_
                            (let* ((_%id139652%_
                                    (_%shadow-type-id139561%_ _%type139647%_))
                                   (_%name139655%_
                                    (let ()
                                      (declare (not safe))
                                      (##type-name _%type139647%_)))
                                   (_%direct-supers139658%_ _%super139650%_)
                                   (_%direct-slots139661%_ '())
                                   (_%properties139687%_
                                    (cons (cons 'struct: '#t)
                                          (cons (cons 'system: '#t)
                                                (cons (cons 'system-type:
                                                            _%type139647%_)
                                                      (append (if (let ((_%type139664%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                 _%type139647%_))
                            (if (let ()
                                  (declare (not safe))
                                  (##type? _%type139664%_))
                                (let ((_%type139669%_ _%type139664%_))
                                  (__type-extensible? _%type139669%_))
                                (begin
                                  (raise-contract-violation-error
                                   '"contract violation"
                                   'context:
                                   'gerbil/runtime/mop
                                   'contract:
                                   '##type?
                                   'value:
                                   _%type139664%_)
                                  '#!void)))
                          '()
                          (cons (cons 'final: '#t) '()))
                      _%properties139559%_)))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                   (_%constructor139690%_ '#f)
                                   (_%id139695%_ _%id139652%_))
                              (if (symbol? _%name139655%_)
                                  (let* ((_%name139706%_ _%name139655%_)
                                         (_%direct-supers139716%_
                                          _%direct-supers139658%_)
                                         (_%direct-slots139726%_
                                          _%direct-slots139661%_)
                                         (_%properties139736%_
                                          _%properties139687%_))
                                    (if (let ((_%$e139748%_ '#t))
                                          (and _%$e139748%_ _%$e139748%_))
                                        (let ((_%constructor139752%_
                                               _%constructor139690%_))
                                          (__make-class-type
                                           _%id139695%_
                                           _%name139706%_
                                           _%direct-supers139716%_
                                           _%direct-slots139726%_
                                           _%properties139736%_
                                           _%constructor139752%_))
                                        (begin
                                          (raise-contract-violation-error
                                           '"contract violation"
                                           'context:
                                           'gerbil/runtime/mop
                                           'contract:
                                           '(? (or not symbol?))
                                           'value:
                                           _%constructor139690%_)
                                          '#!void)))
                                  (begin
                                    (raise-contract-violation-error
                                     '"contract violation"
                                     'context:
                                     'gerbil/runtime/mop
                                     'contract:
                                     'symbol?
                                     'value:
                                     _%name139655%_)
                                    '#!void)))))
                      (let ((__tmp148664
                             (let ()
                               (declare (not safe))
                               (##type-id _%type139647%_))))
                        (declare (not safe))
                        (symbolic-table-set!
                         __shadow-classes
                         __tmp148664
                         _%klass139762%_))
                      _%klass139762%_))))
          (let ()
            (declare (not interrupts-enabled))
            (let _%again139567%_ ((_%spin139570%_ '0))
              (if (let ((__tmp148665
                         (let ()
                           (declare (not safe))
                           (##vector-cas! __shadow-classes-lock '0 '1 '0))))
                    (declare (not safe))
                    (##fx= __tmp148665 '0))
                  (let ((__tmp148666 (current-thread)))
                    (declare (not safe))
                    (##vector-set! __shadow-classes-lock '1 __tmp148666))
                  (if (let () (declare (not safe)) (##fx< _%spin139570%_ '10))
                      (let ()
                        (let () (declare (not safe)) (##thread-yield!))
                        (_%again139567%_
                         (let ()
                           (declare (not safe))
                           (##fx+ _%spin139570%_ '1))))
                      (let ((_%owner139576%_
                             (let ()
                               (declare (not safe))
                               (##vector-ref __shadow-classes-lock '1))))
                        (if (eq? _%owner139576%_ (macro-current-thread))
                            (let ()
                              (declare (not safe))
                              (##thread-deadlock-action!))
                            (if (macro-thread-end-condvar _%owner139576%_)
                                (let ()
                                  (let ()
                                    (declare (not safe))
                                    (##thread-yield!))
                                  (_%again139567%_ '0))
                                (let ()
                                  (declare (not safe))
                                  (##thread-deadlock-action!)))))))))
          (let ((_%$e139582%_
                 (let ((__tmp148667
                        (let ()
                          (declare (not safe))
                          (##type-id _%type139558%_))))
                   (declare (not safe))
                   (symbolic-table-ref __shadow-classes __tmp148667 '#f))))
            (if _%$e139582%_
                (let ()
                  (let ()
                    (declare (not interrupts-enabled))
                    (begin
                      (let ()
                        (declare (not safe))
                        (##vector-set! __shadow-classes-lock '1 '#f))
                      (let ()
                        (declare (not safe))
                        (##vector-cas! __shadow-classes-lock '0 '0 '1))))
                  _%$e139582%_)
                (let _%loop139590%_ ((_%super139592%_
                                      (let ()
                                        (declare (not safe))
                                        (##type-super _%type139558%_)))
                                     (_%hierarchy139593%_ '()))
                  (if _%super139592%_
                      (_%loop139590%_
                       (let ()
                         (declare (not safe))
                         (##type-super _%super139592%_))
                       (cons _%super139592%_ _%hierarchy139593%_))
                      (let _%loop139596%_ ((_%rest139598%_ _%hierarchy139593%_)
                                           (_%precedence-list139599%_ '()))
                        (let* ((_%$%rest139600139608%_ _%rest139598%_)
                               (_%$%else139602139620%_
                                (lambda ()
                                  (let ((_%klass139616%_
                                         (_%make-shadow-class139563%_
                                          _%type139558%_
                                          _%precedence-list139599%_)))
                                    (let ()
                                      (declare (not interrupts-enabled))
                                      (begin
                                        (let ()
                                          (declare (not safe))
                                          (##vector-set!
                                           __shadow-classes-lock
                                           '1
                                           '#f))
                                        (let ()
                                          (declare (not safe))
                                          (##vector-cas!
                                           __shadow-classes-lock
                                           '0
                                           '0
                                           '1))))
                                    _%klass139616%_)))
                               (_%$%K139604139634%_
                                (lambda (_%rest139623%_ _%type139624%_)
                                  (let ((_%$e139626%_
                                         (let ((__tmp148668
                                                (let ()
                                                  (declare (not safe))
                                                  (##type-id _%type139624%_))))
                                           (declare (not safe))
                                           (symbolic-table-ref
                                            __shadow-classes
                                            __tmp148668
                                            '#f))))
                                    (if _%$e139626%_
                                        (_%loop139596%_
                                         _%rest139623%_
                                         (cons _%$e139626%_
                                               _%precedence-list139599%_))
                                        (let ((_%klass139632%_
                                               (_%make-shadow-class139563%_
                                                _%type139624%_
                                                _%precedence-list139599%_)))
                                          (_%loop139596%_
                                           _%rest139623%_
                                           (cons _%klass139632%_
                                                 _%precedence-list139599%_))))))))
                          (if (pair? _%$%rest139600139608%_)
                              (let ((_%$%hd139605139637%_
                                     (let ()
                                       (declare (not safe))
                                       (##car _%$%rest139600139608%_)))
                                    (_%$%tl139606139639%_
                                     (let ()
                                       (declare (not safe))
                                       (##cdr _%$%rest139600139608%_))))
                                (let* ((_%type139642%_ _%$%hd139605139637%_)
                                       (_%rest139644%_ _%$%tl139606139639%_))
                                  (_%$%K139604139634%_
                                   _%rest139644%_
                                   _%type139642%_)))
                              (_%$%else139602139620%_)))))))))))
    (define __shadow-class__0
      (lambda (_%type139772%_)
        (let ((_%properties139774%_ '()))
          (__shadow-class__% _%type139772%_ _%properties139774%_))))
    (define __shadow-class
      (lambda _g148669_
        (let ((_g148670_ (let () (declare (not safe)) (##length _g148669_))))
          (cond ((let () (declare (not safe)) (##fx= _g148670_ 1))
                 (apply __shadow-class__0 _g148669_))
                ((let () (declare (not safe)) (##fx= _g148670_ 2))
                 (apply __shadow-class__% _g148669_))
                (else
                 (##raise-wrong-number-of-arguments-exception
                  __shadow-class
                  _g148669_))))))
    (define __type
      (let* ((_%tb139546%_
              (let ()
                (declare (not safe))
                (##c-code '"___RESULT = ___FIX(___TB);")))
             (_%$e139548%_ _%tb139546%_))
        (if (eq? '2 _%$e139548%_)
            '#(fixnum subtyped special pair)
            (if (eq? '3 _%$e139548%_)
                (let ((_%flonum-self-tagging-tags139551%_
                       (let ()
                         (declare (not safe))
                         (##c-code
                          '"___RESULT = ___FIX(___FLONUM_SELF_TAGGING_TAGS);")))
                      (_%fixnum-tag-bits139552%_
                       (let ()
                         (declare (not safe))
                         (##c-code
                          '"#ifdef ___USE_2_TAG_BITS_FOR_FIXNUMS\n___RESULT = ___FIX(2) ;\n#else\n___RESULT = ___FIX(3) ;\n#endif"))))
                  (let ((_%$e139554%_ _%flonum-self-tagging-tags139551%_))
                    (if (eq? '0 _%$e139554%_)
                        (if (let ()
                              (declare (not safe))
                              (##fx= _%fixnum-tag-bits139552%_ '2))
                            '#(fixnum
                               subtyped
                               special
                               vector
                               fixnum
                               pair
                               undefined
                               haflonum)
                            '#(fixnum
                               subtyped
                               undefined
                               vector
                               special
                               pair
                               undefined
                               haflonum))
                        (if (eq? '1 _%$e139554%_)
                            (if (let ()
                                  (declare (not safe))
                                  (##fx= _%fixnum-tag-bits139552%_ '2))
                                '#(fixnum
                                   subtyped
                                   special
                                   vector
                                   fixnum
                                   pair
                                   stflonum
                                   haflonum)
                                '#(fixnum
                                   subtyped
                                   undefined
                                   vector
                                   special
                                   pair
                                   stflonum
                                   haflonum))
                            (if (eq? '2 _%$e139554%_)
                                '#(fixnum
                                   subtyped
                                   stflonum
                                   haflonum
                                   special
                                   pair
                                   stflonum
                                   undefined)
                                (if (eq? '3 _%$e139554%_)
                                    '#(fixnum
                                       subtyped
                                       haflonum
                                       immedate-flonum
                                       special
                                       pair
                                       stflonum
                                       stflonum)
                                    (if (eq? '4 _%$e139554%_)
                                        '#(fixnum
                                           subtyped
                                           stflonum
                                           stflonum
                                           special
                                           pair
                                           stflonum
                                           stflonum)
                                        (error '"unexpected flonum self tagging tags"
                                               _%flonum-self-tagging-tags139551%_))))))))
                (error '"unexpected tag width" _%tb139546%_)))))
    (define __primitive-class
      (let ((__tmp148671 (vector-length __type)))
        (declare (not safe))
        (##make-vector __tmp148671 '#f)))
    (define __boxvalues-class
      (let () (declare (not safe)) (##make-vector '2 '#f)))
    (define __subtype-class
      (let () (declare (not safe)) (##make-vector '32 '#f)))
    (define __char-class '#f)
    (define __special-class
      (let () (declare (not safe)) (##make-vector '16 '#f)))
    (define __class-of
      (let* ((_%len139436%_ (vector-length __type))
             (_%cv139438%_
              (let () (declare (not safe)) (##make-vector _%len139436%_ '#f))))
        (let _%loop139441%_ ((_%i139443%_ '0))
          (if (let () (declare (not safe)) (##fx< _%i139443%_ _%len139436%_))
              (let* ((_%t139445%_
                      (let ()
                        (declare (not safe))
                        (##vector-ref __type _%i139443%_)))
                     (_%f139543%_
                      (if (eq? _%t139445%_ 'undefined)
                          (lambda (_%obj139448%_)
                            (error '"object type is undefined" _%obj139448%_))
                          (if (let ()
                                (declare (not safe))
                                (##memq _%t139445%_
                                        '(fixnum flonum
                                                 stflonum
                                                 haflonum
                                                 pair
                                                 vector)))
                              (lambda (_%obj139451%_)
                                (declare (not interrupts-enabled) (not safe))
                                (let ((_%$e139454%_
                                       (##vector-ref
                                        __primitive-class
                                        _%i139443%_)))
                                  (if _%$e139454%_
                                      _%$e139454%_
                                      (let ((_%klass139458%_
                                             (__system-class _%t139445%_)))
                                        (##vector-set!
                                         __primitive-class
                                         _%i139443%_
                                         _%klass139458%_)
                                        _%klass139458%_))))
                              (if (eq? _%t139445%_ 'subtyped)
                                  (lambda (_%obj139462%_)
                                    (declare
                                      (not interrupts-enabled)
                                      (not safe))
                                    (let ((_%st139465%_
                                           (##subtype _%obj139462%_)))
                                      (if (##fx= _%st139465%_
                                                 (macro-subtype-structure))
                                          (let ((_%klass139468%_
                                                 (##structure-type
                                                  _%obj139462%_)))
                                            (if (##structure-instance-of?
                                                 _%klass139468%_
                                                 'class)
                                                _%klass139468%_
                                                (__shadow-class__0
                                                 _%klass139468%_)))
                                          (if (##fx= _%st139465%_
                                                     (macro-subtype-boxvalues))
                                              (if (##fx= (##values-length
                                                          _%obj139462%_)
                                                         '1)
                                                  (let ((_%$e139471%_
                                                         (##vector-ref
                                                          __boxvalues-class
                                                          '0)))
                                                    (if _%$e139471%_
                                                        _%$e139471%_
                                                        (let ((_%klass139475%_
                                                               (__system-class
                                                                'box)))
                                                          (##vector-set!
                                                           __boxvalues-class
                                                           '0
                                                           _%klass139475%_)
                                                          _%klass139475%_)))
                                                  (let ((_%$e139478%_
                                                         (##vector-ref
                                                          __boxvalues-class
                                                          '1)))
                                                    (if _%$e139478%_
                                                        _%$e139478%_
                                                        (let ((_%klass139482%_
                                                               (__system-class
                                                                'values)))
                                                          (##vector-set!
                                                           __boxvalues-class
                                                           '1
                                                           _%klass139482%_)
                                                          _%klass139482%_))))
                                              (let ((_%$e139485%_
                                                     (##vector-ref
                                                      __subtype-class
                                                      _%st139465%_)))
                                                (if _%$e139485%_
                                                    _%$e139485%_
                                                    (let ((_%klass139502%_
                                                           (let ((_%$e139489%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                          (##vector-ref __subtype-id _%st139465%_)))
                     (if _%$e139489%_
                         (let ((_%$e139494%_
                                (##vector-ref __subtype-class _%st139465%_)))
                           (if _%$e139494%_
                               _%$e139494%_
                               (let ((_%klass139498%_
                                      (__system-class _%$e139489%_)))
                                 (##vector-set!
                                  __subtype-class
                                  _%st139465%_
                                  _%klass139498%_)
                                 _%klass139498%_)))
                         (error '"unknown class"
                                'object:
                                _%obj139462%_
                                'subtype:
                                _%st139465%_)))))
              (##vector-set! __subtype-class _%st139465%_ _%klass139502%_)
              _%klass139502%_)))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                  (if (eq? _%t139445%_ 'special)
                                      (lambda (_%obj139506%_)
                                        (declare
                                          (not interrupts-enabled)
                                          (not safe))
                                        (let ((_%x139509%_
                                               (##type-cast _%obj139506%_ '0)))
                                          (if (##fx> _%x139509%_ '0)
                                              (let ((_%$e139512%_
                                                     __char-class))
                                                (if _%$e139512%_
                                                    _%$e139512%_
                                                    (let ((_%klass139516%_
                                                           (__system-class
                                                            'char)))
                                                      (set! __char-class
                                                            _%klass139516%_)
                                                      _%klass139516%_)))
                                              (let* ((_%t139519%_
                                                      (##fx- _%x139509%_))
                                                     (_%$e139522%_
                                                      (##vector-ref
                                                       __special-class
                                                       _%t139519%_)))
                                                (if _%$e139522%_
                                                    _%$e139522%_
                                                    (let ((_%klass139540%_
                                                           (if (eq? _%obj139506%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            '())
                       (__system-class 'null)
                       (if (eq? _%obj139506%_ '#f)
                           (__system-class 'false)
                           (if (eq? _%obj139506%_ '#t)
                               (__system-class 'true)
                               (if (eq? _%obj139506%_ '#!void)
                                   (__system-class 'void)
                                   (if (eq? _%obj139506%_ '#!eof)
                                       (__system-class 'eof)
                                       (if (eq? _%obj139506%_ '#!unbound)
                                           (__system-class 'unbound)
                                           (if (eq? _%obj139506%_ '#!unbound2)
                                               (__system-class 'unbound2)
                                               (if (eq? _%obj139506%_
                                                        '#!optional)
                                                   (__system-class 'optional)
                                                   (if (eq? _%obj139506%_
                                                            '#!rest)
                                                       (__system-class 'rest)
                                                       (if (eq? _%obj139506%_
                                                                '#!key)
                                                           (__system-class
                                                            'key)
                                                           (if (eq? _%obj139506%_
;;<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                            (macro-unused-obj))
                       (__system-class 'unused)
                       (if (eq? _%obj139506%_ (macro-deleted-obj))
                           (__system-class 'deleted)
                           (if (eq? _%obj139506%_ (macro-absent-obj))
                               (__system-class 'absent)
                               (__system-class 'unknown))))))))))))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
              (##vector-set! __special-class _%t139519%_ _%klass139540%_)
              _%klass139540%_))))))
;;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                      (error '"unexpected object type"
                                             _%t139445%_)))))))
                (let ()
                  (declare (not safe))
                  (##vector-set! _%cv139438%_ _%i139443%_ _%f139543%_))
                (_%loop139441%_
                 (let () (declare (not safe)) (##fx+ _%i139443%_ '1))))
              _%cv139438%_))))
    (define type-of
      (lambda (_%obj139432%_)
        (let ()
          (declare (not safe) (not interrupts-enabled))
          (##vector-ref __type (##type _%obj139432%_)))))
    (define class-of
      (lambda (_%obj139423%_)
        (let ()
          (declare (not safe) (not interrupts-enabled))
          (let* ((_%t139427%_ (##type _%obj139423%_))
                 (_%f139429%_ (##vector-ref __class-of _%t139427%_)))
            (_%f139429%_ _%obj139423%_)))))
    (define __subtype-id (let () (declare (not safe)) (##make-vector '32 '#f)))
    (vector-set! __subtype-id (macro-subtype-vector) 'vector)
    (vector-set! __subtype-id (macro-subtype-pair) 'pair)
    (vector-set! __subtype-id (macro-subtype-ratnum) 'ratnum)
    (vector-set! __subtype-id (macro-subtype-cpxnum) 'cpxnum)
    (vector-set! __subtype-id (macro-subtype-symbol) 'symbol)
    (vector-set! __subtype-id (macro-subtype-keyword) 'keyword)
    (vector-set! __subtype-id (macro-subtype-frame) 'frame)
    (vector-set! __subtype-id (macro-subtype-continuation) 'continuation)
    (vector-set! __subtype-id (macro-subtype-promise) 'promise)
    (vector-set! __subtype-id (macro-subtype-weak) 'weak)
    (vector-set! __subtype-id (macro-subtype-procedure) 'procedure)
    (vector-set! __subtype-id (macro-subtype-return) 'return)
    (vector-set! __subtype-id (macro-subtype-foreign) 'foreign)
    (vector-set! __subtype-id (macro-subtype-string) 'string)
    (vector-set! __subtype-id (macro-subtype-s8vector) 's8vector)
    (vector-set! __subtype-id (macro-subtype-u8vector) 'u8vector)
    (vector-set! __subtype-id (macro-subtype-s16vector) 's16vector)
    (vector-set! __subtype-id (macro-subtype-u16vector) 'u16vector)
    (vector-set! __subtype-id (macro-subtype-s32vector) 's32vector)
    (vector-set! __subtype-id (macro-subtype-u32vector) 'u32vector)
    (vector-set! __subtype-id (macro-subtype-f32vector) 'f32vector)
    (vector-set! __subtype-id (macro-subtype-s64vector) 's64vector)
    (vector-set! __subtype-id (macro-subtype-u64vector) 'u64vector)
    (vector-set! __subtype-id (macro-subtype-f64vector) 'f64vector)
    (vector-set! __subtype-id (macro-subtype-flonum) 'haflonum)
    (vector-set! __subtype-id (macro-subtype-bignum) 'bignum)
    (define __system-classes
      (let () (declare (not safe)) (make-symbolic-table__% '#f '0)))
    (define __system-class
      (lambda (_%id139417%_)
        (let ((_%$e139419%_
               (let ()
                 (declare (not safe))
                 (symbolic-table-ref __system-classes _%id139417%_ '#f))))
          (if _%$e139419%_
              _%$e139419%_
              (error '"unknown system class" _%id139417%_)))))
    (define __make-system-class
      (lambda (_%id139319%_ _%super139320%_ _%properties139321%_)
        (let ((_%klass139415%_
               (let* ((_%id139323%_ _%id139319%_)
                      (_%name139326%_ _%id139319%_)
                      (_%direct-supers139329%_ _%super139320%_)
                      (_%direct-slots139332%_ '())
                      (_%properties139335%_
                       (cons '(system: . #t) _%properties139321%_))
                      (_%constructor139338%_ '#f))
                 (if (symbol? _%id139323%_)
                     (let ((_%id139343%_ _%id139323%_))
                       (if (symbol? _%name139326%_)
                           (let ((_%name139359%_ _%name139326%_))
                             (if (list? _%direct-supers139329%_)
                                 (let* ((_%direct-supers139369%_
                                         _%direct-supers139329%_)
                                        (_%direct-slots139379%_
                                         _%direct-slots139332%_)
                                        (_%properties139389%_
                                         _%properties139335%_))
                                   (if (let ((_%$e139401%_ '#t))
                                         (and _%$e139401%_ _%$e139401%_))
                                       (let ((_%constructor139405%_
                                              _%constructor139338%_))
                                         (__make-class-type
                                          _%id139343%_
                                          _%name139359%_
                                          _%direct-supers139369%_
                                          _%direct-slots139379%_
                                          _%properties139389%_
                                          _%constructor139405%_))
                                       (begin
                                         (raise-contract-violation-error
                                          '"contract violation"
                                          'context:
                                          'gerbil/runtime/mop
                                          'contract:
                                          '(? (or not symbol?))
                                          'value:
                                          _%constructor139338%_)
                                         '#!void)))
                                 (begin
                                   (raise-contract-violation-error
                                    '"contract violation"
                                    'context:
                                    'gerbil/runtime/mop
                                    'contract:
                                    'list?
                                    'value:
                                    _%direct-supers139329%_)
                                   '#!void)))
                           (begin
                             (raise-contract-violation-error
                              '"contract violation"
                              'context:
                              'gerbil/runtime/mop
                              'contract:
                              'symbol?
                              'value:
                              _%name139326%_)
                             '#!void)))
                     (begin
                       (raise-contract-violation-error
                        '"contract violation"
                        'context:
                        'gerbil/runtime/mop
                        'contract:
                        'symbol?
                        'value:
                        _%id139323%_)
                       '#!void)))))
          (let ()
            (declare (not safe))
            (symbolic-table-set!
             __system-classes
             _%id139319%_
             _%klass139415%_))
          _%klass139415%_)))))
